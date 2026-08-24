/**
 * Stand-alone CLI for the audit trail. Works on the same SQLite store the dsh
 * plugin writes to, so an operator can query/export/replay a session without
 * starting the harness. If the database path is omitted, the default dsh home
 * location is used (same as the plugin).
 *
 *   auditrail help
 *   auditrail stats [--db P]
 *   auditrail query [filters...] [--json|--markdown] [--chains] [--limit N]
 *   auditrail export --format json|markdown|jsonl [--out PATH] [--hash-chain]
 *                   [--chains] [filters...]
 *   auditrail playback [--session S] [--speed N] [--interactive] [--cap N] [--colors]
 *   auditrail policy list | show <id> | enable <id> | disable <id>
 *                    | add --id ID --pattern RE [--severity S] [--scope ARG]
 *   auditrail chain verify [--db P]
 *   auditrail verify-compliant --file PATH
 *
 * The bin launcher (`bin/auditrail.mjs`) calls {@link run} with argv; this
 * module exports `run` for programmatic and test use.
 */
import { readFileSync } from 'node:fs';
import { AuditStore, resolveDbPath } from './store.js';
import { AuditService } from './service.js';
import { normalizeConfig } from './config.js';
import { verifyComplianceJsonl } from './query.js';
import { runInteractive, type TimelineRow } from './playback.js';
import { mergeToolChains } from './query.js';
import { markdownChainReport, markdownReport } from './query.js';
import { SEVERITIES, type AuditFilters, type Severity } from './types.js';
import type { ToolChain } from './types.js';

type Flavor = 'json' | 'markdown' | 'jsonl';

interface ParsedArgs {
  flags: Map<string, string>;
  booleans: Set<string>;
  positionals: string[];
}

function parseArgs(argv: string[]): ParsedArgs {
  const flags = new Map<string, string>();
  const booleans = new Set<string>();
  const positionals: string[] = [];
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i] as string;
    if (token.startsWith('--')) {
      const body = token.slice(2);
      const eq = body.indexOf('=');
      if (eq >= 0) {
        flags.set(body.slice(0, eq), body.slice(eq + 1));
      } else if (i + 1 < argv.length && !(argv[i + 1] as string).startsWith('--')) {
        flags.set(body, argv[i + 1] as string);
        i += 1;
      } else {
        booleans.add(body);
      }
    } else {
      positionals.push(token);
    }
  }
  return { flags, booleans, positionals };
}

function dbPathOf(args: ParsedArgs): string {
  const flag = args.flags.get('db');
  const env = process.env.AUDITRAIL_DB;
  return resolveDbPath(flag, [env]);
}

function buildFilters(args: ParsedArgs): AuditFilters {
  const filters: AuditFilters = {};
  const flag = (name: string): string | undefined => args.flags.get(name);
  if (flag('from')) filters.from = flag('from');
  if (flag('to')) filters.to = flag('to');
  if (flag('session')) filters.sessionId = flag('session');
  if (flag('tool')) filters.toolName = flag('tool');
  const severity = flag('severity') ?? flag('min-severity');
  if (severity && (SEVERITIES as readonly string[]).includes(severity)) {
    filters.minSeverity = severity as Severity;
  }
  if (flag('flag')) filters.flag = flag('flag');
  if (flag('kind')) filters.kind = flag('kind') as AuditFilters['kind'];
  const limit = flag('limit');
  if (limit !== undefined) filters.limit = Math.max(1, Math.min(10000, Number(limit) || 100));
  const offset = flag('offset');
  if (offset !== undefined) filters.offset = Math.max(0, Number(offset) || 0);
  if (flag('order')) filters.order = flag('order') === 'desc' ? 'desc' : 'asc';
  if (flag('sort')) filters.sortBy = flag('sort') === 'time' ? 'time' : 'id';
  return filters;
}

function serviceFor(path: string): { store: AuditStore; service: AuditService } {
  const store = AuditStore.open(path);
  return { store, service: new AuditService(store, normalizeConfig(undefined)) };
}

function printHelp(): void {
  process.stdout.write(
    [
      'auditrail — security audit & forensics for DeepSeek Harness (dsh)',
      '',
      'Usage:',
      '  auditrail help',
      '  auditrail stats [--db P]',
      '  auditrail query [--db P] [--from D] [--to D] [--session S] [--tool T]',
      '                  [--severity LVL] [--flag TAG] [--kind K] [--limit N] [--offset N]',
      '                  [--order asc|desc] [--sort id|time] [--json|--markdown] [--chains]',
      '  auditrail export [--db P] --format json|markdown|jsonl [--out PATH]',
      '                  [--hash-chain] [--chains] [same filters as query]',
      '  auditrail playback [--db P] [--session S] [--speed N] [--interactive] [--cap N] [--colors] [--chains]',
      '  auditrail policy list | show <id> | enable <id> | disable <id>',
      '         | add --id ID --pattern RE [--severity LVL] [--scope args|result|files|network|all|tool]',
      '  auditrail chain verify [--db P]',
      '  auditrail verify-compliant --file PATH',
      '',
      'The default database lives under the dsh home ($DSH_HOME or ~/.dsh):',
      '  <dshHome>/audit-trail/audit.sqlite',
      '',
    ].join('\n'),
  );
}

function serializeRecord(record: {
  id: number;
  ts: number;
  sessionId: string;
  kind: string;
  toolName?: string;
  summary: string;
  severity: string;
  flags: string[];
  status?: string;
  durationMs?: number;
}) {
  return {
    id: record.id,
    ts: record.ts,
    sessionId: record.sessionId,
    kind: record.kind,
    toolName: record.toolName ?? null,
    summary: record.summary,
    severity: record.severity,
    flags: record.flags,
    status: record.status ?? null,
    durationMs: record.durationMs ?? null,
  };
}

/** Execute one CLI invocation; returns the process exit code. */
export async function run(argv: string[]): Promise<number> {
  const args = parseArgs(argv);
  const command = args.positionals[0] ?? 'help';

  if (command === 'help' || command === '--help' || command === '-h') {
    printHelp();
    return 0;
  }

  // `verify-compliant` never touches the audit database — do not open (or,
  // worse, create) the default store as a side effect of a pure read-only check.
  if (command === 'verify-compliant') {
    const path = args.flags.get('file') ?? args.positionals[1];
    if (!path) {
      process.stderr.write('verify-compliant needs --file PATH or a positional path\n');
      return 2;
    }
    try {
      const report = verifyComplianceJsonl(readFileSync(path, 'utf8'));
      if (report.valid) {
        process.stdout.write(`compliance JSONL valid (${report.records} records)\n`);
        return 0;
      }
      process.stderr.write(`${report.issues.length} issue(s):\n`);
      for (const issue of report.issues.slice(0, 20)) process.stderr.write(`  - ${issue}\n`);
      return 1;
    } catch (error) {
      process.stderr.write(`auditrail: ${error instanceof Error ? error.message : String(error)}\n`);
      return 1;
    }
  }

  const dbPath = dbPathOf(args);
  let store: AuditStore | undefined;
  try {
    const opened = serviceFor(dbPath);
    store = opened.store;
    return await dispatch(opened.service, command, args);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(`auditrail: ${message}\n`);
    return 1;
  } finally {
    store?.close();
  }
}

/** Run one sub-command against an open store; returns the exit code. */
async function dispatch(
  service: AuditService,
  command: string,
  args: ParsedArgs,
): Promise<number> {
    switch (command) {
      case 'stats': {
        const stats = service.stats();
        process.stdout.write(
          `${JSON.stringify(
            {
              database: dbPathOf(args),
              total: stats.total,
              schemaVersion: stats.schemaVersion,
              byKind: stats.byKind,
              bySeverity: stats.bySeverity,
              byTag: stats.byTag,
              firstTs: stats.firstTs,
              lastTs: stats.lastTs,
            },
            null,
            2,
          )}\n`,
        );
        return 0;
      }
      case 'query': {
        const filters = buildFilters(args);
        const asChains = args.booleans.has('chains');
        const flavor: Flavor = args.booleans.has('markdown') ? 'markdown' : 'json';
        if (asChains) {
          const chains = service.queryChains(filters);
          if (flavor === 'markdown') {
            process.stdout.write(markdownChainReport(chains, {}));
          } else {
            process.stdout.write(`${JSON.stringify({ count: chains.length, chains }, null, 2)}\n`);
          }
          return 0;
        }
        const { records, total } = service.queryRecords(filters);
        if (flavor === 'markdown') {
          process.stdout.write(markdownReport(records, {}, Date.now()));
        } else {
          process.stdout.write(
            `${JSON.stringify({ count: records.length, total, records: records.map(serializeRecord) }, null, 2)}\n`,
          );
        }
        return 0;
      }
      case 'export': {
        const format = (args.flags.get('format') ?? 'json') as Flavor;
        if (!['json', 'markdown', 'jsonl'].includes(format)) {
          process.stderr.write(`unknown format ${format}\n`);
          return 2;
        }
        const result = service.exportText({
          format,
          filters: buildFilters(args),
          hashChain: args.booleans.has('hash-chain'),
          asChains: args.booleans.has('chains'),
        });
        const outPath = args.flags.get('out');
        if (outPath) {
          const { writeFileSync } = await import('node:fs');
          writeFileSync(outPath, result.content, 'utf8');
          process.stdout.write(
            `${JSON.stringify(
              {
                format,
                path: outPath,
                bytes: Buffer.byteLength(result.content),
                count: result.count,
                hashChain: result.hashChain,
              },
              null,
              2,
            )}\n`,
          );
        } else {
          process.stdout.write(result.content);
        }
        return 0;
      }
      case 'playback': {
        const filters = buildFilters(args);
        const records = service.store.query(filters).records;
        const asChains = args.booleans.has('chains');
        const cap = Number(args.flags.get('cap')) || 100000;
        const chains = asChains ? mergeToolChains(records) : undefined;
        const sourceLen = chains ? chains.length : records.length;
        const over = sourceLen - cap;
        const timelineRows: TimelineRow[] = [];
        if (chains) {
          for (const chain of chains.slice(0, cap)) timelineRows.push(chainToRow(chain));
        } else {
          for (const record of records.slice(0, cap)) timelineRows.push(recordToRow(record));
        }
        await runInteractive(timelineRows, {
          speed: Number(args.flags.get('speed')) || 1,
          colors: args.booleans.has('colors'),
          interactive: args.booleans.has('interactive'),
        });
        if (over > 0) process.stderr.write(`…(+${over} more rows — raise --cap)\n`);
        return 0;
      }
      case 'policy': {
        const sub = args.positionals[1] ?? 'list';
        if (sub === 'list') {
          process.stdout.write(`${JSON.stringify({ rules: service.policyList() }, null, 2)}\n`);
          return 0;
        }
        if (sub === 'add') {
          // flag-driven; no positional id expected
          const rid = args.flags.get('id');
          const pattern = args.flags.get('pattern');
          if (!rid || !pattern) {
            process.stderr.write('policy add needs --id and --pattern\n');
            return 2;
          }
          const scope = args.flags.get('scope') as
            | 'args'
            | 'result'
            | 'files'
            | 'network'
            | 'all'
            | 'tool'
            | undefined;
          const scopes: Array<'args' | 'result' | 'files' | 'network' | 'all' | 'tool'> = [
            'args',
            'result',
            'files',
            'network',
            'all',
            'tool',
          ];
          const severity = args.flags.get('severity') ?? 'high';
          if (!(SEVERITIES as readonly string[]).includes(severity)) {
            process.stderr.write(`invalid severity ${severity} (expected ${SEVERITIES.join('|')})\n`);
            return 2;
          }
          const added = service.policyAdd({
            id: rid,
            severity: severity as Severity,
            pattern,
            scope: scope && scopes.includes(scope) ? scope : 'args',
            description: args.flags.get('description') ?? '',
          });
          if (!added.ok) {
            process.stderr.write(`${added.error}\n`);
            return 2;
          }
          process.stdout.write(`added rule ${rid}\n`);
          return 0;
        }
        const id = args.positionals[2];
        if (sub === 'show') {
          if (!id) {
            process.stderr.write('policy show needs a rule id\n');
            return 2;
          }
          const rule = service.policyList().find((entry) => entry.id === id) ?? null;
          if (rule === null) {
            process.stderr.write(`unknown rule ${id}\n`);
            return 2;
          }
          process.stdout.write(`${JSON.stringify(rule, null, 2)}\n`);
          return 0;
        }
        if (sub === 'enable' || sub === 'disable') {
          if (!id) {
            process.stderr.write(`policy ${sub} needs a rule id\n`);
            return 2;
          }
          if (!service.policySetEnabled(id, sub === 'enable')) {
            process.stderr.write(`unknown rule ${id}\n`);
            return 2;
          }
          process.stdout.write(`${id} ${sub === 'enable' ? 'enabled' : 'disabled'}\n`);
          return 0;
        }
        process.stderr.write(`unknown policy sub-command ${sub}\n`);
        return 2;
      }
      case 'chain': {
        const sub = args.positionals[1] ?? 'verify';
        if (sub === 'verify') {
          const violations = service.verifyChain();
          if (violations.length === 0) {
            process.stdout.write(`hash chain intact (${service.stats().total} records)\n`);
            return 0;
          }
          process.stderr.write(`hash chain violations: ${violations.length}\n`);
          for (const violation of violations.slice(0, 20)) {
            process.stderr.write(`  #${violation.id}: ${violation.reason}\n`);
          }
          return 1;
        }
        process.stderr.write(`unknown chain sub-command ${sub}\n`);
        return 2;
      }
      default:
        process.stderr.write(`unknown command ${command}\n`);
        printHelp();
        return 2;
    }
}

function chainToRow(chain: ToolChain) {
  return {
    id: chain.id,
    ts: chain.ts,
    kind: 'tool_call',
    toolName: chain.toolName,
    severity: chain.severity,
    flags: chain.flags,
    summary: `${chain.toolName ?? ''} ${chain.status}${chain.durationMs != null ? ` in ${chain.durationMs}ms` : ''}`,
    durationMs: chain.durationMs,
  };
}

function recordToRow(record: {
  id: number;
  ts: number;
  kind: string;
  toolName?: string;
  severity: Severity;
  flags: string[];
  summary: string;
  durationMs?: number;
}) {
  return {
    id: record.id,
    ts: record.ts,
    kind: record.kind,
    toolName: record.toolName,
    severity: record.severity,
    flags: record.flags,
    summary: record.summary,
    durationMs: record.durationMs,
  };
}
