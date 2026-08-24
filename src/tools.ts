/**
 * The model-facing tool set this bundle registers on `ctx.tools`:
 *
 *   audit_query    — filter/search the recorded audit trail (JSON or Markdown).
 *   audit_export   — export filtered records as JSON / Markdown / compliance JSONL.
 *   audit_policy   — inspect and tweak the sensitive-rule table at runtime.
 *   audit_playback — render a session/records slice as a plain-text timeline.
 *
 * Each tool is a thin adapter over {@link AuditService}; all state lives in
 * the service (store + rule engine + config).
 */
import { defineTool, type JsonValue } from '@deepseek-ai/dsh-tools';
import { writeFileSync } from 'node:fs';
import { compliancePayload, markdownChainReport, markdownReport, mergeToolChains } from './query.js';
import { renderTimeline } from './playback.js';
import { AUDIT_KINDS, SEVERITIES, type AuditFilters, type Severity } from './types.js';
import type { AuditService, ExportFormat } from './service.js';
import type { RuleScope } from './rules.js';

const asJsonText = (_args: unknown, value: unknown) => [
  { type: 'text' as const, text: JSON.stringify(value, null, 2) },
];

/**
 * dsh tool bodies must return canonical lossless-JSON values. A JSON round-trip
 * both satisfies the declared `{ type: 'json' }` output schema and drops any
 * `undefined` optional fields (which JSON.stringify omits anyway).
 */
function jsonify<T>(value: T): JsonValue {
  return JSON.parse(JSON.stringify(value)) as JsonValue;
}

/** Build typed filters from the flat argument object of a query-style tool. */
function filtersFromArgs(args: Record<string, unknown>): { filters: AuditFilters; params: Record<string, unknown> } {
  const filters: AuditFilters = {};
  const params: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(args)) {
    if (value === undefined || value === null) continue;
    switch (key) {
      case 'session_id': filters.sessionId = String(value); params.sessionId = value; break;
      case 'tool_name': filters.toolName = String(value); params.toolName = value; break;
      case 'min_severity': filters.minSeverity = String(value) as Severity; params.minSeverity = value; break;
      case 'flag': filters.flag = String(value); params.flag = value; break;
      case 'kind': filters.kind = String(value) as AuditFilters['kind']; params.kind = value; break;
      case 'from': filters.from = String(value); params.from = value; break;
      case 'to': filters.to = String(value); params.to = value; break;
      case 'limit': filters.limit = Number(value); params.limit = value; break;
      default: break;
    }
  }
  return { filters, params };
}

export function defineAuditTools(service: AuditService) {
  const auditQuery = defineTool({
    name: 'audit_query',
    description:
      'Query the recorded security audit trail. Returns persisted records (or merged tool ' +
      'invocation chains) filtered by session, tool, minimum severity, sensitive-rule flag, ' +
      'kind, and a time window. Every tool call/result/dispatch is captured from the harness ' +
      'session stream and the tool pipeline, so this answers "what did the agent execute, with ' +
      'what outcome, and did it trip any high-risk pattern".',
    parameters: {
      session_id: { type: 'string', description: 'Restrict to one session id.' },
      tool_name: { type: 'string', description: 'Restrict to records of one tool (e.g. bash, read_file).' },
      min_severity: {
        type: 'string',
        enum: [...SEVERITIES],
        description: 'Only records at least this severe (info|low|medium|high|critical).',
      },
      flag: {
        type: 'string',
        description: 'Only records carrying this sensitive-rule tag (e.g. shell:rm-rf, file:key-material).',
      },
      kind: { type: 'string', enum: [...AUDIT_KINDS], description: 'Restrict to one record kind.' },
      from: { type: 'string', description: 'Earliest bound: ISO datetime or epoch milliseconds.' },
      to: { type: 'string', description: 'Latest bound: ISO datetime or epoch milliseconds.' },
      limit: { type: 'integer', description: 'Maximum rows returned (default 100, max 10000).' },
      chains: {
        type: 'boolean',
        description: 'Merge tool_call + tool_result + tool_dispatch into complete invocation chains.',
      },
      format: { type: 'string', enum: ['json', 'markdown'], description: 'Output format (default json).' },
    },
    output: { schema: { type: 'json' }, render: asJsonText },
    async execute(args) {
      const { filters, params } = filtersFromArgs(args as Record<string, unknown>);
      const limit = typeof filters.limit === 'number' ? filters.limit : 100;
      filters.limit = Math.max(1, Math.min(10000, limit));
      if (args.chains) {
        const chains = mergeToolChains(service.store.query(filters).records);
        if (args.format === 'markdown') {
          return jsonify({ count: chains.length, format: 'markdown', text: markdownChainReport(chains, params) });
        }
        return jsonify({ count: chains.length, format: 'json', chains });
      }
      const { records, total } = service.queryRecords(filters);
      if (args.format === 'markdown') {
        return jsonify({ count: records.length, total, format: 'markdown', text: markdownReport(records, params) });
      }
      return jsonify({ count: records.length, total, format: 'json', records: records.map(compliancePayload) });
    },
  });

  const auditExport = defineTool({
    name: 'audit_export',
    description:
      'Export filtered audit records as a JSON report, a Markdown report, or the fixed-format ' +
      'compliance JSONL (optionally with a SHA-256 event hash chain). Writes to an absolute file ' +
      'path when given, otherwise returns the content inline.',
    parameters: {
      format: {
        type: 'string',
        enum: ['json', 'markdown', 'jsonl'],
        description: 'json (report) | markdown (report/chain report) | jsonl (compliance). Default json.',
      },
      path: {
        type: 'string',
        description: 'Absolute output path to write the file (optional; otherwise content is returned).',
      },
      session_id: { type: 'string' },
      tool_name: { type: 'string' },
      min_severity: { type: 'string', enum: [...SEVERITIES] },
      flag: { type: 'string' },
      kind: { type: 'string', enum: [...AUDIT_KINDS] },
      from: { type: 'string' },
      to: { type: 'string' },
      limit: { type: 'integer', description: 'Maximum rows (default 10000).' },
      hash_chain: { type: 'boolean', description: 'Include the event hash chain (jsonl only).' },
      chains: { type: 'boolean', description: 'Emit merged invocation chains for markdown output.' },
    },
    output: { schema: { type: 'json' }, render: asJsonText },
    async execute(args) {
      const { filters, params } = filtersFromArgs(args as Record<string, unknown>);
      const format = (args.format ?? 'json') as ExportFormat;
      filters.limit = Math.max(1, Math.min(10000, typeof args.limit === 'number' ? args.limit : 10000));
      const result = service.exportText({
        format,
        filters,
        hashChain: args.hash_chain === true,
        asChains: args.chains === true,
        filterSnapshot: params,
      });
      if (typeof args.path === 'string' && args.path.length > 0) {
        writeFileSync(args.path, result.content, 'utf8');
        return jsonify({
          format: result.format,
          path: args.path,
          bytes: Buffer.byteLength(result.content, 'utf8'),
          count: result.count,
          hash_chain: result.hashChain,
          message: `wrote ${result.count} records`,
        });
      }
      return jsonify({
        format: result.format,
        count: result.count,
        hash_chain: result.hashChain,
        content: result.content,
      });
    },
  });

  const SCOPES = ['args', 'result', 'files', 'network', 'all', 'tool'] as const;

  const auditPolicy = defineTool({
    name: 'audit_policy',
    description:
      'Inspect and modify the sensitive-operation rule table. list returns every rule with its ' +
      'enabled state; enable/disable toggles a built-in rule; add registers an operator regex ' +
      'rule. Changes are runtime-only and reset on plugin restart (persist via configuration).',
    parameters: {
      action: {
        type: 'string',
        enum: ['list', 'show', 'disable', 'enable', 'add'],
        description: 'What to do (default list).',
      },
      rule_id: { type: 'string', description: 'Rule id for show/disable/enable.' },
      severity: { type: 'string', enum: [...SEVERITIES], description: 'Severity for a new rule.' },
      pattern: { type: 'string', description: 'Regex source for a new rule.' },
      scope: { type: 'string', enum: [...SCOPES], description: 'Field the new rule inspects (default args).' },
      description: { type: 'string', description: 'Human description for a new rule.' },
    },
    output: { schema: { type: 'json' }, render: asJsonText },
    async execute(args) {
      const action = args.action ?? 'list';
      if (action === 'list') {
        return jsonify({ rules: service.policyList() });
      }
      if (action === 'show') {
        if (!args.rule_id) return jsonify({ ok: false, error: 'rule_id is required' });
        const rule = service.policyList().find((entry) => entry.id === args.rule_id) ?? null;
        return jsonify(rule === null ? { ok: false, error: `unknown rule ${args.rule_id}` } : { rule });
      }
      if (action === 'disable' || action === 'enable') {
        if (!args.rule_id) return jsonify({ ok: false, error: 'rule_id is required' });
        const ok = service.policySetEnabled(args.rule_id, action === 'enable');
        return jsonify(ok ? { ok: true, action, rule_id: args.rule_id } : { ok: false, error: `unknown rule ${args.rule_id}` });
      }
      if (action === 'add') {
        if (!args.rule_id || !args.pattern) {
          return jsonify({ ok: false, error: 'rule_id and pattern are required for add' });
        }
        const scopeTrusted = (SCOPES as readonly string[]).includes(String(args.scope ?? 'args'))
          ? (args.scope as RuleScope)
          : 'args';
        const added = service.policyAdd({
          id: String(args.rule_id),
          severity: (args.severity ?? 'high') as Severity,
          pattern: String(args.pattern),
          scope: scopeTrusted,
          description: typeof args.description === 'string' ? args.description : '',
        });
        return jsonify(
          added.ok
            ? { ok: true, rule_id: String(args.rule_id), severity: args.severity ?? 'high' }
            : { ok: false, error: added.error },
        );
      }
      return jsonify({ ok: false, error: `unknown action ${String(action)}` });
    },
  });

  const auditPlayback = defineTool({
    name: 'audit_playback',
    description:
      'Render a slice of the audit trail as a plain-text terminal timeline for slow-motion review ' +
      '(one line per event: timecode, record id, kind, tool, severity, flags, redacted summary, ' +
      'duration). Prefer chains=true to collapse each tool invocation to its merged outcome line. ' +
      'For interactive pause/step/speed replay use the `auditrail playback` CLI.',
    parameters: {
      session_id: { type: 'string' },
      from: { type: 'string' },
      to: { type: 'string' },
      min_severity: { type: 'string', enum: [...SEVERITIES] },
      flag: { type: 'string' },
      kind: { type: 'string', enum: [...AUDIT_KINDS] },
      limit: { type: 'integer', description: 'Maximum rows considered (default 1000).' },
      cap: { type: 'integer', description: 'Maximum lines returned (default 500).' },
      chains: { type: 'boolean', description: 'Render merged invocation chains as the timeline.' },
    },
    output: { schema: { type: 'json' }, render: asJsonText },
    async execute(args) {
      const { filters } = filtersFromArgs(args as Record<string, unknown>);
      filters.limit = Math.max(1, Math.min(10000, typeof args.limit === 'number' ? args.limit : 1000));
      const cap = Math.max(1, args.cap ?? 500);
      const records = service.store.query(filters).records;
      const lines = args.chains
        ? renderTimeline(mergeToolChains(records).map(chainToTimelineRecord), {})
        : renderTimeline(records, {});
      const totalLines = lines.length;
      const capped = lines.slice(0, cap);
      const truncated = totalLines > cap;
      return jsonify({
        count: capped.length,
        totalLines,
        truncated,
        text:
          capped.join('\n') +
          (truncated ? `\n…(+${totalLines - cap} lines — raise cap or use the CLI)` : ''),
      });
    },
  });

  return [auditQuery, auditExport, auditPolicy, auditPlayback];
}

/** Project a merged chain onto the minimal row the timeline renderer wants. */
function chainToTimelineRecord(chain: {
  id: number;
  ts: number;
  turn?: number;
  step?: number;
  toolName?: string;
  status: string;
  durationMs?: number;
  severity: Severity;
  flags: string[];
  summary: string;
}) {
  return {
    id: chain.id,
    ts: chain.ts,
    kind: 'tool_call',
    turn: chain.turn,
    step: chain.step,
    toolName: chain.toolName,
    status: chain.status,
    durationMs: chain.durationMs,
    severity: chain.severity,
    flags: chain.flags,
    summary: chain.summary,
  };
}
