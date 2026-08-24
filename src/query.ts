/**
 * Pure report/chain logic: merges the three tool record kinds into complete
 * invocation chains, and renders sorted record sets as JSON, Markdown, or the
 * fixed-format compliance JSONL (with an optional SHA-256 event hash chain).
 * This module never touches the store; the service/cli/tools wire it up.
 */
import { sha256Hex, stableStringify } from './util.js';
import {
  maxSeverity,
  type AuditRecord,
  type Severity,
  type ToolChain,
  type ToolStatus,
} from './types.js';

/** Versioned ownership stamp used in exports. */
export const BUNDLE_NAME = 'dsh-audit-trail';
export const COMPLIANCE_SCHEMA = 'dsh-audit-trail/compliance/1';

function unionOrdered(...lists: Array<readonly string[] | undefined>): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const list of lists) {
    for (const item of list ?? []) {
      if (!seen.has(item)) {
        seen.add(item);
        out.push(item);
      }
    }
  }
  return out;
}

function slotOf(rec: AuditRecord): string {
  return `${rec.sessionId}|${rec.turn ?? '-'}|${rec.step ?? '-'}`;
}

function chainKeyOf(rec: AuditRecord): string {
  return rec.callId ?? `${rec.sessionId}|${rec.turn ?? '-'}|${rec.step ?? '-'}|${rec.id}`;
}

/**
 * Merge `tool_call` records with their linked `tool_result` (session+turn+step,
 * consumed FIFO so parallel calls in one step pair in arrival order) and
 * `tool_dispatch` (by callId) into one closed chain per invocation. Records are
 * emitted in the input order of their `tool_call`.
 */
export function mergeToolChains(records: readonly AuditRecord[]): ToolChain[] {
  // Per-slot FIFO of tool_result records, in arrival order.
  const resultQueues = new Map<string, AuditRecord[]>();
  const dispatchByKey = new Map<string, AuditRecord>();
  for (const rec of records) {
    if (rec.kind === 'tool_result') {
      const key = slotOf(rec);
      const queue = resultQueues.get(key);
      if (queue) queue.push(rec);
      else resultQueues.set(key, [rec]);
    } else if (rec.kind === 'tool_dispatch' && rec.callId) {
      dispatchByKey.set(rec.callId, rec);
    }
  }

  const chains: ToolChain[] = [];
  for (const rec of records) {
    if (rec.kind !== 'tool_call') continue;
    const call = rec;
    const dispatch = rec.callId ? dispatchByKey.get(rec.callId) : undefined;
    const key = slotOf(rec);
    const queue = resultQueues.get(key);
    const result = queue?.shift();
    if (queue && queue.length === 0) resultQueues.delete(key);
    chains.push(buildChain(call, dispatch, result));
  }
  return chains;
}

function severityOfMany(...sources: Array<{ severity: Severity } | undefined>): Severity {
  let severity: Severity = 'info';
  for (const source of sources) {
    if (source) severity = maxSeverity(severity, source.severity);
  }
  return severity;
}

function buildChain(call: AuditRecord, dispatch?: AuditRecord, result?: AuditRecord): ToolChain {
  const sources = [call, dispatch, result].filter(Boolean) as AuditRecord[];
  const status: ToolStatus = dispatch?.status ?? result?.status ?? call.status ?? 'pending';
  const durationMs = dispatch?.durationMs ?? result?.durationMs;
  const error =
    dispatch?.detail && dispatch.status !== 'ok' ? dispatch.detail : result?.detail ?? undefined;
  const flags = unionOrdered(...sources.map((s) => s.flags));
  return {
    id: call.id,
    ts: call.ts,
    sessionId: call.sessionId,
    turn: call.turn,
    step: call.step,
    callId: call.callId,
    toolName: call.toolName,
    argsDigest: call.argsDigest,
    status,
    durationMs,
    error,
    severity: severityOfMany(call, dispatch, result),
    flags,
    filesRead: unionOrdered(call.filesRead, dispatch?.filesRead, result?.filesRead),
    filesWritten: unionOrdered(call.filesWritten, dispatch?.filesWritten, result?.filesWritten),
    network: unionOrdered(call.network, dispatch?.network, result?.network),
    summary: dispatch?.summary ?? call.summary ?? call.toolName ?? '',
  };
}

/* ------------------------------------------------------------------------- *
 * Fixed compliance payload shape (schema v1). One field set, used by the
 * JSON report, the JSONL export and its verifier so all three agree.
 * ------------------------------------------------------------------------- */

export function compliancePayload(rec: AuditRecord): Record<string, unknown> {
  return {
    id: rec.id,
    sessionId: rec.sessionId,
    ts: rec.ts,
    kind: rec.kind,
    turn: rec.turn ?? null,
    step: rec.step ?? null,
    toolName: rec.toolName ?? null,
    callId: rec.callId ?? null,
    argsDigest: rec.argsDigest ?? null,
    status: rec.status ?? null,
    durationMs: rec.durationMs ?? null,
    severity: rec.severity,
    flags: [...rec.flags].sort(),
    filesRead: rec.filesRead,
    filesWritten: rec.filesWritten,
    network: rec.network,
    actor: rec.actor ?? null,
    sourceType: rec.sourceType,
    sourceSeq: rec.sourceSeq ?? null,
    summary: rec.summary,
  };
}

export interface ReportFiltersSnapshot {
  [key: string]: unknown;
}

/** A JSON report the CLI and the `audit_export` tool produce. */
export interface JsonReport {
  app: string;
  schema: 'dsh-audit-trail/report/1';
  generatedAt: number;
  count: number;
  filters: ReportFiltersSnapshot;
  records: Array<Record<string, unknown>>;
}

export function jsonReport(
  records: readonly AuditRecord[],
  filters: ReportFiltersSnapshot,
  generatedAt = Date.now(),
): JsonReport {
  return {
    app: BUNDLE_NAME,
    schema: 'dsh-audit-trail/report/1',
    generatedAt,
    count: records.length,
    filters,
    records: records.map(compliancePayload),
  };
}

function timecodeUtc(ts: number): string {
  const d = new Date(ts);
  const pad = (n: number, width = 2): string => String(n).padStart(width, '0');
  return `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}.${pad(d.getUTCMilliseconds(), 3)}`;
}

function isoUtc(ts: number): string {
  return new Date(ts).toISOString();
}

export function markdownReport(
  records: readonly AuditRecord[],
  filters: ReportFiltersSnapshot = {},
  generatedAt = Date.now(),
): string {
  const lines: string[] = [];
  lines.push('# Audit trail report');
  lines.push('');
  lines.push(`- Generated: ${isoUtc(generatedAt)} (UTC) · records: ${records.length}`);
  const filterText = Object.entries(filters)
    .filter(([, value]) => value !== undefined && value !== null && value !== '')
    .map(([key, value]) => `${key}=${Array.isArray(value) ? value.join(',') : String(value)}`);
  if (filterText.length > 0) lines.push(`- Filters: ${filterText.join(' · ')}`);
  if (records.length === 0) {
    lines.push('');
    lines.push('_No records matched the filters._');
    return lines.join('\n') + '\n';
  }
  lines.push('');
  lines.push('| # | Time (UTC) | Kind | Tool | Status | Dur (ms) | Sev | Summary |');
  lines.push('|---|---|---|---|---|---|---|---|');
  for (const rec of records) {
    const tool = rec.toolName ?? '-';
    const status = rec.status ?? '-';
    const duration = rec.durationMs != null ? String(rec.durationMs) : '-';
    const summary = rec.summary.replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
    const sev = rec.severity.toUpperCase();
    const kind = rec.kind;
    lines.push(
      `| ${rec.id} | ${timecodeUtc(rec.ts)} | ${kind} | ${tool} | ${status} | ${duration} | ${sev} | ${summary} |`,
    );
  }
  return lines.join('\n') + '\n';
}

/** Markdown render of full tool invocation chains (forensics-friendly). */
export function markdownChainReport(
  chains: readonly ToolChain[],
  filters: ReportFiltersSnapshot = {},
  generatedAt = Date.now(),
): string {
  const lines: string[] = [];
  lines.push('# Tool invocation chains');
  lines.push('');
  lines.push(`- Generated: ${isoUtc(generatedAt)} (UTC) · chains: ${chains.length}`);
  const filterText = Object.entries(filters)
    .filter(([, value]) => value !== undefined && value !== null && value !== '')
    .map(([key, value]) => `${key}=${String(value)}`);
  if (filterText.length > 0) lines.push(`- Filters: ${filterText.join(' · ')}`);
  lines.push('');
  for (const chain of chains) {
    lines.push(`## ${chain.toolName ?? 'tool'} · ${chain.severity.toUpperCase()} · ${chain.status}`);
    lines.push(`- Record #${chain.id} · session \`${chain.sessionId}\``);
    if (chain.turn != null || chain.step != null) {
      lines.push(`- Turn ${chain.turn ?? '-'} · step ${chain.step ?? '-'}`);
    }
    if (chain.callId) lines.push(`- callId \`${chain.callId}\``);
    if (chain.argsDigest) lines.push(`- args: \`${chain.argsDigest.replace(/\|/g, '\\|')}\``);
    if (chain.durationMs != null) lines.push(`- duration: ${chain.durationMs} ms`);
    if (chain.error) lines.push(`- error: \`${chain.error}\``);
    if (chain.filesRead.length > 0) lines.push(`- files read: \`${chain.filesRead.join(', ')}\``);
    if (chain.filesWritten.length > 0) {
      lines.push(`- files written: \`${chain.filesWritten.join(', ')}\``);
    }
    if (chain.network.length > 0) lines.push(`- network: \`${chain.network.join(', ')}\``);
    if (chain.flags.length > 0) lines.push(`- flags: ${chain.flags.map((f) => `\`${f}\``).join(', ')}`);
    lines.push('');
  }
  return lines.join('\n') + '\n';
}

export interface ComplianceOptions {
  hashChain?: boolean;
}

/**
 * Fixed-format compliance JSONL. Line 1 is a header; each following line holds
 * one record in the v1 payload shape with `prevHash`/`hashSelf` when the hash
 * chain is enabled. `hashSelf` covers the previous line's hash plus this
 * line's content.
 */
export function complianceJsonl(records: readonly AuditRecord[], opts: ComplianceOptions = {}): string {
  const hashChain = opts.hashChain === true;
  const lines: string[] = [];
  const header = {
    schema: COMPLIANCE_SCHEMA,
    generatedAt: Date.now(),
    count: records.length,
    hashChain,
  };
  lines.push(JSON.stringify(header));
  let prevHash = '';
  for (const rec of records) {
    const payload = compliancePayload(rec);
    const line: Record<string, unknown> = { recordId: rec.id, prevHash: prevHash || null, payload };
    if (hashChain) {
      line.hashSelf = sha256Hex(`${prevHash}\n${stableStringify(line)}\n`);
    }
    lines.push(JSON.stringify(line));
    prevHash = hashChain ? String(line.hashSelf) : '';
  }
  return lines.join('\n') + '\n';
}

export interface ComplianceVerification {
  valid: boolean;
  lines: number;
  records: number;
  issues: string[];
}

/** Verify a compliance JSONL produced by {@link complianceJsonl}. */
export function verifyComplianceJsonl(text: string): ComplianceVerification {
  const issues: string[] = [];
  const lines = text.split(/\r?\n/).filter((line) => line.trim() !== '');
  if (lines.length === 0) {
    return { valid: false, lines: 0, records: 0, issues: ['empty document'] };
  }
  let header: Record<string, unknown>;
  try {
    header = JSON.parse(lines[0] as string) as Record<string, unknown>;
  } catch {
    return { valid: false, lines: lines.length, records: 0, issues: ['malformed header'] };
  }
  if (header.schema !== COMPLIANCE_SCHEMA) {
    issues.push(`unexpected schema ${String(header.schema)}`);
  }
  // The header declares whether a hash chain is expected; a chainless export is
  // still structurally verified.
  const hashChain = header.hashChain === true;
  let prevHash = '';
  let records = 0;
  let malformed = 0;
  for (const raw of lines.slice(1)) {
    let line: Record<string, unknown>;
    try {
      line = JSON.parse(raw) as Record<string, unknown>;
    } catch {
      issues.push(`malformed line at record slot #${records + malformed + 1}`);
      malformed += 1;
      continue;
    }
    records += 1;
    if (line.recordId === undefined || line.payload === undefined) {
      issues.push(`record ${String(line.recordId)} missing recordId/payload`);
    }
    const signature = { recordId: line.recordId, prevHash: line.prevHash ?? null, payload: line.payload };
    if (hashChain) {
      if (line.hashSelf === undefined) {
        issues.push(`record ${String(line.recordId)} missing hashSelf`);
      } else {
        const expected = sha256Hex(`${prevHash}\n${stableStringify(signature)}\n`);
        if (line.hashSelf !== expected) {
          issues.push(`record ${String(line.recordId)} hash mismatch`);
        }
      }
      if (line.prevHash !== (prevHash || null)) {
        issues.push(`record ${String(line.recordId)} prevHash mismatch`);
      }
      if (line.hashSelf !== undefined) prevHash = String(line.hashSelf);
    }
  }
  if (typeof header.count === 'number' && header.count !== records) {
    issues.push(`header count ${header.count} does not match ${records} parsed lines`);
  }
  return { valid: issues.length === 0, lines: lines.length, records, issues };
}
