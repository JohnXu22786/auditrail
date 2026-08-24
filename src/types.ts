/**
 * Core domain types for the audit trail: severities, record kinds, the stored
 * record shape, the merged tool-chain view, and query filters.
 */

/** One of five confidence-ish levels attached to every audit record. */
export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

/** Severity values in ascending order (for tool/CLI enumerations). */
export const SEVERITIES: readonly Severity[] = ['info', 'low', 'medium', 'high', 'critical'];

/** Numeric rank used for `minSeverity` filtering; higher is more severe. */
export const SEVERITY_ORDER: Readonly<Record<Severity, number>> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
} as const;

export function severityRank(severity: Severity): number {
  return SEVERITY_ORDER[severity];
}

/** The more severe of two severities. */
export function maxSeverity(a: Severity, b: Severity): Severity {
  return severityRank(a) >= severityRank(b) ? a : b;
}

/**
 * Record kinds the recorder can produce. `tool_call`/`tool_result` come from
 * the durable session event stream; `tool_dispatch` comes from the live tool
 * pipeline hook; `tool_registered` from the registry-changed hook.
 */
export type AuditKind =
  | 'session_live'
  | 'turn_start'
  | 'turn_end'
  | 'step_start'
  | 'step_end'
  | 'user_message'
  | 'assistant_message'
  | 'assistant_chunk'
  | 'todo_update'
  | 'request_header'
  | 'request_context'
  | 'tool_call'
  | 'tool_result'
  | 'tool_dispatch'
  | 'tool_registered';

/** Result state of one tool execution. */
export type ToolStatus = 'ok' | 'error' | 'aborted' | 'pending';

/** Record kinds in stable order (drives enums/CLI completions). */
export const AUDIT_KINDS: readonly AuditKind[] = [
  'session_live',
  'turn_start',
  'turn_end',
  'step_start',
  'step_end',
  'user_message',
  'assistant_message',
  'assistant_chunk',
  'todo_update',
  'request_header',
  'request_context',
  'tool_call',
  'tool_result',
  'tool_dispatch',
  'tool_registered',
];

/**
 * The shape the recorder hands to the store. Identifiers, hashes, and
 * normalized arrays are added by the store before persistence.
 */
export interface AuditRecordInput {
  sessionId: string;
  ts: number;
  kind: AuditKind;
  turn?: number;
  step?: number;
  toolName?: string;
  callId?: string;
  /** Masked + truncated tool-argument summary. */
  argsDigest?: string;
  status?: ToolStatus;
  durationMs?: number;
  severity?: Severity;
  /** Matched sensitive-rule ids (also stored as tags for filtering). */
  flags?: string[];
  summary: string;
  /** Redacted supplementary JSON detail, when any. */
  detail?: string;
  filesRead?: string[];
  filesWritten?: string[];
  network?: string[];
  actor?: string;
  /** Original upstream event type, e.g. `tool/call`. */
  sourceType: string;
  /** Per-session sequence number from the upstream event, when present. */
  sourceSeq?: number;
}

/** A fully materialized, persisted record. */
export interface AuditRecord extends AuditRecordInput {
  id: number;
  severity: Severity;
  flags: string[];
  filesRead: string[];
  filesWritten: string[];
  network: string[];
  hashPrev: string | null;
  hashSelf: string | null;
}

/**
 * One closed tool-invocation entry: a `tool_call` merged with its linked
 * `tool_result` and `tool_dispatch`. This is the "complete invocation chain"
 * (who / when / which command / which files / outcome / duration) surfaced by
 * `audit_query --chains` and the playback/export tools.
 */
export interface ToolChain {
  id: number;
  /** Timestamp of the underlying `tool_call`. */
  ts: number;
  sessionId: string;
  turn?: number;
  step?: number;
  callId?: string;
  toolName?: string;
  argsDigest?: string;
  status: ToolStatus;
  durationMs?: number;
  error?: string;
  severity: Severity;
  flags: string[];
  filesRead: string[];
  filesWritten: string[];
  network: string[];
  summary: string;
}

/** All query dimensions supported by the store and the query tools. */
export interface AuditFilters {
  /** Start bound: epoch ms number, ISO string, or URL-searchable date. */
  from?: number | string;
  /** End bound (inclusive). */
  to?: number | string;
  sessionId?: string;
  toolName?: string;
  /** Only records at least this severe. */
  minSeverity?: Severity;
  /** Only records carrying this sensitive-rule tag. */
  flag?: string;
  kind?: AuditKind | AuditKind[];
  limit?: number;
  offset?: number;
  order?: 'asc' | 'desc';
  sortBy?: 'id' | 'time';
}
