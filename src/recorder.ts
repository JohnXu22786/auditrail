/**
 * The recorder: subscribes to the two observability seams the harness exposes
 * and turns their events into {@link AuditRecordInput} rows.
 *
 * Sources:
 *  - `session/event (session, event)` â€” the append-only, durable session log
 *    (user/assistant messages, turn/step brackets, `tool/call` + `tool/result`,
 *    todo writes, request headers, ...).
 *  - `tools/result (exec, result)` â€” the live, frozen outcome of one tool
 *    dispatch (precise status, structured error, parsed arguments, callId).
 *  - `tools/change ()` â€” the tool registry changed (registrations/unregistrations).
 *
 * All handlers are contained: the recorder must never break the harness, so a
 * failing ingest or malformed event only downgrades to a logged warning.
 *
 * Correlation: each `tool/call` remembers its start timestamp keyed by callId
 * (and, as a fallback, the most recent callId at each session/turn/step slot).
 * The matching `tool/result` (session) and `tools/result` (live) both consume
 * it to compute the wall-clock duration; whichever settles first wins, and the
 * query layer later merges the three kinds into one {@link ToolChain}.
 */
import type { AuditConfig, RedactConfig } from './config.js';
import type { RuleEngine, RuleCandidate } from './rules.js';
import { digestArgs, tryParseJson, maskText, buildSecretMask } from './redact.js';
import { scanText, attributeFiles, stripUrlUserinfo } from './scan.js';
import { asFiniteNumber } from './util.js';
import type { AuditRecordInput, Severity, ToolStatus } from './types.js';

const MAX_PENDING = 8192;

/** Minimal `ctx` surface the recorder needs. */
export interface RecorderContext {
  on(event: string, handler: (...args: unknown[]) => void): () => void;
}

/** How the host feeds the recorder its rows and the helpers it can call. */
export interface RecorderOptions {
  config: AuditConfig;
  engine: RuleEngine;
  /** Persist normalized records (callback into the store; never throws). */
  ingest: (records: AuditRecordInput[]) => void;
  /** Current wall-clock in epoch ms (injectable for tests). */
  now?: () => number;
  /** Snapshot of currently visible tool names for `tools/change` deltas. */
  scrapeTools?: () => string[];
  logger?: { warn?: (message: string, ...details: unknown[]) => void };
}

interface PendingCall {
  sessionId: string;
  ts: number;
  turn?: number;
  step?: number;
  used: boolean;
}

/** Defensive pluck of an object-ish value. */
function obj(value: unknown): Record<string, unknown> {
  return value != null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function str(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

function sessionIdOf(session: unknown): string {
  if (session != null && typeof session === 'object') {
    const record = session as Record<string, unknown>;
    const id = str(record.id) ?? str(record.sessionId);
    if (id) return id;
  }
  return 'unknown';
}

/** Extract textual content from a string, a ContentBlock[], or an object. */
export function extractContentText(value: unknown): string {
  if (typeof value === 'string') return value;
  if (value == null) return '';
  if (Array.isArray(value)) {
    const parts: string[] = [];
    for (const block of value) {
      const text = str(obj(block).text);
      if (text) parts.push(text);
    }
    return parts.join('\n');
  }
  return JSON.stringify(value);
}

/** Map an optional error payload to a {@link ToolStatus}. */
function statusFromError(hasError: boolean, code: string | undefined): ToolStatus {
  if (!hasError) return 'ok';
  if (code === 'ABORTED' || code === 'ABORTED_BEFORE_DISPATCH') return 'aborted';
  return 'error';
}

function slotKey(sessionId: string, turn: number | undefined, step: number | undefined): string {
  return `${sessionId}|${turn ?? '-'}|${step ?? '-'}`;
}

export class Recorder {
  private readonly pendingByCallId = new Map<string, PendingCall>();
  private readonly pendingOrder: string[] = [];
  /** Per (session,turn,step) FIFO of open callIds, in arrival order. */
  private readonly slotQueues = new Map<string, string[]>();
  /** callId â†’ slot key (used to detach a call from its queue on dispatch). */
  private readonly callSlot = new Map<string, string>();

  constructor(private readonly opts: RecorderOptions) {}

  private get redact(): RedactConfig {
    return this.opts.config.redact;
  }

  private now(): number {
    return this.opts.now ? this.opts.now() : Date.now();
  }

  private warn(message: string, error?: unknown): void {
    this.opts.logger?.warn?.(message, error);
  }

/**
   * Subscribe to every configured harness event. Disposers are pushed into the
   * caller-provided array as each subscription succeeds, so if a later
   * `ctx.on` call throws, the subscriptions already registered are still
   * delivered to the caller for cleanup (no partial-subscription leak).
   */
  attach(ctx: RecorderContext, disposers: Array<() => void> = []): Array<() => void> {
    const cfg = this.opts.config.capture;
    if (cfg.toolDispatch) {
      disposers.push(
        ctx.on('tools/result', (exec, result) => this.guarded(() => this.onToolResult(exec, result))),
      );
    }
    if (cfg.toolRegistered) {
      const lastNames = new Set<string>();
      disposers.push(
        ctx.on('tools/change', () => this.guarded(() => this.onToolChange(lastNames))),
      );
    }
    disposers.push(
      ctx.on('session/event', (session, event) => this.guarded(() => this.onSessionEvent(session, event))),
    );
    return disposers;
  }

  private guarded(build: () => AuditRecordInput[]): void {
    try {
      const records = build();
      if (records.length === 0) return;
      this.opts.ingest(records);
    } catch (error) {
      this.warn('audit ingest failed', error);
    }
  }

  /** Normalize one durable session event into audit records. */
  onSessionEvent(session: unknown, event: unknown): AuditRecordInput[] {
    const ev = obj(event);
    const type = typeof ev.type === 'string' ? ev.type : '';
    if (type === '') return [];
    const data = obj(ev.data);
    const sessionId = sessionIdOf(session);
    const ts = asFiniteNumber(ev.time) ?? this.now();
    const sourceSeq = asFiniteNumber(ev.seq);
    const turn = asFiniteNumber(data.turn);
    const step = asFiniteNumber(data.step);
    const base = {
      sessionId,
      ts,
      sourceType: type,
      sourceSeq,
      turn,
      step,
      severity: 'info' as Severity,
      flags: [] as string[],
      filesRead: [] as string[],
      filesWritten: [] as string[],
      network: [] as string[],
    };

    const cfg = this.opts.config.capture;
    switch (type) {
      case 'user/message':
        return [{ ...base, kind: 'user_message', summary: this.preview(extractContentText(data.content ?? data.message)) }];
      case 'assistant/message':
        return [{ ...base, kind: 'assistant_message', summary: this.preview(extractContentText(data.message)) }];
      case 'assistant/chunk':
        return cfg.chunks
          ? [{ ...base, kind: 'assistant_chunk', summary: this.preview(extractContentText(data.chunk)) }]
          : [];
      case 'tool/call':
        return [this.toolCall(base, data)];
      case 'tool/result':
        return [this.toolResult(base, data)];
      case 'turn/start':
        return cfg.turnEvents ? [{ ...base, kind: 'turn_start', summary: `turn ${turn ?? '?'} started` }] : [];
      case 'turn/end': {
        if (!cfg.turnEvents) return [];
        const reason = str(data.reason) ?? '';
        return [
          { ...base, kind: 'turn_end', summary: `turn ${turn ?? '?'} ended${reason ? ` (${reason})` : ''}` },
        ];
      }
      case 'step/start':
        return cfg.stepEvents
          ? [{ ...base, kind: 'step_start', summary: `step ${step ?? '?'} of turn ${turn ?? '?'} started` }]
          : [];
      case 'step/end':
        return cfg.stepEvents
          ? [{ ...base, kind: 'step_end', summary: `step ${step ?? '?'} of turn ${turn ?? '?'} ended` }]
          : [];
      case 'todo/write': {
        const todos = Array.isArray(data.todos) ? data.todos : [];
        const inProgress = todos.filter((t) => obj(t).status === 'in_progress').length;
        return [
          {
            ...base,
            kind: 'todo_update',
            summary: `todo list snapshot (${todos.length} items, ${inProgress} in progress)`,
          },
        ];
      }
      case 'request/header': {
        const header = obj(data.header);
        const cfgObj = obj(header.config);
        const model = str(cfgObj.model) ?? '';
        const provider = str(cfgObj.provider) ?? '';
        return [
          {
            ...base,
            kind: 'request_header',
            summary: `request header${provider ? ` provider=${provider}` : ''}${model ? ` model=${model}` : ''}`,
          },
        ];
      }
      case 'request/context': {
        const provider = str(data.provider) ?? '';
        const model = str(data.model) ?? '';
        return [
          {
            ...base,
            kind: 'request_context',
            summary: `request context${provider ? ` provider=${provider}` : ''}${model ? ` model=${model}` : ''}`,
          },
        ];
      }
      case 'session/end-seed':
        return [{ ...base, kind: 'session_live', summary: 'live history begins' }];
      default:
        // Unknown / ignorable event types are safely skipped.
        return [];
    }
  }

  /** @internal normalized `tool/call` record. */
  private toolCall(
    base: Omit<AuditRecordInput, 'kind' | 'summary'>,
    data: Record<string, unknown>,
  ): AuditRecordInput {
    const name = str(data.name) ?? 'unknown';
    const callId = str(data.callId) ?? str(data.call_id);
    const rawArgs =
      typeof data.arguments === 'string' ? data.arguments : JSON.stringify(data.arguments ?? {});
    const digest = digestArgs(rawArgs, this.redact);
    const scanned = scanText(rawArgs, this.redact);
    const attr = attributeFiles(rawArgs, tryParseJson(rawArgs), scanned.files, this.redact);
    const matched = this.score({
      toolName: name,
      args: rawArgs,
      files: scanned.files,
      network: this.redactNetwork(scanned.network),
    });

    const resolvedCallId = callId ?? `${base.sessionId}:${base.ts}`;
    this.rememberCall(resolvedCallId, base.sessionId, base.ts, base.turn, base.step);

    return {
      ...base,
      kind: 'tool_call',
      toolName: name,
      callId: resolvedCallId,
      argsDigest: digest,
      status: 'pending',
      severity: matched.severity,
      flags: matched.ids,
      filesRead: attr.filesRead,
      filesWritten: attr.filesWritten,
      network: this.redactNetwork(scanned.network),
      summary: this.preview(digest ? `${name} â€” ${digest}` : name),
    };
  }

  /** @internal normalized session `tool/result` record. */
  private toolResult(
    base: Omit<AuditRecordInput, 'kind' | 'summary'>,
    data: Record<string, unknown>,
  ): AuditRecordInput {
    const message = obj(data.message);
    const error = obj(data.error);
    const hasError = data.error != null;
    const code = str(error.code);
    const status = statusFromError(hasError, code);
const resultText = extractContentText(message.content ?? data.message);
    const callId = str(data.callId) ?? this.consumeSlot(base.sessionId, base.turn, base.step);
    const duration = this.endCall(callId, base.ts);
    // An explicit callId on a session result was consumed directly; detach it
    // from the slot FIFO so a later call-less result cannot be misattributed.
    if (callId) this.detachCall(callId);

    const scanned = scanText(resultText, this.redact);
    const matched = this.score({
      result: resultText,
      files: scanned.files,
      network: this.redactNetwork(scanned.network),
    });

    return {
      ...base,
      kind: 'tool_result',
      toolName: undefined,
      callId: callId ?? undefined,
      status,
      durationMs: duration,
      severity: matched.severity,
      flags: matched.ids,
      filesRead: scanned.files,
      filesWritten: [],
      network: this.redactNetwork(scanned.network),
      summary: this.preview(
        `${status}${duration != null ? ` in ${duration}ms` : ''}${code ? ` (${code})` : ''}`,
      ),
      detail:
        code !== undefined || str(error.name) !== undefined
          ? this.preview(JSON.stringify({ error: str(error.name) ?? code, code: code ?? null }))
          : undefined,
    };
  }

  /** @internal normalized live `tools/result` dispatch record. */
  onToolResult(exec: unknown, result: unknown): AuditRecordInput[] {
    const ex = obj(exec);
    const res = obj(result);
    const name = str(ex.name);
    if (!name) return [];

    const callId = str(ex.callId) ?? str(ex.call_id);
    const rawArgs = typeof ex.arguments === 'string' ? ex.arguments : JSON.stringify(ex.arguments ?? {});
    const digest = digestArgs(rawArgs, this.redact);
    const scanned = scanText(rawArgs, this.redact);
    const attr = attributeFiles(rawArgs, tryParseJson(rawArgs), scanned.files, this.redact);
    const ts = this.now();

    const isError = res.isError === true;
    const error = obj(res.error);
    const code = str(error.code);
    const status = statusFromError(isError, code);

    const recall = callId ? this.pendingByCallId.get(callId) : undefined;
    const sessionId = recall?.sessionId ?? 'unknown';
    const duration = this.endCall(callId, ts);
    // The live dispatch already consumed this call; drop it from the slot FIFO
    // so a later session `tool/result` does not misattribute another call.
    if (callId) this.detachCall(callId);

    const resultText = extractContentText(res.content);
    const matched = this.score({
      toolName: name,
      args: rawArgs,
      result: resultText,
      files: scanned.files,
      network: this.redactNetwork(scanned.network),
    });

    return [
      {
        sessionId,
        ts,
        kind: 'tool_dispatch',
        turn: recall?.turn,
        step: recall?.step,
        toolName: name,
        callId: callId ?? undefined,
        argsDigest: digest,
        status,
        durationMs: duration,
        severity: matched.severity,
        flags: matched.ids,
        filesRead: attr.filesRead,
        filesWritten: attr.filesWritten,
        network: this.redactNetwork(scanned.network),
        summary: this.preview(`${name} ${status}${duration != null ? ` in ${duration}ms` : ''}`),
        detail:
          status === 'error' || status === 'aborted'
            ? this.preview(JSON.stringify({ error: str(error.name) ?? code, code: code ?? null }))
            : undefined,
        sourceType: 'tools/result',
      },
    ];
  }

  /** @internal registry-change record (`tools/change`). */
  onToolChange(lastNames: Set<string>): AuditRecordInput[] {
    if (!this.opts.scrapeTools) return [];
    let current: Set<string>;
    try {
      current = new Set(this.opts.scrapeTools());
    } catch (error) {
      this.warn('tool scrape failed', error);
      return [];
    }
    const records: AuditRecordInput[] = [];
    const ts = this.now();
    const emit = (toolName: string, event: string): void => {
      records.push({
        sessionId: 'registry',
        ts,
        kind: 'tool_registered',
        toolName,
        summary: this.preview(`${toolName} ${event}`),
        sourceType: 'tools/change',
      });
    };
    for (const name of current) {
      if (!lastNames.has(name)) emit(name, 'registered');
    }
    for (const name of lastNames) {
      if (!current.has(name)) emit(name, 'unregistered');
    }
    lastNames.clear();
    for (const name of current) lastNames.add(name);
    return records;
  }

  /** Redact outbound network destinations (userinfo + embedded secrets). */
  private redactNetwork(list: readonly string[]): string[] {
    if (list.length === 0) return [];
    const mask = buildSecretMask(this.redact);
    return list.map((entry) => maskText(stripUrlUserinfo(entry), mask));
  }

  /** Mask + truncate a free-form preview string. */
  private preview(text: string): string {
    if (text.length === 0) return '';
    const mask = buildSecretMask(this.redact);
    const masked = maskText(text, mask);
    if (masked.length <= this.redact.truncateSummary) return masked;
    return `${masked.slice(0, this.redact.truncateSummary)}â€¦(+${masked.length - this.redact.truncateSummary} chars)`;
  }

  /** Score a candidate against the effective rule engine. */
  private score(candidate: RuleCandidate): { ids: string[]; severity: Severity } {
    return this.opts.engine.match(candidate);
  }

  /** Start-of-call bookkeeping used by both result sources. */
  private rememberCall(callId: string, sessionId: string, ts: number, turn?: number, step?: number): void {
    this.pendingByCallId.set(callId, { sessionId, ts, turn, step, used: false });
    this.pendingOrder.push(callId);
    if (this.pendingOrder.length > MAX_PENDING) {
      const oldest = this.pendingOrder.shift();
      if (oldest) {
        this.pendingByCallId.delete(oldest);
        this.detachCall(oldest);
      }
    }
    const key = slotKey(sessionId, turn, step);
    this.callSlot.set(callId, key);
    const queue = this.slotQueues.get(key);
    if (queue) queue.push(callId);
    else this.slotQueues.set(key, [callId]);
  }

  /** Remove a call from its slot FIFO (used on eviction and dispatch-consume). */
  private detachCall(callId: string): void {
    const key = this.callSlot.get(callId);
    if (!key) return;
    this.callSlot.delete(callId);
    const queue = this.slotQueues.get(key);
    if (!queue) return;
    const index = queue.indexOf(callId);
    if (index >= 0) queue.splice(index, 1);
    if (queue.length === 0) this.slotQueues.delete(key);
  }

  /** Pop the oldest open callId at (session, turn, step), if any. */
  private consumeSlot(sessionId: string, turn?: number, step?: number): string | undefined {
    const queue = this.slotQueues.get(slotKey(sessionId, turn, step));
    const callId = queue?.shift();
    if (callId === undefined) return undefined;
    if (!this.pendingByCallId.has(callId)) return undefined;
    this.callSlot.delete(callId);
    if (queue && queue.length === 0) this.slotQueues.delete(slotKey(sessionId, turn, step));
    return callId;
  }

  /**
   * Close a pending call and return its wall-clock duration. The first caller
   * (session `tool/result` or live `tools/result`) consumes the entry; later
   * callers get `undefined` (records still carry their own status/detail).
   * Consumed entries are kept until pruned so the live event can still resolve
   * the owning sessionId.
   */
  private endCall(callId: string | undefined, ts: number): number | undefined {
    if (!callId) return undefined;
    const entry = this.pendingByCallId.get(callId);
    if (!entry || entry.used) return undefined;
    entry.used = true;
    return Math.max(0, ts - entry.ts);
  }
}

