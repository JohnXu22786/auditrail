import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Recorder, RuleEngine, DEFAULT_RULES, normalizeConfig } from '../lib/index.js';
import { makeFakeCtx } from './helpers.ts';
import type { AuditRecordInput } from '../lib/index.js';

interface Harness {
  recorder: Recorder;
  ctx: ReturnType<typeof makeFakeCtx>;
  ingested: AuditRecordInput[];
  warnings: unknown[];
}

function recorderFor(opts: { now?: () => number; config?: unknown; ingestError?: boolean } = {}): Harness {
  const config = normalizeConfig(opts.config);
  const engine = new RuleEngine(DEFAULT_RULES, []);
  const ingested: AuditRecordInput[] = [];
  const warnings: unknown[] = [];
  const ctx = makeFakeCtx();
  const recorder = new Recorder({
    config,
    engine,
    now: opts.now ?? (() => 9999),
    ingest: (records) => {
      if (opts.ingestError) throw new Error('boom');
      ingested.push(...records);
    },
    logger: { warn: (message) => warnings.push(message) },
  });
  recorder.attach(ctx);
  return { recorder, ctx, ingested, warnings };
}

/** Drive events through the attached context so the guarded ingest runs. */
function emitSession(ctx: ReturnType<typeof makeFakeCtx>, session = { id: 's1' }, event: { type: string; data: unknown }, seq: number, time: number) {
  ctx.emit('session/event', session, { type: event.type, seq, time, data: event.data });
}

/** A scripted session with a shell call, run through the recorder. */
function scriptedSession(ctx: ReturnType<typeof makeFakeCtx>, offset = 0) {
  const events = [
    { type: 'user/message', data: { content: 'please clean /tmp/x' } },
    { type: 'assistant/chunk', data: { turn: 1, step: 1, chunk: { type: 'text', text: 'a' } } },
    { type: 'turn/start', data: { turn: 1 } },
    { type: 'step/start', data: { turn: 1, step: 1 } },
    {
      type: 'tool/call',
      data: {
        turn: 1,
        step: 1,
        callId: 'call-1',
        name: 'bash',
        arguments: JSON.stringify({ command: 'rm -rf /tmp/x' }),
      },
    },
    { type: 'tool/result', data: { turn: 1, step: 1, message: { content: ['done'] } } },
    { type: 'step/end', data: { turn: 1, step: 1 } },
    { type: 'turn/end', data: { turn: 1, reason: 'complete' } },
  ];
  events.forEach((event, index) => emitSession(ctx, { id: 's1' }, event, index + 1, 1000 + index * 100 + offset));
}

test('records a complete session with flagging, attribution and durations', () => {
  const { ctx, ingested } = recorderFor();
  scriptedSession(ctx);

  const kinds = ingested.map((record) => record.kind);
  assert.ok(kinds.includes('user_message'));
  assert.ok(kinds.includes('turn_start'));
  assert.ok(kinds.includes('step_start'));
  assert.ok(kinds.includes('tool_call'));
  assert.ok(kinds.includes('tool_result'));
  assert.ok(!kinds.includes('assistant_chunk'), 'chunks are off by default');

  const call = ingested.find((record) => record.kind === 'tool_call');
  assert.ok(call);
  assert.equal(call?.toolName, 'bash');
  assert.equal(call?.severity, 'high');
  assert.deepEqual(call?.flags, ['shell:rm-rf']);
  assert.ok(call?.filesRead.includes('/tmp/x'));
  assert.equal(call?.sessionId, 's1');

  const result = ingested.find((record) => record.kind === 'tool_result');
  assert.equal(result?.status, 'ok');
  assert.equal(result?.durationMs, 100, 'duration from event timestamps');
});

test('live tool dispatch picks up callId, status and session via correlation', () => {
  const { ctx, ingested } = recorderFor({ now: () => 5000 });
  scriptedSession(ctx);
  ctx.emit(
    'tools/result',
    {
      callId: 'call-1',
      name: 'bash',
      arguments: { command: 'rm -rf /tmp/x' },
    },
    { isError: false, content: [{ type: 'text', text: 'removed' }] },
  );

  const dispatch = ingested.find((record) => record.kind === 'tool_dispatch');
  assert.ok(dispatch, 'dispatch row recorded');
  assert.equal(dispatch?.toolName, 'bash');
  assert.equal(dispatch?.callId, 'call-1');
  assert.equal(dispatch?.status, 'ok');
  assert.equal(dispatch?.sessionId, 's1', 'session resolved via callId correlation');
  assert.equal(dispatch?.durationMs, undefined, 'consumed by the session result first');
});

test('failed dispatch maps to error/aborted status', () => {
  const { ctx, ingested } = recorderFor();
  ctx.emit(
    'tools/result',
    { callId: 'c-x', name: 'bash', arguments: { command: 'ls' } },
    { isError: true, error: { name: 'ExecError', code: 'EXIT_CODE_1' } },
  );
  const dispatch = ingested.find((record) => record.kind === 'tool_dispatch');
  assert.equal(dispatch?.status, 'error');
  assert.ok(dispatch?.detail?.includes('EXIT_CODE_1'));
});

test('aborted dispatch maps to aborted status', () => {
  const { ctx, ingested } = recorderFor();
  ctx.emit(
    'tools/result',
    { callId: 'c-abort', name: 'bash', arguments: { command: 'sleep' } },
    { isError: true, error: { name: 'AbortError', code: 'ABORTED' } },
  );
  const dispatch = ingested.find((record) => record.kind === 'tool_dispatch');
  assert.equal(dispatch?.status, 'aborted');
});

test('unknown and malformed events are safely skipped', () => {
  const { recorder, ctx, ingested } = recorderFor();
  assert.deepEqual(recorder.onSessionEvent({ id: 's' }, 'garbage'), []);
  assert.deepEqual(
    recorder.onSessionEvent({ id: 's' }, { type: 'some/unknown', data: {} }),
    [],
  );
  ctx.emit('session/event', { id: 's' }, { type: 'plugin/thing', data: {}, ignorable: true });
  assert.equal(ingested.length, 0);
});

test('outbound network requests are captured and flagged', () => {
  const { ctx, ingested } = recorderFor();
  emitSession(
    ctx,
    { id: 's1' },
    {
      type: 'tool/call',
      data: {
        turn: 1,
        step: 1,
        callId: 'c-net',
        name: 'bash',
        arguments: JSON.stringify({ command: 'curl -s https://10.0.0.9:8443/tunnel' }),
      },
    },
    1,
    1000,
  );
  const call = ingested.find((record) => record.kind === 'tool_call');
  assert.ok(call);
  assert.ok(call?.network.includes('https://10.0.0.9:8443/tunnel'));
  assert.ok(call?.flags.includes('net:exfil-literal-ip'));
  assert.equal(call?.severity, 'high');
});

test('ingest failures are contained and logged', () => {
  const { ctx, ingested, warnings } = recorderFor({ ingestError: true });
  assert.doesNotThrow(() => {
    emitSession(
      ctx,
      { id: 's' },
      {
        type: 'tool/call',
        data: { turn: 1, step: 1, callId: 'c', name: 'bash', arguments: 'echo hi' },
      },
      1,
      1,
    );
  });
  assert.equal(ingested.length, 0);
  assert.ok(warnings.length > 0, 'ingest failure logged');
});

test('capture.chunks records assistant chunks when enabled', () => {
  const { ctx, ingested } = recorderFor({ config: { capture: { chunks: true } } });
  emitSession(
    ctx,
    { id: 's' },
    { type: 'assistant/chunk', data: { turn: 1, step: 1, chunk: { type: 'text', text: 'hi' } } },
    9,
    900,
  );
  assert.ok(ingested.some((record) => record.kind === 'assistant_chunk'));
});

test('capture flags disable subscription through attach()', () => {
  const noonAttached = recorderFor({
    config: { capture: { toolDispatch: false, toolRegistered: false } },
  });
  assert.ok(noonAttached.ctx.handlers.has('session/event'));
  assert.ok(!noonAttached.ctx.handlers.has('tools/result'), 'dispatch hook disabled');
  assert.ok(!noonAttached.ctx.handlers.has('tools/change'), 'registry hook disabled');
});

test('tools/change emits registration and unregistration deltas', () => {
  const ingested: AuditRecordInput[] = [];
  let tools = ['bash', 'read_file'];
  const recorder = new Recorder({
    config: normalizeConfig(undefined),
    engine: new RuleEngine(DEFAULT_RULES, []),
    now: () => 42,
    ingest: (records) => ingested.push(...records),
    scrapeTools: () => tools,
    logger: undefined,
  });
  const last = new Set<string>();
  ingested.push(...recorder.onToolChange(last));
  tools = ['bash'];
  ingested.push(...recorder.onToolChange(last));
  const registered = ingested.filter((record) => record.summary.endsWith('registered'));
  const unregistered = ingested.filter((record) => record.summary.endsWith('unregistered'));
  assert.ok(registered.some((record) => record.toolName === 'read_file'));
  assert.ok(registered.some((record) => record.toolName === 'bash'));
  assert.ok(unregistered.some((record) => record.toolName === 'read_file'));
  assert.equal(ingested.filter((record) => record.kind === 'tool_registered').length, 3);
});

test('parallel tool calls in one step pair results in arrival order (FIFO)', () => {
  const { ctx, ingested } = recorderFor();
  // Two calls in the SAME (turn, step), then their results (no callId on the
  // session results) — each result must attach to the *oldest* open call.
  emitSession(ctx, { id: 's1' }, { type: 'tool/call', data: { turn: 1, step: 1, callId: 'p1', name: 'bash', arguments: '{"command":"a"}' } }, 1, 1000);
  emitSession(ctx, { id: 's1' }, { type: 'tool/call', data: { turn: 1, step: 1, callId: 'p2', name: 'bash', arguments: '{"command":"b"}' } }, 2, 2000);
  emitSession(ctx, { id: 's1' }, { type: 'tool/result', data: { turn: 1, step: 1, message: { content: 'r1' } } }, 3, 3000);
  emitSession(ctx, { id: 's1' }, { type: 'tool/result', data: { turn: 1, step: 1, message: { content: 'r2' } } }, 4, 4000);

  const results = ingested.filter((record) => record.kind === 'tool_result');
  assert.equal(results.length, 2);
  // First result pairs with p1 (started at t=1000 → 2000ms), second with p2.
  assert.equal(results[0]?.callId, 'p1');
  assert.equal(results[0]?.durationMs, 2000);
  assert.equal(results[1]?.callId, 'p2');
  assert.equal(results[1]?.durationMs, 2000);
});

test('session results pairing with explicit callId never misattributes a later result', () => {
  const { ctx, ingested } = recorderFor();
  // Same (turn,step): two calls, then a result WITH callId, then a call-less one.
  emitSession(ctx, { id: 's1' }, { type: 'tool/call', data: { turn: 1, step: 1, callId: 'q1', name: 'bash', arguments: '{"command":"a"}' } }, 1, 1000);
  emitSession(ctx, { id: 's1' }, { type: 'tool/call', data: { turn: 1, step: 1, callId: 'q2', name: 'bash', arguments: '{"command":"b"}' } }, 2, 2000);
  emitSession(ctx, { id: 's1' }, { type: 'tool/result', data: { turn: 1, step: 1, callId: 'q1', message: { content: 'r1' } } }, 3, 3000);
  emitSession(ctx, { id: 's1' }, { type: 'tool/result', data: { turn: 1, step: 1, message: { content: 'r2' } } }, 4, 4000);

  const results = ingested.filter((record) => record.kind === 'tool_result');
  assert.equal(results[0]?.callId, 'q1', 'explicit callId honored');
  assert.equal(results[0]?.durationMs, 2000);
  assert.equal(results[1]?.callId, 'q2', 'call-less result takes the next FIFO call');
  assert.equal(results[1]?.durationMs, 2000);
});

test('embedded URL credentials never reach stored record fields', () => {
  const { ctx, ingested } = recorderFor();
  emitSession(
    ctx,
    { id: 's1' },
    {
      type: 'tool/call',
      data: {
        turn: 1,
        step: 1,
        callId: 'curl-1',
        name: 'bash',
        arguments: JSON.stringify({ command: 'curl https://admin:supersecret123@accounts.example.com/api' }),
      },
    },
    1,
    1000,
  );
  const call = ingested.find((record) => record.kind === 'tool_call');
  assert.ok(call);
  assert.ok(!(call?.summary ?? '').includes('supersecret123'), 'summary redacted');
  assert.ok(!(call?.argsDigest ?? '').includes('supersecret123'), 'digest redacted');
  assert.deepEqual(call?.network, ['https://accounts.example.com/api'], 'network column clean');
});

test('recording is deterministic for the same input stream', () => {
  const a = recorderFor();
  const b = recorderFor();
  scriptedSession(a.ctx);
  scriptedSession(b.ctx);
  assert.deepEqual(a.ingested, b.ingested);
});
