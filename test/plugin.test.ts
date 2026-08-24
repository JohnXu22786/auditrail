import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as plugin from '../lib/index.js';
import { makeFakeCtx, tempFilePath } from './helpers.ts';
import { AuditStore } from '../lib/store.js';

test('entry exports the bundle contract', () => {
  assert.equal(plugin.name, 'dsh-audit-trail');
  assert.ok(plugin.inject?.includes('tools'), 'injects the tools service');
  assert.equal(typeof plugin.apply, 'function');
});

test('apply registers the four audit tools and subscribes the recorder', () => {
  const ctx = makeFakeCtx();
  const db = tempFilePath();
  const dispose = plugin.apply(ctx as never, { storage: { path: db } });
  assert.equal(typeof dispose, 'function', 'apply returns a fiber disposer');

  const names = ctx.registeredTools.slice().sort();
  assert.deepEqual(names, [
    'audit_export',
    'audit_playback',
    'audit_policy',
    'audit_query',
  ]);
  assert.ok(ctx.handlers.has('session/event'), 'subscribes to session/event');
  assert.ok(ctx.handlers.has('tools/result'), 'subscribes to tools/result');
  assert.ok(ctx.handlers.has('tools/change'), 'subscribes to tools/change');
  dispose();
});

test('apply records a session tool call into the store end-to-end', () => {
  const ctx = makeFakeCtx();
  const db = tempFilePath();
  const dispose = plugin.apply(ctx as never, { storage: { path: db } });

  ctx.emit(
    'session/event',
    { id: 'sess-1' },
    {
      type: 'tool/call',
      seq: 1,
      time: 1700000000000,
      data: {
        turn: 1,
        step: 1,
        callId: 'call-1',
        name: 'bash',
        arguments: JSON.stringify({ command: 'rm -rf /tmp/scratch' }),
      },
    },
  );
  ctx.emit(
    'session/event',
    { id: 'sess-1' },
    {
      type: 'tool/result',
      seq: 2,
      time: 1700000002000,
      data: { turn: 1, step: 1, message: 'ok' },
    },
  );

  dispose();

  const store = AuditStore.open(db);
  try {
    const { records } = store.query({});
    assert.equal(records.length, 2);
    const call = records.find((rec) => rec.kind === 'tool_call');
    assert.ok(call, 'tool_call recorded');
    assert.equal(call?.toolName, 'bash');
    assert.equal(call?.sessionId, 'sess-1');
    assert.equal(call?.severity, 'high');
    assert.ok(call?.flags.includes('shell:rm-rf'), 'high-risk flag attached');
    assert.ok(call?.filesRead.includes('/tmp/scratch'), 'file attribution recorded');
    const result = records.find((rec) => rec.kind === 'tool_result');
    assert.equal(result?.status, 'ok');
    assert.equal(result?.durationMs, 2000);
    assert.deepEqual(store.verifyChain(), [], 'hash chain intact');
  } finally {
    store.close();
  }
});

test('the disposed store is closed and disposal is idempotent', () => {
  const ctx = makeFakeCtx();
  const db = tempFilePath();
  const dispose = plugin.apply(ctx as never, { storage: { path: db } });
  ctx.emit(
    'session/event',
    { id: 's' },
    { type: 'tool/call', seq: 1, time: 1, data: { turn: 1, step: 1, callId: 'c', name: 'bash', arguments: '{}' } },
  );
  dispose();
  assert.doesNotThrow(() => dispose(), 'a second dispose is a no-op');
});

test('apply accepts partial configuration without throwing', () => {
  const ctx = makeFakeCtx();
  const db = tempFilePath();
  const dispose = plugin.apply(ctx as never, {
    storage: { path: db },
    capture: { chunks: false, turnEvents: false, stepEvents: false },
  });
  dispose();
});
