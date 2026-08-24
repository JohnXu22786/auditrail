import { test } from 'node:test';
import assert from 'node:assert/strict';
import { AuditStore } from '../lib/index.js';
import { tempFilePath } from './helpers.ts';
import type { AuditRecordInput } from '../lib/index.js';

function seed(store: AuditStore) {
  const rows: AuditRecordInput[] = [
    {
      sessionId: 's-a',
      ts: 1000,
      kind: 'tool_call',
      toolName: 'bash',
      callId: 'c1',
      argsDigest: '{"command":"rm -rf /x"}',
      status: 'pending',
      severity: 'high',
      flags: ['shell:rm-rf'],
      summary: 'bash',
      filesRead: ['/x'],
      sourceType: 'tool/call',
      sourceSeq: 1,
    },
    {
      sessionId: 's-a',
      ts: 2000,
      kind: 'tool_result',
      status: 'ok',
      durationMs: 1000,
      summary: 'ok in 1000ms',
      sourceType: 'tool/result',
      sourceSeq: 2,
    },
    {
      sessionId: 's-b',
      ts: 3000,
      kind: 'tool_dispatch',
      toolName: 'git',
      callId: 'c2',
      argsDigest: '{"args":["push","--force"]}',
      status: 'error',
      severity: 'critical',
      flags: ['git:force-push'],
      summary: 'git error',
      sourceType: 'tools/result',
    },
    {
      sessionId: 's-b',
      ts: 4000,
      kind: 'user_message',
      summary: 'hello world',
      sourceType: 'user/message',
      sourceSeq: 3,
    },
  ];
  return store.insert(rows);
}

test('opens with WAL journal mode and creates a usable schema', () => {
  const path = tempFilePath();
  const store = AuditStore.open(path);
  try {
    assert.equal(store.journalMode().toLowerCase(), 'wal');
    assert.equal(store.stats().schemaVersion, 1);
  } finally {
    store.close();
  }
});

test('in-memory store works', () => {
  const store = AuditStore.open(':memory:');
  try {
    const records = seed(store);
    assert.ok(records.length > 0);
    assert.deepEqual(store.verifyChain(), []);
  } finally {
    store.close();
  }
});

test('resolveDbPath passes :memory: through unmodified', async () => {
  const { resolveDbPath } = await import('../lib/store.js');
  assert.equal(resolveDbPath(':memory:'), ':memory:');
  assert.equal(resolveDbPath(':memory:', ['C:/x.sqlite']), ':memory:');
  assert.equal(resolveDbPath(undefined, [':memory:']), ':memory:');
});

test('inserts assign monotonic ids and chain observed times', () => {
  const store = AuditStore.open(':memory:');
  try {
    const inserted = seed(store);
    const ids = inserted.map((record) => record.id);
    assert.deepEqual(ids, [...ids].sort((a, b) => a - b));
    assert.equal(new Set(ids).size, ids.length);
    assert.ok(inserted[0]?.hashSelf, 'first row hashed');
    assert.equal(inserted[1]?.hashPrev, inserted[0]?.hashSelf, 'chain links rows');
    assert.deepEqual(store.query({ sessionId: 's-a' }).records.map((r) => r.sessionId), ['s-a', 's-a']);
  } finally {
    store.close();
  }
});

test('verifyChain detects tampering', () => {
  const store = AuditStore.open(':memory:');
  try {
    seed(store);
    store.db.exec("UPDATE audit_events SET summary = 'tampered' WHERE id = 1");
    const violations = store.verifyChain();
    assert.ok(violations.length > 0, 'tampering must be detected');
    assert.ok(violations.some((v) => v.id === 1));
  } finally {
    store.close();
  }
});

test('a rolled-back batch never poisons the hash chain', () => {
  const store = AuditStore.open(':memory:');
  try {
    const good = (id: string): AuditRecordInput => ({
      sessionId: id,
      ts: 1,
      kind: 'tool_call',
      toolName: 'bash',
      summary: id,
      sourceType: 'tool/call',
    });
    store.insert([good('a')]);
    // Second batch inserts a good row then a row node:sqlite cannot bind —
    // the whole transaction rolls back, and the chain must stay consistent.
    assert.throws(() =>
      store.insert([good('b'), { ...good('c'), sessionId: { bad: true } as unknown as string }]),
    );
    assert.equal(store.stats().total, 1, 'failed batch committed nothing');
    assert.deepEqual(store.verifyChain(), []);
    store.insert([good('d')]);
    assert.deepEqual(store.verifyChain(), [], 'subsequent insert links to committed rows');
  } finally {
    store.close();
  }
});

test('non-string array entries are coerced so hashes stay valid', () => {
  const store = AuditStore.open(':memory:');
  try {
    store.insert([
      {
        sessionId: 's',
        ts: 1,
        kind: 'tool_call',
        toolName: 'bash',
        summary: 'x',
        filesRead: [123, 'ok'] as unknown as string[],
        sourceType: 'tool/call',
      },
    ]);
    assert.deepEqual(store.verifyChain(), [], 'no false tamper alert');
    assert.deepEqual(store.query({}).records[0]?.filesRead, ['123', 'ok']);
  } finally {
    store.close();
  }
});

test('query filters by session, tool, severity, flag, kind, time', () => {
  const store = AuditStore.open(':memory:');
  try {
    seed(store);
    assert.equal(store.query({ sessionId: 's-a' }).total, 2);
    assert.equal(store.query({ toolName: 'bash' }).total, 1);
    assert.equal(store.query({ minSeverity: 'high' }).total, 2);
    assert.equal(store.query({ flag: 'shell:rm-rf' }).total, 1);
    assert.equal(store.query({ kind: 'tool_call' }).total, 1);
    assert.equal(store.query({ from: 2500 }).total, 2);
    assert.equal(store.query({ to: 2500 }).total, 2);
    const desc = store.query({ order: 'desc', limit: 2 });
    assert.equal(desc.records[0]?.id, 4);
    assert.equal(desc.records[1]?.id, 3);
    assert.equal(store.query({ sortBy: 'time', order: 'asc' }).records[0]?.ts, 1000);
  } finally {
    store.close();
  }
});

test('query offset/limit and empty results', () => {
  const store = AuditStore.open(':memory:');
  try {
    seed(store);
    const page = store.query({ limit: 2, offset: 2 });
    assert.equal(page.records.length, 2);
    assert.equal(page.total, 4);
    assert.equal(store.query({ sessionId: 'nope' }).total, 0);
    assert.equal(store.query({ sessionId: 'nope' }).records.length, 0);
    // An explicit empty kind list matches nothing (not everything).
    assert.equal(store.query({ kind: [] }).total, 0);
  } finally {
    store.close();
  }
});

test('stats aggregates counts', () => {
  const store = AuditStore.open(':memory:');
  try {
    seed(store);
    const stats = store.stats();
    assert.equal(stats.total, 4);
    assert.ok(stats.bySeverity.some((s) => s.severity === 'critical' && s.count === 1));
    assert.ok(stats.byTag.some((t) => t.tag === 'shell:rm-rf' && t.count === 1));
    assert.equal(stats.firstTs, 1000);
    assert.equal(stats.lastTs, 4000);
  } finally {
    store.close();
  }
});
