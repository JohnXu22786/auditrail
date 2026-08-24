import { test } from 'node:test';
import assert from 'node:assert/strict';
import { run } from '../lib/cli.js';
import { AuditStore } from '../lib/index.js';
import { complianceJsonl } from '../lib/index.js';
import { writeFileSync, readFileSync, mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { tempFilePath } from './helpers.ts';
import type { AuditRecordInput } from '../lib/index.js';

function seed(path: string) {
  const store = AuditStore.open(path);
  try {
    store.insert([
      {
        sessionId: 's1',
        ts: 1000,
        kind: 'tool_call',
        toolName: 'bash',
        callId: 'c1',
        argsDigest: '{"command":"rm -rf /x"}',
        status: 'pending',
        severity: 'high',
        flags: ['shell:rm-rf'],
        summary: 'bash',
        sourceType: 'tool/call',
      },
      {
        sessionId: 's1',
        ts: 2000,
        kind: 'tool_result',
        status: 'ok',
        durationMs: 100,
        summary: 'ok in 100ms',
        sourceType: 'tool/result',
      },
    ] as AuditRecordInput[]);
  } finally {
    store.close();
  }
}

test('help exits 0', async () => {
  assert.equal(await run(['help']), 0);
});

test('stats and chain verify on a seeded store', async () => {
  const db = tempFilePath();
  seed(db);
  assert.equal(await run(['stats', '--db', db]), 0);
  assert.equal(await run(['chain', 'verify', '--db', db]), 0);
});

test('query returns JSON for the seeded store', async () => {
  const db = tempFilePath();
  seed(db);
  assert.equal(await run(['query', '--db', db, '--json']), 0);
  assert.equal(await run(['query', '--db', db, '--flag', 'shell:rm-rf', '--json']), 0);
  assert.equal(await run(['query', '--db', db, '--markdown']), 0);
});

test('export writes a compliance JSONL that verifies', async () => {
  const db = tempFilePath();
  seed(db);
  const out = tempFilePath('jsonl');
  assert.equal(
    await run(['export', '--db', db, '--format', 'jsonl', '--out', out, '--hash-chain']),
    0,
  );
  const verifyFile = tempFilePath('jsonl');
  writeFileSync(verifyFile, readFileSync(out, 'utf8'));
  assert.equal(await run(['verify-compliant', '--file', verifyFile]), 0);
});

test('export json and markdown', async () => {
  const db = tempFilePath();
  seed(db);
  const dir = mkdtempSync(join(tmpdir(), 'auditrail-'));
  const jsonOut = join(dir, 'report.json');
  assert.equal(await run(['export', '--db', db, '--format', 'json', '--out', jsonOut]), 0);
  assert.ok(JSON.parse(readFileSync(jsonOut, 'utf8')).count === 2);
  assert.equal(await run(['export', '--db', db, '--format', 'markdown']), 0);
});

test('policy list/enable and unknown rule handling', async () => {
  const db = tempFilePath();
  seed(db);
  assert.equal(await run(['policy', 'list', '--db', db]), 0);
  assert.equal(await run(['policy', 'show', 'shell:rm-rf', '--db', db]), 0);
  assert.equal(await run(['policy', 'disable', 'shell:rm-rf', '--db', db]), 0);
  assert.equal(await run(['policy', 'enable', 'shell:rm-rf', '--db', db]), 0);
  assert.equal(await run(['policy', 'show', 'does-not-exist', '--db', db]), 2);
});

test('policy add works and rejects bad patterns', async () => {
  const db = tempFilePath();
  seed(db);
  // Runtime-only mutations: each CLI invocation is a fresh process, so a rule
  // added here is not visible to a later invocation (persist via config).
  assert.equal(
    await run(['policy', 'add', '--db', db, '--id', 'my:rule', '--pattern', 'dropAll', '--severity', 'high']),
    0,
  );
  assert.equal(
    await run(['policy', 'add', '--db', db, '--id', 'my:bad', '--pattern', '(']),
    2,
    'invalid regex must be rejected',
  );
});

test('user/io errors return a clean exit code instead of crashing', async () => {
  assert.equal(await run(['verify-compliant', '--file', 'C:\\definitely\\missing.jsonl']), 1);
  // AuditStore.open mkdirs parents, but a regular file blocking the parent
  // directory cannot be turned into a database path.
  const blocker = tempFilePath('sqlite');
  writeFileSync(blocker, '', 'utf8');
  assert.equal(await run(['query', '--db', join(blocker, 'sub', 'db.sqlite')]), 1);
});

test('verify-compliant does not require (or create) an audit database', async () => {
  const store = AuditStore.open(':memory:');
  store.insert([
    { sessionId: 's', ts: 1, kind: 'user_message', summary: 'hi', sourceType: 'user/message' },
  ]);
  const text = complianceJsonl(store.query({}).records, { hashChain: true });
  store.close();
  const good = tempFilePath('jsonl');
  writeFileSync(good, text, 'utf8');

  // Point the whole default-DB resolution at something unusable: verification
  // must not touch it (no store opened, no side-effect directory created).
  const previous = process.env.AUDITRAIL_DB;
  process.env.AUDITRAIL_DB = 'C:\\definitely\\missing-dir-that-noone-can-create\\db.sqlite';
  try {
    assert.equal(await run(['verify-compliant', '--file', good]), 0);
  } finally {
    if (previous === undefined) delete process.env.AUDITRAIL_DB;
    else process.env.AUDITRAIL_DB = previous;
  }
});

test('policy add rejects invalid severities', async () => {
  const db = tempFilePath();
  seed(db);
  assert.equal(
    await run(['policy', 'add', '--db', db, '--id', 'sev:bad', '--pattern', 'x', '--severity', 'supercritical']),
    2,
  );
});

test('verify-compliant rejects a tampered file', async () => {
  const store = AuditStore.open(':memory:');
  const record: AuditRecordInput = {
    sessionId: 's',
    ts: 1,
    kind: 'user_message',
    summary: 'hello',
    sourceType: 'user/message',
  };
  store.insert([record]);
  const text = complianceJsonl(store.query({}).records, { hashChain: true });
  store.close();

  const good = tempFilePath('jsonl');
  writeFileSync(good, text, 'utf8');
  assert.equal(await run(['verify-compliant', '--file', good]), 0);

  const lines = text.trim().split('\n');
  const last = JSON.parse(lines[1] as string) as { payload: { summary: string } };
  last.payload.summary = 'tampered';
  const bad = tempFilePath('jsonl');
  writeFileSync(bad, `${lines[0]}\n${JSON.stringify(last)}\n`, 'utf8');
  assert.equal(await run(['verify-compliant', '--file', bad]), 1);
});
