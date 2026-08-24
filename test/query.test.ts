import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  mergeToolChains,
  complianceJsonl,
  verifyComplianceJsonl,
  jsonReport,
  markdownReport,
  markdownChainReport,
  compliancePayload,
} from '../lib/index.js';
import type { AuditRecord } from '../lib/index.js';

function record(partial: Partial<AuditRecord> & Pick<AuditRecord, 'id' | 'sessionId' | 'ts' | 'kind' | 'summary'>): AuditRecord {
  return {
    severity: 'info',
    flags: [],
    filesRead: [],
    filesWritten: [],
    network: [],
    hashPrev: null,
    hashSelf: null,
    sourceType: 'test',
    ...partial,
  };
}

test('mergeToolChains combines call + result + dispatch into one entry', () => {
  const records: AuditRecord[] = [
    record({
      id: 1,
      sessionId: 's1',
      ts: 1000,
      kind: 'tool_call',
      turn: 1,
      step: 1,
      callId: 'call-1',
      toolName: 'bash',
      argsDigest: '{"command":"rm -rf /x"}',
      severity: 'high',
      flags: ['shell:rm-rf'],
      filesRead: ['/x'],
      summary: 'bash',
    }),
    record({
      id: 2,
      sessionId: 's1',
      ts: 1100,
      kind: 'tool_result',
      turn: 1,
      step: 1,
      status: 'ok',
      durationMs: 100,
      severity: 'info',
      summary: 'ok in 100ms',
    }),
    record({
      id: 3,
      sessionId: 's1',
      ts: 1150,
      kind: 'tool_dispatch',
      callId: 'call-1',
      toolName: 'bash',
      status: 'ok',
      durationMs: 150,
      severity: 'high',
      flags: ['shell:rm-rf'],
      summary: 'bash ok in 150ms',
    }),
  ];
  const chains = mergeToolChains(records);
  assert.equal(chains.length, 1);
  const chain = chains[0];
  assert.equal(chain.toolName, 'bash');
  assert.equal(chain.status, 'ok');
  assert.equal(chain.durationMs, 150, 'dispatch duration preferred');
  assert.equal(chain.severity, 'high');
  assert.deepEqual(chain.flags, ['shell:rm-rf']);
  assert.deepEqual(chain.filesRead, ['/x']);
});

test('mergeToolChains keeps standalone calls pending when no result', () => {
  const records: AuditRecord[] = [
    record({
      id: 9,
      sessionId: 's2',
      ts: 5,
      kind: 'tool_call',
      callId: 'cc',
      toolName: 'git',
      severity: 'info',
      summary: 'git',
    }),
  ];
  const chains = mergeToolChains(records);
  assert.equal(chains[0]?.status, 'pending');
});

test('mergeToolChains pairs parallel same-slot calls with results FIFO', () => {
  const records: AuditRecord[] = [
    record({ id: 1, sessionId: 's', ts: 1000, kind: 'tool_call', callId: 'p1', turn: 1, step: 1, toolName: 'bash', severity: 'info', summary: 'bash1' }),
    record({ id: 2, sessionId: 's', ts: 2000, kind: 'tool_call', callId: 'p2', turn: 1, step: 1, toolName: 'bash', severity: 'info', summary: 'bash2' }),
    record({ id: 3, sessionId: 's', ts: 3000, kind: 'tool_result', turn: 1, step: 1, status: 'ok', durationMs: 2000, severity: 'info', summary: 'r1' }),
    record({ id: 4, sessionId: 's', ts: 4000, kind: 'tool_result', turn: 1, step: 1, status: 'ok', durationMs: 2000, severity: 'info', summary: 'r2' }),
  ];
  const chains = mergeToolChains(records);
  assert.equal(chains.length, 2);
  assert.equal(chains[0]?.callId, 'p1', 'first call pairs with first result');
  assert.equal(chains[0]?.durationMs, 2000);
  assert.equal(chains[1]?.callId, 'p2', 'second call pairs with second result');
  assert.equal(chains[1]?.durationMs, 2000);
});

test('compliance JSONL with hash chain verifies round-trip', () => {
  const records: AuditRecord[] = [
    record({ id: 1, sessionId: 's', ts: 100, kind: 'tool_call', toolName: 'bash', severity: 'high', flags: ['shell:rm-rf'], summary: 'bash' }),
    record({ id: 2, sessionId: 's', ts: 200, kind: 'tool_result', status: 'ok', durationMs: 50, severity: 'info', summary: 'ok' }),
  ];
  const text = complianceJsonl(records, { hashChain: true });
  const lines = text.trim().split('\n');
  assert.equal(lines.length, 3, 'header + 2 records');
  const header = JSON.parse(lines[0] as string);
  assert.equal(header.schema, 'dsh-audit-trail/compliance/1');
  const verification = verifyComplianceJsonl(text);
  assert.equal(verification.valid, true, verification.issues.join('; '));
  assert.equal(verification.records, 2);
});

test('compliance verification flags tampered records', () => {
  const records: AuditRecord[] = [
    record({ id: 1, sessionId: 's', ts: 100, kind: 'tool_call', toolName: 'bash', severity: 'info', summary: 'bash' }),
  ];
  const text = complianceJsonl(records, { hashChain: true });
  const lines = text.trim().split('\n');
  const last = JSON.parse(lines[1] as string) as { payload: { summary: string } };
  last.payload.summary = 'tampered';
  const tampered = `${lines[0]}\n${JSON.stringify(last)}\n`;
  const verification = verifyComplianceJsonl(tampered);
  assert.equal(verification.valid, false);
  assert.ok(verification.issues.some((issue) => issue.includes('hash mismatch')));
});

test('compliance without chain still verifies structurally', () => {
  const records: AuditRecord[] = [record({ id: 1, sessionId: 's', ts: 1, kind: 'user_message', summary: 'x' })];
  const verification = verifyComplianceJsonl(complianceJsonl(records, { hashChain: false }));
  assert.equal(verification.valid, true);
});

test('compliance verification reconciles header count and malformed lines', () => {
  const records: AuditRecord[] = [
    record({ id: 1, sessionId: 's', ts: 100, kind: 'tool_call', toolName: 'bash', severity: 'info', summary: 'bash' }),
  ];
  const lines = complianceJsonl(records, { hashChain: true }).trim().split('\n');
  // Wrong header count → issue, but data still parses.
  const badHeader = JSON.parse(lines[0] as string) as { count: number };
  badHeader.count = 99;
  const wrongCount = [JSON.stringify(badHeader), lines[1]].join('\n') + '\n';
  const countReport = verifyComplianceJsonl(wrongCount);
  assert.equal(countReport.valid, false);
  assert.ok(countReport.issues.some((issue) => issue.includes('header count')));
  // A malformed line is an issue, not a record.
  const withJunk = `${lines[0]}\n${lines[1]}\nthis is not json\n`;
  const junkReport = verifyComplianceJsonl(withJunk);
  assert.equal(junkReport.valid, false);
  assert.ok(junkReport.issues.some((issue) => issue.includes('malformed line')));
  assert.equal(junkReport.records, 1);
});

test('json report envelope', () => {
  const records: AuditRecord[] = [record({ id: 7, sessionId: 's', ts: 1, kind: 'tool_call', toolName: 'x', severity: 'low', summary: 'x' })];
  const report = jsonReport(records, { sessionId: 's' }, 42);
  assert.equal(report.app, 'dsh-audit-trail');
  assert.equal(report.count, 1);
  assert.deepEqual(Object.keys(report.records[0] ?? {}).sort(), Object.keys(compliancePayload(records[0] as AuditRecord)).sort());
});

test('markdown report and chain report render', () => {
  const records: AuditRecord[] = [
    record({ id: 1, sessionId: 's', ts: 1000, kind: 'tool_call', toolName: 'bash', severity: 'high', flags: ['shell:rm-rf'], summary: 'bash' }),
  ];
  const md = markdownReport(records, { sessionId: 's' }, 0);
  assert.ok(md.includes('# Audit trail report'));
  assert.ok(md.includes('tool_call'));
  assert.ok(md.includes('HIGH'));
  const chains = mergeToolChains(records);
  const cmd = markdownChainReport(chains, {}, 0);
  assert.ok(cmd.includes('Tool invocation chains'));
  assert.ok(cmd.includes('shell:rm-rf'));
});
