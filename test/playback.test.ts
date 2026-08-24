import { test, mock } from 'node:test';
import assert from 'node:assert/strict';
import { renderTimeline, PlaybackController, timecode } from '../lib/index.js';
import type { TimelineRow } from '../lib/index.js';

const rows: TimelineRow[] = [
  { id: 1, ts: Date.UTC(2024, 0, 1, 1, 2, 3, 456), kind: 'tool_call', toolName: 'bash', severity: 'high', flags: ['shell:rm-rf'], summary: 'bash' },
  { id: 2, ts: Date.UTC(2024, 0, 1, 1, 2, 3, 556), kind: 'tool_result', toolName: 'bash', severity: 'info', flags: [], summary: 'ok in 100ms', durationMs: 100 },
];

test('timecode is a fixed-width UTC clock', () => {
  assert.equal(timecode(Date.UTC(2024, 0, 1, 23, 4, 5, 6)), '23:04:05.006');
});

test('renderTimeline is deterministic plain text', () => {
  const first = renderTimeline(rows, {});
  const second = renderTimeline(rows, {});
  assert.deepEqual(first, second);
  const line = first[0] ?? '';
  assert.ok(line.includes('01:02:03.456'));
  assert.ok(line.includes('#000001'));
  assert.ok(line.includes('tool_call'));
  assert.ok(line.includes('[HIGH]'));
  assert.ok(line.includes('shell:rm-rf'));
  const resultLine = first[1] ?? '';
  assert.ok(resultLine.includes('100ms'));
});

test('renderTimeline colors only when asked', () => {
  const plain = renderTimeline(rows, {});
  const colored = renderTimeline(rows, { colors: true });
  assert.ok(!plain[0]?.includes('\u001b['));
  assert.ok(colored[0]?.includes('\u001b[31m'));
});

test('PlaybackController steps and pauses deterministically', () => {
  const emitted: string[] = [];
  const controller = new PlaybackController(rows, (line) => emitted.push(line), { speed: 2 });
  assert.equal(controller.state, 'stopped');
  assert.equal(controller.step(), rows[0] && renderTimeline(rows)[0]);
  assert.equal(controller.state, 'paused');
  assert.ok(controller.step(), 'step while paused advances');
  assert.equal(controller.step(), undefined, 'past the end returns undefined');
  assert.equal(controller.state, 'stopped');
});

test('PlaybackController toggle/seek/speed/reset', () => {
  const emitted: string[] = [];
  const controller = new PlaybackController(rows, (line) => emitted.push(line), {});
  controller.play();
  assert.equal(controller.state, 'playing');
  assert.equal(emitted.length, 1, 'play emits the first line synchronously');
  controller.toggle();
  assert.equal(controller.state, 'paused');
  controller.seek(1);
  assert.equal(controller.position.index, 1);
  controller.seek(999);
  assert.equal(controller.position.index, rows.length - 1);
  controller.seek(-5);
  assert.equal(controller.position.index, 0);
  controller.setSpeed(0.001);
  assert.equal(controller.delayMsPerLine, 1000 / 0.01, 'speed clamped to minimum');
  controller.setSpeed(1e9);
  assert.equal(controller.delayMsPerLine, 1000 / 100, 'speed clamped to maximum');
  controller.reset();
  assert.equal(controller.position.index, 0);
  controller.stop();
  assert.equal(controller.state, 'stopped');
});

test('PlaybackController step returns the rendered line text', () => {
  const controller = new PlaybackController(rows, () => undefined, {});
  const line = controller.step();
  assert.ok(line && line.includes('tool_call'));
});

test('changing speed while playing does not stall playback', () => {
  const emitted: string[] = [];
  const controller = new PlaybackController(rows, (line) => emitted.push(line), { speed: 10 });
  mock.timers.enable({ apis: ['setTimeout'] });
  try {
    controller.play(); // emits line #1 synchronously, schedules the first tick
    assert.equal(emitted.length, 1);
    controller.setSpeed(20); // must re-arm the timer with the new cadence
    assert.equal(controller.delayMsPerLine, 50);
    mock.timers.tick(60);
    assert.equal(emitted.length, 2, 'line stream resumes after a speed change');
    assert.equal(controller.state, 'playing');
  } finally {
    mock.timers.reset();
  }
});

test('changing speed at end of stream settles to stopped instead of stalling', () => {
  const single: TimelineRow[] = [
    { id: 1, ts: 0, kind: 'tool_call', toolName: 'x', severity: 'info', flags: [], summary: 's' },
  ];
  const controller = new PlaybackController(single, () => undefined, { speed: 100 });
  mock.timers.enable({ apis: ['setTimeout'] });
  try {
    controller.play(); // emits the only line; a final tick is still pending
    assert.equal(controller.state, 'playing');
    controller.setSpeed(200); // end-of-stream speed change must not stall
    assert.equal(controller.state, 'stopped');
  } finally {
    mock.timers.reset();
  }
});
