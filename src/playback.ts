/**
 * Plain-text session replay.
 *
 * `renderTimeline` turns sorted audit records into a deterministic, terminal-
 * friendly text timeline; `PlaybackController` is the small state machine that
 * slow-plays it with pause/step/speed/seek; `runInteractive` binds it to a raw
 * TTY so an operator can drive a live replay with keys (no browser needed).
 */
import type { Severity } from './types.js';

/** ANSI palette used only when `colors: true`. */
const ANSI = {
  reset: '\u001b[0m',
  dim: '\u001b[2m',
  bold: '\u001b[1m',
  red: '\u001b[31m',
  yellow: '\u001b[33m',
  green: '\u001b[32m',
  cyan: '\u001b[36m',
  magenta: '\u001b[35m',
} as const;

/** The fields {@link renderTimeline} reads; audit records and merged chains both satisfy it. */
export interface TimelineRow {
  id: number;
  ts: number;
  kind: string;
  toolName?: string;
  severity: Severity;
  flags: string[];
  summary: string;
  durationMs?: number;
}

export interface RenderOptions {
  colors?: boolean;
}

/** UTC timecode `HH:MM:SS.mmm`. */
export function timecode(ts: number): string {
  const d = new Date(ts);
  const pad = (n: number, width = 2): string => String(n).padStart(width, '0');
  return `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}.${pad(d.getUTCMilliseconds(), 3)}`;
}

function severityColor(severity: string, colors: boolean): string {
  if (!colors) return '';
  switch (severity) {
    case 'critical':
    case 'high':
      return ANSI.red;
    case 'medium':
      return ANSI.yellow;
    case 'low':
      return ANSI.magenta;
    default:
      return ANSI.dim;
  }
}

/**
 * Render records to one plain-text line each, in the given order (callers are
 * expected to pre-sort). A line looks like:
 *
 *    07:42:11.234  #000012  tool_call       bash           [HIGH] shell:rm-rf  invoke bash
 */
export function renderTimeline(records: readonly TimelineRow[], opts: RenderOptions = {}): string[] {
  const colors = opts.colors === true;
  const out: string[] = [];
  for (const rec of records) {
    const tag = `[${rec.severity.toUpperCase()}]`;
    const color = severityColor(rec.severity, colors);
    const id = `#${String(rec.id).padStart(6, '0')}`;
    const kind = rec.kind.padEnd(15);
    const tool = (rec.toolName ?? '-').padEnd(10);
    const flags = rec.flags.length > 0 ? rec.flags.join(',') : '';
    const summary = rec.summary.replace(/\r?\n/g, ' ');
    const line =
      `${timecode(rec.ts)}  ${id}  ${kind}  ${tool}  ` +
      `${color}${tag}${colors ? ANSI.reset : ''}  ` +
      `${flags}${flags ? '  ' : ''}${summary}`;
    out.push(line);
  }
  return out;
}

export type PlaybackState = 'stopped' | 'playing' | 'paused';

export interface PlaybackOptions {
  /** Slow-play speed: N lines per second (clamped to 0.01..100). */
  speed?: number;
  colors?: boolean;
}

/** Synchronously consumed next line; implement send/output. */
export type LineSink = (line: string) => void;

/**
 * State machine for slow replay. Designed to be testable without a timer: the
 * key methods (`step`, `seek`, `toggle`, `setSpeed`) are synchronous; `play`
 * only schedules async emission of lines after the first.
 */
export class PlaybackController {
  private readonly lines: string[];
  private index = 0;
  private stateValue: PlaybackState = 'stopped';
  private speed: number;
  private timer: NodeJS.Timeout | null = null;
  private readonly colors: boolean;

  constructor(
    records: readonly TimelineRow[],
    private readonly sink: LineSink,
    opts: PlaybackOptions = {},
  ) {
    this.colors = opts.colors === true;
    this.lines = renderTimeline(records, { colors: this.colors });
    this.speed = clampSpeed(opts.speed ?? 1);
  }

  get state(): PlaybackState {
    return this.stateValue;
  }

  get position(): { index: number; total: number } {
    return { index: this.index, total: this.lines.length };
  }

  get delayMsPerLine(): number {
    return 1000 / this.speed;
  }

  /** Start (or resume) playing. Emits the current line synchronously. */
  play(): void {
    if (this.stateValue !== 'playing') {
      this.stateValue = 'playing';
      this.emitCurrent();
    }
  }

  /** Pause without resetting the position. */
  pause(): void {
    if (this.stateValue !== 'playing') return;
    this.stateValue = 'paused';
    this.clearTimer();
  }

  toggle(): PlaybackState {
    if (this.stateValue === 'playing') this.pause();
    else this.play();
    return this.stateValue;
  }

  /** Advance one line while paused; returns it, or undefined at the end. */
  step(): string | undefined {
    if (this.stateValue === 'playing' || this.index >= this.lines.length) return undefined;
    const removed = this.lines[this.index];
    this.index += 1;
    if (removed !== undefined) this.sink(removed);
    this.stateValue = this.index >= this.lines.length ? 'stopped' : 'paused';
    return removed;
  }

  /** Jump to a line index (clamped); pauses if playing. */
  seek(index: number): void {
    this.pause();
    this.index = clampIndex(index, this.lines.length);
  }

  /** Reset to the start (paused). */
  reset(): void {
    this.pause();
    this.index = 0;
  }

  /** Change speed (lines per second) while playing. */
  setSpeed(speed: number): void {
    const next = clampSpeed(speed);
    const wasPlaying = this.stateValue === 'playing';
    this.speed = next;
    if (wasPlaying) {
      // Keep playing with the new cadence; re-arm the timer without re-emitting
      // the current line. If the stream already ended, settle it instead.
      this.clearTimer();
      if (this.index < this.lines.length) {
        this.timer = setTimeout(() => this.tick(), this.delayMsPerLine);
      } else {
        this.stateValue = 'stopped';
      }
    }
  }

  /** Stop and clear any scheduled timer; position stays. */
  stop(): void {
    this.stateValue = 'stopped';
    this.clearTimer();
  }

  private emitCurrent(): void {
    if (this.index >= this.lines.length) {
      this.stateValue = 'stopped';
      return;
    }
    const line = this.lines[this.index];
    if (line !== undefined) {
      this.index += 1;
      this.sink(line);
    }
    this.timer = setTimeout(() => this.tick(), this.delayMsPerLine);
  }

  private tick(): void {
    this.timer = null;
    if (this.stateValue !== 'playing') return;
    if (this.index >= this.lines.length) {
      this.stateValue = 'stopped';
      return;
    }
    const line = this.lines[this.index];
    if (line !== undefined) {
      this.index += 1;
      this.sink(line);
    }
    this.timer = setTimeout(() => this.tick(), this.delayMsPerLine);
  }

  private clearTimer(): void {
    if (this.timer !== null) {
      clearTimeout(this.timer);
      this.timer = null;
    }
  }
}

function clampSpeed(speed: number): number {
  if (!Number.isFinite(speed)) return 1;
  return Math.min(100, Math.max(0.01, speed));
}

function clampIndex(index: number, total: number): number {
  if (!Number.isFinite(index)) return 0;
  return Math.min(Math.max(0, Math.floor(index)), Math.max(0, total - 1));
}

/**
 * Interactive raw-TTY replay. Holds the terminal in raw mode; the following
 * keys are live:
 *
 *   space  pause / resume
 *   s      step one line forward
 *   + / =  faster   ·   - / _ slower
 *   g      jump to start
 *   q / Ctrl-C  quit
 *
 * When `stdin` is not a TTY (or `interactive` is false) it simply renders the
 * whole timeline and returns.
 */
export async function runInteractive(
  records: readonly TimelineRow[],
  opts: { speed?: number; colors?: boolean; interactive?: boolean } = {},
): Promise<void> {
  const interactive = opts.interactive === true && process.stdin.isTTY === true;
  if (!interactive) {
    for (const line of renderTimeline(records, { colors: opts.colors === true })) {
      process.stdout.write(line + '\n');
    }
    return;
  }

  const { default: readline } = await import('node:readline');
  const clear = (): void => {
    process.stdout.write('\u001b[2K\u001b[0G');
  };
  const banner =
    '[space] pause/resume  [s] step  [+/-] speed  [g] start  [q] quit';
  const controller = new PlaybackController(records, (line) => {
    clear();
    process.stdout.write(line + '\n');
    if (controller.state === 'playing') {
      process.stdout.write(`${banner}  (${
        controller.position.index
      }/${controller.position.total}, ${controller.delayMsPerLine.toFixed(1)} ms/line)\n`);
    }
  }, { speed: opts.speed ?? 1, colors: opts.colors === true });

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    terminal: true,
  });
  const wasRaw = process.stdin.isRaw;
  process.stdin.setRawMode(true);
  process.stdin.resume();

  const cleanup = (): void => {
    process.stdin.setRawMode(wasRaw ?? false);
    rl.close();
  };

  await new Promise<void>((resolve) => {
    controller.play();
    rl.on('line', () => {
      // When the repl handles Enter, just continue.
    });
    process.stdin.on('data', (chunk) => {
      const char = String(chunk).charAt(0);
      switch (char) {
        case ' ':
          controller.toggle();
          break;
        case 's':
          controller.step();
          break;
        case '+':
        case '=':
          controller.setSpeed((opts.speed ?? 1) * 2);
          break;
        case '-':
        case '_':
          controller.setSpeed((opts.speed ?? 1) / 2);
          break;
        case 'g':
        case '0':
          controller.reset();
          break;
        case 'q':
        case '\u0003':
          controller.stop();
          cleanup();
          resolve();
          break;
        default:
          break;
      }
    });
    const stopOnFinish = (): void => {
      if (controller.state === 'stopped') {
        cleanup();
        resolve();
      }
    };
    const alive = setInterval(stopOnFinish, 250);
    rl.on('close', () => {
      clearInterval(alive);
    });
  });
}
