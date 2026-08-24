/**
 * Best-effort content scanning used to enrich tool records: file paths that an
 * operation touches and outbound network destinations it targets. Both are
 * heuristic (tokens that *look like* the thing) and deliberately conservative:
 * they complement, never replace, the structured arguments digest.
 */
import type { RedactConfig } from './config.js';

const URL_RE =
  /(https?|wss?|ftp):\/\/[^\s"'<>[\]{}|\u0000-\u0020]+/gi;

/**
 * Path-ish token matcher. Three alternatives:
 *  1. rooted paths — `/a/b`, `C:\a\b`, UNC `\\host\share`, `~/x`, `./x`, `../x`
 *  2. relative paths with at least one separator — `src/app.ts`
 *  3. bare dotfiles — `.env`, `.ssh/id_rsa`, `.gitignore`
 * Segments stop at characters that don't belong in a path (spaces,
 * quotes, `&`, `;`, `|`, brackets, ...). A leading `/` is excluded when it is
 * a URL scheme separator (`://`), so `https://` does not spawn path noise.
 */
const NAME = 'A-Za-z0-9_.@~+\\-';
const PATH_RE = new RegExp(
  `(?:[A-Za-z]:[\\\\/]|\\\\{1,2}[^\\\\\\s]+[\\\\/]|(?<![A-Za-z0-9:])[\\\\/]|~[\\\\/]|\\.{1,2}[\\\\/])[${NAME}]+(?:[\\\\/][${NAME}]+)*` +
    `|[${NAME}]+(?:[\\\\/][${NAME}]+)+` +
    `|(?<![A-Za-z0-9_.])[.][A-Za-z0-9_~-]{2,}(?:[\\\\/][${NAME}]+)*`,
  'gi',
);

/**
 * Strip URL userinfo anywhere in text (`https://user:pass@host/...` →
 * `https://host/...`). Global + non-anchored so embedded URLs inside a longer
 * string are covered too, and iterated because a password may itself contain
 * `@` (`https://user:p@ss@host` takes two passes to reach `https://host`).
 * Idempotent result; the `[^/@\s]` class cannot cross `/`, `@`, or whitespace,
 * so an `@` inside a path or a bare non-URL email is left untouched.
 */
export function stripUrlUserinfo(text: string): string {
  const pattern = /([a-z][a-z0-9+.-]*:\/\/)[^/@\s]+@/gi;
  let current = text;
  // Each pass removes at least one userinfo `@`; the iteration count is
  // bounded by the input length, far below this guard.
  for (let pass = 0; pass < 32; pass += 1) {
    const next = current.replace(pattern, '$1');
    if (next === current) return current;
    current = next;
  }
  return current;
}

/** Strip query strings/scopes from a captured URL, keeping scheme+authority+path. */
function cleanUrl(url: string): string {
  const clean = stripUrlUserinfo(url);
  const end = clean.search(/[?#]/);
  const path = end >= 0 ? clean.slice(0, end) : clean;
  return path.replace(/[)\]}>'"`]+$/, '').replace(/[.,;:]$/, '');
}

/** Extract up to `max` unique outbound destinations from text. */
export function findNetwork(text: string, max: number): string[] {
  if (!text || max <= 0) return [];
  const seen = new Set<string>();
  const out: string[] = [];
  for (const match of text.matchAll(URL_RE)) {
    const url = cleanUrl(match[0]);
    if (url.length === 0 || seen.has(url)) continue;
    seen.add(url);
    out.push(url);
    if (out.length >= max) break;
  }
  return out;
}

/** Extract up to `max` unique file-path candidates from text. */
export function findFilePaths(text: string, max: number): string[] {
  if (!text || max <= 0) return [];
  const seen = new Set<string>();
  const out: string[] = [];
  for (const match of text.matchAll(PATH_RE)) {
    const raw = match[0];
    // Strip trailing unbalanced punctuation that the parser cannot consume.
    const path = raw.replace(/[\]\)\},.;:'"`]+$/, '');
    if (path.length < 2) continue;
    if (/^[0-9.]+$/.test(path)) continue;
    if (seen.has(path)) continue;
    seen.add(path);
    out.push(path);
    if (out.length >= max) break;
  }
  return out;
}

/** Combined scan of a text blob, with per-list caps from the redact config. */
export function scanText(text: string, redact: RedactConfig): {
  files: string[];
  network: string[];
} {
  return {
    files: findFilePaths(text ?? '', redact.maxFiles),
    network: findNetwork(text ?? '', redact.maxNetwork),
  };
}

/** Argument keys whose string values conventionally denote outputs. */
const WRITE_KEYS: ReadonlySet<string> = new Set([
  'output',
  'out',
  'dest',
  'destination',
  'to',
  'target',
  'write_to',
  'write',
  'save_as',
  'into',
  'redirect',
]);

/** Argument keys conventionally denoting inputs to read. */
const READ_KEYS: ReadonlySet<string> = new Set([
  'path',
  'file',
  'filename',
  'src',
  'source',
  'input',
  'from',
  'read',
  'read_from',
  'dir',
  'directory',
  'working_dir',
  'cwd',
]);

/**
 * Attribute scanned file paths to read vs write buckets using the argument key
 * that produced them. Unknown keys default to *read* (the conservative choice
 * for flagging, and the least likely to mislabel a write).
 *
 * @param argsText raw arguments (used when args is unparseable)
 * @param args parsed arguments object when available
 * @param scanned the file paths already extracted from `argsText`
 */
export function attributeFiles(
  argsText: string,
  args: unknown,
  scanned: string[],
  redact: RedactConfig,
): { filesRead: string[]; filesWritten: string[] } {
  const read: string[] = [];
  const write: string[] = [];

  const bucket = (path: string, isWrite: boolean): void => {
    const list = isWrite ? write : read;
    if (list.length < redact.maxFiles && !list.includes(path)) list.push(path);
  };

  const used = new Set<string>();
  if (args != null && typeof args === 'object' && !Array.isArray(args)) {
    const record = args as Record<string, unknown>;
    for (const key of Object.keys(record).sort()) {
      const value = record[key];
      if (typeof value !== 'string') continue;
      // Only bucket strings that the scan actually flagged as paths.
      if (!scanned.includes(value)) continue;
      used.add(value);
      const isWrite = WRITE_KEYS.has(key);
      const isRead = READ_KEYS.has(key);
      if (isWrite) bucket(value, true);
      else if (isRead) bucket(value, false);
      // Keys matching neither bucket are left out of attribution.
    }
  }

  // Paths not attributable to a known key default to "read".
  for (const path of scanned) {
    if (used.has(path)) continue;
    if (read.length + write.length >= redact.maxFiles) break;
    bucket(path, false);
  }

  // Attribution-before-cap: both lists are capped by maxFiles independently.
  void argsText;
  return { filesRead: read.slice(0, redact.maxFiles), filesWritten: write.slice(0, redact.maxFiles) };
}
