/**
 * Privacy layer: deterministic masking of secret-shaped strings and character
 * truncation. Everything persisted through the audit trail therefore carries
 * only masked + truncated content by default (the "privacy-first" posture: no
 * raw secret material is stored).
 */
import { stableStringify } from './util.js';
import { stripUrlUserinfo } from './scan.js';
import type { RedactConfig } from './config.js';

/** Built-in secret-shaped patterns (regex sources, case-insensitive). */
export const DEFAULT_SECRET_PATTERNS: readonly string[] = [
  // PEM/OpenSSH private key blocks.
  '-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----\\s[\\s\\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----',
  // Authorization headers and bearer tokens.
  '\\b[Aa]uthorization\\s*:\\s*(?:Bearer|Basic)\\s+\\S+',
  '\\b(?:Bearer|Basic)\\s+[A-Za-z0-9._~+/=-]{16,}',
  // Inline assignments: api_key=…, token=…, password=…, JSON "password":"…".
  "\\b(?:api[_-]?key|apikey|access[_-]?key|auth[_-]?token|secret|token|password|passwd|private[_-]?key)\\b\\s*[\"']?[=:]\\s*[\"']?\\S{6,}",
  // Long high-entropy token/secret runs (AWS, GitHub, assorted).
  '\\bAKIA[0-9A-Z]{16}\\b',
  '\\bghp_[A-Za-z0-9]{20,}\\b',
  '\\b[A-Za-z0-9+/]{40,}={0,2}\\b',
];

/**
 * Build one combined, replace-all secret matcher from the defaults plus any
 * operator-supplied patterns. Returns null when masking is disabled.
 */
export function buildSecretMask(redact: RedactConfig): RegExp | null {
  if (!redact.maskSecrets) return null;
  const sources = [...DEFAULT_SECRET_PATTERNS, ...redact.extraSecretPatterns];
  return new RegExp(`(?:${sources.join('|')})`, 'gi');
}

/** Replace every secret-shaped region with the given placeholder. */
export function maskText(text: string, mask: RegExp | null, placeholder = '[REDACTED]'): string {
  if (!mask || text.length === 0) return text;
  return text.replace(mask, placeholder);
}

/** Truncated copy: `…(+N chars)` suffix marks how much was cut. */
export function truncate(text: string, max: number): string {
  if (typeof text !== 'string') text = String(text);
  if (text.length <= max) return text;
  return `${text.slice(0, max)}…(+${text.length - max} chars)`;
}

/** Truncate the tail of the text but keep it aligned to a summary. */
export function truncateTo(text: string, max: number): string {
  return truncate(text, max);
}

/** Try to JSON-parse; on failure fall back to the raw text. */
export function tryParseJson(raw: string): unknown {
  if (raw == null || raw === '') return undefined;
  try {
    return JSON.parse(raw);
  } catch {
    return undefined;
  }
}

/** Mask + truncate an arbitrary unknown to a bounded, redacted string. */
export function redactValue(value: unknown, redact: RedactConfig): string {
  const mask = buildSecretMask(redact);
  let text: string;
  try {
    text = stableStringify(value);
  } catch {
    text = String(value);
  }
  return truncateTo(maskText(text, mask), redact.truncateDetail);
}

/** Keys whose values are treated as whole-value secrets during digesting. */
const SECRET_KEY_RE =
  /(?:password|passwd|token|secret|api[_-]?key|apikey|access[_-]?key|private[_-]?key|authorization|credential|cookie|session[_-]?id)/i;

/**
 * Produce the **tool-argument digest**: a compact, deterministic, masked and
 * truncated summary of the raw arguments a model sent to a tool. Object
 * arguments keep their top-level keys; a value whose key looks secret is
 * replaced entirely, and every other value is masked + truncated. Anything
 * unparseable is treated as plain command text and masked/truncated as a whole.
 */
export function digestArgs(rawArguments: string, redact: RedactConfig): string {
  const source = rawArguments ?? '';
  const mask = buildSecretMask(redact);
  // Per-value cap so a single huge value is bounded before the global cap.
  const valueCap = Math.max(64, Math.floor(redact.truncateArgs / 4));

  const parsed = tryParseJson(source);
  if (parsed != null) {
    return truncateTo(stableStringify(pruneValue(parsed, mask, valueCap)), redact.truncateArgs);
  }
  // Not JSON — treat as a command line / plain text.
  return truncateTo(maskText(stripUrlUserinfo(source), mask), redact.truncateArgs);
}

/** Recursively prune for storage: mask strings, mark secret-keyed values. */
function pruneValue(value: unknown, mask: RegExp | null, cap: number): unknown {
  if (typeof value === 'string') {
    return truncateTo(maskText(stripUrlUserinfo(value), mask), cap);
  }
  if (Array.isArray(value)) {
    return value.slice(0, 64).map((v) => pruneValue(v, mask, cap));
  }
  if (value !== null && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(record).slice(0, 64).sort()) {
      out[key] = SECRET_KEY_RE.test(key) ? '[REDACTED]' : pruneValue(record[key], mask, cap);
    }
    return out;
  }
  return value;
}
