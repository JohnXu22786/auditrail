/**
 * Generic low-dependency utilities shared across the audit trail bundle:
 * deterministic hashing (used by the SQLite hash chain and the compliance
 * JSONL export) and a stable stringifier that sorts object keys so that two
 * semantically-equal values always serialize to the same string.
 */
import { createHash } from 'node:crypto';

/** SHA-256 digest of a UTF-8 string, hex encoded. */
export function sha256Hex(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

/**
 * Deterministic JSON serialization: object keys are sorted lexicographically,
 * arrays keep their order. The output of two runs over equal data is
 * byte-identical, which is what the audit hash chain and the compliance export
 * rely on.
 */
export function stableStringify(value: unknown): string {
  return JSON.stringify(sortValue(value));
}

function sortValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortValue);
  }
  if (value !== null && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(record).sort()) {
      out[key] = sortValue(record[key]);
    }
    return out;
  }
  return value;
}

/** Structural check: a plain (non-array) object. */
export function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Read a number-ish field defensively. Returns undefined when absent/invalid. */
export function asFiniteNumber(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string' && value.trim() !== '') {
    const n = Number(value);
    if (Number.isFinite(n)) return n;
  }
  return undefined;
}

/** Read a non-empty string field defensively. */
export function asString(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}
