/**
 * SQLite persistence for the audit trail.
 *
 * - `node:sqlite` (built into Node >= 22.13) → zero native/dependency weight.
 * - WAL journal mode + `synchronous = NORMAL` for durable, concurrent-safe
 *   appends at room-temperature latency.
 * - Append-only event table with a SHA-256 hash chain (each row binds to the
 *   previous row's hash), plus a tag child table for sensitive-flag filtering.
 * - Deterministic global ordering: rows are inserted with an `AUTOINCREMENT`
 *   id and the store is the single writer (the recorder serializes ingests).
 */
import { DatabaseSync } from 'node:sqlite';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { homedir } from 'node:os';
import { sha256Hex, stableStringify } from './util.js';
import {
  SEVERITY_ORDER,
  severityRank,
  type AuditFilters,
  type AuditKind,
  type AuditRecord,
  type AuditRecordInput,
  type Severity,
} from './types.js';

export const SCHEMA_VERSION = 1;

const SEVERITIES = new Set(['info', 'low', 'medium', 'high', 'critical']);

function isSeverity(value: unknown): value is Severity {
  return typeof value === 'string' && SEVERITIES.has(value);
}

/** Default database location under the dsh home directory. */
export function defaultDbPath(): string {
  const home = process.env.DSH_HOME ?? join(homedir(), '.dsh');
  return join(home, 'audit-trail', 'audit.sqlite');
}

/** Resolve a configured path, falling back to the default. */
export function resolveDbPath(path: string | null | undefined, overrides?: Array<string | null | undefined>): string {
  for (const candidate of [path, ...(overrides ?? [])]) {
    if (candidate === ':memory:') return ':memory:';
    if (typeof candidate === 'string' && candidate.trim() !== '') {
      return resolve(candidate.trim());
    }
  }
  return resolve(defaultDbPath());
}

export interface ChainViolation {
  id: number;
  reason: string;
}

export interface QueryResult {
  records: AuditRecord[];
  total: number;
}

export interface AuditStats {
  total: number;
  schemaVersion: number;
  byKind: Array<{ kind: string; count: number }>;
  bySeverity: Array<{ severity: string; count: number }>;
  byTag: Array<{ tag: string; count: number }>;
  firstTs: number | null;
  lastTs: number | null;
}

/** Fixed field order used by the hash chain — keep stable across releases. */
export function canonicalRecordFields(
  rec: Pick<
    AuditRecord,
    | 'sessionId'
    | 'ts'
    | 'kind'
    | 'turn'
    | 'step'
    | 'toolName'
    | 'callId'
    | 'argsDigest'
    | 'status'
    | 'durationMs'
    | 'severity'
    | 'flags'
    | 'summary'
    | 'detail'
    | 'filesRead'
    | 'filesWritten'
    | 'network'
    | 'actor'
    | 'sourceType'
    | 'sourceSeq'
  >,
): unknown[] {
  return [
    rec.sessionId,
    rec.ts,
    rec.kind,
    rec.turn ?? null,
    rec.step ?? null,
    rec.toolName ?? null,
    rec.callId ?? null,
    rec.argsDigest ?? null,
    rec.status ?? null,
    rec.durationMs ?? null,
    rec.severity,
    [...new Set(rec.flags)].sort(),
    rec.summary,
    rec.detail ?? null,
    rec.filesRead,
    rec.filesWritten,
    rec.network,
    rec.actor ?? null,
    rec.sourceType,
    rec.sourceSeq ?? null,
  ];
}

/** Canonical string that the hash of a row is computed over. */
export function canonicalRecord(rec: Parameters<typeof canonicalRecordFields>[0]): string {
  return `dsh-audit-trail/canonical/1\n${stableStringify(canonicalRecordFields(rec))}\n`;
}

/** The hash of one row given the previous row's hash. */
export function chainHash(prevHash: string | null | undefined, rec: Parameters<typeof canonicalRecordFields>[0]): string {
  return sha256Hex(`${prevHash ?? ''}\n${canonicalRecord(rec)}\n`);
}

const CREATE_TABLES = `
CREATE TABLE IF NOT EXISTS audit_meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT NOT NULL,
  ts INTEGER NOT NULL,
  kind TEXT NOT NULL,
  turn INTEGER,
  step INTEGER,
  tool_name TEXT,
  call_id TEXT,
  args_digest TEXT,
  status TEXT,
  duration_ms INTEGER,
  severity TEXT NOT NULL DEFAULT 'info',
  severity_rank INTEGER NOT NULL DEFAULT 0,
  summary TEXT NOT NULL DEFAULT '',
  detail TEXT,
  files_read TEXT NOT NULL DEFAULT '[]',
  files_written TEXT NOT NULL DEFAULT '[]',
  network TEXT NOT NULL DEFAULT '[]',
  actor TEXT,
  source_type TEXT NOT NULL DEFAULT '',
  source_seq INTEGER,
  hash_prev TEXT,
  hash_self TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_events_ts ON audit_events (ts);
CREATE INDEX IF NOT EXISTS idx_audit_events_session ON audit_events (session_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_tool ON audit_events (tool_name);
CREATE INDEX IF NOT EXISTS idx_audit_events_severity ON audit_events (severity_rank);
CREATE INDEX IF NOT EXISTS idx_audit_events_kind ON audit_events (kind);
CREATE TABLE IF NOT EXISTS audit_tags (
  event_id INTEGER NOT NULL REFERENCES audit_events (id) ON DELETE CASCADE,
  tag TEXT NOT NULL,
  PRIMARY KEY (event_id, tag)
);
CREATE INDEX IF NOT EXISTS idx_audit_tags_tag ON audit_tags (tag);
`;

function parseJsonArray(text: unknown): string[] {
  if (typeof text !== 'string' || text === '') return [];
  try {
    const value = JSON.parse(text);
    if (Array.isArray(value)) return value.filter((x): x is string => typeof x === 'string');
  } catch {
    // fall through
  }
  return [];
}

export class AuditStore {
  readonly db: DatabaseSync;
  readonly path: string;
  private lastHash = '';
  private closed = false;

  private constructor(path: string, db: DatabaseSync) {
    this.path = path;
    this.db = db;
    this.setup();
    this.lastHash = this.loadLastHash();
  }

  private setup(): void {
    this.db.exec('PRAGMA foreign_keys = ON');
    // WAL is a no-op on an in-memory database, which is fine.
    this.db.exec('PRAGMA journal_mode = WAL');
    this.db.exec('PRAGMA synchronous = NORMAL');
    this.db.exec(CREATE_TABLES);
    const row = this.db.prepare("SELECT value FROM audit_meta WHERE key = 'schema_version'").get() as
      | { value: string | null }
      | undefined;
    const existing = row ? Number(row.value) : 0;
    if (existing === 0) {
      this.db
        .prepare("INSERT OR REPLACE INTO audit_meta (key, value) VALUES ('schema_version', ?)")
        .run(String(SCHEMA_VERSION));
    } else if (existing !== SCHEMA_VERSION) {
      throw new Error(
        `audit trail database schema v${existing} is not supported by this bundle (expected v${SCHEMA_VERSION}); ` +
          'move the file away or use a matching bundle version.',
      );
    }
  }

  private loadLastHash(): string {
    const row = this.db.prepare('SELECT hash_self FROM audit_events ORDER BY id DESC LIMIT 1').get() as
      | { hash_self: string | null }
      | undefined;
    return row?.hash_self ?? '';
  }

  /** Open (creating if needed) the store at `path`. */
  static open(path: string): AuditStore {
    if (path !== ':memory:') {
      mkdirSync(dirname(path), { recursive: true });
    }
    const db = new DatabaseSync(path);
    try {
      return new AuditStore(path, db);
    } catch (error) {
      try {
        db.close();
      } catch {
        // ignore close failures during error path
      }
      throw error;
    }
  }

  /** Journal mode in effect (mostly for tests / diagnostics). */
  journalMode(): string {
    const row = this.db.prepare('PRAGMA journal_mode').get() as { journal_mode: string };
    return row?.journal_mode ?? 'unknown';
  }

  /**
   * Append records in one transaction. Returned records carry their real ids
   * and computed hashes. Ordering is safe because the caller (recorder) is the
   * sole writer and ingests synchronously.
   */
  insert(records: readonly AuditRecordInput[]): AuditRecord[] {
    if (records.length === 0) return [];
    const stmt = this.db.prepare(
      'INSERT INTO audit_events (session_id, ts, kind, turn, step, tool_name, call_id, args_digest, ' +
        'status, duration_ms, severity, severity_rank, summary, detail, files_read, files_written, network, ' +
        'actor, source_type, source_seq, hash_prev, hash_self, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
    );
    const tagStmt = this.db.prepare('INSERT INTO audit_tags (event_id, tag) VALUES (?, ?)');
    const createdAt = Date.now();
    const out: AuditRecord[] = [];
    this.db.exec('BEGIN');
    try {
      for (const input of records) {
        const severity = isSeverity(input.severity) ? input.severity : 'info';
        const flags = [...new Set(input.flags ?? [])].sort();
        // Coerce to strings so the hashed value always round-trips through the
        // JSON-encoded column (decodeRow also filters to strings).
        const filesRead = (input.filesRead ?? []).map((item) => String(item));
        const filesWritten = (input.filesWritten ?? []).map((item) => String(item));
        const network = (input.network ?? []).map((item) => String(item));
        const base: AuditRecord = {
          ...input,
          id: 0,
          severity,
          flags,
          filesRead,
          filesWritten,
          network,
          hashPrev: this.lastHash || null,
          hashSelf: null,
        };
        base.hashSelf = chainHash(base.hashPrev, base);
        const info = stmt.run(
          base.sessionId,
          base.ts,
          base.kind,
          base.turn ?? null,
          base.step ?? null,
          base.toolName ?? null,
          base.callId ?? null,
          base.argsDigest ?? null,
          base.status ?? null,
          base.durationMs ?? null,
          base.severity,
          severityRank(base.severity),
          base.summary,
          base.detail ?? null,
          JSON.stringify(filesRead),
          JSON.stringify(filesWritten),
          JSON.stringify(network),
          base.actor ?? null,
          base.sourceType,
          base.sourceSeq ?? null,
          base.hashPrev,
          base.hashSelf,
          createdAt,
        );
        base.id = Number(info.lastInsertRowid);
        for (const tag of flags) {
          tagStmt.run(base.id, tag);
        }
        this.lastHash = base.hashSelf ?? '';
        out.push(base);
      }
      this.db.exec('COMMIT');
    } catch (error) {
      this.db.exec('ROLLBACK');
      // The in-memory chain state must match what actually committed, so a
      // failed batch can never poison the next insert's hash chain.
      this.lastHash = this.loadLastHash();
      throw error;
    }
    return out;
  }

  /** Query records with optional filters, plus a total count. */
  query(filters: AuditFilters): QueryResult {
    const where: string[] = [];
    const params: Array<string | number> = [];

    const from = parseBound(filters.from);
    if (from !== undefined) {
      where.push('ts >= ?');
      params.push(from);
    }
    const to = parseBound(filters.to);
    if (to !== undefined) {
      where.push('ts <= ?');
      params.push(to);
    }
    if (filters.sessionId) {
      where.push('session_id = ?');
      params.push(filters.sessionId);
    }
    if (filters.toolName) {
      where.push('tool_name = ?');
      params.push(filters.toolName);
    }
    if (filters.minSeverity && isSeverity(filters.minSeverity)) {
      where.push('severity_rank >= ?');
      params.push(severityRank(filters.minSeverity));
    }
    if (filters.flag) {
      where.push('id IN (SELECT event_id FROM audit_tags WHERE tag = ?)');
      params.push(filters.flag);
    }
    if (filters.kind !== undefined && filters.kind !== null) {
      const kinds = Array.isArray(filters.kind) ? filters.kind : [filters.kind];
      const uniq = [...new Set(kinds)];
      if (Array.isArray(filters.kind) && uniq.length === 0) {
        // "kind in []" matches nothing rather than everything.
        where.push('1 = 0');
      } else if (uniq.length === 1) {
        const only = uniq[0];
        if (only !== undefined) {
          where.push('kind = ?');
          params.push(only);
        }
      } else if (uniq.length > 1) {
        where.push(`kind IN (${uniq.map(() => '?').join(', ')})`);
        params.push(...uniq);
      }
    }

    const whereSql = where.length > 0 ? ` WHERE ${where.join(' AND ')}` : '';
    const orderCol = filters.sortBy === 'time' ? 'ts' : 'id';
    const orderDir = filters.order === 'desc' ? 'DESC' : 'ASC';
    const limit = Math.max(1, Math.min(10000, Number.isInteger(filters.limit) ? (filters.limit as number) : 100));
    const offset = Math.max(0, Number.isInteger(filters.offset) ? (filters.offset as number) : 0);

    const total = Number(
      (
        this.db.prepare(`SELECT COUNT(*) AS c FROM audit_events${whereSql}`).get(...params) as {
          c: number | bigint;
        }
      ).c,
    );

    const rows = this.db
      .prepare(`SELECT * FROM audit_events${whereSql} ORDER BY ${orderCol} ${orderDir} LIMIT ? OFFSET ?`)
      .all(...params, limit, offset) as unknown as Array<Record<string, unknown>>;

    const tags = this.fetchTags(rows.map((row) => Number(row.id)));
    const records = rows.map((row) => decodeRow(row, tags));
    return { records, total };
  }

  private fetchTags(ids: number[]): Map<number, string[]> {
    const map = new Map<number, string[]>();
    if (ids.length === 0) return map;
    // SQLite cannot bind an array inline; chunk into parameter lists.
    const chunk = 400;
    for (let i = 0; i < ids.length; i += chunk) {
      const slice = ids.slice(i, i + chunk);
      const placeholders = slice.map(() => '?').join(', ');
      const rows = this.db
        .prepare(`SELECT event_id, tag FROM audit_tags WHERE event_id IN (${placeholders})`)
        .all(...slice) as Array<{ event_id: number | bigint; tag: string }>;
      for (const row of rows) {
        const id = Number(row.event_id);
        const list = map.get(id);
        if (list) list.push(row.tag);
        else map.set(id, [row.tag]);
      }
    }
    for (const list of map.values()) list.sort();
    return map;
  }

  /** Verify the append-only hash chain; returns every violation found. */
  verifyChain(): ChainViolation[] {
    const rows = this.db
      .prepare('SELECT * FROM audit_events ORDER BY id ASC')
      .all() as unknown as Array<Record<string, unknown>>;
    const tags = this.fetchTags(rows.map((row) => Number(row.id)));
    const violations: ChainViolation[] = [];
    let expect = '';
    for (const row of rows) {
      const rec = decodeRow(row, tags);
      if (rec.hashPrev !== (expect || null)) {
        violations.push({ id: rec.id, reason: 'previous-hash mismatch' });
      }
      const expected = chainHash(rec.hashPrev, rec);
      if (rec.hashSelf !== expected) {
        violations.push({ id: rec.id, reason: 'self-hash does not match content' });
      }
      expect = rec.hashSelf ?? '';
    }
    return violations;
  }

  /** Aggregate counters for dashboards / the `stats` command. */
  stats(): AuditStats {
    const countOf = (sql: string, params: Array<string | number> = []) =>
      Number(
        (this.db.prepare(sql).get(...params) as { c: number | bigint } | undefined)?.c ?? 0,
      );
    const total = countOf('SELECT COUNT(*) AS c FROM audit_events');
    const firstLast = this.db
      .prepare('SELECT MIN(ts) AS min_ts, MAX(ts) AS max_ts FROM audit_events')
      .get() as { min_ts: number | null; max_ts: number | null };
    const byKind = (this.db
      .prepare('SELECT kind, COUNT(*) AS c FROM audit_events GROUP BY kind ORDER BY c DESC, kind')
      .all() as Array<{ kind: string; c: number | bigint }>).map((row) => ({
      kind: row.kind,
      count: Number(row.c),
    }));
    const bySeverity = (this.db
      .prepare('SELECT severity AS s, COUNT(*) AS c FROM audit_events GROUP BY severity ORDER BY MIN(severity_rank)')
      .all() as Array<{ s: string; c: number | bigint }>).map((row) => ({
      severity: row.s,
      count: Number(row.c),
    }));
    const byTag = (this.db
      .prepare('SELECT tag, COUNT(*) AS c FROM audit_tags GROUP BY tag ORDER BY c DESC, tag')
      .all() as Array<{ tag: string; c: number | bigint }>).map((row) => ({
      tag: row.tag,
      count: Number(row.c),
    }));
    return {
      total,
      schemaVersion: SCHEMA_VERSION,
      byKind,
      bySeverity,
      byTag,
      firstTs: firstLast.min_ts,
      lastTs: firstLast.max_ts,
    };
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    try {
      this.db.close();
    } catch {
      // already closed
    }
  }

  /** Best-effort diagnostic dump of the schema, for README examples. */
  dumpSchemaSql(): string {
    const rows = this.db
      .prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
      .all() as Array<{ sql: string | null }>;
    return rows.map((row) => row.sql ?? '').join(';\n\n') + ';';
  }
}

/** Write the schema SQL to a file (used by the example generator). */
export function writeSchemaExample(target: string): void {
  const db = new DatabaseSync(':memory:');
  db.exec(CREATE_TABLES);
  const sql = (db
    .prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
    .all() as Array<{ sql: string | null }>)
    .map((row) => row.sql ?? '')
    .join(';\n\n');
  db.close();
  writeFileSync(target, `${sql};\n`, 'utf8');
}

function parseBound(value: number | string | undefined): number | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value === 'number') return Number.isFinite(value) ? value : undefined;
  const parsed = Date.parse(value as string);
  return Number.isFinite(parsed) ? parsed : undefined;
}

/** Decode a raw DB row (arrays are JSON text) into an {@link AuditRecord}. */
export function decodeRow(
  row: Record<string, unknown>,
  tags: Map<number, string[]>,
): AuditRecord {
  const id = Number(row.id);
  return {
    id,
    sessionId: strDef(row.session_id, ''),
    ts: numDef(row.ts, 0),
    kind: strDef(row.kind, 'info') as AuditKind,
    turn: numOpt(row.turn),
    step: numOpt(row.step),
    toolName: strOpt(row.tool_name),
    callId: strOpt(row.call_id),
    argsDigest: strOpt(row.args_digest),
    status: strOpt(row.status) as AuditRecord['status'],
    durationMs: numOpt(row.duration_ms),
    severity: isSeverity(row.severity) ? row.severity : 'info',
    flags: tags.get(id) ?? [],
    summary: strDef(row.summary, ''),
    detail: strOpt(row.detail),
    filesRead: parseJsonArray(row.files_read),
    filesWritten: parseJsonArray(row.files_written),
    network: parseJsonArray(row.network),
    actor: strOpt(row.actor),
    sourceType: strDef(row.source_type, ''),
    sourceSeq: numOpt(row.source_seq),
    hashPrev: strNull(row.hash_prev),
    hashSelf: strNull(row.hash_self),
  };
}

/** String field with a required fallback (columns that are never NULL). */
function strDef(value: unknown, fallback: string): string {
  if (typeof value === 'string') return value;
  if (value != null) return String(value);
  return fallback;
}

/** Optional string column (NULL → undefined). */
function strOpt(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

/** Nullable string column (NULL stays null; non-string junk → undefined). */
function strNull(value: unknown): string | null {
  return typeof value === 'string' ? value : null;
}

/** Optional numeric column. */
function numOpt(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (value == null) return undefined;
  const n = Number(value);
  return Number.isFinite(n) ? n : undefined;
}

/** Numeric column with a required fallback. */
function numDef(value: unknown, fallback: number): number {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (value == null) return fallback;
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

/** Convenience: severity rank used by the CLI, kept next to the domain type. */
export { SEVERITY_ORDER };
