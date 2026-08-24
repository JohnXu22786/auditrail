/**
 * dsh-audit-trail — DeepSeek Harness (dsh) bundle entry.
 *
 * A *security auditing & session forensics* plugin. On load it:
 *
 *  1. opens the SQLite (WAL) audit store (privacy-redacted by default),
 *  2. subscribes to the durable `session/event` stream and the live tool
 *     pipeline (`tools/result`, `tools/change`) through the recorder,
 *  3. registers the four model-facing tools
 *     (`audit_query` / `audit_export` / `audit_playback` / `audit_policy`).
 *
 * Everything is torn down when the plugin is disposed (HMR reload, profile
 * change, etc.); the store is reopened on the next load.
 */
import type { Context } from '@deepseek-ai/cordis';
import { normalizeConfig, type AuditConfig } from './config.js';
import { AuditService } from './service.js';
import { Recorder } from './recorder.js';
import { AuditStore, resolveDbPath } from './store.js';
import { defineAuditTools } from './tools.js';

export const name = 'dsh-audit-trail';

/** The bundle needs the tool registry to mount its tools. */
export const inject = ['tools'];

export function apply(ctx: Context, config?: Partial<AuditConfig>): () => void {
  const cfg = normalizeConfig(config);
  const store = AuditStore.open(resolveDbPath(cfg.storage.path));
  const disposers: Array<() => void> = [];
  try {
    const service = new AuditService(store, cfg);
    const namedLogger = ctx.logger('dsh-audit-trail');

    const recorder = new Recorder({
      config: cfg,
      engine: service.engine,
      ingest: (records) => store.insert(records),
      scrapeTools: () => {
        try {
          return ctx.tools.schemas().map((schema) => String(schema.name));
        } catch {
          return [];
        }
      },
      logger: { warn: (message, ...details) => namedLogger.warn(message, ...details) },
    });
    // Subscriptions push into the shared disposers array as they succeed, so a
    // mid-attach failure still leaves earlier subscriptions to be cleaned up.
    recorder.attach(ctx, disposers);

    for (const tool of defineAuditTools(service)) {
      try {
        ctx.tools.register(tool);
      } catch (error) {
        namedLogger.warn('audit tool registration failed: %s', error);
      }
    }
  } catch (error) {
    // Never leave a half-open store behind when later setup steps fail.
    for (const disposer of disposers) {
      try {
        disposer();
      } catch {
        // ignore disposal failures
      }
    }
    store.close();
    throw error;
  }

  // Cordis wires the value returned from `apply` as the fiber's disposer and
  // runs it on unload (HMR reload, profile change, stop). Unlike an event-
  // listener cleanup, this guarantees the SQLite store is closed and the
  // recorder subscriptions are released when the plugin tears down.
  return () => {
    for (const disposer of disposers) {
      try {
        disposer();
      } catch {
        // ignore disposal failures
      }
    }
    store.close();
  };
}

// --- Programmatic surface (used by the CLI and by host integration) --------

export { AuditService } from './service.js';
export type { ExportFormat, ExportOptions, ExportResult } from './service.js';
export { AuditStore } from './store.js';
export type {
  QueryResult,
  AuditStats,
  ChainViolation,
} from './store.js';
export { resolveDbPath, defaultDbPath, canonicalRecord, chainHash } from './store.js';
export { Recorder } from './recorder.js';
export type { RecorderContext, RecorderOptions } from './recorder.js';
export { extractContentText } from './recorder.js';
export { RuleEngine, DEFAULT_RULES, compileRule } from './rules.js';
export type { RuleSpec, RuleScope, RuleCandidate, CompiledRule } from './rules.js';
export { maskText, truncate, digestArgs, buildSecretMask, tryParseJson } from './redact.js';
export { findFilePaths, findNetwork, scanText, attributeFiles } from './scan.js';
export {
  mergeToolChains,
  jsonReport,
  markdownReport,
  markdownChainReport,
  complianceJsonl,
  verifyComplianceJsonl,
  compliancePayload,
  COMPLIANCE_SCHEMA,
} from './query.js';
export type {
  JsonReport,
  ReportFiltersSnapshot,
  ComplianceOptions,
  ComplianceVerification,
} from './query.js';
export {
  renderTimeline,
  PlaybackController,
  runInteractive,
  timecode,
} from './playback.js';
export type {
  TimelineRow,
  PlaybackOptions,
  PlaybackState,
  RenderOptions,
} from './playback.js';
export { normalizeConfig, DEFAULT_CONFIG } from './config.js';
export type { AuditConfig } from './config.js';
export {
  SEVERITIES,
  AUDIT_KINDS,
  SEVERITY_ORDER,
  severityRank,
  maxSeverity,
} from './types.js';
export type {
  Severity,
  AuditKind,
  AuditRecord,
  AuditRecordInput,
  AuditFilters,
  ToolChain,
  ToolStatus,
} from './types.js';
