/**
 * Plugin configuration: typed view of what the bundle accepts and its
 * normalized defaults. The dsh plugin entry (`apply`) receives a raw config
 * object from the patch layer and runs it through `normalizeConfig` so every
 * field is present with a safe default. Configuration is optional in a
 * `cordis.patch.yml` (or per-profile override).
 */
import type { Severity } from './types.js';
import type { RuleScope, RuleSpec } from './rules.js';

/** Redaction / privacy knobs. Masking and truncation are applied at ingest. */
export interface RedactConfig {
  /** Mask known secret patterns (private keys, tokens, passwords...) before storing. */
  maskSecrets: boolean;
  /** Max length of the tool-argument digest string. */
  truncateArgs: number;
  /** Max length of each human summary. */
  truncateSummary: number;
  /** Max length of the redacted detail JSON. */
  truncateDetail: number;
  /** Max number of file paths captured per record. */
  maxFiles: number;
  /** Max number of outbound destinations captured per record. */
  maxNetwork: number;
  /** Extra secret regex patterns merged into the default secret matcher. */
  extraSecretPatterns: string[];
}

/** Sensitive-rule table configuration. Rules are matched at ingest. */
export interface RulesConfig {
  /** Rule ids the operator wants disabled (see the default table in rules.ts). */
  disabledIds: string[];
  /** Operator-defined rules, added to (not replacing) the built-in table. */
  custom: RuleSpec[];
}

/** Which upstream events to capture beyond the always-on core. */
export interface CaptureConfig {
  /** Record every `assistant/chunk` (token-level fidelity). Default off: summaries only. */
  chunks: boolean;
  /** Record `turn/start` and `turn/end`. */
  turnEvents: boolean;
  /** Record `step/start` and `step/end`. */
  stepEvents: boolean;
  /** Record `tool_dispatch` rows from the live tool-pipeline hook. */
  toolDispatch: boolean;
  /** Record `tool_registered` rows when the tool registry changes. */
  toolRegistered: boolean;
}

/** Storage settings. */
export interface StorageConfig {
  /**
   * SQLite database path. `null`/undefined uses the default:
   * `<dshHome>/audit-trail/audit.sqlite` where `dshHome` is `$DSH_HOME` or
   * `~/.dsh`. Supports `$Dsh`-style environment overrides via
   * `AUDITRAIL_DB` when unset.
   */
  path: string | null;
}

/** Top-level configuration accepted by the bundle. */
export interface AuditConfig {
  storage: StorageConfig;
  redact: RedactConfig;
  rules: RulesConfig;
  capture: CaptureConfig;
}

/** Default configuration used when fields are absent. */
export const DEFAULT_CONFIG: AuditConfig = Object.freeze({
  storage: Object.freeze({ path: null }),
  redact: Object.freeze({
    maskSecrets: true,
    truncateArgs: 512,
    truncateSummary: 240,
    truncateDetail: 4096,
    maxFiles: 16,
    maxNetwork: 16,
    extraSecretPatterns: [],
  }),
  rules: Object.freeze({
    disabledIds: [],
    custom: [],
  }),
  capture: Object.freeze({
    chunks: false,
    turnEvents: true,
    stepEvents: true,
    toolDispatch: true,
    toolRegistered: true,
  }),
});

function pickBoolean(value: unknown, fallback: boolean): boolean {
  return typeof value === 'boolean' ? value : fallback;
}

function pickNumber(value: unknown, fallback: number, min = 0): number {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return Math.max(value, min);
  }
  return fallback;
}

function pickStringArray(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value.filter((x): x is string => typeof x === 'string');
  }
  return [];
}

function pickSeverity(value: unknown, fallback: Severity): Severity {
  return typeof value === 'string' &&
    ['info', 'low', 'medium', 'high', 'critical'].includes(value)
    ? (value as Severity)
    : fallback;
}

function pickPath(value: unknown): string | null {
  if (typeof value === 'string' && value.trim() !== '') return value.trim();
  return null;
}

/** Tolerantly merge an unknown config object onto the defaults. */
export function normalizeConfig(raw: unknown): AuditConfig {
  const cfg = (raw != null && typeof raw === 'object' ? raw : {}) as Record<string, unknown>;
  const storage = (cfg.storage ?? {}) as Record<string, unknown>;
  const redact = (cfg.redact ?? {}) as Record<string, unknown>;
  const rules = (cfg.rules ?? {}) as Record<string, unknown>;
  const capture = (cfg.capture ?? {}) as Record<string, unknown>;
  const customRaw = (rules.custom ?? []) as unknown;

  const custom: RuleSpec[] = [];
  if (Array.isArray(customRaw)) {
    for (const entry of customRaw) {
      if (entry == null || typeof entry !== 'object') continue;
      const spec = entry as Record<string, unknown>;
      const id = typeof spec.id === 'string' ? spec.id : '';
      const pattern = typeof spec.pattern === 'string' ? spec.pattern : '';
      if (!id || !pattern) continue;
      custom.push({
        id,
        pattern,
        severity: pickSeverity(spec.severity, 'high'),
        scope: (['args', 'result', 'files', 'network', 'all', 'tool'] as const).includes(
          spec.scope as RuleScope,
        )
          ? (spec.scope as RuleScope)
          : 'args',
        flags: typeof spec.flags === 'string' ? spec.flags : undefined,
        tool: typeof spec.tool === 'string'
          ? [spec.tool]
          : Array.isArray(spec.tool)
            ? spec.tool.filter((x): x is string => typeof x === 'string')
            : undefined,
        description: typeof spec.description === 'string' ? spec.description : '',
      });
    }
  }

  return {
    storage: {
      path: pickPath(storage.path),
    },
    redact: {
      maskSecrets: pickBoolean(redact.maskSecrets, DEFAULT_CONFIG.redact.maskSecrets),
      truncateArgs: pickNumber(redact.truncateArgs, DEFAULT_CONFIG.redact.truncateArgs, 16),
      truncateSummary: pickNumber(
        redact.truncateSummary,
        DEFAULT_CONFIG.redact.truncateSummary,
        8,
      ),
      truncateDetail: pickNumber(
        redact.truncateDetail,
        DEFAULT_CONFIG.redact.truncateDetail,
        64,
      ),
      maxFiles: pickNumber(redact.maxFiles, DEFAULT_CONFIG.redact.maxFiles, 0),
      maxNetwork: pickNumber(redact.maxNetwork, DEFAULT_CONFIG.redact.maxNetwork, 0),
      extraSecretPatterns: pickStringArray(redact.extraSecretPatterns),
    },
    rules: {
      disabledIds: pickStringArray(rules.disabledIds),
      custom,
    },
    capture: {
      chunks: pickBoolean(capture.chunks, DEFAULT_CONFIG.capture.chunks),
      turnEvents: pickBoolean(capture.turnEvents, DEFAULT_CONFIG.capture.turnEvents),
      stepEvents: pickBoolean(capture.stepEvents, DEFAULT_CONFIG.capture.stepEvents),
      toolDispatch: pickBoolean(capture.toolDispatch, DEFAULT_CONFIG.capture.toolDispatch),
      toolRegistered: pickBoolean(capture.toolRegistered, DEFAULT_CONFIG.capture.toolRegistered),
    },
  };
}
