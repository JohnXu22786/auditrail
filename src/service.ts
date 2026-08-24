/**
 * The audit service facade: the single object the dsh tools and the CLI talk
 * to. It owns the SQLite store, the live rule engine (which `audit_policy`
 * reconfigures at runtime), and the report/export builders.
 */
import type { AuditConfig } from './config.js';
import { DEFAULT_RULES, RuleEngine, compileRule, type RuleSpec } from './rules.js';
import type { AuditStore, QueryResult } from './store.js';
import {
  complianceJsonl,
  jsonReport,
  markdownChainReport,
  markdownReport,
  mergeToolChains,
  type ReportFiltersSnapshot,
} from './query.js';
import type { AuditFilters, ToolChain } from './types.js';
import type { Severity } from './types.js';

export type ExportFormat = 'json' | 'markdown' | 'jsonl';

export interface ExportOptions {
  format: ExportFormat;
  filters: AuditFilters;
  hashChain?: boolean;
  asChains?: boolean;
  filterSnapshot?: ReportFiltersSnapshot;
}

export interface ExportResult {
  format: ExportFormat;
  content: string;
  count: number;
  hashChain: boolean;
}

export class AuditService {
  readonly engine: RuleEngine;
  private readonly custom: RuleSpec[];
  private readonly disabled: Set<string>;

  constructor(
    readonly store: AuditStore,
    readonly config: AuditConfig,
  ) {
    this.custom = [...config.rules.custom];
    this.disabled = new Set(config.rules.disabledIds);
    this.engine = new RuleEngine(this.specs(), this.disabled);
  }

  /** The effective rule table (defaults + custom), in stable order. */
  private specs(): RuleSpec[] {
    return [...DEFAULT_RULES, ...this.custom];
  }

  private rebuild(): void {
    this.engine.configure(this.specs(), this.disabled);
  }

  queryRecords(filters: AuditFilters): QueryResult {
    return this.store.query(filters);
  }

  queryChains(filters: AuditFilters): ToolChain[] {
    return mergeToolChains(this.store.query(filters).records);
  }

  verifyChain() {
    return this.store.verifyChain();
  }

  stats() {
    return this.store.stats();
  }

  /** Render records/chains into one export format. */
  exportText(opts: ExportOptions): ExportResult {
    const { records } = this.store.query(opts.filters);
    const snapshot: ReportFiltersSnapshot =
      opts.filterSnapshot ?? (opts.filters as unknown as ReportFiltersSnapshot);
    let content: string;
    let count: number;
    let hashChain = false;
    switch (opts.format) {
      case 'jsonl':
        hashChain = opts.hashChain === true;
        content = complianceJsonl(records, { hashChain });
        count = records.length;
        break;
      case 'markdown':
        if (opts.asChains) {
          const chains = this.queryChains(opts.filters);
          content = markdownChainReport(chains, snapshot);
          count = chains.length;
        } else {
          content = markdownReport(records, snapshot);
          count = records.length;
        }
        break;
      case 'json':
      default:
        content = JSON.stringify(jsonReport(records, snapshot), null, 2);
        count = records.length;
        break;
    }
    return { format: opts.format, content, count, hashChain };
  }

  /** `audit_policy list` payload. */
  policyList() {
    return this.engine.list();
  }

  /** Enable or disable a rule by id (runtime only; persists via config). */
  policySetEnabled(id: string, enabled: boolean): boolean {
    if (!this.specs().some((rule) => rule.id === id)) return false;
    if (enabled) this.disabled.delete(id);
    else this.disabled.add(id);
    this.rebuild();
    return true;
  }

  isRuleEnabled(id: string): boolean {
    return this.engine.isEnabled(id);
  }

  /** Add a custom rule at runtime (validates the pattern actually compiles). */
  policyAdd(spec: RuleSpec): { ok: boolean; error?: string } {
    if (!spec.id || !/^[a-zA-Z0-9:_-]+$/.test(spec.id)) {
      return { ok: false, error: 'invalid rule id (use [a-zA-Z0-9:_-])' };
    }
    if (this.specs().some((rule) => rule.id === spec.id)) {
      return { ok: false, error: `rule id already exists: ${spec.id}` };
    }
    try {
      // Compile directly (RuleEngine.configure swallows compile errors, so an
      // invalid pattern would otherwise be silently adopted as a dead rule).
      compileRule(spec);
    } catch (error) {
      return { ok: false, error: `bad pattern: ${error instanceof Error ? error.message : String(error)}` };
    }
    this.custom.push(spec);
    this.rebuild();
    return { ok: true };
  }

  /** Metadata for diagnostics. */
  describe(): { bundle: string; schema: number; rulesEnabled: number; rulesTotal: number; minSeverity: Severity } {
    const list = this.engine.list();
    return {
      bundle: 'dsh-audit-trail',
      schema: this.store.stats().schemaVersion,
      rulesEnabled: list.filter((rule) => rule.enabled).length,
      rulesTotal: list.length,
      minSeverity: 'low',
    };
  }
}
