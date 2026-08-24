/**
 * Sensitive-operation detection: a configurable table of rules plus the
 * deterministic matcher. The default table covers the classic high-risk
 * patterns (recursive force removal, remote-script piped into a shell,
 * secret/key material, dangerous git history rewrites, outbound network
 * requests, privilege escalation, database destruction, ...). Operators can
 * disable built-in rules and add their own via configuration.
 */
import type { Severity } from './types.js';
import { maxSeverity } from './types.js';

/** Which field(s) of a record a rule inspects. */
export type RuleScope =
  | 'args' // tool arguments / command text
  | 'result' // tool result text
  | 'files' // captured file paths
  | 'network' // captured outbound destinations
  | 'all' // any of the above
  | 'tool'; // the tool name itself

/** A matcher that tests a candidate against the rule. */
export interface RuleSpec {
  /** Stable identifier used for tags, filters and toggling. */
  id: string;
  severity: Severity;
  /** Regular-expression source tested against the scoped field. */
  pattern: string;
  scope: RuleScope;
  /** Regex flags; `i` by default. */
  flags?: string;
  /** Optional: only consider records whose tool name is in this list. */
  tool?: string[];
  description?: string;
}

/** The text candidate one record exposes to the matcher. */
export interface RuleCandidate {
  toolName?: string;
  args?: string;
  result?: string;
  files: string[];
  network: string[];
}

/** The compiled form of a rule, compiled once at construction. */
export interface CompiledRule {
  id: string;
  severity: Severity;
  description: string;
  scope: RuleScope;
  re: RegExp;
  tool?: ReadonlySet<string>;
}

/**
 * The field values {@link RuleEngine.match} tests a rule against, expressed as a
 * list of "text units". `files`/`network` become one unit per entry so `^`/`$`
 * anchors in a rule regex behave per-entry (not per-joined-blob) — a rule
 * never silently misses its target because another entry sits first/last.
 */
function unitsFor(rule: CompiledRule, candidate: RuleCandidate): string[] {
  switch (rule.scope) {
    case 'args':
      return candidate.args === undefined ? [] : [candidate.args];
    case 'result':
      return candidate.result === undefined ? [] : [candidate.result];
    case 'files':
      return candidate.files;
    case 'network':
      return candidate.network;
    case 'all':
      return [candidate.args ?? '', candidate.result ?? '', ...candidate.files, ...candidate.network].filter(
        (text) => text.length > 0,
      );
    case 'tool':
      return candidate.toolName === undefined ? [] : [candidate.toolName];
    default:
      return [];
  }
}

/**
 * The built-in sensitive-rule table. Every pattern here has a dedicated test in
 * test/rules.test.ts; keep both in sync.
 */
export const DEFAULT_RULES: readonly RuleSpec[] = [
  {
    id: 'shell:rm-rf',
    severity: 'high',
    scope: 'args',
    pattern:
      '\\brm\\s+(?:-\\S*[rR][a-zA-Z]*[fF][a-zA-Z]*|-\\S*[fF][a-zA-Z]*[rR][a-zA-Z]*|-[a-zA-Z]*[rR][a-zA-Z]*\\s+-[a-zA-Z]*[fF][a-zA-Z]*|--recursive\\b[^\\n]{0,120}?--force\\b|--force\\b[^\\n]{0,120}?--recursive\\b)',
    description: 'Recursive-force deletion (`rm -rf` and common variants).',
  },
  {
    id: 'shell:pipe-to-shell',
    severity: 'critical',
    scope: 'args',
    pattern:
      '\\b(curl|wget|aria2c|nc|fetch)\\b\\s+[^\\n|]{0,200}?\\|\\s*(sh|bash|zsh|dash|fish)\\b',
    description: 'Remote content piped into an interpreter (`curl | sh`).',
  },
  {
    id: 'shell:base64-to-shell',
    severity: 'high',
    scope: 'args',
    pattern: '\\bbase64\\s*(?:-d|--decode)\\b[^\\n|]{0,120}?\\|\\s*(sh|bash|zsh)\\b',
    description: 'Decoded payload piped into a shell.',
  },
  {
    id: 'file:key-material',
    severity: 'critical',
    scope: 'files',
    pattern:
      '(?:^|[\\\\/])(?:id_rsa|id_ed25519|id_ecdsa|id_ed448|id_dsa)(?:\\.pub)?$' +
      '|\\.(?:pem|key|p12|pfx)$' +
      '|(?:^|[\\\\/])\\.ssh(?:[\\\\/]|$)' +
      '|(?:^|[\\\\/])\\.env(?:[\\\\/.]|$)' +
      '|(?:^|[\\\\/])credentials(?:[\\\\/]|$)' +
      '|(?:^|[\\\\/])\\.aws(?:[\\\\/]|$)' +
      '|(?:^|[\\\\/])\\.azure(?:[\\\\/]|$)',
    description: 'Read/write of private keys, certificates, or credential stores.',
  },
  {
    id: 'secret:inline',
    severity: 'high',
    scope: 'args',
    pattern:
      '\\b(?:api[_-]?key|apikey|access[_-]?key|auth[_-]?token|authorization|bearer|secret|password|passwd|private[_-]?key)\\b\\s*[=: ]+\\S{6,}',
    description: 'Inline secret/key material or auth headers in arguments.',
  },
  {
    id: 'git:force-push',
    severity: 'high',
    scope: 'args',
    pattern: '\\bgit\\b[^\\n]*\\bpush\\b[^\\n]*(?:--force(?:\\s|$)|-(?:[a-zA-Z]*f))',
    description: 'Force push that can destroy remote history.',
  },
  {
    id: 'git:history-rewrite',
    severity: 'medium',
    scope: 'args',
    pattern: '\\bgit\\b[^\\n]*(?:\\breset\\s+--hard\\b|filter-branch|branch\\s+-[a-zA-Z]*D\\b)',
    description: 'Destructive history rewrite / hard reset.',
  },
  {
    id: 'db:destructive',
    severity: 'high',
    scope: 'args',
    pattern: '\\bdrop\\s+(?:table|database)\\b|\\btruncate\\s+table\\b',
    description: 'Destructive database operation.',
  },
  {
    id: 'net:exfil-literal-ip',
    severity: 'high',
    scope: 'network',
    pattern: '\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}(?::[0-9]{1,5})?\\b',
    description: 'Outbound request to a literal (non-DNS) IP address.',
  },
  {
    id: 'net:plaintext-http',
    severity: 'medium',
    scope: 'network',
    pattern: '^http://',
    description: 'Outbound request over plaintext HTTP.',
  },
  {
    id: 'priv:root',
    severity: 'critical',
    scope: 'args',
    pattern: '\\bsudo\\s+su\\b|\\bsudo\\s+-u\\s+root\\b',
    description: 'Privilege escalation to root.',
  },
  {
    id: 'fs:world-writable',
    severity: 'medium',
    scope: 'args',
    pattern: '\\bchmod\\s+(?:777|666|a\\+w)\\b',
    description: 'Marker of a world-writable permission change.',
  },
  {
    id: 'fs:system-dir-write',
    severity: 'high',
    scope: 'files',
    pattern: '(?:^|[\\\\/])(?:etc|usr|bin|sbin|boot|System32|Windows)(?:[\\\\/]|$)',
    description: 'File access inside a system directory.',
  },
  {
    id: 'proc:kill-force',
    severity: 'medium',
    scope: 'args',
    pattern: '\\bkill\\s+-9\\b|\\bpkill\\s+-9\\b',
    description: 'Forceful process termination.',
  },
];

/** Compile a single rule spec into a matcher. */
export function compileRule(spec: RuleSpec): CompiledRule {
  const re = new RegExp(spec.pattern, spec.flags ?? 'i');
  return {
    id: spec.id,
    severity: spec.severity,
    description: spec.description ?? '',
    scope: spec.scope,
    re,
    tool: spec.tool && spec.tool.length > 0 ? new Set(spec.tool) : undefined,
  };
}

/** Whether a rule restricts by tool name. */
function toolApplies(rule: CompiledRule, candidate: RuleCandidate): boolean {
  if (!rule.tool) return true;
  if (!candidate.toolName) return false;
  return rule.tool.has(candidate.toolName);
}

/**
 * Live, re-configurable rule engine. The recorder holds one instance; the
 * `audit_policy` tool reconfigures it at runtime (disable/enable/add) without
 * restarting the plugin.
 */
export class RuleEngine {
  private specs: readonly RuleSpec[] = [];
  private disabledIds = new Set<string>();
  private rules: CompiledRule[] = [];

  constructor(specs: readonly RuleSpec[], disabledIds: Iterable<string> = []) {
    this.configure(specs, disabledIds);
  }

  /** Rebuild the compiled table from specs minus the disabled ids. */
  configure(specs: readonly RuleSpec[], disabledIds: Iterable<string>): void {
    this.specs = specs;
    this.disabledIds = new Set(disabledIds);
    const compiled: CompiledRule[] = [];
    for (const spec of specs) {
      if (this.disabledIds.has(spec.id)) continue;
      try {
        compiled.push(compileRule(spec));
      } catch {
        // A malformed custom pattern must not take the recorder down.
      }
    }
    this.rules = compiled;
  }

  /** All effective (enabled) compiled rules. */
  get all(): readonly CompiledRule[] {
    return this.rules;
  }

  isEnabled(id: string): boolean {
    return this.rules.some((rule) => rule.id === id);
  }

  /**
   * Score a candidate against every enabled rule. Returns the matched rule ids
   * (in table order) and the highest severity among them.
   */
  match(candidate: RuleCandidate): { ids: string[]; severity: Severity } {
    const ids: string[] = [];
    let severity: Severity = 'info';
    for (const rule of this.rules) {
      if (!toolApplies(rule, candidate)) continue;
      const textUnits = unitsFor(rule, candidate);
      if (textUnits.length === 0) continue;
      if (!textUnits.some((text) => rule.re.test(text))) continue;
      ids.push(rule.id);
      severity = maxSeverity(severity, rule.severity);
    }
    return { ids, severity };
  }

  /** The full rule table with enabled state, for `audit_policy list`. */
  list(): Array<{
    id: string;
    severity: Severity;
    scope: RuleScope;
    description: string;
    enabled: boolean;
  }> {
    return this.specs.map((spec) => ({
      id: spec.id,
      severity: spec.severity,
      scope: spec.scope,
      description: spec.description ?? '',
      enabled: !this.disabledIds.has(spec.id),
    }));
  }

  /** Disabled rule ids currently in effect. */
  get disabledIdsSet(): ReadonlySet<string> {
    return new Set(this.disabledIds);
  }
}
