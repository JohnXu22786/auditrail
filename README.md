# dsh-audit-trail

Security auditing & session forensics for [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) (dsh).

A dsh **bundle** (plugin) that records every tool-invocation across the harness
session stream and the tool pipeline, flags high-risk operations, persists a
redacted, hash-chained audit trail to SQLite, and gives you query, export,
policy, and plain-text replay tools — plus a standalone CLI that works on the
same database without starting the harness.

> **Fills a gap:** the dsh ecosystem has observability plugins for *performance*
> (OTel / Prometheus). Nobody was doing a *security* audit trail — complete
> tool-invocation-chain recording with sensitive-operation marking, privacy
> masking, query/export, and text-terminal replay. That is what this bundle is.

---

## Table of contents

- [What it does](#what-it-does)
- [How it works](#how-it-works)
- [Install & integrate with dsh](#install--integrate-with-dsh)
- [Configuration](#configuration)
- [Model-facing tools](#model-facing-tools)
- [CLI](#cli)
- [Replay](#replay)
- [Compliance export format](#compliance-export-format)
- [Sensitive-operation rules](#sensitive-operation-rules)
- [Privacy & redaction](#privacy--redaction)
- [SQLite schema](#sqlite-schema)
- [Project layout](#project-layout)
- [Development](#development)
- [License](#license)

---

## What it does

1. **Complete audit chain recording** — subscribes to the append-only
   `session/event` stream and the live tool pipeline (`tools/result`,
   `tools/change`) and records, for every event: *who* (session/actor), *when*
   (timestamp + sequence), *which command* (tool name + masked argument
   digest), *which files* were touched, *which outbound network destinations*
   were targeted, *result status*, and *duration*.
2. **Sensitive-operation marking** — a configurable rule table detects
   high-risk patterns (`rm -rf`, `curl | sh`, key/secret material, destructive
   git/db operations, outbound exfil-style requests, privilege escalation, …)
   and attaches severity + rule tags to the affected records.
3. **SQLite (WAL) persistence with privacy** — all stored content is masked
   and truncated by default; nothing raw is persisted unless you relax the
   redaction config. An append-only hash chain ties each row to the previous
   one, so tampering is detectable with `auditrail chain verify`.
4. **Query & export** — filter records by time window, session, tool, minimum
   severity, sensitive-rule tag, and kind; export JSON reports, Markdown
   reports, or the fixed-format compliance JSONL (with optional hash chain).
5. **Session replay** — render the audit trail as a plain-text terminal
   timeline and slow-play it with pause / step / seek / speed controls. No
   browser involved.
6. **Compliance output** — a versioned, fixed-format JSONL (`schema:
   dsh-audit-trail/compliance/1`) that third parties can validate with the
   bundled verifier or their own tooling.
7. **Tool chain** — four model-facing tools (`audit_query`, `audit_export`,
   `audit_playback`, `audit_policy`) plus a standalone CLI (`auditrail`).

---

## How it works

```
 ┌────────────── dsh harness ──────────────┐
 │ session/event  (append-only durable log) │
 │ tools/result   (live tool dispatch)      │
 │ tools/change   (registry changes)        │
 └──────────────┬──────────────────────────-┘
                │  Recorder (contained, never throws)
                ▼
        Normalize → RuleEngine (flag) → Redact/mask/truncate
                │
                ▼
        AuditStore (SQLite, WAL, hash chain, tags)
                │
        ┌───────┴───────────┐
        ▼                   ▼
   audit_query / export   auditrail CLI
   /playback / policy      (same database)
```

### Record kinds

| Kind | Source event | Meaning |
|---|---|---|
| `user_message` | `session/event` `user/message` | user/synthetic input |
| `assistant_message` | `session/event` `assistant/message` | model output |
| `assistant_chunk` | `session/event` `assistant/chunk` | token-level (opt-in) |
| `turn_start` / `turn_end` | `turn/start` / `turn/end` | turn brackets |
| `step_start` / `step_end` | `step/start` / `step/end` | step brackets |
| `todo_update` | `todo/write` | todo snapshot |
| `request_header` / `request_context` | `request/header` / `request/context` | model routing |
| `tool_call` | `tool/call` | the durable command record (args digest, files, network, flags) |
| `tool_result` | `tool/result` | the durable outcome (status, error, duration) |
| `tool_dispatch` | `tools/result` | the live precise outcome (status, structured error, duration) |
| `tool_registered` | `tools/change` | registry add/remove deltas |
| `session_live` | `session/end-seed` | live history begins |

`audit_query --chains` merges `tool_call` + `tool_result` + `tool_dispatch`
(correlated by `callId` / session+turn+step) into one **invocation chain** per
tool call — a single row with status, duration, files, network, severity, and
flags.

### Ordering & determinism

The recorder ingests synchronously in arrival order and the store assigns a
monotonic `AUTOINCREMENT` id, so identical input streams produce byte-identical
trails (verified by a dedicated determinism test). Within a session the durable
event stream is already ordered; cross-source ordering (session log vs. live
tool pipeline) is the harness's emission order, and the query layer re-joins
the two sources deterministically by correlation keys.

---

## Install & integrate with dsh

The bundle follows the [official dsh bundle
spec](https://deepseek-harness.github.io/deepseek-harness/en/develop/basic/publish):

- `package.json` declares `dsh: { bundle: { patch: "./cordis.patch.yml" } }`
- `cordis.patch.yml` mounts the plugin row
- the entry module exports `name`, `inject`, and `apply(ctx, config)`

### Local development bundle (link)

```bash
# from a dsh profile directory (a profile's package.json has "dsh": {"profile": {...}})
dsh plugin --profile <name> add /path/to/dsh-plugin/auditrail
dsh --profile <name>
```

`dsh plugin add` links the package into the profile's dependencies and appends
it to `dsh.profile.bundles`, which activates the `cordis.patch.yml` layer.

### From a tarball / npm

```bash
npm pack            # produces dsh-audit-trail-0.1.0.tgz
dsh plugin --profile <name> add ./dsh-audit-trail-0.1.0.tgz
```

On boot the patch layer inserts one row:

```yaml
- insert:
  - id: audit-trail
    name: 'dsh-audit-trail'
```

You normally need **no configuration** — every field defaults in code. To tune
a single profile, override that row (`id: audit-trail`) from the profile's own
`cordis.patch.yml` (a patch replaces the whole `config` block — restate every
field you keep).

### Requirements

- Node.js `>= 22.13` (uses the built-in `node:sqlite`, no native deps).
- A harness that emits `session/event` and `tools/*` events (everything in the
  current `@deepseek-ai/dsh-*` set does).

---

## Configuration

All fields optional. Defaults shown.

```ts
interface AuditConfig {
  storage: {
    /** null => <dshHome>/audit-trail/audit.sqlite
     *  dshHome = $DSH_HOME || ~/.dsh; AUDITRAIL_DB overrides for the CLI */
    path: string | null;
  };
  redact: {
    /** Mask known secret patterns before storing (default true). */
    maskSecrets: boolean;
    /** Tool-argument digest cap in chars.            */ truncateArgs: number;   // 512
    /** Summary cap in chars.                         */ truncateSummary: number; // 240
    /** Detail JSON cap in chars.                     */ truncateDetail: number;  // 4096
    /** Max file paths captured per record.           */ maxFiles: number;        // 16
    /** Max outbound destinations captured per record.*/ maxNetwork: number;      // 16
    /** Extra secret regex patterns (regex source).   */ extraSecretPatterns: string[];
  };
  rules: {
    /** Built-in rule ids to disable, e.g. ["net:plaintext-http"]. */
    disabledIds: string[];
    /** Operator rules added to (not replacing) the default table. */
    custom: Array<{
      id: string; severity: 'info'|'low'|'medium'|'high'|'critical';
      pattern: string; scope: 'args'|'result'|'files'|'network'|'all'|'tool';
      flags?: string; tool?: string[]; description?: string;
    }>;
  };
  capture: {
    chunks: boolean;        // false — record assistant_chunk per token?
    turnEvents: boolean;    // true
    stepEvents: boolean;    // true
    toolDispatch: boolean;  // true — record live tool_dispatch rows
    toolRegistered: boolean;// true — record tools/change deltas
  };
}
```

Example (`cordis.patch.yml` override):

```yaml
- insert:
  - id: audit-trail
    name: 'dsh-audit-trail'
    config:
      storage:
        path: '/srv/audit/audit.sqlite'
      redact:
        truncateArgs: 256
        extraSecretPatterns:
          - '\\bCUSTOM_SECRET_[A-Z0-9]{20,}\\b'
      rules:
        disabledIds:
          - 'net:plaintext-http'
        custom:
          - id: 'my:purge'
            severity: 'critical'
            pattern: '\\bpurgelogs\\b'
            scope: 'args'
      capture:
        chunks: false
```

---

## Model-facing tools

All four are registered on `ctx.tools` when the plugin loads.

### `audit_query`

Query the stored trail.

- Parameters: `session_id`, `tool_name`, `min_severity`
  (`info|low|medium|high|critical`), `flag` (rule tag, e.g. `shell:rm-rf`),
  `kind`, `from`, `to` (ISO date or epoch ms), `limit` (≤ 10000),
  `chains` (merge into invocation chains), `format` (`json` | `markdown`).
- Returns: `{ count, total?, format, records | chains | text }`
  (privacy-redacted; `total` is present on the raw-record path).

### `audit_export`

Export filtered records.

- Parameters: `format` (`json` | `markdown` | `jsonl`), optional `path` (writes
  the file), the query filters above, `hash_chain` (jsonl only), `chains`.
- Returns: `{ format, count, path?, bytes?, hash_chain, content? }`.

### `audit_policy`

Inspect / change the sensitive-rule table at runtime.

- `action: list` returns every rule with its enabled state.
- `action: show|enable|disable` on a `rule_id`.
- `action: add` with `id`, `pattern`, `severity`, `scope`, `description`.
- Runtime-only: persist changes via the plugin config.

### `audit_playback`

Render the trail as a plain-text timeline (one line per event: timecode, id,
kind, tool, severity, flags, redacted summary, duration).

- Parameters: query filters + `limit`, `cap` (max lines), `chains` (collapse to
  invocation-chain lines).
- Returns: `{ count, totalLines, truncated, text }`. For interactive
  pause/step/speed replay use the `auditrail playback` CLI.

---

## CLI

`auditrail` reads the **same SQLite database** the plugin writes to, so you can
operate on a live trail without starting the harness.

```text
auditrail help
auditrail stats [--db P]
auditrail query [--db P] [--from D] [--to D] [--session S] [--tool T]
                [--severity LVL] [--flag TAG] [--kind K] [--limit N] [--offset N]
                [--order asc|desc] [--sort id|time] [--json|--markdown] [--chains]
auditrail export --format json|markdown|jsonl [--out PATH] [--hash-chain] [--chains] [filters]
auditrail playback [--session S] [--speed N] [--interactive] [--cap N] [--colors] [--chains]
auditrail policy list | show <id> | enable <id> | disable <id> | add --id X --pattern RE [--severity S] [--scope ARG]
auditrail chain verify [--db P]
auditrail verify-compliant --file PATH
```

Database resolution: `--db P` → `$AUDITRAIL_DB` → `<dshHome>/audit-trail/audit.sqlite`.
(`--db :memory:` opens an in-memory store.)

> **Note:** `auditrail policy` mutations are **runtime-only for that process** —
> every CLI invocation is a fresh process, so a rule added by one command is
> gone by the next. Toggle/add persistent rules through the dsh plugin's
> `audit_policy` tool (long-lived process) or via the plugin configuration.

Examples:

```bash
auditrail query --session sess-42 --min-severity high --markdown
auditrail export --format jsonl --hash-chain --out trail.jsonl --flag shell:rm-rf
auditrail verify-compliant --file trail.jsonl
auditrail playback --session sess-42 --interactive --speed 2 --colors
auditrail chain verify
```

---

## Replay

`renderTimeline()` produces a deterministic plain-text line per event:

```
09:00:05.000  #000002  user_message     -           [INFO]   fetch the deployment script and run it
09:00:10.000  #000003  tool_call        bash        [CRITICAL] shell:pipe-to-shell  curl -sSL ... | sh
09:00:15.000  #000004  tool_result      -           [INFO]   ok in 5000ms
```

`PlaybackController` slow-plays the lines with pause / step / seek / speed;
`runInteractive()` binds it to a raw TTY. Keys (interactive):

```text
space  pause / resume      s  step one line       + / -  speed up / down
g      jump to start        q  (or Ctrl-C) quit
```

Non-TTY (`--interactive` omitted, or piped) renders the whole timeline at once.

---

## Compliance export format

Fixed, versioned, line-oriented JSON:

```jsonl
{"schema":"dsh-audit-trail/compliance/1","generatedAt":1750000000000,"count":2,"hashChain":true}
{"recordId":1,"prevHash":null,"payload":{"id":1,"sessionId":"sess-42","ts":1750000000000,"kind":"tool_call","turn":1,"step":1,"toolName":"bash","callId":"call-1","argsDigest":"{\"command\":\"curl ...\"}","status":"pending","durationMs":null,"severity":"critical","flags":["shell:pipe-to-shell"],"filesRead":[],"filesWritten":[],"network":["https://..."],"actor":null,"sourceType":"tool/call","sourceSeq":1,"summary":"bash"},"hashSelf":"a1b2..."}
```

- Line 1 is a header (`schema`, `generatedAt`, `count`, `hashChain`).
- Each data line is a single JSON object; the payload uses one fixed field set
  (see `compliancePayload` in `src/query.ts`).
- With `hashChain: true`, `hashSelf` is `sha256(prevHash + "\n" + canonical
  line + "\n")` and `prevHash` echoes the previous line's `hashSelf`, forming a
  chain. `auditrail verify-compliant` and `verifyComplianceJsonl()` validate it
  (and will report any tampered or reordered line).

---

## Sensitive-operation rules

Built-in table (rules can be disabled / extended; each has a dedicated test in
`test/rules.test.ts`):

| id | severity | scope | pattern (abridged) |
|---|---|---|---|
| `shell:rm-rf` | high | args | `rm -rf` / `-fr` / `--recursive --force` / `-r -f` variants |
| `shell:pipe-to-shell` | critical | args | `curl\|wget\|nc … \| sh\|bash` (first-pipe) |
| `shell:base64-to-shell` | high | args | `base64 -d \| sh` |
| `file:key-material` | critical | files | `.ssh`, `id_rsa*`, `.pem/.key/.p12/.pfx`, `.env`, `credentials`, `.aws/.azure` |
| `secret:inline` | high | args | `api_key=`, `token=`, `password=`, `Authorization: Bearer …` |
| `git:force-push` | high | args | `git push --force` / `-f` |
| `git:history-rewrite` | medium | args | `reset --hard`, `filter-branch`, `branch -D` |
| `db:destructive` | high | args | `drop table/database`, `truncate table` |
| `net:exfil-literal-ip` | high | network | outbound to a literal IP |
| `net:plaintext-http` | medium | network | outbound `http://` |
| `priv:root` | critical | args | `sudo su`, `sudo -u root` |
| `fs:world-writable` | medium | args | `chmod 777/666` |
| `fs:system-dir-write` | high | files | access under `/etc`, `/usr`, `System32`, … |
| `proc:kill-force` | medium | args | `kill -9`, `pkill -9` |

Matched rule ids are stored as **tags** on the record (and in the `audit_tags`
table), the record severity becomes the highest matched severity, and both can
be queried (`--flag`, `--severity` / `min_severity`).

---

## Privacy & redaction

- Only **redacted** content is persisted by default: argument digests are
  masked (private keys, bearer/basic tokens, `key=value` secrets, long
  high-entropy runs) and truncated; summaries and details are capped.
- `digestArgs` also understands structure: an object value whose key looks like
  a secret (`password`, `token`, `api_key`, `authorization`, …) is replaced
  entirely while its key (a label) is kept.
- The audit trail itself records *that* sensitive operations happened (the
  forensic value); it does not store their secret values.
- Disable masking with `redact.maskSecrets: false` only if you fully trust the
  store location — this is not recommended.

---

## SQLite schema

One store, a handful of tables (WAL journal, `synchronous = NORMAL`):

```
audit_meta     key/value metadata (schema_version)
audit_events   the append-only trail
   id, session_id, ts, kind, turn, step, tool_name, call_id, args_digest,
   status, duration_ms, severity, severity_rank, summary, detail,
   files_read, files_written, network, actor, source_type, source_seq,
   hash_prev, hash_self, created_at
audit_tags     (event_id, tag) — sensitive-rule tags, indexed
```

Indexes cover `ts`, `session_id`, `tool_name`, `severity_rank`, `kind`, `tag`.
`chain verify` walks rows by `id` and recomputes every hash.

---

## Project layout

```
auditrail/
  package.json        dsh bundle manifest (dsh.bundle.patch) + scripts
  cordis.patch.yml    bundle patch layer mounting the plugin
  tsconfig.json       TypeScript → lib/ (NodeNext ESM)
  bin/auditrail.mjs   CLI launcher (calls lib/cli.js)
  src/
    index.ts          bundle entry: name / inject / apply + programmatic exports
    config.ts         config types, defaults, tolerant normalization
    types.ts          domain types (severity, kinds, records, filters)
    rules.ts          sensitive-rule table + deterministic matcher (RuleEngine)
    redact.ts         secret masking, truncation, argument digesting
    scan.ts           heuristic file-path / network extraction + attribution
    store.ts          node:sqlite WAL store, queries, hash chain, stats
    recorder.ts       event subscription + normalization + correlation
    query.ts          chain merging + JSON/Markdown/compliance reports + verify
    playback.ts       plain-text timeline renderer + playback controller + TTY
    tools.ts          audit_query / audit_export / audit_policy / audit_playback
    service.ts        facade shared by tools and CLI
    cli.ts            standalone CLI
  test/               node:test suite (record completeness, flagging, query,
                      export, playback, redaction, plugin contract, CLI)
  examples/           usage.mjs + generator + committed sample artifacts
  README.md / README.zh.md / LICENSE
```

---

## Development

```bash
npm install
npm run build        # tsc → lib/
npm run typecheck    # tsc --noEmit
npm test             # build + node --test test/*.test.ts
node bin/auditrail.mjs help
node examples/generate-examples.mjs    # refresh examples/*.jsonl|*.md
node examples/usage.mjs                # programmatic API demo
```

## License

MIT — see [LICENSE](LICENSE).
