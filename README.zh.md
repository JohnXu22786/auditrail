# dsh-audit-trail

面向 [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness)（dsh）的安全审计与会话取证插件。

一个 dsh **bundle（插件）**：订阅 harness 的会话事件流与工具调用流水线，记录每一次工具调用的完整调用链，标记高风险操作，把经过隐私脱敏、带哈希链的审计轨迹持久化到 SQLite，并提供查询、导出、策略与纯文本回放工具，外加一个可直接读取同一数据库的独立 CLI。

> **填补空白：** dsh 生态里已有的观测类插件（OTel / Prometheus）面向**性能**，而面向**安全审计**的完整工具调用链记录 + 回放此前无人实现。这正是本插件的定位。

---

## 目录

- [它做了什么](#它做了什么)
- [工作原理](#工作原理)
- [安装与接入 dsh](#安装与接入-dsh)
- [配置](#配置)
- [面向模型的工具](#面向模型的工具)
- [CLI](#cli)
- [会话回放](#会话回放)
- [合规导出格式](#合规导出格式)
- [敏感操作规则表](#敏感操作规则表)
- [隐私与脱敏](#隐私与脱敏)
- [SQLite 结构](#sqlite-结构)
- [项目结构](#项目结构)
- [开发](#开发)
- [许可证](#许可证)

---

## 它做了什么

1. **完整审计链记录** —— 订阅只追加的 `session/event` 事件流与实时工具流水线（`tools/result`、`tools/change`），对每条事件记录：**谁**（会话/角色）、**何时**（时间戳 + 序号）、**什么命令**（工具名 + 脱敏后的参数摘要）、**读写哪些文件**、**外发哪些网络地址**、**结果状态** 与 **耗时**。
2. **敏感操作标记** —— 可配置的规则表识别高风险模式（`rm -rf`、`curl | sh`、密钥读写、破坏性的 git/数据库操作、疑似外传的网络请求、提权等），为相关记录打上严重度与规则标签。
3. **SQLite（WAL）持久化 + 隐私保护** —— 默认只持久化经过掩码与截断的内容；每条记录与上一条通过 SHA-256 哈希链关联，可用 `auditrail chain verify` 检测篡改。
4. **查询与导出** —— 支持按时间窗口、会话、工具、最低严重度、敏感规则标签、记录类型过滤；导出为 JSON 报告、Markdown 报告或固定格式的合规 JSONL（可选哈希链）。
5. **会话回放** —— 把审计轨迹渲染为纯文本终端时间线，支持慢速播放、暂停、单步、跳转、调速。不依赖浏览器。
6. **合规输出** —— 带版本号的固定格式 JSONL（`schema: dsh-audit-trail/compliance/1`），可用内置校验器或第三方工具验证。
7. **工具链** —— 四个面向模型的工具（`audit_query` / `audit_export` / `audit_playback` / `audit_policy`）+ 独立 CLI（`auditrail`）。

---

## 工作原理

```
 ┌────────────── dsh harness ──────────────┐
 │ session/event  （只追加的持久会话日志）   │
 │ tools/result   （实时工具分发结果）       │
 │ tools/change   （工具注册表变化）         │
 └──────────────┬───────────────────────────┘
                │  Recorder（隔离运行，绝不抛错）
                ▼
        归一化 → RuleEngine（打标）→ 掩码/截断
                │
                ▼
        AuditStore（SQLite、WAL、哈希链、标签）
                │
        ┌───────┴───────────┐
        ▼                   ▼
   audit_query / export   auditrail CLI
   /playback / policy      （同一数据库）
```

### 记录类型

| 类型 | 来源事件 | 含义 |
|---|---|---|
| `user_message` | `user/message` | 用户/系统输入 |
| `assistant_message` | `assistant/message` | 模型输出 |
| `assistant_chunk` | `assistant/chunk` | token 级（可开关） |
| `turn_start` / `turn_end` | `turn/start` / `turn/end` | 回合边界 |
| `step_start` / `step_end` | `step/start` / `step/end` | 步骤边界 |
| `todo_update` | `todo/write` | 待办快照 |
| `request_header` / `request_context` | `request/header` / `request/context` | 模型路由 |
| `tool_call` | `tool/call` | 持久命令记录（参数摘要、文件、网络、标签） |
| `tool_result` | `tool/result` | 持久结果（状态、错误、耗时） |
| `tool_dispatch` | `tools/result` | 实时精确结果（状态、结构化错误、耗时） |
| `tool_registered` | `tools/change` | 工具注册/注销增量 |
| `session_live` | `session/end-seed` | 实时历史开始 |

`audit_query --chains` 会把 `tool_call` + `tool_result` + `tool_dispatch`（按 `callId` / 会话+回合+步骤关联）合并为每次调用的**调用链**——一行包含状态、耗时、文件、网络、严重度与标签。

### 顺序与确定性

记录器同步按到达顺序摄取，存储层分配单调递增的 `AUTOINCREMENT` 主键，因此相同输入流会产生逐字节一致的轨迹（由专门的一致性测试验证）。同会话内持久事件流本身有序；跨来源（会话日志 vs 实时流水线）的顺序遵循 harness 的发出顺序，查询层按关联键确定性地把两路来源重新合并。

---

## 安装与接入 dsh

本 bundle 遵循[官方 dsh bundle 规范](https://deepseek-harness.github.io/deepseek-harness/en/develop/basic/publish)：

- `package.json` 声明 `dsh: { bundle: { patch: "./cordis.patch.yml" } }`
- `cordis.patch.yml` 挂载插件行
- 入口模块导出 `name`、`inject`、`apply(ctx, config)`

### 本地开发 bundle（链接）

```bash
# 在某个 dsh profile 目录下（其 package.json 带有 "dsh": {"profile": {...}}）
dsh plugin --profile <name> add /path/to/dsh-plugin/auditrail
dsh --profile <name>
```

`dsh plugin add` 会把包链接进 profile 依赖，并追加到 `dsh.profile.bundles`，从而激活 `cordis.patch.yml` 层。

### 通过 tarball / npm

```bash
npm pack            # 生成 dsh-audit-trail-0.1.0.tgz
dsh plugin --profile <name> add ./dsh-audit-trail-0.1.0.tgz
```

启动后补丁层插入一行：

```yaml
- insert:
  - id: audit-trail
    name: 'dsh-audit-trail'
```

通常**无需任何配置**——所有字段都在代码中提供默认值。如需为某个 profile 定制，在 profile 自己的 `cordis.patch.yml` 里覆盖该行（`id: audit-trail`）。注意补丁是**整块替换 `config`**——要保留的字段需全部重写。

### 运行环境要求

- Node.js `>= 22.13`（使用内置 `node:sqlite`，无原生依赖）。
- harness 需发出 `session/event` 与 `tools/*` 事件（当前 `@deepseek-ai/dsh-*` 全系均满足）。

---

## 配置

所有字段均可选，默认值如下。

```ts
interface AuditConfig {
  storage: {
    /** null => <dshHome>/audit-trail/audit.sqlite
     *  dshHome = $DSH_HOME || ~/.dsh；CLI 可用 AUDITRAIL_DB 覆盖 */
    path: string | null;
  };
  redact: {
    /** 存储前掩码已知密钥模式（默认 true）。*/
    maskSecrets: boolean;
    /** 工具参数摘要最大字符数。    */ truncateArgs: number;   // 512
    /** 摘要最大字符数。            */ truncateSummary: number;// 240
    /** 详情 JSON 最大字符数。      */ truncateDetail: number; // 4096
    /** 每条记录最多捕获的文件路径数。*/ maxFiles: number;     // 16
    /** 每条记录最多捕获的外发地址数。*/ maxNetwork: number;   // 16
    /** 额外的密钥正则（正则源字符串）。*/ extraSecretPatterns: string[];
  };
  rules: {
    /** 要禁用的内置规则 id，如 ["net:plaintext-http"]。*/
    disabledIds: string[];
    /** 追加（而非替换）默认表之外的操作者规则。*/
    custom: Array<{
      id: string; severity: 'info'|'low'|'medium'|'high'|'critical';
      pattern: string; scope: 'args'|'result'|'files'|'network'|'all'|'tool';
      flags?: string; tool?: string[]; description?: string;
    }>;
  };
  capture: {
    chunks: boolean;        // false —— 是否逐 token 记录 assistant_chunk？
    turnEvents: boolean;    // true
    stepEvents: boolean;    // true
    toolDispatch: boolean;  // true —— 是否记录实时 tool_dispatch 行
    toolRegistered: boolean;// true —— 是否记录 tools/change 增量
  };
}
```

示例（`cordis.patch.yml` 覆盖）：

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

## 面向模型的工具

插件加载后会向 `ctx.tools` 注册以下四个工具。

### `audit_query`

查询已存储的审计轨迹。

- 参数：`session_id`、`tool_name`、`min_severity`（`info|low|medium|high|critical`）、`flag`（规则标签，如 `shell:rm-rf`）、`kind`、`from`、`to`（ISO 日期或毫秒时间戳）、`limit`（≤ 10000）、`chains`（合并为调用链）、`format`（`json` | `markdown`）。
- 返回：`{ count, total, records | chains | text }`（已脱敏）。

### `audit_export`

导出过滤后的记录。

- 参数：`format`（`json` | `markdown` | `jsonl`）、可选 `path`（写文件）、上述查询过滤参数、`hash_chain`（仅 jsonl）、`chains`。
- 返回：`{ format, count, path?, bytes?, hash_chain, content? }`。

### `audit_policy`

运行时查看/修改敏感规则表。

- `action: list` 返回所有规则及其启用状态。
- `action: show|enable|disable` 配合 `rule_id`。
- `action: add` 配合 `id`、`pattern`、`severity`、`scope`、`description`。
- 仅运行时生效：如需持久化请写入插件配置。

### `audit_playback`

把轨迹渲染为纯文本时间线（每事件一行：时间码、id、类型、工具、严重度、标签、脱敏摘要、耗时）。

- 参数：查询过滤参数 + `limit`、`cap`（最大行数）、`chains`（折叠为调用链行）。
- 返回：`{ count, totalLines, truncated, text }`。交互式暂停/单步/调速请用 `auditrail playback` CLI。

---

## CLI

`auditrail` 读取与插件**同一个 SQLite 数据库**，无需启动 harness 即可操作在线轨迹。

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

数据库路径解析：`--db P` → `$AUDITRAIL_DB` → `<dshHome>/audit-trail/audit.sqlite`。

示例：

```bash
auditrail query --session sess-42 --min-severity high --markdown
auditrail export --format jsonl --hash-chain --out trail.jsonl --flag shell:rm-rf
auditrail verify-compliant --file trail.jsonl
auditrail playback --session sess-42 --interactive --speed 2 --colors
auditrail chain verify
```

---

## 会话回放

`renderTimeline()` 产出确定性的纯文本行，每事件一行：

```
09:00:05.000  #000002  user_message     -           [INFO]   fetch the deployment script and run it
09:00:10.000  #000003  tool_call        bash        [CRITICAL] shell:pipe-to-shell  curl -sSL ... | sh
09:00:15.000  #000004  tool_result      -           [INFO]   ok in 5000ms
```

`PlaybackController` 以慢速播放这些行，支持暂停 / 单步 / 跳转 / 调速；`runInteractive()` 将其绑定到原始 TTY。交互按键：

```text
空格   暂停 / 继续           s  单步前进         + / -  加速 / 减速
g     回到起点              q  （或 Ctrl-C）退出
```

非 TTY 环境（省略 `--interactive` 或管道输出）会一次性渲染全部时间线。

---

## 合规导出格式

固定、带版本号的逐行 JSON：

```jsonl
{"schema":"dsh-audit-trail/compliance/1","generatedAt":1750000000000,"count":2,"hashChain":true}
{"recordId":1,"prevHash":null,"payload":{"id":1,"sessionId":"sess-42","ts":1750000000000,"kind":"tool_call","turn":1,"step":1,"toolName":"bash","callId":"call-1","argsDigest":"{\"command\":\"curl ...\"}","status":"pending","durationMs":null,"severity":"critical","flags":["shell:pipe-to-shell"],"filesRead":[],"filesWritten":[],"network":["https://..."],"actor":null,"sourceType":"tool/call","sourceSeq":1,"summary":"bash"},"hashSelf":"a1b2..."}
```

- 第 1 行为头（`schema`、`generatedAt`、`count`、`hashChain`）。
- 每条数据行是单个 JSON 对象；payload 使用固定字段集（见 `src/query.ts` 的 `compliancePayload`）。
- 开启 `hashChain` 后，`hashSelf = sha256(prevHash + "\n" + 本行规范化 + "\n")`，且 `prevHash` 回显上一行的 `hashSelf`，构成链。`auditrail verify-compliant` 与 `verifyComplianceJsonl()` 可校验（能指出被篡改或换序的行）。

---

## 敏感操作规则表

内置规则表（可禁用/扩展；每条都有对应测试，见 `test/rules.test.ts`）：

| id | 严重度 | 作用域 | 模式（简写） |
|---|---|---|---|
| `shell:rm-rf` | high | args | `rm -rf` / `-fr` / `--recursive --force` / `-r -f` 变体 |
| `shell:pipe-to-shell` | critical | args | `curl\|wget\|nc … \| sh\|bash`（首个管道） |
| `shell:base64-to-shell` | high | args | `base64 -d \| sh` |
| `file:key-material` | critical | files | `.ssh`、`id_rsa*`、`.pem/.key/.p12/.pfx`、`.env`、`credentials`、`.aws/.azure` |
| `secret:inline` | high | args | `api_key=`、`token=`、`password=`、`Authorization: Bearer …` |
| `git:force-push` | high | args | `git push --force` / `-f` |
| `git:history-rewrite` | medium | args | `reset --hard`、`filter-branch`、`branch -D` |
| `db:destructive` | high | args | `drop table/database`、`truncate table` |
| `net:exfil-literal-ip` | high | network | 外发到字面 IP |
| `net:plaintext-http` | medium | network | 外发 `http://` |
| `priv:root` | critical | args | `sudo su`、`sudo -u root` |
| `fs:world-writable` | medium | args | `chmod 777/666` |
| `fs:system-dir-write` | high | files | 访问 `/etc`、`/usr`、`System32` 等目录 |
| `proc:kill-force` | medium | args | `kill -9`、`pkill -9` |

命中的规则 id 会作为**标签**存到记录上（也在 `audit_tags` 表中）；记录的严重度取命中规则中的最高值；两者都可用于查询（`--flag`、`--severity` / `min_severity`）。

---

## 隐私与脱敏

- 默认**只持久化脱敏后的内容**：参数摘要在存储前会做掩码（私钥块、Bearer/Basic token、`key=value` 密钥、长高位随机串）并截断；摘要与详情同样有长度上限。
- `digestArgs` 还理解结构：对象中 key 形似密钥（`password`、`token`、`api_key`、`authorization` 等）的值会被整体替换为 `[REDACTED]`，而 key（标签）保留。
- 审计轨迹记录的是「发生了敏感操作」这一取证事实，而不是敏感值本身。
- 仅在完全信任存储位置时才建议 `redact.maskSecrets: false`（不推荐）。

---

## SQLite 结构

一个存储、少量表（WAL 日志、`synchronous = NORMAL`）：

```
audit_meta     key/value 元数据（schema_version）
audit_events   只追加的审计轨迹
   id, session_id, ts, kind, turn, step, tool_name, call_id, args_digest,
   status, duration_ms, severity, severity_rank, summary, detail,
   files_read, files_written, network, actor, source_type, source_seq,
   hash_prev, hash_self, created_at
audit_tags     (event_id, tag) —— 敏感规则标签，带索引
```

索引覆盖 `ts`、`session_id`、`tool_name`、`severity_rank`、`kind`、`tag`。`chain verify` 按 `id` 顺序遍历并重算每个哈希。

---

## 项目结构

```
auditrail/
  package.json        dsh bundle 清单（dsh.bundle.patch）+ 脚本
  cordis.patch.yml    挂载插件的 bundle 补丁层
  tsconfig.json       TypeScript → lib/（NodeNext ESM）
  bin/auditrail.mjs   CLI 启动器（调用 lib/cli.js）
  src/
    index.ts          bundle 入口：name / inject / apply + 编程式导出
    config.ts         配置类型、默认值、宽容归一化
    types.ts          领域类型（严重度、类型、记录、过滤条件）
    rules.ts          敏感规则表 + 确定性匹配器（RuleEngine）
    redact.ts         密钥掩码、截断、参数摘要
    scan.ts           文件路径 / 网络地址启发式提取 + 归属
    store.ts          node:sqlite WAL 存储、查询、哈希链、统计
    recorder.ts       事件订阅 + 归一化 + 关联
    query.ts          调用链合并 + JSON/Markdown/合规报告 + 校验
    playback.ts       纯文本时间线渲染 + 回放控制器 + TTY
    tools.ts          audit_query / audit_export / audit_policy / audit_playback
    service.ts        供工具与 CLI 共用的门面
    cli.ts            独立 CLI
  test/               node:test 套件（记录完整性、打标、查询、导出、
                      回放、脱敏、插件契约、CLI）
  examples/           usage.mjs + 生成器 + 提交的示例产物
  README.md / README.zh.md / LICENSE
```

---

## 开发

```bash
npm install
npm run build        # tsc → lib/
npm run typecheck    # tsc --noEmit
npm test             # build + node --test test/*.test.ts
node bin/auditrail.mjs help
node examples/generate-examples.mjs    # 刷新 examples/*.jsonl|*.md
node examples/usage.mjs                # 编程式 API 演示
```

## 许可证

MIT —— 见 [LICENSE](LICENSE)。
