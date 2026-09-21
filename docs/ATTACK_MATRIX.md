# 攻防对抗矩阵

> 由 `tools/drills.py matrix` 从 `drills/*.json` 生成。
> 攻击记录数: 125（SDK 回归断言不计入）

| 模块 | BLOCKED | PARTIAL | BREACHED | SKIP | 合计 |
|------|---------|---------|----------|------|------|
| `antidebug` | 1 | 5 | 0 | 2 | 8 |
| `blob` | 6 | 0 | 0 | 0 | 6 |
| `dbiguard` | 1 | 5 | 1 | 0 | 7 |
| `hostid` | 1 | 1 | 0 | 0 | 2 |
| `indirect` | 3 | 0 | 0 | 0 | 3 |
| `integrity` | 10 | 5 | 0 | 0 | 15 |
| `license` | 8 | 3 | 2 | 1 | 14 |
| `revoke` | 1 | 0 | 0 | 0 | 1 |
| `selfcrypt` | 10 | 4 | 0 | 0 | 14 |
| `strcrypt` | 2 | 0 | 0 | 0 | 2 |
| `syscall` | 0 | 1 | 1 | 0 | 2 |
| `vm` | 3 | 2 | 0 | 0 | 5 |
| `vmdetect` | 0 | 2 | 0 | 0 | 2 |
| *(未映射)* | 19 | 20 | 2 | 3 | 44 |

## 显式 BREACHED（诚实边界）

| id | 模块 | 说明 | 来源 |
|----|------|------|------|
| `drill9.2` | `syscall` | syscall 直调在**内核级**攻击面前完全无效 —— 直调只规避用户态 ntdll hook, 无法规避内核拦截。这是诚实边界, 不是缺陷: 项目定位于用户态保护 (见 pu | `docs/PRODUCTION.md A6 节 ("仅在攻击者已 hook ntdll 场景有增量")` |
| `drill520260825.D5` | `dbiguard` | fake winhttp.dll in dir affected run (exit=3221225776 劫持生效?) | `attack-drill5-20260825.json` |
| `drill6.S5_ledger_wipe` | `unmapped` | recorded): issue-log.csv editable/deletable with no checksum or alerting; mitigation candi | `attack-drill6-20260828.json` |
| `drill6.L3_pubkey_swap` | `license` | D2a known boundary, environment prerequisite: install files writable): attacker with write | `attack-drill6-20260828.json` |
| `drill6.L4_clock_rollback` | `license` | expired 3072 license accepted after Set-Date rollback (2024-12-31) on real machine; EXPIRE | `attack-drill6-20260828.json` |
| `drill6.V3_ledger_csv_injection` | `unmapped` | tool-layer): customer/note with comma+CRLF creates forged ledger rows (csv structure injec | `attack-drill6-20260828.json` |
