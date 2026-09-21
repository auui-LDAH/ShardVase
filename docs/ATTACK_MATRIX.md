# 攻防对抗矩阵

> 由 `tools/drills.py matrix` 从 `drills/*.json` 生成。
> 攻击记录数: 111（SDK 回归断言不计入）

| 模块 | BLOCKED | PARTIAL | BREACHED | SKIP | 合计 |
|------|---------|---------|----------|------|------|
| `antidebug` | 1 | 5 | 0 | 1 | 7 |
| `blob` | 5 | 0 | 0 | 0 | 5 |
| `dbiguard` | 1 | 5 | 1 | 0 | 7 |
| `hostid` | 0 | 1 | 0 | 0 | 1 |
| `indirect` | 2 | 0 | 0 | 0 | 2 |
| `integrity` | 10 | 5 | 0 | 0 | 15 |
| `license` | 5 | 3 | 2 | 1 | 11 |
| `selfcrypt` | 9 | 4 | 0 | 0 | 13 |
| `strcrypt` | 2 | 0 | 0 | 0 | 2 |
| `vm` | 0 | 2 | 0 | 0 | 2 |
| `vmdetect` | 0 | 2 | 0 | 0 | 2 |
| *(未映射)* | 19 | 20 | 2 | 3 | 44 |

## 显式 BREACHED（诚实边界）

| id | 模块 | 说明 | 来源 |
|----|------|------|------|
| `drill520260825.D5` | `dbiguard` | fake winhttp.dll in dir affected run (exit=3221225776 劫持生效?) | `attack-drill5-20260825.json` |
| `drill6.S5_ledger_wipe` | `unmapped` | recorded): issue-log.csv editable/deletable with no checksum or alerting; mitigation candi | `attack-drill6-20260828.json` |
| `drill6.L3_pubkey_swap` | `license` | D2a known boundary, environment prerequisite: install files writable): attacker with write | `attack-drill6-20260828.json` |
| `drill6.L4_clock_rollback` | `license` | expired 3072 license accepted after Set-Date rollback (2024-12-31) on real machine; EXPIRE | `attack-drill6-20260828.json` |
| `drill6.V3_ledger_csv_injection` | `unmapped` | tool-layer): customer/note with comma+CRLF creates forged ledger rows (csv structure injec | `attack-drill6-20260828.json` |
