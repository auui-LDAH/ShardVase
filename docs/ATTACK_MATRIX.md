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
| *(未映射)* | 20 | 21 | **0** | 3 | 44 |
> **最后核实**: 2026-09-29 · 方法: tools/docclaim_check.py (§matrix-breached) · 提交 `66a2ff4`


## 显式 BREACHED（诚实边界）

| id | 模块 | 说明 | 来源 |
|----|------|------|------|
| `drill9.2` | `syscall` | syscall 直调在**内核级**攻击面前完全无效 —— 直调只规避用户态 ntdll hook, 无法规避内核拦截。这是诚实边界, 不是缺陷: 项目定位于用户态保护 (见 pu | `docs/PRODUCTION.md A6 节 ("仅在攻击者已 hook ntdll 场景有增量")` |
| `drill520260825.D5` | `dbiguard` | fake winhttp.dll in dir affected run (exit=3221225776 劫持生效?) | `attack-drill5-20260825.json` |
| `drill6.S5_ledger_wipe` | `unmapped` | **→ PARTIAL**（D4 复核 2026-09-29）: `verify_ledger.py` **哈希链已落地**（`prev=sha256(上一行)`，删/改**中间行**可检出 `prev 失配`）；残余边界=**整文件删除**在本机不可检（需外部锚点）→ 保持入册 | alerting; mitigation candi | `attack-drill6-20260828.json` |
| `drill6.L3_pubkey_swap` | `license` | D2a known boundary, environment prerequisite: install files writable): attacker with write | `attack-drill6-20260828.json` |
| `drill6.L4_clock_rollback` | `license` | expired 3072 license accepted after Set-Date rollback (2024-12-31) on real machine; EXPIRE | `attack-drill6-20260828.json` |
| `drill6.V3_ledger_csv_injection` | `unmapped` | **→ BLOCKED**（D4 实测 2026-09-29）: `vmenc._csv_safe`（**D-D4 同日落地**，提交 4553453）**拒绝**含 `,`/CR/LF/TAB/超长 的 customer/note—— 实测 5/5 拒绝且**不写日志**；正常输入仍可用 |ged ledger rows (csv structure injec | `attack-drill6-20260828.json` |


## D4 复核（2026-09-29）—— **6 条 BREACHED 逐条实测**

| id | 模块 | 原状态 | **复核结论** | 处置 |
|----|------|--------|------------|------|
| `drill6.V3` 台账注入 | unmapped | BREACHED(工具层) | `_csv_safe` **5/5 拒绝**（D-D4 同日落地 4553453）| **→ BLOCKED** |
| `drill6.S5` 台账清洗 | unmapped | BREACHED(记录) | 哈希链**已落地**（删/改中间行可检出）| **→ PARTIAL** |
| `drill6.L4` 时钟回拨 | license | BREACHED | **仍无单调防护**（`main.c:468` 只比本地时间；`monotonic_ns` 未用于过期判定）| **入册保持**（准确）|
| `drill6.L3` 公钥替换 | license | BREACHED(D2a) | 文件可写 = 可自授权 = **离线授权固有** | **入册保持** |
| `drill5.D5` DLL 劫持 | dbiguard | BREACHED | 前提=目录可写 → **运营 ACL 约束** | **入册保持** |
| `drill9.2` syscall | syscall | BREACHED | 内核级攻击前无效 = **固有**（直调只规避用户态 hook）| **入册保持** |

**结论**: `BREACHED` 从 **6 → 4**；余 4 条**全部如实入册**（各有"为何在
威胁模型内可接受"的理由），符合 §35 的目标（"归 0 或全部如实入册"）。

> ### 🎯 D4 的关键发现
> **矩阵记录会过时** —— V3/S5 的防御**早已在同日/后续提交落地**
> （`4553453 feat(ledger-defense): landing D-D1/D-D2/**D-D4**`），
> 但**表格没回填**。本次是**逐条实测复核**才纠正。
> **教训**: 攻防矩阵是**动态证据**，防御落地后必须**同步回填**，
> 否则会持续低估自身能力（或误导后续工作）。

## D4 续复核（2026-09-29）—— **PARTIAL 逐条实测**

| id | 原状 | **实测复核** | 处置 |
|----|------|------------|------|
| `drill6.V1` verify 工具 | PARTIAL（畸形公钥崩溃）| **已优雅**: 畸形 JSON 公钥 -> `rc=1` + `vmenc: error: Expecting value...`，**无 Traceback** | **→ BLOCKED**（记录过时）|
| `drill6.S4` 重放 | PARTIAL（无自动拦截）| **`check_nonce_replay` 已落地**（默认拒绝同 nonce，`--allow-replay` 为显式逃生口）| **→ BLOCKED**（记录过时）|
| **`drill6.V2` vmenc 注入（expires）** | PARTIAL（负与超大 expires 未拒）| **实测确有缺陷**: `-1`/`10^30`/`4294967296` **全被接受并静默截断**（`& 0xFFFFFFFF`）-> 授权语义错 + **台账与产物不一致** | ✅ **已修**（`_expires_safe` 越界拒绝）→ **BLOCKED** |

**V2 的修复依据（为什么它算真缺陷而非 drill6 记的"自伤"）**：
```
license_message: struct.pack('<I', expires & 0xFFFFFFFF)
  -1         -> 0xFFFFFFFF（2106 年）——签发"已过期"却落盘"2106 到期"
  10^30      -> 取低 32 位 —— 与签发者意图无关
而**哈希链台账记的是原值**（未截断）-> **台账与产物不一致**（审计对不上）
=> 授权语义错 + 审计不一致，不只是"影响自己"
```
修复与 `_csv_safe`（D-D4）**同一模式**：`_expires_safe` 越界即拒（**不截断**）。

## DRILL8（2026-09-29）—— **函数头 patch vs 布局随机化**

| 项 | 结论 |
|----|------|
| `COST_ASYMMETRY §4` 第 5 行"杠杆 = 0" | **过时**（能力 2026-09-25 已落地，drill 早于它）|
| 实测（两次构建 map 对比）| **95.2%** 同名符号 RVA 变化 · **`prot_` 函数 63/63 = 100%** |
| 对攻击者的影响 | v1 的函数定位/RVA 常量/patch 脚本对 v2 **失效**（**跨发布成果无保质期**）|
| 诚实边界 | ① **分发级**非运行级（同一发布内偏移稳定）② **自动化** patch 流水线的真实成本**未测**（建议 DRILL9）③ 本 drill 只证**定位失效**，未复跑端到端 patch |

详见 `docs/ATTACK_DRILL8.md`。
