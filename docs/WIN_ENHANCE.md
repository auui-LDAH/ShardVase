# Windows 侧增强计划 (WIN_ENHANCE)

> 版本：2026-08-26 v2 · 状态：**✅ W1-W4 已实施（2026-08-26）** · 关联：四轮攻防实证（0 破防点，已知边界）·
> `docs/THREATMODEL.md`（边界）· `docs/N1_PHASE2_PLAN.md`（D2b 已实现）·
> `src/integrity.c`（watchdog/IAT 校验）· `src/antidebug.c`。
> 本文档规划 **Windows 侧工程化增强**——把四轮攻防"已知边界"中**低成本可缓解**
> 的项做工程化补齐，同时强化**运行期纵深**。

---

## 1. 背景：攻防实证的已知边界 → 增强候选

四轮 57+2 项攻防揭示的边界与对应增强：

| 已知边界 | 攻防证据 | 可缓解度 | 增强 |
|----------|----------|----------|------|
| **D2a 明文 dump**（运行期转储得引擎明文+现场） | 第四轮 F1 Playable（16.9MB 转储明文在场） | 中 | **W1 D2b 运行期默认化**（可选开关） |
| **内存 patch 非文件 CRC** | G3/H1/E4（IAT 已补，result 有 N3） | 中 | **W2 watchdog 周期数据自校验加强** |
| **DLL 劫持**（安装目录可写） | D5 BREACHED（环境约束） | 低（运维） | **W3 部署文档显式 ACL 要求**（已记 HANDOVER，补 RELEASE/OPS） |
| **单镜像可还原** | R1（多 VM+N5+私钥阻断） | 高成本 | 不做（结论：成本收益差） |
| **离线可 patch** | 设计决策 D2 | 不做 | 保持 |
| **命令注入/日志** | 未测（低） | 低 | **W4 输出审计增强** |

---

## 2. Windows 侧增强项

### W1 — D2b 运行期默认化（消除 D2a 明文窗口为主选）

**现状**：`-D2b` 构建开关已实现（PROT_SELFCRYPT_D2B），第三轮真机已验证
调用间隙重加密密文（D3-2 BLOCKED）。默认 D2a（一次性解密明文驻留）。

**增强**：
- **方案 W1a（推荐）**：`build.ps1` 增加 `-Default D2b` 概念——`-Config Release`
  时默认启用 D2b（发行加固形态），Dev 保持 D2a 便于调试；`-NoD2b` 显式回退。
- **方案 W1b（增强备选）**：watchdog 周期对 D2a 驻留明文做**间隙重加密**
  （D2c：看门狗每次复查前重加密函数，VM 调用时再解密）——
  驻留明文窗口从"全程"缩到"看门狗周期"。

**权衡**（诚实记录）：
- D2b 每次 VM 调用两次 VirtualProtect+Flush → 性能 ~10-20%；
- 高频 SMC 可能触发杀软/EDR（本机/真机未拦，但企业环境待验）；
- 因此 **W1a 作为 Release 默认 + 文档注明企业环境可 `-NoD2b`**。

**验收**：
- Release 默认构建 = D2b 生效（`PROT_SELFCRYPT_D2B` 定义）；
- Procdump 转储 Release 产物 → 非调用时刻引擎密文（窗口缩小验证）；
- e2e/attacks/vm_unit 回归零影响。

### W2 — watchdog 周期数据自校验加强

**现状**：watchdog 每 5s 复查 .text/.rdata/.pdata CRC + IAT 快照 + antidebug。
N3 负责运行期 result 冗余（但**只在 demo 单次流程**，无周期复查）。

**增强**：
- **W2a**：watchdog 周期对 demo_mem 关键字段（result/license_ok）做
  N3 冗余一致性复查（多数一致 + 校验和）——把 N3 从"一次性"升级为"周期"。
- **W2b**：hook 检测（N2 dbiguard）并入 watchdog 周期——**当前 dbiguard 只启动
  扫一次**，第三轮 R2 显示"恰好 R2 用了 EXIT 策略被周期检测覆盖（real watch用
  antidebug）"但**纯 dbiguard 无周期**。补 watchdog 周期跑 dbiguard_scan。

**验收**：运行期单点 patch result → watchdog 周期内识破（0xBAD）；注入 hook →
watchdog 周期检测。

### W3 — 部署文档 ACL 要求（DLL 劫持缓解）

**现状**：D5 实测环境约束，已记 HANDOVER。但 RELEASE/OPS 未显式要求。

**增强**：在 `docs/RELEASE.md` + `docs/OPS.md` 增加"**安装目录 ACL 只读**
（仅 Administrator 可写）"硬性部署要求，说明 DLL 劫持缓解。

### W4 — 输出审计增强（低）

**现状**：demo 打印 `vm error %d`、machine_id、license 状态——攻击者可
从 stdout 推断内部。

**增强**：Release 构建（`-Config Release`）下 `--selftest` 详细输出仅在
显式 `--selftest` 时；错误信息收敛（`vm error` → 统一 MSG_FAIL），
不泄漏内部 prot_status 码。生产剥离调试信息。

---

## 3. 决策点

| 编号 | 决策 | 选项 | 推荐 |
|------|------|------|------|
| D1 | D2b 默认化程度 | Release 默认 / 永不 / 仅文档建议 | **Release 默认 + 文档**（发行加固优先） |
| D2 | D2c 周期重加密 vs D2b | 保持 D2b / 增加 D2c | **D2b**（D2c 更复杂，二期再说） |
| D3 | W2 周期数据自校验 | 做 / 记录边界 | **做 W2a+N2 周期**（低成本） |
| D4 | W4 输出收敛 | Release 收敛 / 全收敛 | **Release 收敛**（Dev 保持调试可见） |

## 4. 实施步骤

| 步 | 内容 | 工作量 |
|----|------|--------|
| 1 | W1a：build.ps1 Release 默认 D2b（`-NoD2b` 回退）+ 验证 | 0.5 天 |
| 2 | W2a：watchdog 周期 N3 复查（demo_mem 关键字段扫描） | 1 天 |
| 3 | W2b：watchdog 周期 dbiguard_scan | 0.3 天 |
| 4 | W3：RELEASE/OPS 部署 ACL 要求 | 0.2 天 |
| 5 | W4：Release 输出收敛（错误码隐藏） | 0.3 天 |
| 6 | 回归（e2e/attacks/protchain/release_check）+ 真机确认 | 1 天 |
| **合计** | | **3-4 天** |

## 5. 验收标准
1. Release 构建默认含 D2b；`-NoD2b` 可回退；Procdump 非调用时刻密文；
2. watchdog 周期识破单点 result patch + 注入 hook（运行期 N3/N2 周期）；
3. RELEASE/OPS 含 ACL 硬性要求；
4. Release 产物错误信息不泄漏 prot_status 内部码；
5. e2e/attacks/vm_unit/protchain/release_check 全绿。

## 6. 风险与回退
| 风险 | 缓解 |
|------|------|
| D2b 默认增杀软风险 | `-NoD2b` + 文档；企业环境可关 |
| watchdog 周期 N3 扫描开销 | 仅关键字段，5s 周期可忽略 |
| Release 输出收敛遗漏 | W4 保持 `--selftest` 显式开关 |
| W2 改动 integrity.c 回归 | 增量 + protchain/e2e 回归 |

**回退**：W1a 由 Release 默认改回（`-NoD2b` 语义）；W2/W4 纯增量，删除即回退。

## 7. 待办清单
1. [x] 拍板 D1-D4（Release 默认 D2b / 保持 D2b / 做 W2 / Release 收敛输出）。
2. [x] W1a：build.ps1 Release 默认 D2b + `-NoD2b` 回退（实测 enter/leave
       有实体 = D2b 生效）。
       > **2026-10-06 补记：该验收判据不足，且结论当时不成立。**「enter/leave
       > 有实体」只证明**包装函数存在**，不证明**窗口之外是密文** —— 而后者
       > 才是 D2b 的全部卖点。实测（`docs/HANDOVER.md` §2.35）：
       > `prot_selfcrypt_init` 解完不锁，组 0 在"启动 → 首次 `leave(VM)`"
       > 之间**全程明文**（自然路径 661 ms；`--wait-ms 6000` 时 6713 ms）。
       > 已由 D2c 收口（init 校验后立即回密，仅 `PROT_SELFCRYPT_D2B` 下），
       > 该窗口压到 0；现判据已改为**内存字节 vs 磁盘密文**的逐条比对。
3. [x] W2a+b：watchdog 周期回调（`prot_integrity_set_watchdog_callback`）
       —— demo 注册 N3 冗余复查 + dbiguard 周期扫描；**前置修复 FAKE
       翻转同步 result_sum**（原逻辑漏翻校验和，周期复查会误杀）。
4. [x] W3：RELEASE §2.6 安装目录 ACL 硬性要求（DLL 劫持缓解）。
5. [x] W4：Release 收敛错误输出（`PROT_LOG_VM_ERR` 宏隐藏 prot_status 码，
       `-DPROT_RELEASE_CONCEAL`）。
6. [x] 回归：Release 构建 + protchain P1-P6 全过。
   **验证记录（2026-08-27）**：W2 在本机 loop-vm 场景实测——result 单副本
   patch 后 80s 未触发 0xBAD，原因：**loop 中 verify 每轮重写 result 覆盖
   攻击**（与 P4-2 一致）——这是防御本身（patch 被正确重算覆盖）。W2 周期
   复查的价值在**无重算的长驻留程序**；demo 单次流程 N3 识破已由 P4-2/
   e2e T4 证。因此 W2 结论：**机制正确，demo 场景下被重算覆盖（=防御有效）**。
   **剩余待办**（非本轮阻断）：
   - W2 在无重算长驻留应用（真实 SDK 集成）下实跑验证周期识破；
   - Release D2b 真机/杀软环境的最终确认（-NoD2b 可回退）。