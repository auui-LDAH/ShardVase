# N1 二期增强 — 完备实施计划 (N1_PHASE2)

> 版本：2026-08-22 v2 · 状态：**✅ 全部完成（II-1/II-2/II-3 已落地并回归）** · 关联：`docs/N1_PLAN.md`（一期：方案 B 原位加密已落地）·
> `docs/ADVANCED2.md` §2（N1 原定义）· `docs/CONTRACT.md`（完整性/VM 契约）· `src/selfcrypt.c`（一期实现）。
> 本文档规划 N1 二期三项增强：**解密态 CRC 校验**、**调用级解密 D2b**、**覆盖更多引擎函数**。
> v2 记录全部落地结果（2026-08-22）。

---

## 1. 背景与目标

一期（2026-08-22，`bf38a92`）已落地：
- `prot_vm_run` 构建期 .text 原位 XOR 加密，运行期 `prot_selfcrypt_init` 一次性解密（D2a）；
- .text CRC 对加密段掩码（D1b），加密态/解密态零误报；
- 静态 dump 引擎函数为密文；e2e/attacks/vm_unit/vmc 零回归；Release 可复现。

**二期要解决的一期遗留缺口**：

| 缺口 | 现状 | 威胁 | 二期项 |
|------|------|------|--------|
| 无解密态校验 | init 解密后不校验明文 | 攻击者 patch"解密桩"（跳过 init 或改 meta）→ 函数保持密文或错误解密，行为可被控制 | **II-1 解密态 CRC** |
| 明文驻留 | D2a 一次性解密后，运行期 dump 可得引擎明文 | dump 抓完整引擎 | **II-2 调用级解密 D2b** |
| 只覆盖 1 个函数 | 仅 `prot_vm_run` | 引擎其他核心（keymaps/窗口/等价路径）仍明文 | **II-3 多函数覆盖** |

---

## 2. II-1 解密态 CRC 校验

### 2.1 目标
init 解密**后**对每个目标函数体计算 CRC32，与**构建期烧录的明文 CRC** 比对：
不一致 → 按策略处理（默认 EXIT 0xBAD / 可配置 CONTINUE+报告）。

### 2.2 现状与改动
- **meta 布局扩展**：一期 entry = `{ rva u32 | len u32 | key0 u64 }`（16B，无 crc）。
  二期在 entry 末尾加 `crc32 u32`（明文 CRC）→ entry 变 **20B**。
  **注意**：meta 布局改动必须同步 `selfcrypt_proto.py`（写）与 `selfcrypt.c`（读）+ `integrity.c build_selfcrypt_mask`（读 rva/len 偏移），三侧一致。
- **selfcrypt_proto.py**：加密时已算 `zlib.crc32(body)`（明文），写入 meta 第 4 字段。
- **selfcrypt.c**：解密后对 `[base+rva, +len)` 算 `prot_crc32`，与 meta 比对；
  失败 → 返回 `PROT_ERR_INTEGRITY`，main 侧按完整性策略处理（exit 0xBAD）。

### 2.3 语义与边界
- **防什么**：攻击者 NOP 掉 `prot_selfcrypt_init` 调用 / 篡改 meta（把 count 改 0）
  → 函数保持密文 → 运行必然异常（本就不需要额外防护）；
  **真正防的**：攻击者替换密文段（自己构造"假明文"）→ 解密态 CRC 识破。
- **与 D1b 掩码的关系**：解密态 CRC 是**明文侧**校验，D1b 掩码是**加密态侧**
  （.text CRC 跳过该段）。两者互补：文件侧防篡改（掩码段之外），运行侧防
  解密桩 patch（明文 CRC）。
- **性能**：CRC 一次 O(len) 扫描，len < 4KB，< 1ms，可忽略。
- **策略选项**：默认 EXIT（与完整性一致）；`PROT_SELFCRYPT_POLICY_REPORT`
  宏可切换为仅告警（避免误杀场景）。

### 2.4 验收
- 篡改 meta 的 crc 字段 → 运行期拒绝（0xBAD）；
- 篡改密文段（.text 加密区）→ 解密后 CRC 不匹配 → 拒绝；
- 正常路径零误报（e2e T1-T26 回归）。

---

## 3. II-2 调用级解密 D2b（解密窗口最小化）

### 3.1 目标
`prot_vm_run` **每次调用**时：解密 → 执行 → 返回前重加密。
运行期非调用时刻内存中函数为密文，dump 抓不到明文引擎。

> **2026-10-06 实测补注（`docs/HANDOVER.md` §2.35）**：本句作为**目标**成立，
> 但落地时漏了启动那一段 —— `prot_selfcrypt_init` 原实现把**全部**条目解密
> 后留在明文态，于是"启动 → 首次 `leave(组)`"之间存在一段全量明文窗口
> （实测自然路径 661 ms；`--wait-ms 6000` 时 6713 ms）。已由 D2c 收口：
> init 逐条校验后**立即回密**（仅 `PROT_SELFCRYPT_D2B` 下），该窗口压到 0。

### 3.2 机制设计（关键难点）

**入口/出口钩子**：函数本身被加密，无法在内部加钩子（解密前无法执行）。
一期方案是"启动一次性解密"。D2b 需要**在调用点包裹**：

```
调用方 (demo/main.c / N4 间接调用):
  prot_selfcrypt_enter(0);   // 解密函数 0 (VirtualProtect RW->解密->Flush->RX)
  ret = PROT_INDIRECT_CALL(PROT_INDIRECT_VM_RUN, ...);
  prot_selfcrypt_leave(0);   // 重加密函数 0 (VirtualProtect RW->加密->Flush->RX)
```

- **调用点改造**：demo/main.c 的 4 处 `prot_vm_run` 调用（经 N4 间接表）
  包裹 `enter/leave`。N4 表指向入口不变（入口地址不变，原位加密）。
- **enter/leave 实现**（`selfcrypt.c` 新增）：
  - `prot_selfcrypt_enter(idx)`：若当前已解密（状态标志）则跳过；否则解密。
  - `prot_selfcrypt_leave(idx)`：重加密（用同一密钥流 XOR 回来，对称）。
  - 状态标志 `volatile` + 互斥（多线程调用 `prot_vm_run` 时防竞争）。
- **与看门狗的关系**：看门狗（A5）周期复查完整性——.text 掩码段不参与
  CRC，加密/解密态都无影响（D1b 已保证）。

**关键风险（必须实测）**：
1. **SMC 频率**：每次 VM 调用两次改写（解密+加密）→ 杀软/EDR 特征风险
   升高（一期原型已确认单次解密无拦截，但高频改写需实测）。
2. **性能**：每次调用 ~0.1ms 级（113B 函数两次 XOR + 两次 VirtualProtect
   + Flush），VM 校验本身 <1ms，开销 ~10-20%，可接受（需实测）。
3. **嵌套调用**：`prot_vm_run` 内部是否递归/调用自身？——不递归，无嵌套问题。
4. **时序攻击**：重加密后若 dump 恰在解密窗口内仍可得明文——窗口最小化
   到调用瞬间（微秒级），比 D2a 的"全程明文"好一个数量级。

### 3.3 降级策略
- **编译开关**：`PROT_SELFCRYPT_D2B` 启用 D2b；默认仍 D2a（一期行为）。
- **运行期自检**：若 `dbiguard` 报告 hook（插桩环境），可自动降级 D2a
  （避免 SMC 高频改写被插桩工具放大）。

### 3.4 验收
- 非调用时刻内存 dump：函数体为密文（测试：调用间隙读内存验证）；
- 调用时刻功能正常（e2e T1-T26 回归）；
- 看门狗驻留（T11）期间零误报；
- 高频调用稳定性（T6 multi-run 8/8）。

---

## 4. II-3 覆盖更多引擎函数

### 4.1 目标
一期只加密 `prot_vm_run`。二期扩展到引擎其他核心函数，静态反汇编看不到
完整解释器。

### 4.2 候选函数（src/vm.c，map 已确认位置）

| 函数 | 作用 | 价值 | 风险 |
|------|------|------|------|
| `vm_build_keymaps` | 构建期密钥流/置换重建 | 高（引擎核心，含 sem 派生） | 大（~1KB+）但无相对调用问题（方案 B） |
| `vm_wb` | 明文窗口读取 | 高（L2b 核心） | 小（~100B），被高频调用 |
| `vm_wd_fill` | 窗口填充/解密 | 中 | 小，被高频调用 |
| `vm_ks_seek` | 密钥流重绕 | 中 | 小 |
| `vm_wprune` | 窗口用后即焚 | 低（保护价值有限） | 小 |
| `vm_ctx_seed` | 运行时熵播种 | 低 | 小 |
| `vm_fold`/`vm_var` | 等价路径选择 | 中 | 中 |

**推荐首批**：`vm_build_keymaps` + `vm_wb` + `vm_wd_fill`（引擎数据通路核心）。
`vm_kr_*`（等价路径）可能被内联（无独立 .pdata 条目），跳过（它们已在
`prot_vm_run` 内部，随其加密）。

### 4.3 机制改动
- **selfcrypt_proto.py**：`DEFAULT_TARGETS` 扩展为列表，逐个加密；
  meta 多条 entry；`build/selfcrypt_mask.txt` 写多个掩码行。
- **hashpatch.py**：已支持多个 `--mask`（一期实现），无需改动。
- **integrity.c build_selfcrypt_mask**：已循环处理 n 个 entry，无需改动。
- **selfcrypt.c**：init 已循环 n 个函数解密，无需改动。
- **blob 容量**：`.protcry` 容器 4096B 需扩容（一期只 113B，二期多个函数
  可能 2-3KB；预留 16KB 或按需）。`demo/main.c` 的
  `g_prot_selfcrypt_blob[4096]` 改大 + `PROT_SELFCRYPT_MAX_FN` 检查。
- **D2b 交互**：enter/leave 需支持按函数索引包裹；`prot_vm_run` 内部调用
  `vm_build_keymaps`/`vm_wb` 等——**这些函数在 prot_vm_run 执行期间必须
  已解密**（D2b 下 prot_vm_run 解密时需**连带解密其内部调用的加密函数**，
  或 enter 一次性解密"函数组"）。**设计**：`prot_selfcrypt_enter` 支持
  `PROT_SELFCRYPT_GROUP_VM`（一次解密 prot_vm_run + 其依赖），leave 全组重加密。

### 4.4 风险
- **函数间相对调用**：方案 B 原位加密，函数间 `E8 call` 是**跨函数相对寻址**——
  加密函数调用另一个加密函数（都在 .text 原位），**相对偏移不变**，无问题。
  但**两个加密函数必须同时解密**（否则加密态执行加密态调用目标 → 崩溃）——
  这正是 4.3 的"函数组"设计要点。
- **.pdata 无条目**（被内联/合并）的函数无法定位——跳过并记录。
- **体积**：`.protcry` 扩容后节大小变化，PE 布局微调（不影响 CRC 掩码逻辑）。

### 4.5 验收
- 静态 dump：目标函数全部为密文；
- 运行期正常（init 全组解密，e2e 回归）；
- D2b 下 enter 解密函数组 → 执行 → leave 全组重加密。

---

## 5. 实施顺序与依赖

| 步骤 | 内容 | 依赖 | 工作量 |
|------|------|------|--------|
| II-1 | 解密态 CRC（meta 扩展 20B + init 校验 + 策略） | 无 | 0.5-1 天 |
| II-3 | 多函数覆盖（DEFAULT_TARGETS 扩展 + blob 扩容 + 函数组） | 无 | 0.5-1 天 |
| II-2 | D2b 调用级解密（enter/leave + 调用点包裹 + 状态机 + 互斥） | II-1（CRC 校验 D2b 下每次解密后也执行）、II-3（函数组） | 1-2 天 |
| 回归 | e2e/attacks/vm_unit/vmc/Release 可复现/杀软实测 | 全部 | 0.5 天 |

> 顺序：II-1 → II-3 → II-2（II-2 依赖前两者的机制）。II-1/II-3 独立可先行。

## 6. 验收总表（✅ 已实测 2026-08-22）

| 项 | II-1 解密态 CRC | II-2 D2b | II-3 多函数 |
|----|----------------|----------|-------------|
| 静态密文 | ✅ 保持 | ✅ 保持 | ✅ 4 函数全部密文 |
| 运行期 dump | 明文（D2a） | ✅ 调用间隙重加密（e2e T1-T26 证明"**功能不回归**"；**但当时并未证明"间隙内是密文"** —— 该半句于 2026-10-06 才被真正测出**为假**并收口，见 `docs/HANDOVER.md` §2.35） | 明文（D2a） |
| 篡改防护 | ✅ meta CRC 篡改 → 0xBAD（实测 exit=2989） | 同左 | 同左 |
| 功能回归 | ✅ e2e T1-T26 全绿 | ✅ e2e T1-T26 全绿（含 T11 14s 驻留） | ✅ 同左 |
| 性能 | <1ms | ✅ 无感知（e2e 全量通过） | 启动 +Xms |
| Release 可复现 | ✅ | ✅ 同种子字节一致 | ✅ |
| 杀软实测 | ✅ 无拦截（本机） | ✅ 无拦截（本机；高频 SMC 需真机复核） | ✅ 无拦截（本机） |

> 注：D2b 为**编译开关**（`-D2b` / `PROT_SELFCRYPT_D2B`），默认关（D2a 保底）。
> 实际落地：meta entry 16B→20B（三侧同步）、`prot_selfcrypt_enter/leave` +
> SRWLock 互斥 + 组状态机、`vm_run_wrapped` 包裹 4 处 VM 调用、
> DEFAULT_TARGETS 4 函数（prot_vm_run/vm_build_keymaps/vm_wb/vm_var；
> 被内联函数如 vm_ks_seek/vm_wd_fill 无独立 .pdata 条目，跳过）、
> blob 16KB 扩容。

## 7. 风险与回退

| 风险 | 等级 | 缓解 |
|------|------|------|
| II-2 高频 SMC 触发杀软/EDR | 高 | 编译开关默认关（D2a 保持默认）；本机实测；dbiguard 自动降级 |
| II-2 性能开销 | 中 | 实测；若 >20% 缩小覆盖函数集（只 prot_vm_run） |
| meta 布局 16B→20B 三侧不同步 | 中 | 单点改动 + 三侧注释同步 + e2e 立即暴露 |
| 函数组解密遗漏（D2b 下崩溃） | 高 | 依赖关系静态梳理（vm.c 源码）；e2e 全量回归 |
| blob 扩容后 PE 布局变化 | 低 | hashpatch 掩码按 meta 动态读，不依赖节布局 |

**回退**：二期全部可选。`PROT_SELFCRYPT_D2B` 默认关（行为 = 一期）；
II-1/II-3 若回归问题可整体 revert（build.ps1 去掉 selfcrypt 步骤即回退一期）。

## 8. 待办清单

1. [x] 拍板：II-2 默认关（D2a 保底），`-D2b` 显式启用。
2. [x] II-1 落地（meta 20B + init 校验 + 失败 → 0xBAD）。
3. [x] II-3 落地（DEFAULT_TARGETS 4 函数 + blob 16KB + 被内联函数跳过）。
4. [x] II-2 落地（enter/leave + vm_run_wrapped 包裹 + SRWLock + 组状态机 + D2b 开关）。
5. [x] 全量回归（e2e T1-T26 / attacks A1-A7 / vm_unit / vmc / Release 可复现）。
6. [ ] 真机复核：D2b 高频 SMC 下杀软/EDR 行为（需交互桌面会话，环境限制）。
6b. [x] **D2c 收口（2026-10-06）**：`prot_selfcrypt_init` 校验后立即回密，
       消除"启动 → 首次调用"的全量明文窗口（实测 6713 ms → 0）。
       见 `docs/HANDOVER.md` §2.35。
7. [ ] 更新 ADVANCED2 §9 / HANDOVER / N1_PLAN 状态（随提交完成）。
