# N1 运行时自变形 — 完备实施计划 (N1_PLAN)

> 版本：2026-08-22 v2 · **2026-10-06 复核** · 状态：**阶段 0-3 已完成（方案 B 原位加密落地）；
> 二期 II-1/II-2/II-3 亦已完成**（2026-08-22 提交 `73f2381`；正式状态见
> `docs/N1_PHASE2_PLAN.md` 与 `docs/ADVANCED2.md:167`）—— 本文档 v2 的头部与
> §10 待办清单在二期落地时**未回填**，2026-10-06 复核时修正（见 §11 复核记录）·
> 关联：`docs/ADVANCED2.md` §2（N1 原定义）·
> `docs/CONTRACT.md`（完整性/VM 契约）· `docs/THREATMODEL.md`（威胁模型）· `docs/ADVANCED2.md`（N2-N5 已落地）。
> 本文档是 N1 从"想法"到"可执行"的完整计划：目标、与现有机制的重叠分析、可选技术路线、
> 决策点、分阶段实施、验收、风险、工作量与回退方案。v2 记录阶段 0 关键结论
> （方案 C 证伪 → 方案 B）与阶段 1-3 落地结果。

---

## 1. 背景：N1 要解决的问题

**威胁路径**（THREATMODEL §2，A3 专业破解）：合法购买授权 → 程序正常运行 →
dump 内存 / 动态逆向 → 还原算法或定制 patch。此路径**无 100% 技术防御**，
目标是抬高成本直到"成本 > 收益"。

**N1 原目标**（ADVANCED2 §2.1）：VM 引擎（`src/vm.c` 的解释循环、`vm_build_keymaps`、
窗口解密等）**静态是密文**，运行时解密执行，执行后立即重新加密——dump 时抓不到
完整引擎，静态反汇编看不到解释器逻辑。

**现状盘点**（N1 提出前已落地的机制，与 N1 目标重叠）：

| 机制 | 已做到 | 未做到（N1 的剩余价值） |
|------|--------|--------------------------|
| L2a 多小 VM（`license_{hash,mix,verify,gate}.vasm`） | 单镜像 dump 只有 1/3 逻辑 | 引擎本身（vm.c）仍是明文，dump 可得完整解释器 |
| L2b 窗口加密+用后即焚（`vm.c` win[64]/wprune） | 镜像明文不驻留堆 | **引擎函数代码静态可读**（`mov r10,rcx` 等特征码可定位） |
| L2d 镜像外部装载（`blob.c` + vm.blob） | exe 内无 VM 镜像 | 引擎仍在 exe 内 |
| L4a 完整性 CRC（`.protcrc` 烧录 .text/.rdata/.pdata） | 字节级补丁被杀 | **内存改写**（不碰文件）不触发 |
| N2/N3/N4/N5 | 反 DBI / 数据冗余 / 间接调用 / 会话期望值 | — |

**结论**：N1 的独特价值 = 让 **vm.c 引擎函数本身**在静态与 dump 下都不可直接分析
（其余机制都不覆盖引擎代码）。但这也正是**风险最大**的一层——与现有完整性机制
（`.text` CRC 烧录在 `.protcrc`）直接冲突，且 Windows 下自修改代码（SMC）会触发
杀软/EDR 告警。

---

## 2. 与现有机制的重叠与冲突分析（关键决策依据）

### 2.1 与 L4a 完整性（`.protcrc` CRC）的冲突

- **现状**：`hashpatch.py` 对 `.text` 段全段算 CRC 并烧录到 `.protcrc`；
  `integrity.c` 运行期复算比对（含 IAT/重定位掩码两侧一致）。
- **冲突**：若 N1 把 vm.c 引擎函数改为"运行时解密执行"，运行期该段字节
  与文件字节不同（解密态 ≠ 加密态）→ **CRC 必然误报**。
- **解法（二选一，决策点 D1）**：
  - **D1a：密文段不进 CRC 覆盖区**。把引擎函数放入**专用节 `.protcrypt`**
    （仿 `.protcrc`），`.text` CRC 仍覆盖其余代码，`.protcrypt` 独立处理
    （见 §3.2）。**推荐**——冲突最小，现有 3 段 CRC 逻辑零改动。
  - **D1b：CRC 对"已加密形态"校验**。运行期 CRC 只校验密文段未变（加密态
    字节恒定），解密态不校验。需改 `integrity.c` 的掩码/覆盖逻辑，改动面大。
- **推荐 D1a**，理由：`blob.c` 已证明"专用节 + 独立校验"模式可行（`.protcrc`
  就是先例）；不动 `.text` CRC 语义，回归风险最低。

### 2.2 与 L2b 窗口解密/用后即焚的关系

- L2b 保护的是**镜像数据**（密文不进堆），N1 保护的是**引擎代码本身**。
- 二者正交：N1 落地后，镜像数据仍走 L2b 窗口解密，引擎函数走 N1 段解密。
- **无需改动** vm.c 的窗口逻辑；N1 只影响"引擎函数入口"这一层。

### 2.3 与 N4 函数级间接化的关系

- N4 已把 `prot_vm_run` 的**调用点**间接化（静态无直接 call）。
- N1 补的是**函数体**本身（反汇编不可读）。
- 叠加效果：调用点不可见（N4）+ 函数体不可读（N1）→ 静态面双盲。
- **不冲突**，N4 的 resolve 层可原样保留；N1 的 `selfcrypt` 在 vm.c 编译后
  对函数体加密，N4 的表仍指向函数入口。

### 2.4 与杀软/EDR 的冲突（Windows 现实）

- 运行时自修改代码（SMC：VirtualProtect RWX + 改写 + 执行）是**杀软/EDR
  的高危特征**，托管/企业环境可能直接报毒或拦截（本项目已有 WDAC 拦截先例，
  HANDOVER §4.5）。
- **缓解**（必须内置，否则 N1 不可发布）：
  1. 解密窗口**最小化**（仅调用瞬间解密，返回即重加密，窗口 < 1ms）；
  2. **页属性瞬态**：RWX 窗口用 `VirtualProtect` 只读→可写→可执行，
     或 RW→RX 两步（避免同时 W+X，降低 AV 特征）；
  3. `FlushInstructionCache` 每次改写后必须调用；
  4. 提供**开关**：`PROT_SELFCRYPT_DISABLE` 编译宏 / 运行期检测到
     敏感环境（如 `dbiguard` 报告 hook）时自动降级为不解密直接运行
     （功能优先，保护次之——与 D2 离线优先语义一致）。

### 2.5 与完整性看门狗（A5）的兼容

- 看门狗每 5s（±40%）复查 `.text/.rdata/.pdata` CRC。N1 若只加密
  `.protcrypt` 专用节，看门狗逻辑**零改动**。
- 若看门狗未来扩展覆盖 `.protcrypt`，需按"加密态 CRC"设计（见 D1b）。

---

## 3. 技术路线（推荐方案，基于 D1a）

### 3.1 构建期：宿主函数加密（`tools/vmenc.py` 扩展 + 新工具）

**目标**：把指定函数（默认 vm.c 的 `prot_vm_run`、`vm_build_keymaps`、
`vm_wb`/`vm_wd_fill` 等引擎核心）在链接后加密，生成：
1. 密文段（`.protcrypt` 专用节）
2. 解密密钥/派生种子
3. 解密器入口（`selfcrypt.c` 的启动桩）

**实现路径（分两步）**：

- **步骤 A（PE 后处理，推荐首期）**：仿 `hashpatch.py` 的 PE 解析，新增
  `tools/selfcrypt.py`：
  1. 解析 demo.exe，定位目标函数（符号表/映射文件，构建期生成 .map）；
  2. 把函数体字节 XOR 密钥流（复用 CONTRACT §3 滚动密钥流）加密；
  3. 把密文写入 `.protcrypt` 专用节（`#pragma section` + `__declspec(allocate)`
     预留给 `.protcrypt` 的占位区），原函数体处放**解密桩**（跳转到 selfcrypt
     解密例程）；
  4. 生成 `selfcrypt_meta.c`（函数地址/长度/密钥种子表，供运行期解密）。
- **步骤 B（编译期标记，后续增强）**：`PROT_SELFCRYPT` 宏包裹函数体，
  编译期直接产出密文段 + 解密桩（更像 VM 引擎的构建期随机化，支持种子）。
  首期可只做 A（对现有 vm.c 零源码改动，风险最低）。

**种子注入**：步骤 A 的密钥种子支持 `--seed`（I3 可复现构建，与
indirect/strgen 同一 `-SeedsFile` 机制）。注意：**加解密形态的字节是确定性的**，
同种子两次构建字节一致。

### 3.2 运行期：`src/selfcrypt.c` + `include/protect/selfcrypt.h`

```
启动早期 (main 调用 prot_vm_run 之前):
  1. 定位 .protcrypt 段 (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE, 无 WRITE)
  2. VirtualProtect 改 RW (或 RWX 瞬态, 见 §2.4) -> 解密全部密文函数
  3. FlushInstructionCache
  4. VirtualProtect 改回 RX (只读可执行)
  5. 置全局标志 g_selfcrypt_ready = 1
  之后 prot_vm_run 等函数正常运行 (已解密)
看门狗/退出钩子:
  6. 重新加密 (volatile 防优化, 与 L2b 用后即焚同思路)
```

**窗口策略**（决策点 D2）：
- **D2a：启动一次性解密，驻留明文**。最简单，静态面已消除（文件是密文），
  但运行期 dump 仍是明文。**推荐首期**——性价比最高，风险最低。
- **D2b：调用-解密-返回-重加密**（原 N1 设想）。每次 `prot_vm_run` 调用
  解密 → 执行 → 返回重加密。dump 时机窗口极小，但 SMC 频率高（每调用一次
  改写两次），AV 风险大、性能开销明显。二期再做。
- **D2c：看门狗周期重加密**。定期把驻留明文重新加密，下次调用前再解密。
  折中方案，可作 D2a→D2b 的过渡。

### 3.3 完整性集成

- `.protcrypt` 段**不进** `.text`/`.rdata`/`.pdata` CRC 覆盖区（D1a）。
- `.protcrypt` 自身可选独立校验：
  - **加密态 CRC**：文件侧（`hashpatch.py` 扩展）对 `.protcrypt` 密文算 CRC
    烧录到 `.protcrc` 增加第 4 个标记（`PROTCRYP`），运行期对**密文形态**
    校验（不解密时）。解密态不校验（不冲突）。
  - **解密态校验**：解密后立即对函数体算 CRC（与 L4a 同算法），失败 → 按
    完整性策略 EXIT（0xBAD）。**推荐**：防"解密桩被 patch 跳过"。
- 两态校验互补：密文态防文件篡改，解密态防运行期 patch。

### 3.4 与 N4 间接化的共存

- N4 的 `s_fn[]` 表指向函数入口。N1 加密后，**入口地址不变**（函数体原位
  加密，解密桩在原函数入口处），N4 表零改动。
- 注意：解密桩本身必须是**少量固定字节**（跳转指令），不能被加密
  （否则无法启动）。设计：函数体加密从入口 +16 字节之后开始，前 16 字节
  留作解密桩（`jmp` 到 selfcrypt 解密例程）。

### 3.5 性能与体积

- 解密开销：vm.c 引擎函数总字节估计 < 4KB，XOR 解密 < 1ms（可忽略）。
- 体积：密文与原函数体等长（XOR 不膨胀）；`.protcrypt` 节增加 ~4KB。
- 启动时间：D2a 一次性解密 < 1ms；D2b 每调用两次改写（~0.1ms 级，可接受）。

---

## 4. 决策点汇总（开工前必须拍板）

| 编号 | 决策 | 选项 | 实际采用 | 理由 |
|------|------|------|------|------|
| D1 | 完整性冲突解法 | D1a 专用节不进 CRC / D1b 加密态 CRC（段掩码） | **D1b（阶段 0 实测）** | D1a（方案 C 搬移）被函数内相对 call 错位证伪；D1b 掩码两侧一致，零误报 |
| D2 | 解密窗口策略 | D2a 启动一次性 / D2b 调用级 / D2c 周期重加密 | **D2a（已实现）** | 性价比最高；D2b 二期 |
| D3 | 实现路径 | A PE 后处理 / B 编译期宏 | **A（已实现，原位加密变体）** | 对 vm.c 零源码改动；原位加密避免搬移问题 |
| D4 | 加密算法 | 复用 CONTRACT §3 滚动密钥流 / 新算法 | **复用滚动密钥流（已实现）** | 与全套件一致 |
| D5 | 是否默认启用 | 默认启用 / 默认禁用+开关 | **默认启用 + PROT_SELFCRYPT_DISABLE 降级** | 价值在启用 |

---

## 5. 分阶段实施计划

### 阶段 0：原型验证（0.5-1 天）— 决定是否继续

- [x] **方案 C（搬移+跳板）证伪**：函数体搬到 `.protcry` 执行时，函数内
  相对 `call`（`E8 rel32`）按 .text 位置编译，搬移后目标错位 → 崩溃。
  x64 下不做指令级重写无法修复，复杂度不可接受。**放弃方案 C**。
- [x] **方案 B（原位加密）验证通过**：函数体 .text 原位 XOR 加密（不搬移，
  无跳板），运行期 `prot_selfcrypt_init` 原位解密；函数内相对引用不受影响。
- [x] 完整性冲突解法（D1b）：.text CRC 对加密段掩码（`hashpatch.py --mask` +
  `integrity.c build_selfcrypt_mask`），加密态/解密态该段不参与 CRC，
  两侧一致 → 零误报。
- [x] 杀软/EDR 当前环境无拦截（本机实测）。
- [x] 验收全绿：e2e T1-T26、attacks A1-A7、vm_unit、vmc 零回归；
  Release 可复现（同种子字节一致）；静态 dump 引擎函数为密文
  （无 `40 55` 序言特征码）。
- **结论：继续**（方案 B，工作量比原估计略低，因不搬移、无跳板）。

**阶段 0 产出**：
- `src/selfcrypt.c` + `include/protect/selfcrypt.h`（D2a 一次性解密）
- `tools/selfcrypt_proto.py`（原位加密 + meta 写入 .protcry）
- `hashpatch.py --mask` / `integrity.c build_selfcrypt_mask`（D1b 掩码）
- `demo/main.c` `.protcry` 容器 + init 调用
- `build.ps1` 步骤 6（selfcrypt → hashpatch 带 mask）

### 阶段 1：构建期加密工具 — ✅ 已落地（`tools/selfcrypt_proto.py` + build.ps1 步骤 6）

- [x] PE 解析 / .map 定位 / .pdata 取大小（复用 pe_sections）；
- [x] XOR 加密（原位，方案 B）+ meta 写 `.protcrypt`；`--seed`/`--dry-run`/`--disable`；
- [x] build.ps1 集成（selfcrypt → hashpatch 带 mask）。
- 验收：dumpbin 目标函数为密文 ✓；同种子可复现 ✓。

### 阶段 2：运行期解密器 — ✅ 已落地（`src/selfcrypt.c`）

- [x] D2a 一次性解密 + FlushInstructionCache + RX + `PROT_SELFCRYPT_DISABLE`；
- [x] D1b 掩码（`integrity.c build_selfcrypt_mask`，载荷从 .protcry meta 读）；
- [x] 二期待办（部分）：**解密态 CRC 校验** ✅（II-1）、**D2b 调用级** ✅（II-2）
      —— 见 `docs/N1_PHASE2_PLAN.md`。
- [ ] 二期待办（仍缺）：**D2c 看门狗周期重加密** ❌ —— **全库无实现**
      （`src/` 内搜 `D2c|reencrypt|周期重加密` 零命中）。这是本文档列出的
      三个二期项中**唯一未落地**的一个，如实保留未勾。
- [x] demo/main.c 接入：早期调用 `prot_selfcrypt_init()`（`demo/main.c:525`，
      失败即 `:527 MSG_TAMPER` + `:529 exit(PROT_EXIT_TAMPERED)`）。

### 阶段 3：测试与回归（1 天）— ✅ 已随一期待办完成

- [x] e2e T1-T26 全绿（含 T4 篡改检测 0xBAD）；
- [x] attacks A1-A7 全绿；
- [x] Release 可复现验证（同种子两次构建字节一致）。
- [x] **二期待办（已落地部分，2026-10-06 复核）**：解密态 CRC 校验（II-1，含
      meta 20B + 校验失败 → `0xBAD`）、D2b 运行期 dump 窗口（II-2，`enter/leave`
      + SRWLock + 编译开关）、覆盖更多引擎函数（II-3，4 函数）
      —— 见 `docs/N1_PHASE2_PLAN.md`。
- [x] **二期 T29（解密态 CRC 回归）已于 2026-10-06 闭合**：复核当日实测
      `tests/e2e.py` 编号止于 T28、全库搜 `T29` 零命中（见 §11），现已补齐
      `T29 meta-crc` —— 翻 `.protcry` meta 第 0 条 entry 的 crc32 字段
      （节内偏移 `4 + 0*24 + 16`）⇒ 实测 `exit=2989 (0xBAD)` +
      `完整性校验失败`；对照（翻节尾填充）与基线同码 `exit=0` ⇒ 判据绑定的
      确实是 meta 内容本身。29/29 PASS，变异回退后立刻变红。
- [x] **二期 T30（密文态篡改回归）亦于 2026-10-06 闭合**：翻 `.text` 内
      **被段 CRC 掩码剔除的 selfcrypt 密文函数体**（`build/selfcrypt_mask.txt`
      最大区间的中点）⇒ 实测 `exit=2989 (0xBAD)` + `完整性校验失败`；
      对照（翻 `.text` 末字节，走段 CRC 路径）同样 `0xBAD`，但**拒止点更晚**
      —— 密文态篡改在 `demo/main.c:525 prot_selfcrypt_init()` 就被抓住
      （stdout **不含** `反调试扫描`），而段 CRC 要等 `:631
      prot_integrity_check_self()`。30/30 PASS；变异退回 T4 路径后立刻
      变红（`early` 由 `yes` 变 `no`）。
- [ ] **仍缺的是密文态 CRC（`PROTCRYP` 第 4 标记）**：`T30` 验的是"密文被
      解密后按 meta 明文 CRC 重算"，**不是**"密文形态本身有独立 CRC"。
      后者从未实现：`tools/hashpatch.py:47 MAGICS = (b'PROTCRCP',
      b'PROTCRCD', b'PROTCRDP', b'PROTCRCX')` 只有 4 个，搜 `PROTCRYP`
      全库零命中。⇒ 如实保留未勾，**不把"机制在"读成"验收过"**，
      也**不把 T30 读成 PROTCRYP**。

---

## 6. 验收标准（可测试、可证伪）

1. **静态面**：`dumpbin /DISASM build\demo.exe` 中，目标引擎函数主体为密文
   （无 `mov r10,rcx` / `push rbp` / 引擎特征指令序列）；仅解密桩可见。
2. **动态面**：D2a 下运行期 dump 可得明文（可接受，记录在案）；D2b 下
   非调用时刻 dump 为密文。
3. **功能**：e2e T1-T26 零回归；attacks A1-A7 零回归；vm_unit PASS。
4. **完整性**：解密态 CRC 与密文态 CRC 均生效；T4/T9/T10/T29/T30 全 PASS。
   > **2026-10-06 复核**：本条**部分达成**。`T4`/`T9`/`T10`（`.text`/`.rdata`/
   > `.pdata` 翻转 → `0xBAD`）、**`T29`（`.protcry` meta crc32 翻转 →
   > `0xBAD`）** 与 **`T30`（密文函数体翻转 → `0xBAD`，同日补齐）** 全
   > PASS；但 **密文态 CRC（`PROTCRYP`）从未实现** ⇒ 仍是缺口。此处措辞
   > 需分清：「T30 密文态篡改」= 篡改密文、由**解密态** CRC 抓住；
   > 「密文态 CRC」= 对密文形态本身独立校验 —— 后者不存在。
5. **可复现**：同种子两次 Release 构建 SHA-256 一致。
6. **降级开关**：`PROT_SELFCRYPT_DISABLE` 构建后功能全绿（N1 完全旁路）。

---

## 7. 风险与缓解

| 风险 | 等级 | 缓解 |
|------|------|------|
| SMC 触发杀软/EDR | 高 | §2.4 窗口最小化 + RW→RX 两步 + 降级开关；原型阶段先验证 |
| 与 `.text` CRC 冲突 | 高 | D1a 专用节，不动现有 3 段 CRC 逻辑 |
| 解密桩被 patch | 中 | 解密态 CRC 校验（阶段 2），失败 0xBAD |
| 链接器/优化器干扰（函数被合并/裁剪） | 中 | 目标函数 `__declspec(noinline)` + 保留符号；构建期用 .map 精确取址 |
| 多线程并发调用 `prot_vm_run` | 中 | 解密态互斥（临界区）；D2b 时解密/重加密加锁 |
| 增量链接导致函数地址漂移 | 低 | 构建用 `/INCREMENTAL:NO`（Release 已是） |
| 复杂度摊薄收益 | 中 | 与 N2-N5 叠加评估；若原型显示静态面收益有限则回退 |

---

## 8. 回退方案（重要）

- **技术回退**：N1 是**可选增强**，任何阶段失败均可整体回退——
  - 构建期：`build.ps1` 移除 selfcrypt 步骤即可（一行）；
  - 源码：`selfcrypt.c`/`selfcrypt.h` 移除，`main.c` 去掉 init 调用；
  - 完整性：`.protcrc` 第 4 标记可留空（hashpatch 对缺失标记是警告非致命）。
- **决策回退**：原型阶段门槛失败 → 维持"待定"状态，把本文档标记为
  "评估结论：暂缓"，理由记录到 ADVANCED2 §9 状态表。
- **语义保证**：无论启用与否，**离线优先（D2）与功能正确性永远第一**；
  N1 只是把静态分析成本从"小时"推到"天"级，不改变"合法运行 + dump"
  无法绝对防御的边界（THREATMODEL §4 一致）。

---

## 9. 工作量与里程碑

| 阶段 | 内容 | 工作量 | 依赖 |
|------|------|--------|------|
| 0 | 原型验证（解密桩 + 杀软探测 + 功能） | 0.5-1 天 | 无 |
| 1 | selfcrypt.py 构建期加密 | 1-2 天 | 阶段 0 通过 |
| 2 | selfcrypt.c 运行期解密 + 完整性集成 | 1 天 | 阶段 1 |
| 3 | 测试/回归/文档 | 1 天 | 阶段 2 |
| **合计** | | **3.5-5 天** | |

里程碑状态跟踪（追加到 ADVANCED2.md §9）：

| 里程碑 | 状态 | 完成日期 |
|--------|------|---------|
| N1 阶段 0 原型 | ✅ 通过（方案 B 原位加密；方案 C 搬移证伪；e2e/attacks/vm_unit/vmc 零回归；Release 可复现；静态密文） | 2026-08-22 |
| N1 阶段 1 构建期加密工具 | ✅ 完成（selfcrypt_proto.py + build.ps1 集成 + hashpatch --mask） | 2026-08-22 |
| N1 阶段 2 运行期解密器 | ✅ 完成（selfcrypt.c D2a 一次性解密 + D1b 掩码；解密态 CRC 已由二期 II-1 补上） | 2026-08-22 |
| N1 阶段 3 测试回归 | ✅ 完成（T1-T26/A1-A7/vm_unit/vmc 全绿；Release 可复现） | 2026-08-22 |
| N1 二期增强（II-1/II-2/II-3） | ✅ 完成（2026-08-22 提交 `73f2381`）——见 **`docs/N1_PHASE2_PLAN.md`**；**本表原写"计划完成，未开工"是未回填的陈旧值** | 2026-08-22 |

---

## 10. 待办清单（下一步）

1. [x] 拍板决策点 D1-D5（§4）——D1b/D2a/D3-A/D4/D5 已定。
2. [x] 阶段 0 原型验证（方案 B 通过，方案 C 证伪）。
3. [x] 阶段 1-3 落地（selfcrypt_proto.py + selfcrypt.c + 掩码 + 回归）。
4. [x] 二期增强（**II-1/II-2/II-3 于 2026-08-22 落地**，提交 `73f2381`）：解密态
      CRC 校验（防解密桩被 patch）✅、D2b ✅、覆盖更多引擎函数
      （`prot_vm_run`/`vm_build_keymaps`/`vm_wb`/`vm_var` 4 个）✅。
      **仍缺**：D2c 看门狗周期重加密 ❌（全库无实现）、**密文态 CRC
      （`PROTCRYP`）从未实现** —— 详见 §4 阶段 3 与 §6 验收标准第 4 条的
      复核注。（**T29/T30 均已于 2026-10-06 补齐**；T30 ≠ PROTCRYP。）
5. [ ] 杀软/EDR 跨环境验证（真机、企业环境）—— 与 `docs/N1_PHASE2_PLAN.md:210`
      同一挂账，**需真机**。

---

## 11. 复核记录（2026-10-06）

**性质**：本文档在二期（`docs/N1_PHASE2_PLAN.md`）全部落地时**未同步回填** ——
`73f2381`（2026-08-23，II-1/II-2/II-3 落地）的改动面是
`build.ps1` / `demo/main.c` / `docs/ADVANCED2.md` / `docs/HANDOVER.md` /
`docs/N1_PHASE2_PLAN.md` / `include/protect/selfcrypt.h` / `src/integrity.c` /
`src/selfcrypt.c` / `tools/selfcrypt_proto.py` —— **9 个文件，不含本文档**
（`docs/N1_PLAN.md`）。`docs/ADVANCED2.md:167` 与 `docs/N1_PHASE2_PLAN.md:3`
都如实记了"二期全部完成"，只有本文档留在"未开工"。

**本轮修正**（均为就地改现值，不改历史结论）：

| 位置 | 原 | 现 |
|------|----|----|
| 头部状态行 | `阶段 0-3 已完成` | `阶段 0-3 已完成；二期 II-1/II-2/II-3 亦已完成` |
| §4 阶段 2 待办 | `[ ] 二期待办：解密态 CRC、D2c、D2b` | 拆为已落地（II-1/II-2）与**真实缺口（D2c）**两条 |
| §4 阶段 2 接入 | `[ ] demo/main.c 接入（✅ 已接入）`（自相矛盾） | `[x]` + 行号证据 |
| §4 阶段 3 待办 | `[ ] T29/T30/D2b/多函数` | `[x]` 已落地部分 + 当时实测 **T29/T30 均不存在**（**两者均后于 2026-10-06 补齐**） |
| §6 验收 4 | `T29/T30 全 PASS` | 加复核注：**本条未达成** |
| §9 里程碑 | `计划完成，未开工` | `✅ 完成（73f2381）` |
| §10 待办 4 | `[ ]` | `[x]` 已落地 + 明确仍缺项 |

**本轮发现的真实缺口（不是陈旧标记，是真没做）** —— 三条，均已如实保留未勾：

1. **D2c 看门狗周期重加密**：`docs/N1_PLAN.md:139` 定义的"折中方案"，`src/` 内
   搜 `D2c|D2C|周期重加密|reencrypt` **零命中**。
2. **T29/T30 回归测试**：复核当日 `tests/e2e.py` 的 ID 实测止于 **T28**
   （26 个 ID：T1–T8、T11–T28），全库搜 `T29|T30` 零命中；
   `git log -S 'T29'` 只命中本文档创建提交 `80b4ce5`。
   ⇒ **`T29` 与 `T30` 均已于 2026-10-06 补齐**（`tests/e2e.py` 的
   `T29 meta-crc` / `T30 cipher-crc`，30/30 PASS + 两次变异验证）。
3. **密文态 CRC（`PROTCRYP` 第 4 标记）**：`docs/N1_PLAN.md:146-148` 计划给
   `.protcrypt` 加第 4 个烧录标记；实测 `tools/hashpatch.py:47`
   `MAGICS = (b'PROTCRCP', b'PROTCRCD', b'PROTCRDP', b'PROTCRCX')` 只有 4 个，
   搜 `PROTCRYP` 全库**零命中**。⇒ **II-1 只做了"解密态"一半**。

**由此暴露的覆盖缺口（最值得记的一条）**：**II-1 的机制已实现、却没有任何
回归测试触发它**。`src/selfcrypt.c` 在解密后逐函数校验 CRC 并与 meta 里的
明文 CRC 比对，失败即 `demo/main.c:529 exit(PROT_EXIT_TAMPERED)`；
复核当日 `tests/` 内没有任何一处**篡改 `.protcry` meta**（搜索结果显示
`tests/attack_drill.py` 对 `.protcry` 只有**读**操作 D2/D3，
`tests/protchain_check.py:149 selfcrypt_meta` 只做解析）。这与 §2.24（T3 孤儿）、
§2.27（`exit_pol` 未定义名）同型：**失败路径的代码最难被测试碰到**。
> **同日闭合（2026-10-06）**：该缺口已由 `tests/e2e.py` 的 `T29 meta-crc`
> 补上 —— 翻 meta entry0 的 crc32 字段 → `0xBAD`，对照（翻节尾填充）与基线
> 同码，且**变异回退后立刻变红**（证明不是"只会通过的检查器"）。
> 同日另补 `T30 cipher-crc`：翻段 CRC 已掩码剔除的**密文函数体** → 仍
> `0xBAD`，并由「拒止点早于 `反调试扫描`」把它与段 CRC 路径区分开。

**诚实边界**：
- 本复核**未重跑门禁**；N1 相关结论只依据静态代码/测试搜索与 `git log -S`。
  （后续 T29/T30 落地时已实跑门禁，见 §4 阶段 3。）
- "`.protcry` meta 篡改测试不存在"是**全库文本搜索的结论**，不是"做不到"——
  理论上可以加，只是当时没有（**T29 已于同日补上**）。
- II-1 退 `0xBAD` 现已有**本机实测证据**（`T29 meta-crc`）；但仍是
  **Windows x64 本机构建**下的证据，**未在真机/企业环境验证**
  （与 §10 第 5 条同一挂账）。
- D2c 的"零命中"只覆盖 `src/`；未搜 `tools/` 与文档（定义处当然在文档里）。
