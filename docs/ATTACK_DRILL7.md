# ATTACK_DRILL7 — 符号表解析器攻击面（内存补丁工具链）

> 版本：2026-08-30 v1 · **2026-10-06 补记 v2** · 状态：**WinPE 实证完成（mock 目标）→ 真实 demo.exe 闭环见 §6；Android 宿主编译就绪**
> 关联：`docs/MEMPATCH_PLAN.md`（规划）、`tools/attacker/`（工具）、
> `docs/ATTACK_DRILL1-6.md`（此前攻防）、`docs/EXTENSION_PLAN.md`（Android 规划 T1）。
> 本文档记录**真实破解者工具链**形态的攻击：运行时符号表解析 + 内存补丁，
> 补齐此前"硬编码偏移/dumpbin 静态定位"的空白。

---

## 1. 目标与背景

### 1.1 此前已测（DRILL1-6）
- 写 PEB.BeingDebugged / NtGlobalFlag（ScyllaHide 动作）→ PARTIAL（多因子仍拦）；
- 写判定布尔/result → PARTIAL（周期重算覆盖）；
- 注入 + IAT hook + patch 全链 → BLOCKED；
- 暂停 watchdog + .text patch → BLOCKED。

### 1.2 本次新增
1. **PE 符号解析器**（MAP + 导出表 + COFF）——动态符号定位，替代硬编码偏移；
2. **ELF 符号解析器**（.symtab/.dynsym）——Android 形态；
3. **内存补丁闭环**：附加 → 定位 → 改写 → 观察盾行为。

---

## 2. 工具链

```
tools/attacker/
  winpe_sympatcher/      Windows: PE/MAP 符号解析 + OpenProcess 写内存
    symparse.{h,c}       MAP + 导出表 + COFF 符号解析
    mempatch.{h,c}       OpenProcess/Read/WriteProcessMemory (+ASLR 换算)
    main.c               命令行入口
    test_target.c        带符号测试目标 (模拟"盾")
    build.ps1            构建
  android_jniptrace/     Android: ELF 符号解析 + JNI/ptrace patch
    elfparse/{elfparse.h,elfparse.c}
    elfdump.c            宿主编译命令行
    gen_test_elf.py      测试 ELF 生成
    patcher_jni.c        JNI 模块 (同进程/ptrace 两模式)
    ptrace_patcher_cli.c 命令行 ptrace 补丁器
```

---

## 3. 实证记录（Windows）

### 3.1 测试目标
`test_target.c` 模拟"盾"：`prot_antidebug_scan()` 扫描 PEB 更新
`is_debugger_attached`；`prot_antidebug_detected()` 聚合判定。
`--fake-debug` 模式把 PEB.BeingDebugged 置 1，模拟被调试。

### 3.2 步骤与结果

| 步骤 | 操作 | 结果 |
|------|------|------|
| 1 | 符号解析（MAP）定位 `prot_antidebug_scan`/`detected`/`is_debugger_attached` | ✅ VA 全部命中 |
| 2 | 附加 + 写 `is_debugger_attached=0` | ✅ 写入成功，但**盾仍检测**（下一轮 scan 重算覆盖）|
| 3 | patch `prot_antidebug_scan` 头 (`31 C0 C3`) | ✅ 写入成功，盾仍检测（scan 只是设置者）|
| 4 | **patch `prot_antidebug_detected` 头 (`31 C0 C3`)** | ✅ **盾失效：DETECTED → clean（持续）** |

### 3.3 结论
- **符号表解析（MAP）定位成功**——真实破解者工具链能力达成；
- **改判定布尔无效**（周期重算覆盖，与 DRILL2 P4-2 一致）；
- **patch 判定函数本体有效**——"盾"的判定被永久关闭；
- **ASLR 必须处理**（运行时基址 ≠ 编译时 VA，--pref 换算）；
- RELEASE 构建（/DEBUG:NONE /OPT:REF,ICF）**无 COFF 符号、无 MAP** → 符号定位失败，
  需 MAP 文件或 PDB（记录为边界，D4 验证）。

---

## 4. Android 形态（宿主编译验证）

### 4.1 ELF 符号解析器
- 生成测试 ELF（gen_test_elf.py，.symtab + .dynsym）；
- **6/6 符号命中**：`prot_antidebug_scan` 等静态符号（.symtab）、
  `Java_com_prot_demo_Prot_nativeIsDebugged` 等 JNI 导出（.dynsym）；
- 关键 bug 修复记录：ELF64 节头结构体 `sh_size/sh_addralign/sh_entsize`
  必须 8 字节（Q），否则字段错位（sh_offset 读 0）。

### 4.2 JNI/ptrace 补丁模块（代码就绪）
- `patcher_jni.c`：同进程 patch（免 root）/ ptrace 附加（root）双模式；
- `ptrace_patcher_cli.c`：命令行版；
- **待真机验证**（NDK 编译 + root 环境，见 EXTENSION_PLAN T1）。

---

## 5. 边界与后续

| 边界 | 说明 |
|------|------|
| RELEASE 无符号 | 需 MAP/PDB；真实破解者同样受限（记录为已知边界）|
| 函数头 patch 可被完整性检测捕获 | 本项目 demo 的 CRC 覆盖 .text——**注意**：本次 test_target 无完整性校验，真实 demo 会有 watchdog/CRC 拦截（DRILL3 已证 .text patch → 0xBAD）|
| Android 真机未测 | NDK/root 环境就绪后补（T1 第一项）|

**后续建议**：
1. ~~对真实 demo.exe（Dev 构建带 MAP）跑完整闭环（含 watchdog 对抗）~~ ✅ **已完成（2026-10-06，见 §6）** —— 符号定位成功，但 patch 判定函数被 `.text` 段 CRC 拦下（exit=2989），**不再静默失效**；
2. Android 真机验证 ptrace 附加 + 同进程 patch；
3. 增加 PDB 解析器（可选，真实破解者常用）；
4. 与完整性校验对抗：patch 后需同时处理 CRC 重算（hashpatch 思路）。

---

## 6. 真实目标闭环（2026-10-06 补记）

**缘起**：§3 的"盾失效"结论是在 `test_target.c`（模拟盾，**无完整性校验、
无副本冗余**）上取得的。§5 第 1 条把"对真实 demo.exe 跑完整闭环"挂了近 5 周。
本轮用同一工具链打真实 `build\demo.exe`（Release，带 `demo.map`），
把 mock 与真实目标的差异变成数字。

**方法**：`tools/attacker/winpe_sympatcher.exe --map build\demo.map --sym <name>`
定位 → `ReadProcessMemory` 确认序言 → `VirtualProtectEx` + `WriteProcessMemory`
写 `31 C0 C3`（`xor eax,eax; ret`）→ 喂 stdin 使目标自然退出（**不 kill**，否则
退出码不可信）。探针 `build/_drill7_clean.py`（只读诊断，未入库）。

**四组实测**（同一构建，`real_base=0x7ff6d37d0000`）：

| 组 | 操作 | 符号 / 运行时 VA / 序言 | 写入 | 退出码 | MSG_TAMPER |
|----|------|------------------------|------|--------|-----------|
| A | 基线（不附加、不写） | — | — | `1` (0x1) | ✗ |
| D | 附加 + 符号定位，**只读不写** | `prot_antidebug_detected` @`0x140001420` → `0x7ff6d37d1420`，序言 `48 83 ec` | ✗ | `1` (0x1) | ✗ |
| B | patch `prot_antidebug_detected` 头 | 同上 | ✅ `31 c0 c3` | **`2989` (0xBAD)** | **✓** |
| C | patch `prot_antidebug_detected_multi` 头 | `…_multi` @`0x1400015b0` → `0x7ff6d37d15b0`，序言 `48 89 5c` | ✅ `31 c0 c3` | **`2989` (0xBAD)** | **✓** |

四组均 `natural=True`（自然退出，无强杀）。

**结论（与 mock 目标的三点差异）**：

1. **符号定位在真实目标上同样成功** —— MAP 通道给出 `prot_antidebug_detected` /
   `_multi` 的编译时 VA，ASLR 换算（`Toolhelp32` 取模块基址，**不是**拿 `PREF`
   硬读 —— 后者会 `err=299 ERROR_PARTIAL_COPY`）后序言与预期一致。⇒
   "真实破解者工具链"的**定位能力**在 Release 构建（有 MAP 时）成立。
2. **附加本身不再触发检测** —— 组 D 只定位不写，退出码与基线同为 `1`、无
   `MSG_DBG`。这与 §3 的 mock 场景不同（mock 会因附加被检测）。
   **旁注**：`prot_antidebug_detected` 在本次构建里对"外部附加"未报 `0xDB`，
   与本轮 e2e T3（用 `DebugActiveProcess` 附加派生进程，确实得 `exit=219`）
   并不矛盾 —— T3 附加的是 `--wait-ms 4000` 的同一 exe 且由调试器持有线程，
   形态不同；此处不深挖，**如实记为观察**。
3. **patch 判定函数在真实目标上不再静默生效** —— 组 B/C 写入成功（读回
   `31 c0 c3` 一致），但目标没有"判定被关掉后继续跑"，而是打印
   `完整性校验失败，程序可能已被篡改。` 并以 `2989`（`PROT_EXIT_TAMPERED`）
   退出。**机制**：`prot_antidebug_detected` / `_multi` 的 map 段号都是
   `0001` = `.text$mn`，而 `.text` 是 baked-CRC 的**第 0 个目标**
   （`src/integrity.c` 的 `g_prot_baked_crc[0]`，覆盖含调零掩码），
   改它必然被段 CRC 抓到 —— 这正是 DRILL3 罪证在真实目标上的复现。

**因此 §3 的"盾失效"必须限定**：它成立于**无完整性校验的 mock 目标**；
在真实 demo 上，符号定位仍是可达的，但**单点 patch 判定函数的收益被
`.text` 段 CRC 收走**（想静默失效须同时重算段 CRC —— 即 `hashpatch` 思路，
且 R3.2-c 之后还有 4 副本 + 位置抖动抬高定位成本）。

**诚实边界**：

- 本轮只测**单点 patch**；"同时中和段 CRC + 4 副本"的完整对抗链**未测**
  （DRILL9 §5 已记 F/G/H 由此翻转为 `0xBAD`，属另一条线的结论）；
- Release 构建有 `demo.map` 是本轮前提；**无 MAP/PDB 时 MAP 通道失效**
  （§5 边界表第 1 条），COFF 通道在 `/DEBUG:NONE` 下同样为空；
- 组 D 的"附加不触发检测"只测了一个构建一个时刻，**未做多次/多形态**；
- Android 侧真机仍未测（§4.2）。

*2026-10-06 v2*
