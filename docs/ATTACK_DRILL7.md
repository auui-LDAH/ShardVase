# ATTACK_DRILL7 — 符号表解析器攻击面（内存补丁工具链）

> 版本：2026-08-30 v1 · 状态：**WinPE 实证完成，Android 宿主编译就绪**
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
1. 对真实 demo.exe（Dev 构建带 MAP）跑完整闭环（含 watchdog 对抗）；
2. Android 真机验证 ptrace 附加 + 同进程 patch；
3. 增加 PDB 解析器（可选，真实破解者常用）；
4. 与完整性校验对抗：patch 后需同时处理 CRC 重算（hashpatch 思路）。
