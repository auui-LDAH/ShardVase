# 双向打通：内存补丁工具（加固↔破解）工程规划

> 版本：2026-08-30 v1 · **2026-10-06 补记 v3** · 状态：**两个工具均已落地**（WinPE 侧另有真实 demo.exe 闭环，见 `docs/ATTACK_DRILL7.md` §6；Android 侧**真实 NDK r28 交叉编译通过**并修复 5 处从未被编译暴露的缺陷，真机仍待）· 关联：`docs/EXTENSION_PLAN.md`（Android 规划）、
> `docs/ATTACK_DRILL*.md`（Windows 攻防实证）、`docs/CONTRACT.md`（契约/算法）。
> 本文档规划两个**攻击侧**工具（用于攻防演练与能力验证，不对外发布）：

1. **WinPE-SymPatcher**：PE 符号表解析器 + 运行时内存补丁器（Windows x64）；
2. **Android-JniPtracePatcher**：JNI + ptrace 进程跟踪 + ELF 符号解析内存补丁器（Android）。

---

## 0. 背景：这个攻击点我们测过什么、没测过什么

### 已测（Windows x64，ATTACK_DRILL1-6 实证）
| 攻击 | 结果 | 出处 |
|------|------|------|
| 写 PEB.BeingDebugged=0 + NtGlobalFlag=0（ScyllaHide 核心） | **PARTIAL**（PEB 绕过，多因子 NtQuery 仍工作） | DRILL2 E1-2 |
| 持续写 result 判定（158 次） | **PARTIAL**（验签先于写，时序败） | DRILL2 P4-2 |
| 注入→IAT hook→patch 全链 | **BLOCKED**（3.1s 被 G2 拦） | DRILL3 C1 |
| 暂停 watchdog + .text patch | **BLOCKED**（0xBAD / 0xC0000005） | DRILL3 C3 |
| DLL 注入（CreateRemoteThread+LoadLibrary） | **PARTIAL**（注入成功） | DRILL2 G1 |
| dump→patch→重打包 | **BLOCKED**（blob 签名拒） | DRILL2 G4 |

### 没测过（本次要做的新角度）
1. **符号表解析器**：现有测试用硬编码偏移 / dumpbin 静态定位；真实破解者工具链是
   **运行时解析 PE/ELF 符号表**（.symtab/.dynsym/.pdata）动态定位目标。项目里没有
   自研解析器（tools/selfcrypt_elf.py 只有 ELF 符号定位骨架）。
2. **Android/JNI 形态**：libprot.c 有 TracerPid 反调试（nativeIsDebugged），但针对
   Android 的 **ptrace 内存补丁工具从未写过、未测过**（EXTENSION_PLAN T1 是空的）。

---

## 1. 目标

### 1.1 工具一：WinPE-SymPatcher（Windows x64）
- 解析 PE 导出表（.edata）与 COFF 符号表（.symtab），按符号名定位函数/变量地址；
- 附加目标进程 → 运行时定位 `prot_antidebug_scan` 等关键符号 → 内存改写（PEB 位/
  判定布尔）→ 验证"盾"失效路径；
- 与既有攻防结论对齐：验证符号表定位是否比硬编码偏移更强（或同样被多因子拦）。

### 1.2 工具二：Android-JniPtracePatcher
- JNI 加载到目标 App 进程（注入载体）或独立 ptrace 附加；
- 解析目标 ELF .symtab/.dynsym → 定位 `Java_com_prot_demo_Prot_nativeIsDebugged` /
  TracerPid 相关符号 → 运行时改写；
- 绕过 TracerPid 反调试（改写 /proc/self/status 读取路径或内存变量）→ 验证盾失效。

### 1.3 共同收获
- 打通"加固↔破解"两端：既知道盾怎么防，也知道矛怎么破；
- 补 EXTENSION_PLAN T1 空白（Android 攻防矩阵第一项）；
- 给 Windows 侧新增一个"真实破解者工具链"攻击面（符号表解析器）。

---

## 2. 设计

### 2.1 WinPE-SymPatcher 设计

```
tools/winpe_sympatcher/
  symparse.h/.c       PE 导出表 (.edata) + COFF 符号表 (.symtab) 解析器
  mempatch.h/.c       附加进程 + 写内存 (OpenProcess/WriteProcessMemory)
  main.c              命令行入口: --pid <pid> --symbol <name> --write <hex|off>
  CMakeLists.txt      独立构建 (MinGW/MSVC)
```

- 符号解析：`IMAGE_EXPORT_DIRECTORY` → NamePointerTable + OrdinalTable；COFF 符号表
  （`IMAGE_FILE_POINTER_TO_SYMBOL_TABLE`）→ SymbolTable。
- 定位策略：符号名 → RVA → 基址 + RVA = VA。
- 目标符号（本项目）：`prot_antidebug_scan`（函数）/ `prot_antidebug_detected`（聚合
  判定）/ `g_int3_caught`（变量）。**注意**：这些符号在 RELEASE 构建可能被 strip
  （/PDB 分离），需验证 DEBUG 构建可定位。
- 验证：对 demo.exe（DEBUG 构建）附加 → 定位 → 改写 → 观察行为（对照已测结论）。

### 2.2 Android-JniPtracePatcher 设计

```
examples/cross_platform/android/patcher/
  ptrace_attach.h/.c  ptrace(PTRACE_ATTACH/SEIZE) + 寄存器读写
  elfsym.h/.c         ELF64 .symtab/.dynsym 解析 (解析 /proc/pid/maps 定位基址)
  memwrite.h/.c       目标进程写内存 (process_vm_writev / ptrace POKETEXT)
  patcher_jni.c       JNI 入口: nativePatch(nativeIsDebugged 地址, 0)
  Android.mk / CMakeLists.txt
```

- 两种工作模式：
  - **A. 独立 patcher**（ptrace 附加其他 App）：需 root（ptrace 附加限制）；
  - **B. 同进程内 patch**（JNI 注入后直接改自己进程内存）——无需 root，但"盾"
    已在运行，改内存变量等效绕过。
- 目标符号：`Java_com_prot_demo_Prot_nativeIsDebugged`（JNI 导出函数，.dynsym 必有）、
  `/proc/self/status` 读取路径可改为 hook `fopen`/直接写内存返回 0。
- 注意：Android 9+ 隐藏 pidof/附加限制；先以 **API 21-28 + root 测试环境**为主。

---

## 3. 验收标准

### WinPE-SymPatcher
- [x] 解析器能定位 demo.exe 的 `prot_antidebug_scan`/`prot_antidebug_detected` —— **已达成（2026-10-06，Release + MAP）**：`--map build\demo.map` 得 `_detected` @`0x140001420` / `_multi` @`0x1400015b0` / `_scan` @`0x140001a50`；
- [x] 附加 → 定位 → 改写判定聚合位 → 观察盾行为变化 —— **已达成**：写 `31 C0 C3` 到 `prot_antidebug_detected` / `_multi` 头，读回一致，目标以 `2989`(`0xBAD`) + `完整性校验失败` 退出（`ATTACK_DRILL7.md` §6 组 B/C）；
- [x] 对照 ATTACK_DRILL 结论 —— **已记录**：真实目标上符号定位**可达**，但单点 patch **被 `.text` 段 CRC 收走**（不再是 mock 上的"盾永久失效"）；即定位能力成立、**静默改写不成立**（同 `ATTACK_DRILL7.md` §6 结论 3）；
- [x] 单元测试：符号解析对已知 PE 正确性 —— **已达成**：`README.md` 记录 user32.dll 导出表通道；本轮补 demo.exe MAP 通道实测；

### Android-JniPtracePatcher
- [x] ELF 符号解析器定位 JNI 导出符号 —— **已达成（含真实 NDK 产物，2026-10-06）**：`gen_test_elf.py` 样本 **6/6 符号命中**（`.symtab` + `.dynsym`）；**真实 NDK r28c aarch64 产物 `build/_ndk_out/libprot.so`（10192 B, `ARM aarch64` DYN）同样 6/6 命中** —— `nativeVerifyLicense 0x4de0` / `nativeCheckIntegrity 0x50ac` / `nativeIsDebugged 0x50c4` / `nativeDetectHook 0x5174` / `nativeStartWatchdog 0x5220` / `nativeStopWatchdog 0x5294`，负向对照 `Java_com_prot_demo_Prot__nope` ⇒ `not found`。宿主 x86_64 版（`build/_libprot_host.so` 16864 B）亦 6/6。**原文「无 NDK 环境」已事实过期**（NDK 在 `D:\environment\android-sdk\ndk\28.2.13676358`）；
- [ ] 同进程模式（B）改写 nativeIsDebugged 返回 0 → 验证 TracerPid 检测被绕过
      （/proc/self/status 读取路径被改）—— **代码就绪（NDK API 21/23/28 交叉编译通过），真机未测**（需 Android 设备/root；NDK 环境本身已具备）；
- [ ] ptrace 附加模式（A）在 root 测试环境对目标进程写内存成功 —— **代码就绪，真机未测**（需 root，D3「先宿主编译验证」的既定边界）；
- [ ] 回归：不破坏 libprot.so 既有功能 —— **未测**（随真机验证一并做）。

---

## 4. 决策点（拍板用）—— **2026-10-06 记：四项均按"推荐"列执行**

| 编号 | 决策 | 选项 | 推荐 |
|------|------|------|------|
| D1 | 先做哪个工具 | WinPE 先行 / Android 先行 | **WinPE 先行**（符号解析器可复用 ELF 思路，且已有 demo 产物可测） |
| D2 | 工具放置位置 | tools/（攻击工具与构建工具混放）/ 独立 tools/attacker/ | **tools/attacker/**（与既有工具分离，明确"攻击侧"属性） |
| D3 | Android 是否需要真机 | 宿主编译验证 / 真机 root 测试 | **先宿主编译验证**（原记「无 NDK/真机环境时文档化后续步骤」；**2026-10-06 更新：NDK r28 已就位并实跑交叉编译**，故本步已兑现且暴露并修复 5 处缺陷，真机测试仍为后续） |
| D4 | 是否对 RELEASE（strip）构建测试 | 是 / 否 | **是**（符号被 strip 是真实挑战，记录定位失败路径） |

---

## 5. 风险与缓解

| 风险 | 缓解 |
|------|------|
| RELEASE 构建符号被 strip → 定位失败 | **2026-10-06 实测按符号类别区分**：对真实 NDK 产物跑 `llvm-strip --strip-all`（`libprot_stripped.so` 7424 B）后，**JNI 导出（本工具的目标符号）仍 6/6 可定位** —— 它们必须留在 `.dynsym` 供 `dlsym` 解析，strip 不掉；**消失的是内部静态符号**（`wd_loop` / `g_wd_stop` / `g_wd_thread` 由 `S` 变 `not found`）、`.symtab` 整体消失（`symtab=0`）。⇒ 该风险**不对本工具成立**；若将来目标转为内部符号，再上 `.pdata`/`.rdata` 启发式（后置） |
| Android 无真机/NDK 环境 | **2026-10-06 更新：NDK r28c 已具备**，交叉编译已实跑（API 21/23/28 × `aarch64-linux-android`，`-Wall -Wextra -Werror` 全绿）。剩余缺口仅「真机 + root」；真机步骤仍待文档化 |
| ptrace 附加受限（Android 9+） | 同进程 JNI 模式（B）为主，ptrace 模式（A）标注需 root |
| 工具被误用于攻击他人软件 | 仅用于本项目攻防演练；不对外发布；文档声明用途 |

---

## 6. 实施步骤（待拍板后执行）

1. **WinPE-SymPatcher**（2-3 天）：
   - ① PE 导出表 + COFF 符号表解析器（纯 C）；
   - ② 附加 + 写内存（OpenProcess/WriteProcessMemory）；
   - ③ 对 demo.exe（DEBUG）定位 + 改写 + 对照既有攻防结论；
   - ④ 单元测试（user32.dll 已知导出符号验证）。
2. **Android-JniPtracePatcher**（2-3 天，宿主编译）：
   - ① ELF64 .symtab/.dynsym 解析器；
   - ② JNI 同进程 patch（nativeIsDebugged → 0）；
   - ③ ptrace 附加模式（root 环境，代码就绪+文档化）；
   - ④ prot_test.c 回归。
3. 文档：`docs/ATTACK_DRILL7.md`（符号表解析器攻击面）+ EXTENSION_PLAN T1 第一项。

---

## 7. 边界声明

- 这两个工具**仅用于本项目自有产物的攻防演练**（合法授权测试），不用于攻击第三方软件；
- 工具代码属于攻击侧能力，不进入 release 分发物；
- 结论如实记录（能破=破，不能破=边界+原因），延续"诚实边界"原则。
