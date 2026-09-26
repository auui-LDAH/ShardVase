# Linux 移植清单（L5a）

> **来源**：`tools/migration_inventory.py` **实测枚举**（非人工猜测）
> **日期**：2026-09-23
> **关联**：`docs/PORTABILITY_ASSESSMENT.md`（评估）、
> `tests/platform_conformance.c`（验收条件）

---

## 0. 如何使用本文档

```
① 看 §2 的总览 -> 知道还剩多少
② 看 §3 的逐条清单 -> 每条含【语义 / Linux 等价物 / **差异**】
③ 实现时: 改 src/platform/ 下的平台层，**不改模块**
④ 验收: 跑 tests/platform_conformance.c（**唯一判据**）
```

> **关键纪律**：新平台的正确性**由契约测试判定**，不靠人工评审。
> 这就是 L4-A 的设计目的（见 `PORTABILITY_ASSESSMENT.md` §8.2）。

---

## 1. 实测总览

| 项 | 数量 |
|----|------|
| 扫描的 C 文件 | 全部 `src/` `demo/` `tools/attacker/` `prot_sdk/` |
| **发现的平台 API** | **31 个** |
| **✅ 已被平台层封装** | **17 个** |
| **⬜ 待封装** | **14 个** |

**含义**：
- 已封装的 17 个 -> `src/platform/` 内，**Linux 实现只需写平台层**
- 待封装的 14 个 -> 仍**散落在模块里**，需先**抽象**再实现

---

## 2. 待封装清单（**14 个**，按调用点数量）

| # | API | 处数 | Linux 等价物 | 难度 |
|---|-----|------|-------------|------|
| 1 | `GetCurrentProcess` | 20 | `getpid()` | 🟢 易 |
| 2 | `Sleep` | 10 | `nanosleep` | 🟢 易 |
| 3 | `CloseHandle` | 10 | `close`/`dlclose` | 🟡 中（按对象类型分）|
| 4 | `TerminateProcess` | 7 | `_exit`/`kill` | 🟡 中（语义抉择）|
| 5 | `GetProcAddress` | 7 | `dlsym` | 🟢 易 |
| 6 | `WinHttpOpen` | 4 | `libcurl` | 🟡 中（新增依赖）|
| 7 | `WinHttpConnect` | 4 | `libcurl` | 🟡 中 |
| 8 | `WinHttpSendRequest` | 4 | `libcurl` | 🟡 中 |
| 9 | `NtQuerySystemInformation` | 3 | `/proc` `/sys` | 🔴 难（无对应）|
| 10 | `__readgsqword` | 3 | FS 段 / `__builtin_thread_pointer` | 🔴 难（架构特定）|
| 11 | `OpenProcess` | 2 | （无句柄模型）| 🔴 难（**需重构调用方**）|
| 12 | `GetCurrentThread` | 2 | `gettid()` | 🟢 易 |
| 13 | `__cpuid` | 2 | `__get_cpuid()` | 🟢 易 |
| 14 | `__rdtsc` | 1 | `__builtin_ia32_rdtsc()` | 🟢 易 |

---

## 3. 逐条清单（**含真实差异**）

> **"差异"栏是本文档最重要的部分** ——
> 移植的难点不在"找到等价物"，而在**知道它们不等价在哪**。

### 3.1 🟢 低难度（7 个，几乎 1:1）

| API | 语义 | Linux | **差异** |
|-----|------|-------|---------|
| `GetCurrentProcess` | 当前进程伪句柄 | `getpid()` | 模型不同但用途等价 |
| `Sleep` | 睡眠 | `nanosleep`/`usleep` | 基本等价（精度单位不同）|
| `GetProcAddress` | 按名解析符号 | `dlsym(handle, name)` | 基本等价；Linux 需先 `dlopen` |
| `GetCurrentThread` | 当前线程 | `gettid()` | 基本等价（`gettid` 需 syscall 封装）|
| `__cpuid` | CPUID 指令 | `__get_cpuid()` | 基本等价 |
| `__rdtsc` | 时间戳计数器 | `__builtin_ia32_rdtsc()` | 基本等价 |
| `CloseHandle` | 关闭句柄 | `close`/`dlclose` | **按对象类型分**（文件/库/进程）|

### 3.2 🟡 中难度（4 个，需抉择或新依赖）

| API | 语义 | Linux | **差异** |
|-----|------|-------|---------|
| `TerminateProcess` | 终止进程 | `_exit`/`kill` | **`exit()` 会跑 atexit、`_exit()` 不会** —— 反调试场景应用 `_exit`（避免析构被 hook）|
| `WinHttpOpen` | HTTP 客户端 | `libcurl` | **新增链接依赖**；注意这是**可选在线路径**，离线不受影响 |
| `WinHttpConnect` | HTTP 连接 | `libcurl` | 同上 |
| `WinHttpSendRequest` | HTTP 请求 | `libcurl` | 同上 |

### 3.3 🔴 高难度（3 个，**机制不同或无对应**）

| API | 语义 | Linux | **差异（真难点）** |
|-----|------|-------|------------------|
| `NtQuerySystemInformation` | 查系统信息（隐藏 API）| `/proc` `/sys` | **机制完全不同**；Windows 上用它是为了**绕过 hook**（用户态 API 可被 hook，NT API 更难），Linux 无此层次划分 |
| `__readgsqword` | 读 GS 段（TEB/PEB）| FS 段 | **段寄存器不同**: Windows 用 GS 指向 TEB，Linux 用 FS 指向 TLS；**且 Linux 无 PEB 概念**（反调试机制需重新设计）|
| `OpenProcess` | 打开进程句柄 | （无）| **Linux 无句柄模型** —— ptrace 附加即"打开"；**需重构调用方逻辑**，不是换个函数 |

---

## 4. 已封装清单（17 个，Linux 实现只需写平台层）

| 组 | API | 平台层函数 |
|----|-----|-----------|
| 页管理 | `VirtualAlloc`/`VirtualProtect`/`VirtualFree` | `prot_plat_alloc`/`protect`/`free` |
| 进程枚举 | `CreateToolhelp32Snapshot`/`Process32*W` | `prot_plat_enum_processes` |
| 模块枚举 | `EnumProcessModules`/`GetModuleInformation`/`GetModuleFileNameA` | `prot_plat_enum_modules`/`self_path` |
| 调试检测 | `IsDebuggerPresent`/`CheckRemoteDebuggerPresent`/`GetThreadContext` | `prot_plat_debug_primitives` |
| 计时 | `QueryPerformanceCounter`/`Frequency` | `prot_plat_monotonic_ns` |
| 密码学 | `BCrypt*`（10 个）| `prot_crypto_sha256`/`rsa_verify_sha256` |

> **注意 `QueryPerformanceFrequency` 无 Linux 对应物** ——
> 平台层已**吸收该差异**（Linux 直接给纳秒，无需频率）。
> **这正是抽象层的价值**: 平台差异被封装在一个函数里。

### 4.1 ⚠️ 关键真实差异（已封装但仍需注意）

| 差异 | 说明 |
|------|------|
| **进程名长度** | Linux `TASK_COMM_LEN` = **15 字符**；Windows 无此限制 —— 长名会被**截断** |
| **释放页** | Windows `VirtualFree(addr, 0, MEM_RELEASE)`；Linux `munmap(addr, **len**)` —— **必须传原长度**（平台层已处理）|
| **改页保护** | Windows `VirtualProtect` 返回**旧属性**；Linux `mprotect` **不返回** —— 需自己记 |
| **W^X** | Android 10+ / 部分内核**禁止 RWX 页** —— 需 `mmap(RW)` + `mprotect(RX)` 两步 |
| **硬件断点** | 读 `Dr0-Dr3` 在 Linux 需 `ptrace` 附加；**读自身也受限** |

---

## 5. 建议实施顺序

| 阶段 | 内容 | 理由 |
|------|------|------|
| **S1** | 封装 7 个🟢低难度 | 快速收敛，且**降低 API 面** |
| **S2** | 封装 4 个🟡中难度 | 含 `libcurl` 依赖决策 |
| **S3** | `hostid` 解耦（L5b）| 见 `hostid` 专项 |
| **S4** | 3 个🔴高难度 | **需重新设计**（尤其 PEB 反调试）|
| **S5** | 写 `prot_platform_linux.c` | 平台层 |
| **S6** | 跑契约测试 | **唯一验收判据** |

---

## 6. 诚实边界

| 边界 | 说明 |
|------|------|
| **本清单是"静态枚举"** | 基于 API 调用点；**不包含**"逻辑上依赖平台语义"的地方（如靠 GS 段间接反调试）|
| **未评估工作量** | 只列了"改什么"，**未估算"多少小时"** |
| **🔴 三项可能是"重新设计"** | 尤其 `__readgsqword`（PEB 反调试）在 Linux **无对应机制**，不是移植而是**重做** |
| **`tools/attacker/` 未纳入** | 攻击侧的 Android 工具（`elfparse` 等）是**另一套**，未在本清单 |

---

*2026-09-23 · L5a 完成：31 个 API 逐一枚举，含真实差异*
