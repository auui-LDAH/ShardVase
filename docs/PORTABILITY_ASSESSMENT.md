# 跨平台可行性评估（缺口 #3）

> **结论先行**：**不做全平台移植**。做到"**平台抽象接口 + 可移植性证明**"为止。
>
> **状态**：✅ 接口已定义且可编译；⬜ Linux/Android 实现**未做**
> **日期**：2026-09-23

---

## 1. 实测数据（先看清代价）

### 1.1 平台相关代码占比

| 项 | 实测 |
|----|------|
| `src/` + `include/protect/` | **34 文件 / 4661 行** |
| **含 Windows API 的文件** | **13 个（38%）** |

**API 使用频次**：
```
NtQuery*            14      VirtualProtect       6
GetProcAddress      13      Toolhelp             3
windows.h           11      VirtualAlloc         2
TerminateProcess     9      GS/FS 段读            1
                            OpenProcess          1
```

### 1.2 构建系统耦合

| 项 | 数量 |
|----|------|
| PowerShell 脚本 | **9 个** |
| 含 MSVC 调用（`cl`/`vcvars`/`/link`）| 6 个 |
| Python 工具 | 43 个 |

### 1.3 Python 工具的可移植性

| 类别 | 数量 | 说明 |
|------|------|------|
| **平台相关** | **19** | `hashpatch`（PE 节表）/`indirect`/`measure_sections`/`observability` … |
| **纯逻辑（可移植）** | **24** | `compose`/`conformance`/`attackcheck`/`identity`/`hostgen`/`gen_sections` … |

> **这是好消息**：**56% 的 Python 工具是纯逻辑**，可直接跨平台使用。

### 1.4 已有跨平台资产

| 资产 | 状态 |
|------|------|
| **Android 攻击工具**（`tools/attacker/android_jniptrace/`）| ✅ **7 个文件**（`ptrace_patcher_cli.c` / `elfparse` / `elfdump`）|
| Linux 相关 | ❌ **无** |

---

## 2. 诚实判断：Linux 适配的真实工作量

### 2.1 为什么不是"改几行 `#ifdef`"

**机制完全不同**：

| 能力 | Windows | Linux |
|------|---------|-------|
| 页管理 | `VirtualAlloc` / `VirtualProtect` | `mmap` / `mprotect` |
| 调试检测 | `IsDebuggerPresent` / PEB 读 | `/proc/self/status`（TracerPid）/ `ptrace` |
| 进程枚举 | Toolhelp32 / `NtQuerySystemInformation` | `/proc` 遍历 |
| 映像格式 | **PE** | **ELF** |
| 自身路径 | `GetModuleFileName` | `/proc/self/exe` |

### 2.2 工作量估算（**诚实**）

| 部分 | 可复用性 |
|------|---------|
| VM / crc32 / strcrypt / 授权链（纯逻辑）| ✅ **可复用**（约 30–40%）|
| 页管理 / 反调试 / 完整性（平台机制）| ❌ **相当于重写**（38% 的文件）|
| PE 相关工具（`hashpatch`/节表/填充）| ❌ **需重写为 ELF 版** |

> **结论**：Linux 适配 ≈ **重写 38% 的 C 代码 + 40% 的 Python 工具**。

### 2.3 Android 的特殊性

| 项 | 说明 |
|----|------|
| 已有资产 | **攻击侧**有 `jniptrace`（7 文件）—— **防御侧为零** |
| 缺少 | NDK / JNI / Bionic libc 适配 |
| 无 PE | `hashpatch` / 节表 / 填充等**全部需重写** |
| 额外风险 | SELinux / W^X（Android 10+ 禁 `mmap` RWX）|

---

## 3. 本轮的**最小有价值一步**

**不做**移植；**做**平台抽象接口 —— 它的价值是：

> **证明「模块协议可跨平台」，而非「完成 Linux 支持」。**

### 3.1 交付：`include/protect/prot_platform.h`

**设计原则**：把平台原语抽成**薄接口**，使：
- 纯逻辑模块（VM/crc32/strcrypt/授权链）**不直接调用**平台 API
- 平台相关模块通过本接口访问平台能力
- **新增平台 = 实现本接口**，而非改所有模块

**四组接口**：

| 组 | 内容 |
|----|------|
| **页管理** | `prot_plat_alloc` / `prot_plat_protect` / `prot_plat_free` |
| **调试原语** | `prot_plat_debug_primitives`（返回**原语**，非判断）|
| **进程/模块** | `prot_plat_enum_processes` / `prot_plat_enum_modules` |
| **计时/自身** | `prot_plat_monotonic_ns` / `prot_plat_self_path` |

**两个关键设计**：

1. **能力位掩码**（`PROT_PCAP_*`）
   > 模块可据此**声明自己需要什么** —— 缺少能力时应**优雅降级或明确拒绝**，
   > 而非静默失效（P4 诚实边界）。

2. **平台给原语，模块给判断**
   > `prot_plat_debug_primitives` 只采集**事实**（`being_debugged` 等），
   > **不决定**"检测到怎么办" —— 与 `host_hooks` 的职责分离一致。

### 3.2 验证（**实测**）

**编译验证**（`/W4 /WX /std:c11`）：
```
编译: ✓ 成功    警告: 0
```

**接口审查 7/7**：
```
✓ 无 windows.h 泄漏到公共接口
✓ 含平台标识宏（3 个平台）
✓ 未知平台 -> #error（不静默）
✓ 含能力位掩码（模块可声明需求）
✓ 含 3 组原语（页/调试/进程）
✓ 含计时与自身映像
✓ 明确标注诚实边界
```

---

## 4. 诚实边界

| 边界 | 说明 |
|------|------|
| **仅接口，无实现** | Linux/Android 实现**未做**（调用会返回未实现）|
| **未接入构建** | 独立头文件，**不影响**现有 Windows 构建 |
| **38% 的 C 文件仍直接依赖 Windows API** | 接口**尚未被现有模块使用** |
| **不是"运行期 ABI"** | 仍是**编译期**选择平台实现（`PROT_PLATFORM` 宏）|
| **PE 相关工具未抽象** | `hashpatch`/节表/填充等仍需 **ELF 版重写** |

---

## 5. 若要继续（建议路径）

| 阶段 | 内容 | 说明 |
|------|------|------|
| **L1** | 接入构建：实现 Windows 版平台层，**让 1–2 个模块改用它** | 证明接口可用 |
| **L2** | 把**纯逻辑模块**（crc32/strcrypt/VM）与平台层解耦 | 提高可复用比例 |
| **L3** | 抽出可移植内核（平台无关的 C 子集）| 为多平台铺路 |
| **L4** | Linux 实现平台层（`mmap`/`ptrace`/`/proc`）| **本阶段才开始真正移植** |
| **L5** | ELF 版工具链（节表/填充/hashpatch）| 工具层适配 |

**L1 是下一个自然步骤** —— 它风险低（只改 1–2 个模块）且可验证。

---

*2026-09-23 · 评估 + 接口定义；实现未做（见 §4 诚实边界）*
