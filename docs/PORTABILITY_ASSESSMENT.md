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

## 5. 实施路径

### 5.1 L1 ✅ **已完成**（2026-09-23）

| 阶段 | 内容 | 说明 |
|------|------|------|
| **L1** | 接入构建：Windows 版平台层 + **让模块实际改用它** | ✅ **已完成，见 §5.2** |
| **L2** | 把**纯逻辑模块**（crc32/strcrypt/VM）与平台层解耦 | 提高可复用比例 |
| **L3** | 抽出可移植内核（平台无关的 C 子集）| 为多平台铺路 |
| **L4** | Linux 实现平台层（`mmap`/`ptrace`/`/proc`）| **本阶段才开始真正移植** |
| **L5** | ELF 版工具链（节表/填充/hashpatch）| 工具层适配 |

**L1 是下一个自然步骤** —— 它风险低（只改 1–2 个模块）且可验证。

---

*2026-09-23 · 评估 + 接口定义；实现未做（见 §4 诚实边界）*

### 5.2 L1 完成记录（2026-09-23）

**目标**：证明平台接口**可用**（而非纸面设计）。

#### 交付

| 文件 | 内容 |
|------|------|
| `src/platform/prot_platform_win.c` | **Windows 实现**（委托既有 API）|
| `modules.json` | 注册 `platform_win` 为**原语**（与 `crc32`/`vm_rekey` 同类）|
| `include/protect/protdef.h` | 新增 `PROT_ERR_UNSUPPORTED` |
| `src/vmdetect.c` | **改用平台层**（首个接入模块）|

#### 为什么选 `vmdetect` 作为首个接入点

实测筛选（标准：WinAPI 少 / 未被 selfcrypt 加密 / 有小文件 / 有 drill 覆盖）：

| 模块 | 行数 | WinAPI | drill | 评估 |
|------|------|--------|-------|------|
| **vmdetect** | **110** | **1** | 2 | ✅ **风险最低** |
| vm | 1083 | 1 | 5 | 核心模块，风险高 |
| antidebug | 405 | 15 | 8 | API 过多 |

#### 接入方式

`has_vm_process()` 此前用 `CreateToolhelp32Snapshot` + `_wcsicmp`
（**平台特有**）；改用 `prot_plat_enum_processes` 后：

- ✅ 该函数**不再含平台 API** —— 跨平台时无需改动
- ✅ 新增平台只需实现平台层，**不必碰本模块**

#### 验证（**实测**）

| # | 验证项 | 结果 |
|---|--------|------|
| V1 | **功能等价** | ✅ e2e T1-T28 / attacks A1-A12 / protchain P1-P6 全绿 |
| V2 | **平台层真实编入产物** | ✅ `build/demo.map` 含 `prot_plat_enum_processes` |
| V3 | **vmdetect 摆脱平台 API** | ✅ 无 Toolhelp32 符号；`<tlhelp32.h>` 已移除 |
| V4 | **可复现性保持** | ✅ `repro_check` PASS（SHA-256 一致）|
| V5 | **门禁 19 项** | ✅ 全绿（含变异测试/骨架回归/迁移成本）|

#### 关键等价性验证（**专门做的**）

我把 `_wcsicmp`（locale 规则）换成手写 ASCII 比较 —— **这是真实的行为风险**。
故写 C 程序**穷举比对**：

```
输入: 12 个目标进程名 × 16 个测试输入（含大小写变体/边界/空串/前缀后缀）
结果: compared=192  mismatches=0
=> ✓ 对目标名集合，两种比较**完全等价**
```

#### 过程中发现的问题（**门禁抓到的**）

| # | 问题 | 谁抓到 |
|---|------|--------|
| 1 | `strncpy` 触发 C4996（`/WX` 下为错误）| **编译** |
| 2 | `vmdetect` 新增对 `prot_platform` 的依赖，但注册表未登记 | **modcheck** |
| 3 | `INFRA_HEADERS` 白名单**第三次**需手工更新 | modcheck |

**问题 3 的处置**：加了 **R20 检查** —— 枚举 `include/protect/*.h`，
凡既不在注册表、也不在白名单中的头 -> **报错并提示如何修**。

> **R20 立即体现价值**：它一运行就报出 `version.h` 也是基础设施头
> —— 这是**手工白名单从未包含的**（此前无模块 include 过它）。
> **=> 白名单从"手工维护"变为"自动发现完整清单"。**

#### 诚实边界（L1 未做到的）

| 边界 | 说明 |
|------|------|
| **只接入 1 个模块** | 其余 12 个模块仍直接调 Windows API |
| **只实现 Windows** | Linux/Android 实现**未做** |
| **接口未全覆盖** | `prot_plat_alloc/protect/free` 等尚无模块使用 |
| **未验证跨平台可行性** | 只证明"接口能接入 Windows"，未证明"同一接口能接 Linux"|
| **仍是编译期选择** | 非运行期 ABI |

#### 下一步（L2）

| 阶段 | 内容 |
|------|------|
| **L2** | 把**纯逻辑模块**（`crc32`/`strcrypt`/VM 部分）与平台层解耦 |
| L3 | 抽出可移植内核（平台无关的 C 子集）|
| L4 | Linux 实现平台层（`mmap`/`ptrace`/`/proc`）—— **本阶段才真正移植** |
| L5 | ELF 版工具链 |

---

*2026-09-23 · L1 完成：接口可用性已**实测证明**；§5.2 含完整验证记录与诚实边界*
