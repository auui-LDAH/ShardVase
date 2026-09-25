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

---

## 6. L2 完成记录：纯逻辑模块解耦（2026-09-23）

### 6.1 目标
把**纯逻辑模块**与平台层解耦 —— 提高可跨平台复用的比例。

### 6.2 勘查：真实耦合（**不只看 WinAPI**）

L1 的扫描只查"直接调 WinAPI"，结论是 8 个模块 0 WinAPI。
但**没有 WinAPI 不等于可移植** —— L2 用 5 个维度重查：

| 维度 | 检查内容 |
|------|---------|
| 平台头 | `windows.h` / `tlhelp32.h` / `bcrypt.h` … |
| PE 依赖 | `IMAGE_*` / `PIMAGE_*` |
| 平台类型 | `DWORD` / `HANDLE` / `BOOL` / `PUCHAR` … |
| MSVC 专有 | `__declspec` / `#pragma section` / `__cpuid` … |
| 其它平台头 | `intrin.h` / `winternl.h` / `wincrypt.h` … |

**结果**：

| 模块 | 判定 |
|------|------|
| `crc32` / `vm_rekey` / `strcrypt` / `blob` / `revoke` | ✅ **零耦合**（真纯逻辑）|
| `indirect` | ⚠️ `__declspec(noinline)` ×1（**编译器专有**）|
| `hostid` | ⚠️ `windows.h` + 注册表/卷序列号（**平台本质差异**）|
| `license` | ⚠️ `windows.h` + BCrypt（**密码学调用**）|

### 6.3 解耦 1：`indirect` 的编译器专有语法 ✅

**新增** `include/protect/prot_compiler.h`：

| 宏 | MSVC | GCC/Clang |
|----|------|-----------|
| `PROT_NOINLINE` | `__declspec(noinline)` | `__attribute__((noinline))` |
| `PROT_USED` | （空）| `__attribute__((used))` |
| `PROT_CALL` | `__cdecl` | （空）|
| `PROT_PACK_*` | `__pragma(pack(...))` | `__attribute__((packed))` |

`src/indirect.c` 改用 `PROT_NOINLINE` -> **不含编译器专有语法**。

**验证**：MSVC 下宏**展开为完全相同的 `__declspec(noinline)`**；
`prot_indirect_resolve` 在 map 中**仍是独立符号**（未被内联）——
即**间接化语义保持**。

> **设计说明**：这是 L1 平台抽象层（**运行期**能力）的
> **编译期对应物** —— 两者共同构成"跨平台"的两个维度。

### 6.4 解耦 2：`license` 的密码学 ✅（**价值最高**）

**改动前**：`src/license.c` **直接调用 BCrypt** 做 SHA-256 与 RSA 验签
-> **整个授权链（14 条 drill）不可移植**。

**改动后**三层分离：

```
license.c            消息构造 + 流程编排   <- 纯逻辑，可移植
     ↓
prot_crypto.h        密码学接口（只暴露算法语义）
     ↓
prot_crypto_win.c    BCrypt 实现            <- 平台层
```

**`license.c` 的变化**：
- 行数 **105 -> 78**
- **残留平台符号：0**（`BCRYPT_*` / `NTSTATUS` / `PUCHAR` 等全部消失）
- 不再 `#include <windows.h>` / `<bcrypt.h>`

**关键设计（接口层）**：
| 设计 | 理由 |
|------|------|
| 公钥为**不透明 blob + 长度** | Windows 用 `BCRYPT_RSAPUBLIC_BLOB`；其它平台可换标准格式 |
| **不暴露平台类型** | 接口只用 `uint8_t` / `size_t` / `int` |
| **错误与验签失败都返回 0** | 授权路径**不应泄漏**"是格式错还是签名错"（会成为 oracle）|
| `PROT_SIG_LEN` 是**协议常量** | 384 字节（RSA-3072），非平台相关 |

### 6.5 关键：BCrypt 调用是**逐字迁移**（而非重写）

> 授权链有 **14 条 drill**，验签失败直接影响授权判定。
> **重写密码学调用 = 引入真实风险。**
> 故 `sha256_digest()` 与 `prot_license_verify()` 的 BCrypt 代码
> **逐字搬到** `prot_crypto_win.c`，只换成接口签名。

**行为等价性验证（实测）**：

| # | 项 | 结果 |
|---|----|------|
| V1 | `license.c` 无平台符号 | ✅ **0 处** |
| V2 | 密码学层真实编入 | ✅ **单独编译时 3 个符号全在 obj 中**；`demo.exe` **仍导入全部 7 个 BCrypt 函数**（证明调用链完整）|
| V3 | **授权链功能**（e2e T1-T28 含授权用例）| ✅ PASS |
| V4 | **攻击侧**（attacks A1-A12 含伪造/篡改授权）| ✅ PASS |
| V5 | 保护链 P1-P6 | ✅ PASS |
| V6 | **可复现性** | ✅ PASS（SHA-256 一致）|
| V7 | R20 白名单自动发现 | ✅ 负向验证通过 |

### 6.6 ⚠️ 门禁抓到的**真实回归**（L1 时漏检的路径）

**现象**：`example E1-E7` 构建失败
```
license.obj : error LNK2019: 无法解析的外部符号
              prot_crypto_rsa_verify_sha256
```

**根因**：`examples/tool_demo/build_example.ps1` 有**自己的硬编码
源文件列表**（L89），未含新平台层。

> **这是 L1 时我没发现的** —— L1 只改了 `vmdetect`（未被 example 引用），
> 故 example 不受影响；L2 改 `license.c`（**被 example 引用**）后暴露。

**教训**：**硬编码源文件列表有三处** ——
`build.ps1` / `build_skeleton.ps1` / `build_example.ps1`。
新增平台层必须**三处同改**。

> 同类问题在本项目**反复出现**：
> `SOURCE_ORDER` 硬编码（W3.3 已解决）、`INFRA_HEADERS` 白名单（R20 已解决）、
> **构建脚本的源文件列表（本次，尚未自动化）**。

### 6.7 解耦成果汇总

| 模块 | L1 判定 | **L2 后** |
|------|---------|----------|
| `crc32` / `vm_rekey` / `strcrypt` / `blob` / `revoke` | 纯逻辑 | ✅ 纯逻辑（未变）|
| `indirect` | ⚠️ 编译器专有 | ✅ **纯逻辑**（用 `PROT_NOINLINE`）|
| `license` | ⚠️ BCrypt | ✅ **纯逻辑**（密码学已抽出）|
| `hostid` | ⚠️ 注册表/卷序列号 | ⚠️ **未解耦**（见 §6.8）|

**=> 从 5 个纯逻辑模块提升到 7 个**（13 个模块中）。

### 6.8 诚实边界（L2 **未**做到的）

| 边界 | 说明 |
|------|------|
| **`hostid` 未解耦** | 注册表 + 卷序列号是**平台本质差异**（Linux 用 `/etc/machine-id` + `statvfs`）—— 不是"抽个接口"就能解决，需真正实现 |
| **密码学层只覆盖 2 个原语** | SHA-256 / RSA 验签；对称加密与 KDF **仍各自为政** |
| **未实现其它平台** | Linux/Android 仍**未做** |
| **平台层仍只 1 处被用** | `prot_plat_alloc/protect/free` 等**尚无模块使用** |
| **构建脚本列表未自动化** | 三处硬编码列表仍需**手工同改**（§6.6）|

### 6.9 下一步（L3）

把**可移植内核**抽出为一个明确的 C 子集（平台无关），
并**自动化构建脚本的源文件列表**（消除 §6.6 的三处手工同步）。

---

*2026-09-23 · L2 完成：授权链与间接化已解耦；§6.6 记录门禁抓到 L1 漏检的回归*

---

## 7. L3 完成记录：消除"硬编码源文件列表"（2026-09-23）

### 7.1 目标
L2 结尾暴露了一个**反复出现**的问题：新增平台层后
`examples/tool_demo` 构建失败（`LNK2019`），因为它有**自己的硬编码
源文件列表**。L3 的目标是**根治这一类问题**。

### 7.2 勘查：三处构建脚本的实际情况

| 脚本 | 机制 | 结论 |
|------|------|------|
| `build.ps1` | `tools/compose.py --sources-out` | ✅ **已注册表驱动** |
| `prot_sdk/skeleton/build_skeleton.ps1` | 同上 | ✅ **已注册表驱动** |
| **`examples/tool_demo/build_example.ps1`** | **硬编码 12 个 src/*.c** | ❌ **漂移源** |

**修正了 L2 的判断**：L2 认为"三处都硬编码"，实测**只有一处**。

### 7.3 修复 1：`build_example.ps1` 改为注册表驱动 ✅

新增 `compositions/example.json`（示例专用组合），脚本改用
`compose.py example --sources-out`。

**过程中发现并修正了 2 个我自己的错误**：

| # | 错误 | 表现 |
|---|------|------|
| 1 | 把 `crc32` 写进 `modules` 数组 | `compose: 拼装图含未登记模块: crc32`（它是**原语**）|
| 2 | 从下限中去掉 `strcrypt` | `LNK2019: prot_str_decrypt`（`strings.c` **调用**它）|

> **错误 2 的教训**：**"gen 产物存在" != "不需要对应模块"** ——
> gen 产物往往**调用**对应模块，而非替代它。

### 7.4 修复 2（**核心发现**）：`SUBSTRATE` 是第四次硬编码 ✅

**发现经过**：改用 compose 后，示例**仍链接失败** ——
因为**宿主下限强制补入 `indirect`**，而
`tools/indirect.py` 生成的 `indirect_table.c` **硬编码**：
```c
extern int load_and_verify_license(const char*, demo_mem*);
```
其中 `demo_mem` 是 **`demo/main.c` 的私有类型** -> 示例无法使用。

**试 `exclude_primitives: ["indirect"]` -> 无效**：
`compose.py` L249 `full |= set(SUBSTRATE)` **无条件补入**。

**根因**：`SUBSTRATE` 是**硬编码模块名列表**，其注释写着
"宿主下限: **main.c** 无条件调用这些模块" —— 而 `main.c` 指 **demo 的**。

> **故"宿主下限"不是普遍规律，而是"demo 宿主的硬引用集"。**
> 换宿主（示例 / 第三方工具）下限**不同**，但旧机制**无法表达**。

**修复**（低风险，保留既有行为）：
```python
_substrate = comp.get('host_substrate')
if _substrate is None:
    _substrate = SUBSTRATE      # demo 默认，既有组合行为**逐字不变**
full |= set(_substrate)
```

**验证**：
| 组合 | 结果 |
|------|------|
| `minimal` / `standard` / `hardened` / `full` | ✅ **源文件列表逐字不变**（12/15/17/17）|
| `example` | ✅ 正确排除 `indirect`（14 源文件，含 strcrypt）|

### 7.5 修复 3：加**防复发**检查（S1/S2）✅

**为什么必须加**：本项目**四次**同类问题
```
① SOURCE_ORDER 硬编码       -> W3.3 拓扑排序
② INFRA_HEADERS 白名单      -> R20 自动发现
③ 构建脚本源文件列表        -> L3 compose 驱动
④ SUBSTRATE 宿主下限        -> L3 按宿主可声明
```
前三次都是"事后修"，**缺少防复发**（除 ② 的 R20）。

**S1/S2 规则**（加入 `modcheck`）：
| 规则 | 内容 |
|------|------|
| **S1** | 构建脚本**不得硬编码 ≥3 个 `src/*.c`**（阈值 3：1–2 个可能是合法引用）|
| **S2** | 组合的 `host_substrate` 模块必须**真实存在** |

**S1 的**显式豁免机制**（`# S1-ALLOW: <理由>`）**：
- 某些脚本**合法地**需要特定最小集
- 豁免必须**显式标注 + 给理由**，且 modcheck 会**列出全部豁免**
- **不静默**（静默豁免 = 可绕过的检查，违反 P3 教训）

### 7.6 ⚠️ 负向验证发现的问题（**我的错误**）

**第一次负向验证：S1/S2 都抓到 ✗**

**根因**：`check_build_scripts` 函数**定义了但从未被调用** ——
我的插入脚本用 `if 'S1/S2: 防' in t` 判断"是否已插入"，
而**我自己刚写的函数 docstring 里就有这段文字** -> 误判 -> 跳过。

> **这与 R20 那次是同一类错误（第二次）**：
> **存在性检查必须查调用点（`check_x(reg)`），而非裸名字或注释文本。**

**修正后**：S1/S2 **都正确抓到**。

### 7.7 S1 的**第一次真实捕获**：`build_dotnet_gate.ps1`

S1 上线后立即抓到 `tools/build_dotnet_gate.ps1:57`
硬编码 4 个 `src/*.c`。

**分析**（`gate.c` 只引用 `prot_antidebug_report`）：
| 项 | 结果 |
|----|------|
| 真实需要 | `antidebug`（+ 依赖 `syscall`）|
| 缺 | 无 |
| 多 | `crc32`（原语）/ `strcrypt`（`strings.c` 需要）|

**=> 列表是"正确的最小集"，不是漂移** —— 但仍是**手工维护**的
（`antidebug` 新增依赖时不会自动跟上）。

**处置**：加 `S1-ALLOW` 豁免 + **修正原注释**
（原注释说"用 minimal"，但 minimal **不含** antidebug —— 注释与实际不符）。

### 7.8 成果

| 项 | 结果 |
|----|------|
| 构建脚本硬编码列表 | ✅ **已消除**（example 改 compose 驱动）|
| 宿主下限 | ✅ **按宿主可声明**（既有组合行为不变）|
| 防复发检查 | ✅ **S1/S2**（含显式豁免机制）|
| 门禁 | ✅ **19 项全绿** |
| example 构建 | ✅ 成功（`license_ok=1`）|

### 7.9 诚实边界（L3 **未**做到的）

| 边界 | 说明 |
|------|------|
| **`indirect_table.c` 仍硬编码 demo 宿主函数** | `load_and_verify_license(const char*, demo_mem*)` —— 换宿主**仍需改工具**（`tools/indirect.py` L63/L141）|
| **`build_dotnet_gate.ps1` 仍是手工最小集** | 用了 S1-ALLOW 豁免（**显式**，但仍是手工）|
| **未实现其它平台** | Linux/Android 仍为零 |
| **平台层仍只 2 处被用** | `prot_plat_alloc/protect/free` 等仍无模块使用 |
| **`hostid` 未解耦** | 注册表/卷序列号是平台本质差异 |

### 7.10 下一步（L4）

**L4 = 真正实现 Linux 平台层**（`mmap`/`ptrace`/`/proc`）。
前置条件已具备:
- ✅ 平台接口已定义且**已被 2 处使用**（L1/L2）
- ✅ 纯逻辑模块 **7/13**
- ✅ 构建脚本**注册表驱动**（新增平台层不会再漏）

---

*2026-09-23 · L3 完成：四次"硬编码列表"问题全部收尾；§7.6 记录第二次"检查匹配到自己的注释"错误*
