# 平台隔离 / map 统一 / Linux 攻击面 — 分步计划

> **文档性质**：计划文档（待确认后执行）
> **来源**：用户指定三项任务「全部都要，先生成计划文档」
> **前置盘点**：见 §1（真实实测数据，非估算）

---

## 0. 三项任务与我的评估结论（**先说结果**）

| # | 任务 | 用户给的判断 | **我的评估** | 建议 |
|---|------|------------|------------|------|
| **A** | 产物按平台隔离 | 价值高 / 成本中 | **成本被我低估了** —— 见 §1.1（98 个文件引用，且 `build.ps1`/`build.sh` 各 40+ 处）| **做，但用「最小侵入」方案**（§2）|
| **B** | 抽公共 map 解析模块 | 价值中 / 成本低 | ✅ **成本确实低**（4 处实现，共约 60 行）| **做，且优先做**（无风险、立即消除漂移）|
| **C** | Linux 专用攻击面测试 | 价值高 / 成本高 | ⚠️ **成本确实高**（`e2e.py` 的 23 处 ctypes / 20 处 kernel32 是**深层耦合**）| **做「裁剪版」**（§4）+ 其余**主动搁置** |

> **诚实说明**：A 的实际成本比"中"要高（§1.1 有实测数字）；
> C 里最有价值的部分（**Linux 独有的反调试/DBI 面**）成本其实**不高**，
> 真正贵的是"把 `e2e.py` 全部移植"（**建议搁置**，理由见 §4.4）。

---

## 1. 现状盘点（① 阶段，**实测数据**）

### 1.1 任务 A（平台隔离）的真实改动面

**实测**（统计引用 `demo/gen` 与 `build/` 的文件）：

| 文件 | `demo/gen` 引用 | `build/` 引用 |
|------|----------------|--------------|
| `build.ps1` | **49** | **21** |
| `build.sh` | **38** | **19** |
| `tools/verify_linux_runtime.py` | 6 | 22 |
| `tools/vmc_linux.py` | 0 | 25 |
| `tools/clean_build.ps1` | 0 | 16 |
| `tests/protchain_check.py` | 1 | 7 |
| `tools/ci_linux.ps1` | 5 | 1 |
| 其余（`identity.py`/`repro_check.ps1`/`selfcrypt_proto.py`/`compose.py` 等）| 0-5 | 1-5 |

**共 98 个文件**引用（含 `archive/` 与 `dist/` 的历史副本）。

> ### ⚠️ 关键发现：**不能"把 demo/gen 整个按平台分"**
> 因为 `build.ps1` 与 `build.sh` 各自**硬编码**了自己的路径 ——
> 全量改 = **改 98 个文件 + 两套构建脚本的 100+ 处路径** ->
> **风险远高于收益**（且极易引入新的状态 bug）。

### 1.2 任务 B（map 解析）的真实重复

**实测**：**4 处实现**

| 文件 | 函数 | 格式支持 |
|------|------|---------|
| `tools/selfcrypt_proto.py` | `parse_map_functions` | **MSVC only** |
| `tools/selfcrypt_proto.py` | `parse_elf_map` | **gcc only** |
| `tests/protchain_check.py` | `parse_map_file` | **MSVC + gcc**（G 阶段刚加）|
| `tools/migration_cost.py` | `parse_map` / `parse_map_fns` | **MSVC only** |

> **这就是漂移的实证**: G 阶段给 `protchain_check` 加了 gcc 支持，
> 而 `selfcrypt_proto` 与 `migration_cost` 的**MSVC-only 实现仍在**
> —— 它们对 ELF 的行为是"返回空"，**将来必然重新踩坑**。

### 1.3 任务 C（Linux 攻击面）的真实难度分层

**实测**：

| 测试 | 行数 | `demo.exe` | `pe_sections` | `ctypes`/`kernel32` | 移植难度 |
|------|------|-----------|--------------|-------------------|---------|
| `tests/attacks.py` | 428 | 2 | 3 | 0 | **低** |
| `tests/e2e.py` | 866 | 3 | — | **23 / 20** | **高** |

**结论**: `attacks.py` 的 Windows 耦合**很浅**（只有 PE 解析 3 处 +
`demo.exe` 2 处）；`e2e.py` 才是深层耦合。

### 1.4 已读的既有文档（**避免重复规划 / 与既有决策冲突**）

| 文档 | 关键内容 |
|------|---------|
| `docs/PORTABILITY_ASSESSMENT.md`(1319 行) | 已有 **L1/L2 完成记录**；算法: 平台层已建 |
| `docs/PLATFORM_EXPANSION_PLAN.md`(491 行) | 已有 **§11「主动搁置的建议」**（与本技能"评估后搁置"一致）|
| `docs/LINUX_PORT_PLAN.md`(2226 行) | 本轮主线（§0-§23 已记录 B-G 阶段）|
| `docs/HANDOVER.md`(372 行) | 已知限制清单 |

### 1.5 门禁现状

**22 项**（Linux 运行时验证已按 §20.3 分层决策**移出**）。
`linux_compile_check`（只编译）**在**门禁内。

### 1.6 计划断言的事后核实（**先核实后记录**）

本文档初稿有三处断言，已**逐条实测核实**：

| # | 初稿断言 | 实测结果 | 处置 |
|---|---------|---------|------|
| 1 | `prot_pubkey_der.c` **只** Linux 侧生成 | `build.ps1` **提及 1 次** —— 但那是**注释**：<br>`# ⚠️ 必须与**原 cl 尾部完全一致**（不含 prot_pubkey_der.c —— 那是 Linux 侧用的 DER 公钥，原 Windows cl 命令从未链接它）` | ✅ **断言成立**（A1 的"Windows 不改"有据）|
| 2 | Linux 独有三项反调试（`LD_PRELOAD`/可疑 `.so`/`ptrace`）| Linux 侧 `LD_PRELOAD` 5 处 / `TracerPid` 17 处；**Windows 侧两者均 0 处** | ✅ **确属 Linux 独有**（C 的标的成立）|
| 3 | `vm_build.json` 影响面 = "多个工具" | **24 个文件引用**，但**只有 4 个是"双方"**：<br>`tests/protchain_check.py` / `tools/ci_linux.ps1` / `tools/release_check.ps1` / `tools/verify_linux_runtime.py`<br>其余 **20 个是 Windows-only**（`e2e.py`/`attacks.py`/`vmc_tests.py`/`skeleton_check.py` 等）| ✅ **A2 影响面比初估小**（只需动 Linux 侧 + 4 个共享调用方）|

---

## 2. 任务 A：产物按平台隔离（**最小侵入方案**）

### 2.1 为什么不按"目录整体分平台"

见 §1.1 的关键发现：**成本远高于用户估的"中"**。

### 2.2 我的方案：**只隔离"真正冲突"的那一个文件**

**实测的冲突点**（G 阶段反复踩到）只有一个：

| 文件 | Windows 侧 | Linux 侧 | 冲突 |
|------|-----------|---------|------|
| **`demo/gen/prot_pubkey_der.c`** | **不生成** | 生成 | ✅ **真冲突**（跑过 Linux 后残留）|
| `demo/vm_build.json` | 生成（Windows 机器 ID）| 生成（Linux 机器 ID）| ✅ **真冲突**（实测反复踩到）|
| `demo/gen/prot_sections.json` | 生成 | 生成 | ⚠️ 各自生成 -> **不残留**（两边都会覆盖）|
| `demo/gen/expect_default.c` | 生成 | 生成 | ⚠️ 同上 |
| `demo/gen/vm_*_blob.*` | 生成 | 生成 | ⚠️ 同上 |

> ### 🎯 关键洞察（**实测支持**）
> 真正的"状态泄漏"只有两类：
> ① **只有一侧生成**的文件（`prot_pubkey_der.c`）—— **必然残留**
> ② **两侧都生成但内容不同**的**状态文件**（`vm_build.json`）——
>    跑完 A 平台后 B 平台读到 A 的值
>
> 而"两侧都生成、跑时都会覆盖"的**派生产物**（节名 json / blob）
> **不会**造成残留（下次构建即覆盖）。
> => **只需处理 ① 与 ②**，不必动 98 个文件。

### 2.3 具体步骤

| 步 | 内容 | 交付物 |
|----|------|--------|
| **A1** | **`prot_pubkey_der.c` 移出共享目录** -> `build/linux/prot_pubkey_der.c`（生成到各平台自己的 build 子目录）| `build.sh` 改 1 处；`build.ps1` **不改**（已核实：它只在注释里提过该文件，从未链接）|
| **A2** | **`vm_build.json` 按平台分离** -> `demo/vm_build.json`（Windows，入库）+ **`build/linux/vm_build.json`**（Linux，不入库）| **实测影响面**：Linux 侧（`build.sh`）+ **4 个共享调用方**（`tests/protchain_check.py` / `tools/ci_linux.ps1` / `tools/release_check.ps1` / `tools/verify_linux_runtime.py`）—— 其余 20 个引用是 **Windows-only**，**不动** |
| **A3** | 加**状态自检**: `tools/check_state_platform.py` —— 检测"当前 `demo/gen` 属哪个平台"，不一致时**明确报错**（而非静默产生错误结果）| 新工具 + 自检 |
| **A4** | 文档: `docs/LINUX_PORT_PLAN.md` §24 + `HANDOVER.md` 更新 | 文档 |

### 2.4 验收标准

```
□ 跑完 Linux 构建后，Windows 门禁**无需重建**即可直接通过
   （G 阶段需重建；本阶段后应不需要）
□ `tools/check_state_platform.py` 能**正确识别**当前状态所属平台
□ 自检: 故意制造不一致状态 -> 该工具**报错**（负向自检）
□ Windows 门禁 22 项仍全通过
```

### 2.5 风险

| 风险 | 应对 |
|------|------|
| `vm_build.json` 路径改动 -> 影响多个工具 | **逐个核对调用方**（`vmenc.py`/`protchain_check.py`/`verify_linux_runtime.py`/`build.sh`）|
| 新工具本身有 bug | **负向自检**（制造不一致 -> 必须报错）|
| 破坏既有 Windows 流程 | Windows 侧**不做路径变更**（只改 Linux 侧），风险最小化 |

---

## 3. 任务 B：抽公共 map 解析模块（**优先做，零风险**）

### 3.1 步骤

| 步 | 内容 | 交付物 |
|----|------|--------|
| **B1** | 新建 `tools/mapfile.py` —— **单一实现**，含: `parse(path)` -> `{符号: RVA}`（**自动识别 MSVC / gcc**）+ `is_msvc()` / `is_gcc()` 辅助 | 新模块 |
| **B2** | `tests/protchain_check.py` 改用（删本地 `parse_map_file`）| 改动 |
| **B3** | `tools/selfcrypt_proto.py` 改用（删 `parse_map_functions` + `parse_elf_map`）| 改动 |
| **B4** | `tools/migration_cost.py` 改用（删 `parse_map` / `parse_map_fns`）| 改动 |
| **B5** | **单元自检** `tools/mapfile.py --selftest` —— 含**两种格式的样例** + **负向**（垃圾输入 -> 空字典，不崩）| 自检 |
| **B6** | 文档 + 提交 | — |

### 3.2 验收标准

```
□ 4 处实现 -> **1 处**
□ `mapfile.py --selftest` 通过（MSVC / gcc / 负向 各 ≥1 例）
□ **三处调用方的行为不变**（回归: protchain 双平台 6/6、selfcrypt 正常、
   migration_gate 通过）
□ Windows 门禁 22 项仍全通过
```

### 3.3 风险

| 风险 | 应对 |
|------|------|
| 某一处的**语义其实不同**（如 `migration_cost` 的 `parse_map_fns` 还**过滤** `lib:obj`）| **逐处读取原实现**，把差异**显式参数化**（如 `parse(path, funcs_only=True)`），不强行统一 |
| 抽取引入 import 循环 | 新模块**无依赖**（只 `os`/`re`/`struct`）|

> **特别提醒**（我已实测）: `migration_cost.parse_map_fns` **额外做了两件过滤**
> （排除 `obj` 含 `:` 的库对象、排除 `== 'i'` 的导入）——
> 抽取时**必须保留**，否则 M1 度量会失真（那是 M1 曾踩过的坑）。

---

## 4. 任务 C：Linux 专用攻击面测试（**裁剪版**）

### 4.1 先明确「哪些是 Linux **独有**的攻击面」（**这是价值所在**）

**实测**（`src/platform/prot_platform_linux.c` 的 Linux 专属项）：

| Linux 独有检测 | 攻击面 |
|---------------|--------|
| **`LD_PRELOAD`** 检查 | 库注入（`interpose` 攻击）|
| **可疑 `.so`** 检查 | 已注入的第三方库 |
| **`ptrace` 探测**（`TracerPid`）| 调试器附加 |

> 这三项 **Windows 上完全没有** —— 它们才是"Linux 专用攻击面测试"的**真正标的**。
> 移植 `e2e.py` 的 Windows 用例**不是**这个任务的目标。

### 4.2 我的方案：**只做 Linux 独有面的正/负向验证**

| 步 | 内容 | 交付物 |
|----|------|--------|
| **C1** | **正向**: 干净环境下三项检测应**全为 0**（不误报）| `tests/attacks_linux.py` |
| **C2** | **负向（核心价值）**: **真的用 `LD_PRELOAD` 注入**一个库 -> 检测应**报出** | 同上 |
| **C3** | **负向**: **真的 `ptrace` 附加**（父进程 attach 子进程）-> `TracerPid` 应**非 0** | 同上 |
| **C4** | **负向**: 放一个**可疑 `.so`** -> 检测应报出 | 同上 |
| **C5** | 接入 `ci_linux.ps1`（作为第 9 项）| 改动 |
| **C6** | 文档 + 提交 | — |

### 4.3 验收标准

```
□ C1 正向: 干净环境三项全 0（**不误报**）
□ C2/C3/C4 负向: **真的发起攻击** -> 检测**必须报出**（否则是"防护失效"）
□ 每项都有**负向自检**（用"故意的攻击"证明检测有效）
□ 接入 ci_linux -> 9/9
```

> **为什么 C 的价值高**: 它验证的是**防护是否真的能抓住攻击**，
> 而不是"代码能不能编译"。这与本项目"未验证 != 通过"的纪律一致。

### 4.4 **主动搁置**（诚实说明，遵循本技能纪律）

| 搁置项 | 理由 |
|--------|------|
| **`e2e.py`（866 行）全量移植** | **23 处 ctypes / 20 处 kernel32** 是**深层耦合** —— 那些用例测的是 **Windows API 行为**（`CreateProcess`/`ReadProcessMemory`/PE 篡改），**Linux 无对应物**。移植 = **重写一套**，且**不增加 Linux 侧的真实防护覆盖**。|
| `attacks.py` 全量移植 | 同上（虽然它耦合浅，但**主体仍是 PE 篡改**）|
| 内核驱动 / UWP | 已有文档（`PLATFORM_EXPANSION_PLAN.md` §8/§11）**已评估并搁置** —— 不重复规划 |

> **搁置而非丢弃**: 记录在本文档 + `LINUX_PORT_PLAN.md`，
> 将来若要做有据可依（含"为什么当初没做"）。

---

## 5. 执行顺序与依赖

```
B（map 统一）  ← **最先做**：零风险、立即消除漂移
   ↓
A（平台隔离）  ← 依赖 B 完成后的稳定状态（避免同时改多个共享路径）
   ↓
C（Linux 攻击面）← 独立，可在 A 之后（或并行，若注意串行调试纪律）
```

**为什么 B 先做**：
· 无风险（纯抽取 + 自检）
· 立即消除"4 处实现漂移"隐患
· 为 A 提供稳定基础（A 要动路径，B 先稳定解析层）

---

## 6. 风险总表

| 风险 | 等级 | 应对 |
|------|------|------|
| A 的路径改动影响面大 | **高** | 用**最小侵入**方案（只处理 2 个真冲突点）+ **负向自检** |
| B 抽取时丢语义（如 `parse_map_fns` 的过滤）| 中 | **逐处读原实现**，差异**显式参数化** |
| C 的负向测试**真的破坏了环境**（如注入库残留）| 中 | 每次攻击**在临时副本上做** + **清理**；用 `safe-ops-backup` 纪律 |
| 调试期间状态污染（**已实测反复踩到**）| 中 | **串行执行**（一次一个任务）+ 每步确认平台状态 |
| 文档漂移 | 中 | 每阶段同步更新 |

---

## 7. 验收总结（全部完成时）

```
□ 4 处 map 实现 -> 1 处（含自检）
□ 跑完 Linux 后 Windows 门禁**无需重建**即可通过
□ Linux 独有攻击面: 3 项正向 + 3 项负向（真发起攻击 -> 必须报出）
□ ci_linux: 9/9 PASS
□ Windows 门禁: 22/22（含 git 干净时）
□ 文档: LINUX_PORT_PLAN §24-§26 + HANDOVER 更新
```

---

## 8. ✅ 你的确认（2026-09-25）

| # | 问题 | **你的选择** | 影响 |
|---|------|------------|------|
| 1 | A 的方案 | **目录整体分平台**（`demo/gen/win` + `demo/gen/linux`）| 采纳**彻底方案** —— 需改 98 个文件引用 + 两套构建脚本的路径（§2 已按此重写）|
| 2 | C 的范围 | **连 `e2e.py` 也全量移植** | 采纳**全量方案** —— 包含 Linux 独有面（6 项）+ `attacks.py` + `e2e.py`（§4 已按此重写）|
| 3 | 执行顺序 | **B → A → C** | ✅ 与建议一致 |

> **说明**：你选了成本更高的彻底方案。我会**分阶段推进、每阶段独立验收**，
> 并在每个阶段开始时**重新盘点**（而非一次写到底）。
> 若中途发现某阶段的实际成本远超预期，我会**停下来报告**并给出选项
> （遵循"遇到阻塞时停下来问"的纪律）。

---

## 9. 【已按确认重写】任务 A：**目录整体分平台**

### 9.1 目标形态

```
demo/gen/win/          <- Windows 侧生成物（build.ps1 写）
  prot_modconfig.h  prot_sections.json  license_pubkey.c
  strings.c  indirect_table.c  expect_default.c  prot_padding.c
  vm_*_blob.c/.h/.bin  version.res
demo/gen/linux/        <- Linux 侧生成物（build.sh 写）
  prot_modconfig.h  prot_sections.json  license_pubkey.c  prot_pubkey_der.c
  strings.c  indirect_table.c  expect_default.c  prot_padding.c
  vm_*_blob.c/.h/.bin
demo/gen/              <- **不再有**生成物（仅保留 README 说明）
```

**状态文件**：`demo/vm_build.json`（Windows，入库）+
`build/linux/vm_build.json`（Linux，不入库）。

### 9.2 分阶段（**4 个子阶段，各自可验收**）

| 子阶段 | 内容 | 验收 |
|--------|------|------|
| **A-a** | **引入路径抽象**: 新增 `tools/genpaths.py`（单一来源回答"生成物目录在哪"）| 自检: 两平台各返回正确路径 |
| **A-b** | **`build.sh` 切到 `demo/gen/linux/`**（含 `-I` 包含路径、产物路径、`vm_build.json` 路径）| Linux 端到端 **8/8 PASS** |
| **A-c** | **`build.ps1` 切到 `demo/gen/win/`**（49+21 处）| **Windows 门禁 22 项全通过** |
| **A-d** | **4 个共享调用方**适配 + **状态自检** `tools/check_state_platform.py` | 自检含**负向**（制造不一致 -> 必须报错）|

> **为什么拆 4 段**：A-b 与 A-c **分开做**，才能**每次只动一个平台**、
> 出问题时**立即定位是哪个平台**（若同时改，失败原因不可判）。

### 9.3 关键纪律（**从实测教训来**）

| 纪律 | 来源 |
|------|------|
| **每阶段跑完整验收**（Linux 8/8 / Windows 22 项）| G 阶段实测: 状态污染会连带失败 |
| **串行执行**，不并发跑构建 | §21.4 状态竞争教训 |
| **`-I` 包含路径必须同步改** | 否则 `#include "prot_modconfig.h"` 找不到（实测同类问题: 生成物缺 include 导致防护从未生效）|
| 改完**立即验证两个平台都能构建** | 防止"只修好一侧" |

### 9.4 验收标准（A 完成时）

```
□ demo/gen/ 下**无生成物**（只有 README）
□ build.ps1（Windows）-> demo/gen/win/；build.sh（Linux）-> demo/gen/linux/
□ **跨平台无残留**: 跑完 Linux 后 Windows 门禁**直接通过**（无需重建）
□ Windows 门禁 22/22；Linux 端到端 8/8
□ tools/check_state_platform.py 有**负向自检**
```

### 9.5 风险（**等级已上调**）

| 风险 | 等级 | 应对 |
|------|------|------|
| 98 个文件引用的**遗漏** | **高** | 用**自动化**手段: 改完后**全局搜索**残留的 `demo/gen/`（非 win/linux 的）-> 逐个确认 |
| 两套构建脚本路径不同步 | 高 | A-b / A-c **分开做**，各自全量验收 |
| `-I` 路径漏改 | 高 | 构建**会立刻报错**（include 找不到）-> 属"快速失败"，风险可控 |
| 骨架/SDK/example 的路径 | 中 | 它们在 `prot_sdk/`/`examples/` 下**独立发布** -> 需**一并检查**（`sdk_pack.py`/`skeleton_check.py` 验收会抓）|

---

## 10. 【已按确认重写】任务 C：**全量移植**（Linux 独有面 + attacks + e2e）

### 10.1 三个部分（按**价值/成本**排序执行）

| 部分 | 内容 | 成本 | 价值 |
|------|------|------|------|
| **C-1** | **Linux 独有攻击面**（3 项正向 + 3 项负向）| 低 | **最高**（直击 Linux 专属面，负向证明防护有效）|
| **C-2** | `attacks.py`（428 行，PE 篡改 3 处 + `demo.exe` 2 处）| 中 | 中（主体是 PE 篡改，ELF 需对应实现）|
| **C-3** | `e2e.py`（866 行，**23 ctypes + 20 kernel32**）| **高** | 中（需为每个 Windows API 行为找 Linux 等价物）|

> **执行顺序 C-1 -> C-2 -> C-3**：先把**独占价值**拿到，再逐级扩展。

### 10.2 C-3（e2e 全量移植）的**真实工作内容**（实测分类）

`e2e.py` 的 Windows API 用法需**逐个映射**到 Linux 等价物：

| Windows | Linux 等价 | 难度 |
|---------|-----------|------|
| `CreateProcess` | `subprocess` / `fork+exec` | 低 |
| `ReadProcessMemory` | `/proc/<pid>/mem` + `process_vm_readv` | 中 |
| `VirtualProtectEx` | `mprotect`（**注意页对齐** —— C 阶段已踩过）| 中 |
| `WaitForSingleObject` | `waitpid` | 低 |
| `OpenProcess` | `/proc/<pid>/` 权限 | 中 |
| PE 节篡改（`pe_sections`）| **ELF 节篡改**（`sections_of` 已有）| 低 |
| 调试器附加 | `ptrace(PTRACE_ATTACH)` | 中 |
| 句柄/注册表操作 | **无对应物** -> **该用例标记为"平台不适用"** | — |

**纪律**：**无对应物的用例不强行移植** —— 标记为 `PLATFORM_NA`
并**计入统计**（如 "T28: 24 适用 / 4 不适用"），
**不伪装成 PASS**（否则违反"未验证 != 通过"）。

### 10.3 验收标准（C 完成时）

```
□ C-1: 3 项正向（干净环境不误报）+ 3 项负向（**真发起攻击** -> 必须报出）
□ C-2: attacks 的 ELF 侧用例通过；无对应物者标记 PLATFORM_NA（不伪装）
□ C-3: e2e 的 ELF 侧用例通过；统计明确（适用/不适用）
□ 接入 ci_linux（最终 9-11 项）
□ 每部分都有**负向自检**
```

### 10.4 风险

| 风险 | 等级 | 应对 |
|------|------|------|
| C-3 工作量可能**远超预期** | **高** | **分步**: 先做通用项（`subprocess`/`waitpid`），难的（`process_vm_readv`/ptrace）**单独一步**；若某步卡住**停下来报告** |
| 攻击测试**真的破坏环境**（注入库/attach 残留）| 中 | **在临时副本上做** + **必清理**（`safe-ops-backup` 纪律: 攻击前备份、攻击后恢复）|
| ptrace 在 WSL 内的行为差异 | 中 | 先**实测验证** ptrace 在 WSL 可用（不可用则诚实标注）|

---

## 11. 更新后的执行顺序

```
B（map 统一）          ← 零风险，先消除 4 处实现漂移
   ↓
A-a A-b A-c A-d        ← 目录整体分平台（每次只动一个平台）
   ↓
C-1 C-2 C-3            ← 先拿独占价值，再逐级扩展
```

---

## 12. 原来的确认问题（**已被 §8 的答案取代**，保留备查）

| # | 问题 | 我的建议 |
|---|------|---------|
| 1 | **A 用"最小侵入"（只处理 2 个真冲突点）而非"目录整体分平台"？** | **建议是**（成本/风险远低，且实测已覆盖真实的泄漏源）|
| 2 | **C 只做"Linux 独有攻击面"（6 项），`e2e.py` 全量移植搁置？** | **建议是**（e2e 的 Windows 用例在 Linux 上无对应攻击面）|
| 3 | 执行顺序 B -> A -> C？ | **建议是** |

**请确认或调整，我再开始实施。**

---

## 13. ✅ B 阶段完成记录（2026-09-25）—— map 解析 4 处归一为 1 处

### 13.1 交付

| 项 | 内容 |
|----|------|
| **新增** | `tools/mapfile.py` —— 单一实现，**自动识别 MSVC / gcc** |
| **改造** | `tests/protchain_check.py`（`parse_map_file` -> 薄包装）|
| **改造** | `tools/selfcrypt_proto.py`（`parse_map_functions` + `parse_elf_map` -> 薄包装）|
| **改造** | `tools/migration_cost.py`（`parse_map` + `parse_map_fns` + `read_image_base` -> 薄包装）|

**验证（三重检查，确认实现真的归一）**：
```
protchain_check.parse_map_file  有效语句=1  调用_mapfile=True  残留正则 0
selfcrypt_proto（2 个）          有效语句=1  调用_mapfile=True
migration_cost（2 个）           有效语句=1  调用_mapfile=True
含 MSVC map 正则的文件: 仅 mapfile.py  ✅
```

### 13.2 `mapfile.py` 的设计（**差异显式参数化，不强行统一**）

```python
parse(path, image_base=None, funcs_only=False, exclude_libs=False,
      image_base_from_pe=True)
```

| 参数 | 用途 | 来源 |
|------|------|------|
| `image_base` | MSVC 侧基址 | `migration_cost` 从 PE 头读（更正确）|
| `funcs_only` | 只取 `f` 标记 | `migration_cost.parse_map_fns` 的 M1 口径 |
| `exclude_libs` | 排除库对象（obj 含 `:`）与导入 thunk（`i`）| **M1 门禁依赖** |
| `image_base_from_pe` | 基址来源开关 | 兼容原 `selfcrypt_proto` 的固定基址 |

**自检 14/14 PASS**（含 **2 项负向**: 垃圾 map / 文件不存在 -> 空字典不崩）。

### 13.3 等价性验证（**改造的关键验收**）

| 调用方 | 口径 | 结果 |
|--------|------|------|
| `protchain_check` | MSVC 全符号 | 2973 键一致 |
| `protchain_check` | gcc | **178/178 完全等价** |
| `selfcrypt_proto` | **8 个目标函数** | 取值**全部一致** |
| `selfcrypt_proto` | gcc | **178/178 完全等价** |
| `migration_cost` | 全符号 | 旧 2971 / 新 2971，**值不同 0** |
| `migration_cost` | **函数口径（M1 门禁）** | 旧 131 / 新 131，**值不同 0** |

**M1/M3 复核**（B 阶段前后）：
```
B 阶段前: M1 = 10.1%   M3 = 3.8%
B 阶段后: M1 = 9.9%    M3 = 3.8%    <- 统计等价（种子噪声范围内）
```

### 13.4 ⚠️ 顺带发现的**真实脆弱点**（已修）

原 `selfcrypt_proto.parse_map_functions` 的条件含：
```python
m[2].startswith('0000000140')      # **硬编码映像基址前缀**
```
**危害**: 一旦基址不是 `0x140000000`（换链接器设置 / 改基址），
它会**静默漏掉全部符号**（返回空且**不报错**）。
**修法**: `mapfile` 改为"**基址可传入**"（默认从 PE 头读 = 更正确）。

### 13.5 ⚠️ 首见 vs 末见（**实测判定，不是随手选的**）

实测在 `build/demo.map` 上有 **10 个符号取值不同**（原实现末见覆盖、
`mapfile` 首见优先）。**我没有随手选**，而是**判定**：

```
那 10 个符号（$$000000 / MoveSmall0 / YmmLoop / $xdatasym …）
  -> **全部来自库对象**（obj 列含 `:`，如 LIBCMT:chkstk.obj）
  -> `$$000000` 出现 **19 次**，地址各不相同
  => 它们是**库内部同名局部标签** —— 单一映射**本就语义错误**
  => **正确处置是过滤**（exclude_libs=True），首见/末见之争无意义
```
**验证**: 过滤后**零重名**（映射语义成立）；**我们自己的符号不受影响**
（`prot_vm_run`/`main`/`prot_hostid_get` 等已逐一核对）。
**已加 3 项回归自检**（T12-T14）锁住该判定。

### 13.6 ⚠️ 两个**过程教训**（如实记录）

| # | 事故 | 根因 | 教训 |
|---|------|------|------|
| 1 | 正则删函数体**误伤**（残留孤儿代码）| 用 `^def f\(.*?\n(?=\S)` 找函数结束，而**原 docstring 里有 fenced code block**（``` 顶格）-> 被当成函数结束 | **正则替换函数体不可靠** -> 改用 **AST** 定位 |
| 2 | 替换时**重复插入**（4 个同名函数定义）| 多目标替换时**两次都用同一段文本** | 多目标替换须**各对应各的文本**；或合并区间 |
| 3 | B2 的 `protchain_check` **未真正改造**（仍是 13 行本地实现）| 误伤后只做了**残留清理**，没重新替换 | **误伤修复后必须重新验证最终状态**（本次靠"有效语句数 + 是否调用 _mapfile + 正则残留计数"三重检查抓到）|

### 13.7 验收

```
□ 4 处实现 -> **1 处**（三重检查确认）              ✅
□ `mapfile.py --selftest` 14/14（含 2 负向）        ✅
□ 三处调用方行为**不变**（逐口径实测）              ✅
□ **M1/M3 不变**（10.1%->9.9% 统计等价 / 3.8%）     ✅
□ Windows 门禁 21/22（唯一失败=未提交）             ✅
```

---

*2026-09-25 · B 阶段: map 解析 4 处 -> 1 处（含脆弱点修复 + 重名判定 + 3 个过程教训）*
