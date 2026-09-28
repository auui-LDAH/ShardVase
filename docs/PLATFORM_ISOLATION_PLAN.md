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

---

## 14. ✅ A-a 完成记录：路径抽象 `tools/genpaths.py`（2026-09-25）

### 14.1 设计依据（**先盘点，再设计**）

动手前先盘点了"**路径抽象到底要回答哪些问题**"（避免设计出"整洁但没人用"的模块）：

**① `demo/gen` 的路径形态**（build.ps1 + build.sh 合计）：
```
<目录>           14 次
expect_default.c  7 次     indirect_table.c  7 次
strings.c         6 次     license_pubkey.c  4 次
prot_sections.json 4 次    prot_modconfig.h  4 次
prot_padding.c    4 次     prot_pubkey_der.c 4 次
vm_*_blob.bin     各 3 次  vm_*_blob.c/.h    各 1 次
version.res       2 次
```

**② 按用途分类**：
| 类别 | 引用数 |
|------|-------|
| C 源（编译输入）| **42** |
| BIN（打包输入）| 12 |
| 头文件（`-I` 包含）| 10 |
| JSON（工具间数据）| 4 |
| 资源 | 2 |

**③ `build/` 下的形态**（关键发现）：
```
build/vmc_linux  25 次    build/demo.exe      14 次
build/keys       13 次    build/vm.blob       12 次
build/demo_linux 10 次    build/license.txt    8 次
...
```

> ### 🎯 关键洞察（**决定了设计范围**）
> `build/` 下的东西**本来就已按平台区分文件名**
> （`build/demo.exe` vs `build/demo_linux`）—— **不冲突**。
> **真正冲突的只有 `demo/gen/`（共享目录）** + 状态文件 `vm_build.json`。
> => `genpaths.py` **只负责这两类**，**不做大包大揽**
>    （过度抽象会引入无谓的间接层）。

### 14.2 交付: `tools/genpaths.py`

**接口**：
```python
paths(platform=None, layout=None, repo=None) -> GenPaths
```
| 成员 | 说明 |
|------|------|
| `.gen` | 生成物目录（`demo/gen/win` 或 `demo/gen/linux`）|
| `.vm_build_json` | 状态文件（Windows: `demo/vm_build.json`；Linux: `build/linux/vm_build.json`）|
| `.g('strings.c')` | 便捷拼路径（**避免调用方各自拼**）|
| `.as_dict()` | 供构建脚本诊断输出 |

**两种布局**（迁移期兼容）：
| 布局 | `gen` | 用途 |
|------|-------|------|
| `split`（默认）| `demo/gen/<platform>` | **目标形态** |
| `flat` | `demo/gen` | **迁移期回退**（`PROT_GEN_LAYOUT=flat`）|

**设计原则**：
① **显式平台参数**（不依赖环境猜测）—— 构建脚本**必须**明确自己在为哪个平台构建（否则"猜错平台"这类 bug 无法定位）
② `default_platform()` **仅作兜底**（已注明：推断会掩盖"在错误平台构建"）
③ 返回**不可变结构**（便于打印/比对/自检）

**自检 13/13 PASS**（含 **2 项负向**：
非法平台 / 非法布局 -> **抛异常**而非静默用错误路径）。

### 14.3 验收

```
□ genpaths.py --selftest **13/13 PASS**（含 2 负向）      ✅
□ 实际路径查询正确（win/linux/flat 三种）                ✅
□ **门禁 21/22**（唯一失败=未提交）—— **零影响**         ✅
   （A-a 只新增文件，不改变任何既有行为）
```

### 14.4 为什么 A-a 只做"抽象"而不改调用方

**分阶段的价值**: A-a **纯新增、零行为改变** ->
· 门禁全绿，证明"抽象层本身正确"
· 下一步 A-b（`build.sh` 切到 linux 目录）若出问题，
  **可以确定是 A-b 引入的**，而非抽象层

> 这遵循计划 §9.2 的纪律: **每次只动一个变量**。

---

*2026-09-25 · A-a: 路径抽象（盘点驱动设计，只覆盖真冲突的两类路径）*

---

## 15. ✅ A-b 完成记录：`build.sh` 切到 `demo/gen/linux/`（2026-09-25）

### 15.1 交付

| 项 | 内容 |
|----|------|
| **新增** | `build.sh` 顶部 `GEN` / `VM_JSON` / `VM_JSON_PATH` / `GEN_PATH`（值由 `tools/genpaths.py` 给出）|
| **路径统一** | 33 处 `demo/gen` 引用 -> `"$GEN"`（含 `-I` 包含路径、生成/读取、mkdir）|
| **状态文件** | 9 处 `demo/vm_build.json` -> `"$VM_JSON"`（Linux: `build/linux/vm_build.json`）|
| **布局回退** | `PROT_GEN_LAYOUT=flat` -> genpaths 返回旧 `demo/gen`，**本脚本零改动回退** |

**核心设计**：路径**只在一处决定**（`genpaths.py`）—— 将来改布局只改一处。

### 15.2 验收

```
端到端构建: **DONE**（8 步生成链 + 24 文件编译 + selfcrypt + 烧录 + 填充）
产物: build/demo_linux 103424 字节 / ELF ✅
生成物落点: demo/gen/linux/  ✅（实测输出路径确认）
```

### 15.3 ⚠️ 六个**实测踩坑**（都是 shell/路径的真实陷阱）

| # | 坑 | 根因 | 修法 |
|---|----|------|------|
| 1 | `bad escape (end of pattern)` | 用 `re.subn` 时**替换串以 `\` 结尾** -> 被当转义序列 | 改 `str.replace`（**字面替换**）|
| 2 | `NameError: VM_JSON_PATH` | **quoted heredoc**（`<<'PYEOF'`）**不展开** shell 变量 -> 需 env 传递 | `export` + `os.environ[...]` |
| 3 | **引号嵌套**（`open('_g('x')', 'w')`）| 在**带引号的表达式**上做字符串替换 -> 引号层级被破坏 | **整体重写**该 heredoc（不再零敲碎打）|
| 4 | **顺序矛盾**：`prot_padding.c` 缺失 | 它由**步骤 4.2 生成**，却在**步骤 3 被要求存在** | 移出前置必需列表；生成后强校验 |
| 5 | 路径被**词分割**（`-I /mnt/d/specifically` + `for` + …）| `CFLAGS="$CFLAGS -I $GEN"` **字符串拼接** -> 展开时词分割（**路径含空格**）| `CFLAGS` 改**数组** |
| 6 | 子 shell 拿不到 `CFLAGS` | **bash 数组无法 export** 给 `bash -c` | **函数内字面参数** + `export` 标量 |

> ### 🎯 本次核心教训：**路径含空格 + quoted heredoc 是本项目的双重陷阱**
> 本仓库路径是 `…/Reverse Engineering`（**含空格**）——
> · shell 里**引号必须包住完整路径**（`"$GEN/x"` 而非 `"$GEN"/x`）
> · 需要传参的场景用**数组**或**函数内字面量**，不能依赖字符串变量
> · **quoted heredoc 内不能出现任何 shell 变量**（改用 env）

> ### 🎯 副产物：**平台隔离暴露了一个隐式依赖缺陷**
> 坑 4（`prot_padding.c` 顺序矛盾）在**旧 flat 布局下无法暴露** ——
> 因为那时它是 **Windows 侧遗留文件**，"恰好"通过检查。
> 切到全新空目录 `demo/gen/linux/` 后**立刻暴露**。
> => **这正是平台隔离的价值**: 让"依赖旧产物"的隐式假设浮出水面。

### 15.4 遗留（**A-d 的内容，已实测确认**）

ci_linux 从 8/8 变为 **6/8**，两处失败**根因相同**：

| 失败项 | 根因 |
|--------|------|
| `protchain` P1-P6（4 PASS / 2 FAIL）| `protchain_check.py` 读 `demo/gen/prot_sections.json`（**旧 flat 路径**）|
| 节名随机化 | `verify_linux_runtime.py` 读 `demo/gen/prot_sections.json`（**同上**）|

**这正是 A-d 的工作内容**（4 个共享调用方适配）——
A-b 完成"生产侧"，A-d 完成"消费侧"，**中途验收必然失败**（属预期）。

---

*2026-09-25 · A-b: build.sh 切到 demo/gen/linux（33 处路径统一 + 6 个 shell 陷阱）*

---

## 16. ✅ A-c / A-d 完成记录（2026-09-25）—— **平台隔离落地**

### 16.1 A-c: `build.ps1` 切到 `demo/gen/win/`

| 项 | 内容 |
|----|------|
| **新增** | `$genDir` / `$vmJson`（值由 `tools/genpaths.py --platform win`）|
| **路径统一** | 37 行替换（`demo\gen` -> `${genDir}`；`demo\vm_build.json` -> `${vmJson}`）|
| **单引号场景** | 28 处 -> `(Join-Path $genDir 'x')`（**PowerShell 单引号不插值**）|
| **命令串场景** | 4 处 -> `` `"${genDir}`" ``（**内联字面**必须转义）|

**验收**: Windows 构建 **DONE** + **门禁 21/22**（唯一失败=未提交）。

### 16.2 A-d: 消费侧适配（3 个 Python 工具）

| 文件 | 改动 |
|------|------|
| `tests/protchain_check.py` | `resolve_gen_paths(exe)` —— **按产物格式**判定平台（ELF/PE）|
| `tools/verify_linux_runtime.py` | `gen_dir()` / `vm_build_json()`（固定 linux）|
| `tools/vmc_linux.py` | `vm_build_json()`（固定 linux）|

**验收**: `ci_linux` **8/8 PASS**。

### 16.3 🎯 **关键洞察：相对路径从根上消除引号问题**

**过程**（我在引号形态上花了 6 轮，最后**换方向**才解决）:

| 尝试 | 结果 |
|------|------|
| 内层普通 `"` | 失败（`C1083` / `LNK1181`）|
| 内层 `` `" `` | 失败 |
| 内层 `\"` | 失败 |
| **实测确定形态**（4 次实验）| 得到"内联用 `` `" `` / 变量值用 `"`"的结论 |
| **按结论修正** | **仍失败**（`LNK1181`）|
| **加调试输出** | **找到真因**: 传给 compose 的是**绝对路径**（含空格 `Reverse Engineering`）|

> ### 真因与修法
> **根因不是引号形态，而是"传了含空格的绝对路径"**。
> `build.ps1` 在**仓库根**执行 -> 用**相对路径** `demo/gen/win`
> -> **根本没有空格** -> 所有引号/拆词问题**一并消失**。
>
> **教训**: 当"修 A 无效、修 B 无效、修 C 也无效"时，
> **应加诊断输出找真因**，而非继续在同一个方向试错。
> （本次靠 `Write-Host` 打印 `$compSrcJoined` 的值才定位到
>   `"D:\specifically for development and work\Reverse Engineering\..."` ——
>   一眼看出是**绝对路径**问题。）

**实现**: `genpaths.py` 新增 `--print-gen-rel`（相对仓库根，**无空格**）。

### 16.4 ⚠️ 本轮踩坑汇总（**7 个，都有记录价值**）

| # | 坑 | 根因 | 教训 |
|---|----|------|------|
| 1 | `re.subn` 替换串尾 `\` -> `bad escape` | 正则替换串有转义语义 | 用**字面替换** |
| 2 | **全局空格规整破坏 770 行** | `re.sub(r'  +', ' ')` 作用于整文件 | **绝不对整文件做通用空白规整** |
| 3 | `$genDir` 定义早于 `$py` | 插入位置未核对依赖顺序 | 变量定义要**核对前置依赖** |
| 4 | `'${genDir}'` 单引号不插值 | PowerShell 语义 | 用 `Join-Path` |
| 5 | `cmd /c` 内层引号被消耗 | 三层引号传递 | **实测**确定形态（4 次实验）|
| 6 | **`load_section_names` 静默降级**（**真实缺陷**）| `encoding='ascii'` 读含中文的 JSON -> `UnicodeDecodeError` 被吞 -> 回退固定节名 | 编码改 **utf-8** + **不静默** |
| 7 | P6 只参数化一半 | `json_path` 改了、`exp_path` 仍硬编码 | **参数化要彻底**（检查所有同类路径）|

> **坑 6 值得强调**: 文件**存在且完全正确**，却因**编码假设错**被判"读不到"，
> 然后**静默**用回退值 -> 与"未验证 != 通过"的纪律**直接冲突**。
> 已修为"打印警告 + 正确编码"。

### 16.5 A 阶段完成度

| 子阶段 | 状态 | 验收 |
|--------|------|------|
| **A-a** 路径抽象 | ✅ | 自检 13/13 |
| **A-b** `build.sh` | ✅ | 端到端 DONE |
| **A-c** `build.ps1` | ✅ | 构建 DONE + 门禁 21/22 |
| **A-d** 消费侧 | ✅ | ci_linux 8/8 |

**核心成果**:
```
demo/gen/win/      <- Windows 生成物（build.ps1 写）
demo/gen/linux/    <- Linux 生成物（build.sh 写）
```
**两平台产物彻底隔离** —— 跑完任一侧**不再需要重建**另一侧。

### 16.6 诚实边界

| 边界 | 说明 |
|------|------|
| **`build.sh` 仍用绝对路径** | 实测 Linux 侧（bash）无此问题（A-b 已验证 DONE）；但**未改成相对路径**（可后续统一）|
| `demo/gen/` 空目录残留 | 旧文件仍在（未删除）—— 不影响正确性，**建议后续清理** |
| 其他消费方（`examples/`、`prot_sdk/`）| `build_example.ps1` 等**13 处**引用 `demo/gen`，**未适配**（它们有**独立发布**需求，属另一范畴）|

---

*2026-09-25 · A-c/A-d: 平台隔离落地（相对路径从根上消除引号问题 + 7 个踩坑记录）*

---

## 17. ✅ A 阶段**最终完成**（2026-09-25）—— 隔离判据通过

### 17.1 核心判据（**A 阶段存在的唯一理由**）

计划文档 §2.4 / §9.4 定义：
> 「跑完 Linux 构建后，Windows 门禁**无需重建**即可直接通过」

**实测结果**：
```
① Windows 构建: DONE
② Linux 构建:   DONE（改 demo/gen/linux + build/linux）
③ **不重建**直接跑 Windows 门禁:
   失败项（除 git）: **0**  ✅
   → **平台隔离生效**
```

### 17.2 🎯 方法突破：**快照法**定位泄漏（而不是逐项猜）

**问题**：隔离判据第一轮仍失败 2 项（`e2e` / `mutate_check`），
但"逐项读代码找残留依赖"效率低且**不完整**。

**改用快照法**（决定性）：
```python
① 跑 Windows 构建  -> 快照所有 build/ 与 demo/ 文件的 (mtime, size)
② 跑 Linux 构建
③ 再快照 -> **diff** 出被改动的文件
   => 过滤掉 build/linux 与 demo/gen/linux 内的（预期内）
   => 剩下的就是**泄漏清单**
```

**首次结果（4 个泄漏）**：
```
build/_composition_srcs.txt     666 B   <- 两平台都写
build/section_baseline.json    1419 B   <- 两平台都写（归一化基线）
build/demo_linux / .map                 <- 平台专属产物（预期）
```

**修复后**：
```
非 linux 目录的改动: **2 个**（仅 build/demo_linux 与 .map —— **预期内**）
```

> ### 🎯 教训（**通用方法**）
> 找"状态泄漏 / 跨模块污染"时，**快照 diff 比读代码可靠** ——
> 它**不依赖"我是否想到了某个路径"**（读代码只能发现我已经想到的）。
> 这与 B 阶段的"穷举"、G 阶段的"四路交叉验证"是**同一类方法论改进**。

### 17.3 ⚠️ 顺带发现的**真实缺口**：`measure_sections.py` 是 PE-only

**现象**：修完泄漏后 Linux 构建**失败**：
```
FileNotFoundError: build/linux/section_actual.json
```

**根因**：
```
measure_sections.py 的 read() 只认 PE —— 对 ELF 按 PE 头解析
-> struct.unpack_from('<H', d, e+6) 越界
```

**关键洞察（**这是个长期潜伏的真实缺陷**）**：
> `build.sh` 里该步骤用 `|| warn`（**吞掉失败**）——
> 所以 **A-b 接线以来它一直失败**，而 `section_actual.json` 从未生成
> -> `merge_baseline` / `gen_padding` 连锁失败
> -> **填充（第二支柱）在 Linux 上从未生效**。
>
> => **"被 warn 吞掉的失败"会长期潜伏** —— 与"静默降级"同类。
> 本次因"泄漏修复后 die 变严格"才暴露（顺序矛盾的修复把它顶到前台）。

**修法**: 加 ELF 分支（`--- 识别 magic -> _read_elf / _read_pe`）。

**验收**：
```
measure_sections: build/demo_linux -> build/linux/section_actual.json
                  （103392 字节, **35 节**）
```
=> **Linux 侧填充第一次真正生效**。

### 17.4 本轮完整改动（A-d 补完部分）

| 项 | 内容 |
|----|------|
| `genpaths` | + `build_dir`（win: `build/`；linux: `build/linux/`）+ `b()` + `--print-build-dir` + T14-T17 自检（**17/17**）|
| `build.sh` | + `$BDIR`；`vm.blob`/`license.txt`/`selfcrypt_mask.txt`/`_composition_srcs.txt`/`section_baseline.json`/`section_actual.json` 全部按平台分 |
| `build.ps1` | + `$buildDir`；同上（源清单/基线/实际） |
| `verify_linux_runtime` | + `build_dir()`/`build_dir_wsl()`；7 处路径 + 格式化参数 |
| `protchain_check` | + `_platform()`；`--blob` 与 **mask 路径**按平台分 |
| `measure_sections` | **+ ELF 分支**（真实缺口修复） |

### 17.5 A 阶段总完成度

| 子阶段 | 状态 | 验收 |
|--------|------|------|
| A-a 路径抽象 | ✅ | 17/17 自检 |
| A-b `build.sh` | ✅ | 端到端 DONE |
| A-c `build.ps1` | ✅ | 构建 DONE |
| A-d 消费侧 + 状态文件隔离 | ✅ | ci_linux **8/8** |
| **隔离判据** | ✅ | **跑完 Linux 后 Windows 门禁 0 失败** |

**最终产物布局**：
```
demo/gen/win/         demo/gen/linux/
build/（win 状态）     build/linux/（linux 状态）
build/demo.exe        build/demo_linux
```

### 17.6 诚实边界

| 边界 | 说明 |
|------|------|
| `build.sh` 仍用绝对路径 | bash 无此问题（已验证 DONE）；未改相对（可后续统一）|
| `demo/gen/` 旧文件残留 | 不影响正确性 |
| `examples/` 与 `prot_sdk/` 的 13 处 | **未适配**（独立发布需求，另一范畴）|
| **`measure_sections` 的 warn** | 已修为 die（严格），但**其他 `\|\| warn` 处未全部审查** —— 建议后续统一（"warn 吞掉失败"是**系统性风险**）|

---

*2026-09-25 · A 阶段完成: 隔离判据通过（快照法定位泄漏 + measure_sections 真实缺口）*

---

## 18. ✅ C-1 完成记录：Linux 独有攻击面（2026-09-25）—— **9/9**

### 18.1 目标与依据（**从源码实测得出**）

`src/platform/prot_platform_linux.c` 的 `prot_plat_extra_debug_flags()`
实现**三个 Windows 没有**的检测（Windows 侧实测 0 处）：

| # | 检测 | 触发条件 | 读什么 |
|---|------|---------|--------|
| ① | **LD_PRELOAD** | `/proc/self/environ` 有非空 `LD_PRELOAD=` | 内核提供，**用户态不可伪造** |
| ② | **可疑 .so** | `/proc/self/maps` 有 `/tmp/`、`/dev/shm/`、`/var/tmp/` 下的 `.so` | frida-gadget 等的常见位置 |
| ③ | **ptrace 已被跟踪** | `ptrace(PTRACE_TRACEME)` 失败 | 内核调试状态 |

**汇总路径**（`src/antidebug.c` L489-496）：
```
PRELOAD | SUSP_SO  -> report.ppid_blacklist = 1
PTRACED            -> report.debug_object   = 1
```
=> demo 的 `--selftest` 打印这两个字段 -> **可作验证判据**。

> **为什么复用既有字段而不加新字段**（源码注释已说明）：
> `prot_antidebug_report` 是**对外契约**，加字段会**破坏 ABI**；
> 用既有字段 + 注释记录语义扩展（**最小侵入**）。

### 18.2 交付: `tests/attacks_linux.py`（7 项）

**正向 4 项**（**不误报**）：
```
ok  demo 输出反调试字段（18 个字段）
ok  正向①: 干净环境无 LD_PRELOAD/.so（ppid_blacklist=0）
ok  正向②: 干净环境无 ptrace（debug_object=0）
ok  正向③: 其余反调试字段**全为 0**（不误报）
```

**负向 3 项**（**真发起攻击 -> 必须被检出**）：
```
ok  负向①: LD_PRELOAD 注入 -> ppid_blacklist=1
ok  负向②: 可疑 /tmp/.so   -> ppid_blacklist=1
ok  负向③: ptrace ATTACH   -> debug_object=1
```

> ### 🎯 本项的**核心价值**
> 前几项验证"代码能跑 / 契约满足"；
> **本项真的发起攻击**（`LD_PRELOAD` 注入库 / 父进程 `PTRACE_ATTACH`）
> 并断言**被检出** -> 证明防护**有效**，而非只证明"能编译"。

### 18.3 ⚠️ 两处"**差点误报缺陷**"（都是我的测试问题）

**诊断证据（决定性）**：
```
[tracer] attached to 412
反调试扫描: **发现可疑**
  debug_object: **1**            <- ptrace 被检出（检测完全正常）
检测到调试环境，程序即将退出。       <- 防护**主动阻止**（比"检出"更强）
```

| # | 我的 bug | 根因 | 修法 |
|---|---------|------|------|
| 1 | **环境变量位置错** | `LD_PRELOAD=x printf ... \| ./demo` —— shell 里 `VAR=x cmd1 \| cmd2` 的 VAR **只作用于 cmd1**（管道左侧）| 环境变量放到**管道右侧**（demo 命令前）|
| 2 | **tracer 缺 `PTRACE_CONT`** | attach 后子进程**停在 SIGSTOP**，直到 tracer 退出才恢复 -> 输出被截断 -> 判为"检测失效" | 补 `waitpid` + `PTRACE_CONT` |

> ### 🎯 教训（**第三次"测量问题而非缺陷"**）
> 负向测试失败时，**先验证"攻击是否真的生效"**。
> 本次靠"打印完整输出"才发现 demo **确实报了** `debug_object: 1` ——
> 若直接判"检测失效"，就会**误报缺陷**。
> （前两次: G 阶段的 vmc 退出码、C-1 的这个 —— **同类方法论**。）

### 18.4 第 9 项接入

```
--- 运行时验证（9 项）---
  ok   构建 / vm_unit / 契约测试 / 授权链
  ok   VM 合约测试 (vmc) 功能 6/6 + 错误 3/3
  ok   保护链静态断言 (P1-P6) 6 PASS / 0 FAIL
  ok   **Linux 独有攻击面 7/7**        <- 新增
  ok   节名随机化 / 文件大小统一
[verify_linux_runtime] PASS: 9/9
[ci_linux] PASS
```

### 18.5 诚实边界

| 边界 | 说明 |
|------|------|
| 攻击**改变进程环境**（LD_PRELOAD / ptrace）| 都在**临时目录**做 + **必清理**（`rm -rf`）；但**同一进程内**无法完全隔离 |
| ptrace 在 WSL 内可用 | 实测**可用**（已成功 attach）；其他环境（受限容器）可能不可用 -> 应视为**环境依赖** |
| 可疑 .so 的检测**与 LD_PRELOAD 同字段** | 负向②实际也走 LD_PRELOAD（因两者都会命中）—— **未单独验证**"/tmp 下的 .so 但不用 LD_PRELOAD"的路径 |
| 其余 Linux 独有项未覆盖 | 如 `dbi_rxrw_regions` / `dbi_thread_count` 的 Linux 实现（同为 DBI 面）|

### 18.6 C 阶段进度

| 部分 | 状态 |
|------|------|
| **C-1** Linux 独有攻击面 | ✅ **7/7**（9/9 集成）|
| C-2 `attacks.py` 移植 | ⬜ |
| C-3 `e2e.py` 全量移植 | ⬜ |

---

*2026-09-25 · C-1: Linux 独有攻击面（真攻击被检出 + 两处测试 bug 修正）*

---

## 19. ✅ C-2 完成记录：`attacks.py` 移植（**10/10 集成**，2026-09-25）

### 19.1 改动面（**与计划一致，极小**）

| 项 | 内容 |
|----|------|
| 路径常量 | `EXE` / `LICENSE` / `JSON_PATH` 按平台（复用 `genpaths`）|
| `run_demo` | Linux 侧**经 WSL 直执** + **自动补 `--vm-blob`** + **路径型参数转 WSL 形态** |
| `blob_bytes` | 生成物目录按平台 |
| A10/A11 | `pe_sections` -> `sections_of`（**自动分派 PE/ELF**）|
| 退出码 | `_norm_exit` / `_norm_expect`（**平台语义归一化**）|
| A12 | 按平台标记 `PLATFORM_NA` |
| 统计 | `PASS n / FAIL m / NA k`（**NA 透明列出，不混入 PASS**）|

### 19.2 验收

```
Linux  : [attacks] 平台=linux  总计 12: **PASS 11 / FAIL 0 / NA 1**
Windows: [attacks] 平台=win    总计 12: **PASS 12 / FAIL 0 / NA 0**
ci_linux: **10/10 PASS**
```

### 19.3 🎯 查明的两个**真实缺陷**（都在**测试侧**，非产品）

#### ① A5 的篡改逻辑**根本没改到字节**（**假失败**）

**决定性实测**：
```
A5 的篡改: b[len(b)//2] = ord('B')      <- **硬编码写入 'B'**
实测结果:  「改了: **False**」—— 该位置**本来就是 'B'**！
=> 篡改无效 -> 验签通过 -> A5 "FAIL"（**假失败**）
```
  Windows 侧 A5 PASS 是**巧合**（其 license 的中间字符不是 `'B'`）；
  Linux 侧重新生成的 license **恰好**该位置是 `'B'`。

> **教训（**通用**）**: "篡改型"测试必须**断言"篡改确实发生了"** ——
> 否则会因**巧合**而假通过或假失败。
> 这与"每个 checker 需要负向自检"**同一精神**:
> **测试自己要能证明"我确实做了那件事"**。

#### ② A12 是**平台能力缺失**（非缺陷）

A12 依赖**在线会话**（HTTP 服务器 + `--check-url http://127.0.0.1:PORT`），
而服务器跑在 **Windows 侧** -> **WSL 的 `127.0.0.1` != Windows 的** ->
demo 连不上 -> 走**离线降级** -> `code=0`。

**这是预期行为**（C 阶段已记录: Linux 侧网络能力**如实降级**）。
=> 标记 `PLATFORM_NA`，**不伪装成 PASS**。
**诚实说明**: 若把 HTTP 服务器放进 WSL 内，本项**可验证**（记为剩余工作）。

### 19.4 ⚠️ 一处**差点误报为严重缺陷**

**过程**：我曾实测到"篡改签名后 Linux 侧仍 `license: 1` + 校验通过"，
一度判定为**严重缺陷**（验签失效）。

**三路对照后推翻**：
```
① 篡改签名（直执）  : rc=1, license: 0   <- **正确拒绝** ✅
② 不存在的 license  : rc=1, license: 0   <- **正确拒绝** ✅
③ Windows 侧对照    : rc=1, license: 0   <- 基线一致 ✅
```
=> demo 的许可验签**完全正常**；"`license: 1`"来自
  **A5 的篡改本身无效**（见 19.3 ①）。

> ### 🎯 教训（**本项目第 N 次"测量问题而非缺陷"**）
> 负向测试失败时，**必须先确认"攻击/输入真的生效并传到了被测程序"**。
> 本次若直接记录"验签失效"，就会**误报严重缺陷**。
> **方法论三连**: 直执对照 + 边界对照（不存在的路径）+ **跨平台基线对照**。

### 19.5 本轮踩的坑（**都为其他工作留下经验**）

| # | 坑 | 根因 | 教训 |
|---|----|------|------|
| 1 | `bash -c "... \| demo"` 环境变量无效 | shell 的 `VAR=x cmd1 \| cmd2` 中 VAR **只作用于 cmd1** | 环境变量放**管道右侧** |
| 2 | `bash -c` **吞掉 stdin** | shell 包装干扰子进程 IO | **凡需精确控制子进程 IO -> 不经 shell 包装** |
| 3 | Windows 路径传给 WSL 里的 demo | 只改了"路径来源"忘了"路径形态" | **两个维度都要管**（与 A 阶段同一教训）|
| 4 | 缺 `--vm-blob` -> "VM 镜像装载失败" | Windows 侧 cwd 恰好能找到；Linux 不能 | **平台差异由适配层吸收**（单点）|
| 5 | 旧产物导致误判 | 未先重建 | **测量前确认产物新鲜**（计划 §9.3 已有纪律）|

### 19.6 C 阶段进度

| 部分 | 状态 |
|------|------|
| **C-1** Linux 独有攻击面 | ✅ 7/7（9/9 集成）|
| **C-2** `attacks.py` 移植 | ✅ **11 PASS / 0 FAIL / 1 NA**（10/10 集成）|
| **C-3** `e2e.py` 全量移植 | ⬜ 未开始 |

### 19.7 诚实边界

| 边界 | 说明 |
|------|------|
| A12 未在 Linux 验证 | 需把 HTTP 服务器放进 WSL（**可做，未做**）|
| A8/A9/A12 的退出码归一化 | Linux 只保留低 8 位（**POSIX 语义**）—— 归一化是**精确比较**（低 8 位 vs 低 8 位），**不是放宽** |
| `attacks.py` 的 Linux 分支 | 在**同一文件**里分派（非独立文件）—— 若继续增长建议拆分 |

---

*2026-09-25 · C-2: attacks.py 移植（11 PASS / 1 NA；含 2 个测试侧缺陷查明 + 1 次误报避免）*

---

## 20. ✅ C-3 完成记录：`e2e.py` 全量移植 —— **C 阶段收官**（2026-09-25）

### 20.1 验收

```
Linux  : [e2e] 平台=linux  总计 28: **PASS 20 / FAIL 0 / SKIP 1 / NA 7**
Windows: [e2e] 平台=win    总计 28: **PASS 27 / FAIL 0 / SKIP 1 / NA 0**（零回归）
ci_linux: **11/11 PASS**
```

### 20.2 依赖分层（**计划 §10.2 的纪律，先分层再动手**）

| 类别 | 用例 | 处置 |
|------|------|------|
| 平台无关（跑 demo+解析）| T1/T2/T5/T6/T7/T8/T11/T12/T13/T14/T15-T21 | 路径 + run_demo 分派 |
| **PE 篡改** | T4/T9/T10（`make_tampered_copy`）| **ELF 适配**（复用 `sections_of`）|
| 调试器附加 | T3 | 原设计 preflight -> **SKIP**（环境不支持）|
| **在线会话** | T22-T28（7 项）| **PLATFORM_NA**（网络边界，见 20.3）|

**分层的价值**：866 行、23 处 ctypes 实测中，真正需改的只有
**4 个点**（import 条件化 / run_demo / 篡改函数 / 路径）。

### 20.3 🎯 决定性探测：**WSL2 与 Windows loopback 独立**

```
curl 127.0.0.1:PORT -> **Connection refused**（rc=7）
Python urllib      -> 同样失败
=> mock HTTP 服务器跑在 Windows Python -> WSL 内**不可达**
```

**诚实处置（含"假通过"）**：7 项在线用例全部标 `PLATFORM_NA` ——
**包括那些判据上"通过"的**：
| 用例 | 表面 | 实情 |
|------|------|------|
| T23 online-ok | exit=0 符合判据 | **巧合**（离线路径恰好 0）|
| T24 online-degrade | "降级"符合判据 | **巧合**（不可达即降级，但原因是宿主差异）|
| T25 session accepted | 符合判据 | **巧合** |
| T28 tampered rejected | exit=11 符合判据 | **巧合**（实为连不上 → blob missing）|
| T22/T26/T27 | FAIL | 平台网络差异（非缺陷）|

> **这是"未验证 != 通过"纪律的一次完整实践**：
> 假通过比假失败**更危险**（掩盖了未验证状态）。
> **剩余工作**：mock 服务器放进 WSL（或 host IP）→ 7 项可完整验证。

### 20.4 移植中修的 6 处（**逐个实测驱动**）

| # | 用例 | 根因 | 修法 |
|---|------|------|------|
| 1 | T4 `unpack requires a buffer` | `make_tampered_copy(from_end)` **内嵌 PE 头解析** | 改用 `section_bounds`（复用 `sections_of`，含 CRC 长度语义）|
| 2 | T9/T10 `.rdata/.pdata not found` | Linux 是 `.rodata/.eh_frame` | **按文件格式**做节名映射（`SECTION_NAME_ALIAS`）|
| 3 | T5 `exit=127` | `vm_unit` 指向 `vm_unit.exe` | 平台分派（`build/vm_unit_linux`）|
| 4 | T8 篡改无效 | `b[mid] = 'B'` **可能本来就相等**（与 C-2 A5 同因）| 改为"**保证改变**" |
| 5 | T13/T14/T27 `exit=11` 等 | `0xB10B & 0xFF`（**POSIX 低 8 位**）| `_norm_exit` / `_norm_expect`（**8 处判据**）|
| 6 | **T15 revoke-hit** | `privkey = BUILD/keys/...` 平台化后**不存在** -> revoke 未签名（v0）-> 按无效不阻断 | 密钥改**共享路径** |

> ### 🎯 第 6 处是**重要边界认知**（A 阶段隔离的适用范围）
> `build/` 下不是所有东西都该按平台分：
> · **平台产物**（vm.blob/license/mask/baseline…）-> 分 ✅
> · **密钥材料**（`build/keys/`）-> **两平台同一把私钥**（B 阶段已证实
>   BCRYPT 与 DER 同源）-> **共享，不参与隔离**
> 我曾把"路径抽象"**用过了头**（全局套 `BUILD`）——
> **隔离的边界 = 平台产物**，不是"build/ 下所有东西"。

### 20.5 复用的既有资产（**避免重复实现**）

| 资产 | 来源阶段 | C-3 的用法 |
|------|---------|-----------|
| `protchain_check.sections_of` | F 阶段 | 节表 + 篡改位置（**自动分派**）|
| `attacks.py` 的 WSL 直执形态 | C-2 | `run_demo` 分派（**不经 bash** —— 它会吞 stdin/退出码）|
| `_norm_exit` 思路 | C-2 | 8 处退出码判据 |
| `genpaths` | A 阶段 | 路径 + `build_dir` |

### 20.6 交付与验收

| 项 | 状态 |
|----|------|
| C-1 Linux 独有攻击面 | ✅ 7/7（9/9 集成）|
| C-2 attacks.py | ✅ 11 PASS / 1 NA（10/10 集成）|
| **C-3 e2e 全量** | ✅ **20 PASS / 1 SKIP / 7 NA / 0 FAIL**（11/11 集成）|
| **Windows 零回归** | ✅ e2e 27/28 PASS + 门禁 21/22 |
| **ci_linux** | ✅ **11/11** |

### 20.7 诚实边界（C-3）

| 边界 | 说明 |
|------|------|
| 7 项在线用例未验证 | WSL2/Windows loopback 独立；**需 mock 服务器进 WSL**（可做）|
| T3 SKIP | 原设计（self-preflight 环境自检）—— **非本轮引入**；Linux 可用 ptrace 实现真实附加（C-1 已有基础，**剩余工作**）|
| 节名映射按格式 | `SECTION_NAME_ALIAS` 仅映射 3 个标准节（够用；新节需补映射）|
| e2e 在**同一文件**分派 | 与 C-2 同；若继续增长建议拆平台模块 |

---

*2026-09-25 · C-3: e2e 全量移植（20 PASS/1 SKIP/7 NA/0 FAIL；依赖分层 4 个改动点；含假通过处置）—— **C 阶段完成***
