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
> → ✅ **已于 §33/W4 完成**（W3 先补了 Linux 的 POSIX socket HTTP，再把 mock 放进 WSL -> 7 项**真跑全过**）。

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
| A12 未在 Linux 验证 | 需把 HTTP 服务器放进 WSL（可做，未做） -> ✅ **已于 §33/W4 完成**（A12 真跑，双平台 12/12）|
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
> → ✅ **已于 §33/W4 完成**（`mock_http.py` 复活 + Linux HTTP 实现）。

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
| 7 项在线用例未验证 | ~~WSL2/Windows loopback 独立~~ → ✅ **已于 §33/W4 完成**（7 项真跑全过）|
| T3 SKIP | 原设计（self-preflight 环境自检）—— **非本轮引入**；→ ✅ **已由 §28 处置**（preflight 改子进程探针 + **Linux 标 NA 指向 C-1**，本环境 `winerror 5` = 环境限制）|
| 节名映射按格式 | `SECTION_NAME_ALIAS` 仅映射 3 个标准节（够用；新节需补映射）|
| e2e 在**同一文件**分派 | 与 C-2 同；若继续增长建议拆平台模块 |

---

*2026-09-25 · C-3: e2e 全量移植（20 PASS/1 SKIP/7 NA/0 FAIL；依赖分层 4 个改动点；含假通过处置）—— **C 阶段完成***

---

## 21. ✅ A-d 补完：**状态自检** `tools/check_state_platform.py`（2026-09-25）

### 21.1 背景（**目标清单的补漏**）

目标 §2.3 写明 A-d 含"状态自检（**含负向**）" —— A-d 的路径适配完成后
此项遗漏，本次补齐。

**工具查什么（跨平台错配）**：
```
demo/gen/<plat>/prot_sections.json 的**必需三节**必须出现在对应产物里
+ expect_default.c 与 vm_build.json 的 expect 一致性
```
错配（win json + linux 产物 / 反之）-> **FAIL**（而非静默降级）。

### 21.2 判据的**事实核查**（读源码 + map + readelf 三处确证）

初版判据"json 全部节名 ⊆ 产物"导致 **T1 正向失败** ——
实测发现 `protxec`/`fptable` 在 ELF **不存在**。**逐处核查**后：

| 节 | Windows | Linux | **性质（核查结论）** |
|----|---------|-------|------------------|
| `protxec` | ✅ 有 | **缺** | `PROT_CODE_SEG` 在 gcc = **文档化 no-op**（`prot_compiler.h`: "无对应：PE 段布局是平台概念"）-> **设计使然** |
| `fptable` 随机名 | **缺**（仅字面 `.fptable`）| **缺** | `PROT_SEC_FPT` **全库无使用者**（只有定义与随机化）-> 随机名**两平台都无效** |
| `protcrc`/`protcry`/`protpad` | ✅ | ✅ | **功能必需**（selfcrypt meta / CRC 烧录 / 填充）-> **可靠判据** |

**据此修正判据**（**按事实，不按假设**）：
· 必需三节缺一个 = **跨平台错配**（FAIL）
· `protxec`/`fptable` 缺失 = **已知设计差异**（info 提示，**不 FAIL**）

> ### 🎯 观察结论（如实记录）
> `fptable` 的**随机化是无效的** —— `gen_sections` 给它生成随机名，
> 但 `PROT_SEC_FPT` **无人使用** -> 产物里只有字面 `.fptable`
> （来源待查，可能来自链接期）。**不影响功能**，但"第二支柱"在该节上
> **未实际生效** —— 记为**待查小项**。

### 21.3 自检（**6/6**：1 前置 + 1 正向 + **4 负向**）

```
ok  T0 前置: 两平台产物与生成物存在
ok  T1 **正向**: linux 产物 + linux 生成物 -> PASS
ok  T2 **负向**: linux 产物 + win 生成物 -> **必须 FAIL**
      detail: REQUIRED section protcrc=.62yxrna not in artifact
              **(cross-platform mismatch? ...)**        <- 失败原因正确
ok  T3 **负向**: win 产物 + linux 生成物 -> **必须 FAIL**
      detail: REQUIRED section protcrc=.mkpisv7 not in artifact
ok  T4 **负向**: 文件缺失 -> **必须 FAIL**（不崩溃）
      detail: missing .../prot_sections.json
ok  T5 **负向**: expect 不一致 -> **FAIL 且因 expect**
      detail: expect mismatch: default=0x.../0xaaaa vs vm_build.json=...
[check_state_platform-selftest] PASS
```

> **T5 的断言特意包含"失败原因"**（`'expect mismatch' in detail`）——
> 防止"**因错误原因通过**"（若因节名错配先失败，expect 检查就测不到）。
> 与 mutate_check 的"检查器必须能抓错"**同一精神**。

### 21.4 接入门禁（第 23 项）

```
Check '构建状态自检 (check_state_platform)'
  ① --selftest（6 项，含 4 负向）
  ② 双平台实跑（win 与 linux 各自目录内自洽）
```

**为什么适合放门禁**：**只读**（不改状态）、**双向**（不依赖"最新是哪个平台"）——
与 §20.3 的分层原则一致（重的/改状态的在 `ci_linux`，轻的/只读的在门禁）。

### 21.5 门禁项数变更

**22 -> 23 项**（`doccheck` 强制对外文档数字一致 —— 已同步 `publish/`）。

### 21.6 诚实边界

| 边界 | 说明 |
|------|------|
| `fptable` 来源待查 | 字面 `.fptable`(0x100) 在 Windows 产物里的**发射方未定位**（全库源码无引用）—— 记为小项 |
| 未验 `--platform both` 下的**中间态** | 若只有单平台构建过，另一平台的失败是合理的（T0 前置已覆盖） |
| 判据覆盖 3+2 节 | 未来若新增随机节（gen_sections 扩展），REQUIRED 集需同步 |

---

*2026-09-25 · A-d 补完: 状态自检（6/6，含 4 负向断言失败原因）+ 两处事实核查*

---

## 22. 📋 遗留项分步计划（**盘点驱动**，2026-09-25，待确认）

### 22.1 现状盘点的**三个修正**（读代码 + 实测，推翻原假设）

| # | 原判断（诚实边界） | **实测事实** | 影响 |
|---|------------------|------------|------|
| ① | T3 SKIP 是"移植缺口" | **Windows 的 SKIP 就是 T3**（27P/1S，与 Linux **同**）；且核心检出已被 **C-1 负向③**（ptrace 附加→`debug_object=1`）覆盖 | **降级为可选**（原计划的"Linux ptrace 实现 T3"价值低）|
| ② | T24"巧合通过"→标 NA | 判据 = "服务不可达→**静默降级**"（硬编码 59999）；WSL 内同样不可达 -> **语义完全成立** | **改真验证**（NA 过于保守）|
| ③ | `fptable` 随机化"无效待查" | 生产者 = **`?function_pointers` @ `libucrt:winapi_thunks.obj`（CRT 库符号，非本项目代码）** | **澄清为"为不存在之物做映射"，非防护缺口**；处置=从 gen_sections 移除该逻辑名 |

### 22.2 在线用例的可行方案（**核心技术判断**）

```
探测已证: WSL2 与 Windows loopback 独立（curl rc=7）
但: T22-T28 的 mock 服务器是 **in-process http.server**
    -> demo 在 WSL 内 -> 服务器必须也进 WSL（同 loopback 才通）
```

**方案**：`tools/mock_http.py`（纯标准库，无依赖）在 **WSL 内**起服务：
```
① wsl -- python3 tools/mock_http.py --mode check|expect|blob ...
   -> stdout 打印 PORT=xxxxx（端口协商）
② e2e 读 PORT -> URL=http://127.0.0.1:PORT/...
   -> demo（在 WSL 内）连 WSL 自己的 loopback ✅
③ 用完 kill（子进程生命周期在 e2e 内管理）
```
**handler 三类**（对应 e2e 现有 start_*，**语义逐字复刻**）：
`check_mock`（吊销/不吊销）、`expect_mock`（正确/错误期望）、
`blob_mock`（签名版/篡改版）。

### 22.3 分步计划（每步独立交付 + 独立验收）

| 步 | 内容 | 交付 | 验收 | 成本 |
|----|------|------|------|------|
| **S1** | T24 从 NA 改真验证 + `mock_http.py` 骨架（check 模式）| 新工具 + e2e T22/T23 真跑 | e2e: T22/T23 从 NA→PASS；**T24 仍真降级**（负向）| 小 |
| **S2** | expect + blob 两个 handler 移植 | `mock_http.py` 完整 | e2e: **7 项在线全部真跑**（T22-T28 中除 T24 外）；**attacks A12 真跑**（去 NA）| 中 |
| **S3** | fptable 澄清落地: `gen_sections` 移除 `fptable` 逻辑名 + `check_state_platform` info 更新 + 文档 | 改动 2 文件 | 自检 6/6；门禁 23/23；**info 行不再出现 fptable** | 小 |
| **S4** | `demo/gen/` 旧文件清理（确认 gitignore 覆盖后删旧 flat 文件）| 脚本/手工清理 | 门禁 23/23 + ci_linux 11/11 | 极小 |
| **S5** | 平台公共层抽取 `tests/_platform.py`（to_wsl / wsl 直执 / norm_exit / _Results 等，e2e 17 处 + attacks 17 处引用）| 新模块 + 两测试瘦身 | **双平台回归全绿**（23/23 + 11/11，各测试结果与抽取前**逐项一致**）| 中 |
| **S6**（可选）| T3 preflight 改为"attach 无害子进程"（两平台真可用）| e2e 改动 | T3 从 SKIP→真测（**若仍不可用则诚实保留 SKIP**）| 小-中 |

**执行顺序**：S1 → S2 → S3 → S4 → S5 →（S6 视情况）
理由：S1/S2 先消除最大缺口（8 项 NA）；S3/S4 是低成本澄清；
S5 放最后（重构不与功能改动混做，回归基线才干净）。

### 22.4 各步验收与总验收

| 项 | 目标值 |
|----|--------|
| e2e（Linux）| **NA 8→0**（T24 转真验证、7 项在线真跑），FAIL=0 |
| attacks（Linux）| **NA 1→0**（A12 真跑）|
| Windows 门禁 | **23/23**（每步后）|
| Linux ci_linux | **11/11**（每步后）|
| `check_state_platform --selftest` | **6/6**（每步后）|

### 22.5 不做什么（**范围边界**）

| 不做 | 理由 |
|------|------|
| e2e/attacks 按平台**拆成独立文件** | S5 只抽**公共层**；拆文件收益小（分支已可控），且大改文件风险高 |
| `protxec` 的 gcc 实现 | `PROT_CODE_SEG` 在 gcc **文档化无对应**（PE 段布局是平台概念）—— **设计决策，不重开** |
| Linux 数字签名 | 无 signtool 等价物（既有边界）|
| 网络能力（`prot_plat_http_get`）接 libcurl | demo 的 HTTP 走宿主；库级能力缺失是既有记录的边界 |

### 22.6 风险

| 风险 | 应对 |
|------|------|
| S1/S2 的 WSL 子服务器生命周期（泄漏端口/进程）| e2e 内 try/finally 确保 kill；每用例独立端口 |
| S5 抽取引入回归 | **逐项 diff 对照**抽取前输出（双平台），任何一项差异即回滚 |
| S3 移除 fptable 后 Windows 构建产物节集合变化 | 预期（少一个映射）；门禁 + P1-P6 + state check 三重验证 |
| 在线测试使 e2e 变慢/不稳（跨进程服务器）| 单用例超时 10s 上限；失败明确报错（不吞）|

---

*2026-09-25 · §22: 遗留项分步计划（S1-S6，盘点驱动；三个原判断经实测修正）*

---

## 23. ✅ S1+S2 完成：在线用例的**诚实处置**（2026-09-25）

### 23.1 ⚠️ **方案被实测推翻**（本阶段最重要的记录）

**原计划 §22.2 的技术判断**：
```
"把 mock 服务器放进 WSL（同 loopback）-> 7 项在线用例可完整验证"
```

**实测结论：不可行 —— 根因不在"服务器位置"**：
```
src/platform/prot_platform_linux.c:
  prot_plat_http_get()      -> return PROT_ERR_UNSUPPORTED;   <- 如实未实现
  prot_plat_http_get_mem()  -> return PROT_ERR_UNSUPPORTED;
  源码注释: "为什么不用 libcurl（决策记录）: ①不引入新依赖 ②诚实 ③可扩展"
```
**实测验证**（先做了 mock，才发现的）：
```
WSL 内起 mock_http（check 模式）-> 端口协商 PORT=44765 ✅
WSL 内 curl -> {"status":"revoked","reason":"e2e"} ✅（**服务器完全正常**）
但 demo（WSL 内，--check-url 指向它）-> **仍 license: 1**（在线检查未生效）
=> Linux 侧根本没有 HTTP 能力 -> demo **不会发起请求**
=> 服务器放哪里都无用
```

> ### 🎯 教训（**"服务器就绪"≠"被测程序会用它"**）
> 我验证了"服务器在 WSL 内可用"就以为方案成立 —— 但**没有先确认
> "被测程序在该平台具备发起请求的能力"**。
> 正确顺序应是: **先查被测方能力（源码/平台层），再设计测试基础设施**。
> （与 §19.4/A5、"负向测试先确认攻击生效"是**同一类错误**的另一个面。）

### 23.2 处置（**不把"设计上不可验证"伪装成"待做"**）

| # | 处置 | 依据 |
|---|------|------|
| ① | **删除** `tools/mock_http.py` | 方案不可行 -> 即死代码 |
| ② | NA **原因描述修正** | 从"服务器在 Windows 侧不可达"（**表象**）改为"**Linux 无 HTTP 能力**（`PROT_ERR_UNSUPPORTED`，设计决策）"（**根因**）|
| ③ | **T24 转真验证** | 见 23.3 |
| ④ | libcurl 记为**产品待办**（非测试缺口）| §22.5 已列"不做"，此处明确**归因** |

### 23.3 T24 为何**可以**真验证（**代码路径同一性**）

```
判据: "服务不可达 -> 静默降级（不锁死）"
  · Windows: 端口 59999 未监听 -> prot_plat_http_get_mem 返回网络失败
             -> **走 else（降级）分支**
  · Linux  : prot_plat_http_get_mem 返回 PROT_ERR_UNSUPPORTED
             -> **走同一个 else（降级）分支**
=> **代码路径相同**（"HTTP 不成功就降级"）-> Linux 的结果是对
   **同一分支**的真实验证（**只是触发原因不同**）
```
**诚实标注**（写入代码注释）：若将来 Linux 实现 HTTP，本用例需**复查**
（届时触发原因才与 Windows 一致）。

### 23.4 验收

```
Linux  : [e2e] 总计 28: **PASS 21 / FAIL 0 / SKIP 1 / NA 6**   （NA 7 -> 6）
Windows: [e2e] 总计 28: **PASS 27 / FAIL 0 / SKIP 1 / NA 0**   （零回归）
```
**NA 从 8 -> 6**（S1 的 T24 转真 + 原属 N/A 的项不变）；
**剩余 6 项 NA = 6 个在线用例**（T22/T23/T25/T26/T27/T28），
根因统一为"**Linux 无 HTTP 能力**"。

### 23.5 对原计划 §22 的**修订**

| 原步 | 修订 |
|------|------|
| **S1** | ✅ 完成（T24 转真验证 + NA 原因修正）|
| **S2** | ⚠️ **取消**（"mock 进 WSL"方案不可行）—— 其目标（消除 8 项 NA）**改为**"如实归因 + 转为产品待办" |
| S3-S5 | 不变 |

**当前 NA 归零的**唯一路径**：先在 Linux 实现 HTTP（libcurl 或自实现）——
**产品特性决策**，需单独评估（不属本次遗留项清理）。

---

*2026-09-25 · S1+S2: 在线用例诚实处置（方案被实测推翻 + T24 转真验证；NA 8->6）*

---

## 24. ✅ S3 完成：`fptable` 澄清落地 + **A10 真实缺陷修复**（2026-09-25）

### 24.1 S3: fptable 的三处核查与清理

**核查结论（三处证实"都是死的"）**：
| # | 位置 | 事实 |
|---|------|------|
| ① | `gen_sections` L37（`'fptable': ('read','write')`）| 生成 `PROT_SEC_FPT` 宏 -> **全库无使用者** |
| ② | `gen_padding` L63（`'fptable': (...) -> g_pad_fpt`）| 实测生成的 `prot_padding.c` **无 `g_pad_fpt`**（条目已死）|
| ③ | 产物里的 `.fptable` 段 | 生产者 = **CRT**（`?function_pointers` @ `libucrt:winapi_thunks.obj`，`build/demo.map` 可见）—— **非本项目代码** |
| ④ | `observability` 的 `STD_SECTIONS` | **保留**（`.fptable` 确为外来/标准节 —— 与该结论一致 ✅）|

**清理（4 文件，含"防重加"留证）**：
```
· tools/gen_sections.py      移除 NAMES 条目 + PROT_SEC_FPT 宏生成（+ CRT 结论注释）
· tools/gen_padding.py       移除死条目（+ 说明）
· include/.../prot_sections.h 移除 PROT_SEC_FPT 默认定义（+ 说明）
· check_state_platform.py    optional 列表只留 protxec（fptable 不再是"设计差异"）
· tools/observability.py     加"为何在标准节表里"的留证注释
```

**验收**：
```
check_state_platform selftest: **6/6**
[win]  **4/4** section names applied（原 4/5 —— fptable 映射已消失）
[linux] 4/5（protxec = 平台设计差异）
Windows 重建: **DONE**
```
> **为什么"移除"而非"留着"**: 留着 = **误导性的死映射**
> （为不存在之物生成随机名，后人会以为"防护覆盖了 5 个节，实际 4 个"）。
> 且 `PROT_SEC_FPT` 宏是**死代码**（无人使用）。

### 24.2 ⚠️ A10 的**真实缺陷**（S3 重建后暴露）

**现象**：
```
ci_linux: attacks **PASS 10 / FAIL 1**
A10 static-trace FAIL: direct calls to indirect slots: ['prot_hostid_get']
但 protchain 的 **P5 同一函数 PASS**（"P1-P6 6 PASS"）
```

**根因（调用差异）**：
```
protchain L627: ('P5 ...', p5_indirect_no_direct_call, (data, secs, **map_path**))
attacks   L487: p5_indirect_no_direct_call(exe_data, secs)     <- **未传 map_path**
=> 默认值 = **硬编码的 Windows map**（build/demo.map）
=> Linux 产物 + Windows map -> **坐标系错配** -> 误报
```

**为什么现在才暴露**：S3 改动 `gen_sections` -> Windows 重建 ->
`build/demo.map` 的符号 RVA 变化 -> 错配从"偶然对上"变成"明显不符"。
（**这不是 S3 引入的缺陷，是 S3 让它显形** —— 与 `measure_sections`
被"warn 吞掉"同类：**潜伏缺陷需要一个契机才暴露**。）

**修法（关键判断：修在判据内部，而非调用方）**：
```python
# p5_indirect_no_direct_call 内按产物 magic 自动定位平台 map
if data[:4] == b'\x7fELF':  map_path = build/demo_linux.map
else:                        map_path = build/demo.map
```
**为什么不在调用方修（attacks 传参）**：
> P5 源码注释已记载**两次同类缺陷**（`scan_e8_calls` 偏移基准、map 硬编码），
> 教训是"**穷尽所有坐标系来源**"。但"靠调用方记得传参"**必然再犯** ——
> 第三个调用方出现时就是第三次缺陷。
> => 让判据**自己**判定平台（**消除参数依赖 = 单一来源**），
>    `map_path` 参数保留供显式覆盖。
> **这是"复制即漂移"教训的又一次应用**（与 §15 的"同一判据不写两遍"同源）。

**验收**：
```
attacks Linux:   **PASS 11 / FAIL 0 / NA 1** ✅
attacks Windows: **PASS 12 / FAIL 0 / NA 0** ✅（零回归）
ci_linux:        **PASS**（9/9 with -SkipBuild）
```

### 24.3 附带修正：A12 的 detail 文案

S1 修正 A12 时只改了**注释**，**detail 字符串**仍是旧原因
（"服务器在 Windows 侧"）-> 本次改为根因（"Linux 无 HTTP 能力"）。
> **教训**: 改"原因说明"时要**同时改注释与输出串** ——
> 只改一处会让**对外可见的信息**与注释不一致。

### 24.4 门禁状态（**待查项**）

```
Windows 门禁（23 项完整）: **21/23**（失败 2）
  · git 工作区干净（未提交 —— 预期）
  · **mutate_check** ← 需查
但 mutate_check **单独跑 PASS**（6 健康 / 0 盲）
=> 疑似**门禁顺序/状态**问题（与 §21.4 的 `--quiet` 那次同类）
```

**下一步（S4 前）**：查明门禁内 `mutate_check` 失败的**真实原因**
（不改判据、不放宽标准）。
> → ✅ **已由 §25 结案**（状态竞争；**串行**后 24/24）。

---

*2026-09-25 · S3: fptable 澄清（4 文件清理）+ A10 真实缺陷修复（P5 map 自动定位）*

---

## 25. 🔍 §24.4 待查项结案：门禁 `mutate_check` 失败 = **状态竞争**（2026-09-25）

### 25.1 现象与结案

```
现象: 门禁（23 项完整）**21/23**，失败 2（git + mutate_check）
但:   mutate_check **单独跑 PASS**（6 健康 / 0 盲）
结案: 我**并发**跑了 `ci_linux`（写 `demo/gen/linux` + `build/linux`）
      与门禁 -> **共享状态争用** -> mutate_check 的基线被污染
=> **串行重跑: 门禁 23/23 全通过** ✅
```

### 25.2 这是**已知纪律的重复违反**（必须记名）

本项目**早已记录**该纪律：
> §"状态争用"（并发后台任务读写共享产物 -> "莫名"失败）
> —— 正确做法是**串行**跑门禁与 Linux 验证。

**本次我违反了它**，代价：一次假缺陷排查 + 一轮误判（一度怀疑
"门禁顺序问题"）。**判定依据很简单**：单独跑就过 -> 先怀疑**并发**，
而不是怀疑判据。
> ### 🎯 教训（**排查顺序**）
> "单独过、门禁里失败"的**第一嫌疑是状态/顺序**（并发写入、
> 前置项改了输入），**不是判据本身**。
> 与 §21.4 的 `--quiet` 那次（真接线错误）**对策不同**：
> 那次是**真错**（参数不存在），这次是**状态**——
> 但两者的正确第一步**都是先跑一次"隔离复现"**（单独跑 / 串行跑）。

### 25.3 当前验收状态

```
Windows 门禁: **23/23 全通过** ✅（串行）
Linux ci_linux: 见下（串行）
```

---

*2026-09-25 · §24.4 结案: 门禁 mutate_check 失败 = 状态竞争（并发违反既有纪律）*

---

## 26. ⚠️ S4 完成：**原计划被推翻**（不能清理 flat 目录）（2026-09-25）

### 26.1 原计划 vs 审计结果

**原计划**：`demo/gen/` 的 38 个 flat 遗留文件"零风险清理"
（理由：`demo/gen/` 整体被 .gitignore 覆盖）。

**审计（逐文件扫描 `demo/gen/<名>` 形态，区分注释与活跃代码）**：
```
"活跃"引用 24 处，分三类:
① **工具默认值（真缺陷，A 阶段漏改）**:
   · tools/gen_padding.py     L115-123  二级回退 = 'demo/gen/prot_sections.json'
   · tools/measure_sections.py L134     default='demo/gen/prot_sections.json'
② **examples 的 flat 依赖（独立范畴，§22.5 已列"不做"）**:
   · examples/tool_demo/build_example.ps1  **5 处主动读写** demo\gen\*
③ **tools/build_dotnet_gate.ps1 L70** `demo\gen\strings.c`（同 ② 类）
④ 其余 = docstring / help / _constraint 文本（非执行路径）
```

**结论**：**不能删除 flat 目录** —— ②③ 是**活跃依赖**，
删了会**直接断掉 example E1-E7**（门禁第 10 项）。

> ### 🎯 教训（**"gitignore 覆盖"≠"无引用"**）
> 我把"git 不追踪"当成了"可以删" —— 但**引用关系与版本控制无关**。
> 正确顺序: **先穷举引用者，再决定删留**。
> （§17.2 的"快照法找泄漏"是同一课的另一面: **让机械方法替我穷举**，
> 而不是靠"我觉得应该没人用"。）

### 26.2 实际处置

| # | 处置 | 说明 |
|---|------|------|
| ① | **修两个工具的默认值**（**真缺陷**）| 标注为"flat 旧路径、**不可信**"，并说明它是**二级回退**（首选 = `dirname(--actual)/prot_sections.json`，平台正确）|
| ② | **保留 flat 目录** | 有活跃依赖（examples / build_dotnet_gate）|
| ③ | flat 清理**转归**"examples 适配"（§22.5 的"不做"范畴）| 需先改 examples 用平台路径 |

**重要细节（读码后修正我的初判）**：
`gen_padding.py` 的那行**不是 argparse 默认值**，而是
**文件缺失时的二级回退**：
```python
j = os.path.join(os.path.dirname(args.actual), 'prot_sections.json')  # 首选（平台正确）
if not os.path.exists(j):
    j = 'demo/gen/prot_sections.json'                                  # 回退（flat 遗留）
```
=> 它的**风险等级低于**我初判（正常构建走首选分支）；
但仍标注为**不可信**（若首选缺失，会静默用错平台的映射）。

### 26.3 验收

```
Windows 门禁: **22/23**（唯一失败 = git 未提交，**零回归**）
Linux ci_linux: **PASS**（9/9 with -SkipBuild）
```

### 26.4 遗留（**转入后续**）

| 遗留 | 归属 |
|------|------|
| examples 的 5 处 flat 依赖 | §22.5 "不做"（examples 适配 = 独立范畴）|
| `build_dotnet_gate.ps1` L70 | 同上 |
| flat 目录本身（38 文件）| **保留**（有依赖）；待 examples 适配后再评估 |
| 注释/docstring 里的 flat 提及（~19 处）| 低优先（非执行路径）；未来统一文档时一并更新 |

---

*2026-09-25 · S4: 原计划被推翻（不能清理 flat 目录 —— 有活跃依赖）+ 修 2 处工具默认值*

---

## 27. ✅ S5 完成：抽公共层 `tests/_platform.py`（2026-09-25）

### 27.1 为什么抽（**"复制即漂移"的实证**）

`e2e.py` 与 `attacks.py` 各自实现了**同一批**平台适配。**漂移证据**：
```
_run_demo_wsl:  e2e 28 行  vs  attacks 55 行
```
同一契约（"经 WSL 直执，stdin/退出码直达"）实现了两遍 ——
C-2 修好的细节（**不经 bash** / 路径转形态 / 自动补 `--vm-blob`）
在 C-3 里**又踩了一遍**才补上。
=> 抽为**单一来源**（与 §24.2 的 P5 修复同一动机）。

### 27.2 交付 `tests/_platform.py`

| 函数 | 契约 |
|------|------|
| `parse_platform(argv)` | 解析 `--platform` 并**移除**（不移除会让下游 argparse 退出 2，**实测踩到**）|
| `to_wsl(p)` | `D:\x` -> `/mnt/d/x` |
| `norm_exit` / `norm_expect` | **平台语义归一化**（Linux 低 8 位；**不是放宽判据**）|
| `fix_path_args(args)` | Windows 绝对路径参数 -> WSL 形态（**实测**: 不转则 demo 打不开 license -> 误判"验签失效"）|
| `run_demo_via_wsl(...)` | **不经 bash** 直 exec + 可选自动补 `--vm-blob` |

**自检（`--selftest`，9 项含 3 负向）**：
```
ok T1 norm_exit(0xB10B, linux) == 0x0B
ok T2 norm_exit(0xB10B, win) == 0xB10B
ok T3 **负向**: 两平台归一化结果**不同**      <- 若相同则归一化无意义
ok T4 norm_expect 与 norm_exit 配对一致
ok T5 to_wsl 处理盘符与空格
ok T6 fix_path_args 只转路径型
ok T7 **负向**: WSL 路径不被二次转换
ok T8 parse_platform 解析并移除
ok T9 **负向**: 缺参数时用默认 win
[_platform-selftest] PASS: 9 项（含 3 负向）
```

**抽取原则（**只搬不改良**）**：
· 只放**两处都用**的；单处用的（`_Results` / `section_bounds` /
  `mapped_sec_name`）**留在原处**
· `run_demo` 等**保留原签名**（薄包装委托），避免改几十个调用点

### 27.3 验收（**逐行 diff 对照**）

```
attacks linux ✅ 逐行一致     attacks win ✅ 逐行一致
e2e     linux ✅ 逐行一致     e2e     win ✅ 逐行一致
Windows 门禁: **22/23**（唯一失败 = git 未提交，**零回归**）
Linux ci_linux: **PASS**（9/9）
```
> **为什么要逐行 diff**：重构的验收标准不是"测试通过"（可能通过但行为已变），
> 而是"**输出逐行一致**" —— 这才证明**行为零变化**。

### 27.4 ⚠️ 过程中的**一次事故与教训**（**记名**）

**事故**：
```
我用 re.search(r'^def _norm_expect\(.*?\n(?=\ndef )', t, re.S) 替换 _norm_expect
-> re.S 让 `.` 匹配换行，而 (?=\ndef ) 只保证"下一个 def 之前"
-> **贪婪吞掉**中间的 `ONLINE_LABELS` 与 `class _Results`（它们不是 def）
-> NameError: name '_Results' is not defined
```

**修复**：从 `git show HEAD:tests/e2e.py` **逐字取回**两个块，按**行号区间**
插回（不凭记忆重写 —— 否则无法证明"行为零变化"）。

> ### 🎯 教训（**本项目第二次"通用替换"事故**）
> | 事故 | 操作 | 后果 |
> |------|------|------|
> | 先前（A-c）| `re.sub(r'  +', ' ', body)` | **毁掉 770 行缩进** |
> | 本次（S5）| `re.S` + `(?=\ndef )` | **吞掉非 def 的块** |
> **规律**: **跨行正则替换代码块 = 高风险**。
> 正确做法: 用**精确起止锚**（明确结束标记）或 **AST / 行号区间**，
> 而不是"点号贪婪 + 下一个关键字"。
> **推论**: 凡是"改代码结构"的操作，**优先按行号区间切片**（本次修复即用此法）。

### 27.5 遗留

| 遗留 | 说明 |
|------|------|
| `_platform` 未入门禁自检 | 其 `--selftest` 目前**手工跑**；建议接入（低成本，但会增门禁项数）|
| `DISTRO` 固定 `Ubuntu-24.04` | 换发行版需改公共层一处（已集中，优于原先两处）|
| e2e/attacks 仍在**同一文件**含平台分支 | 只抽了**公共层**；拆文件仍是 §22.5 的"不做" |

---

*2026-09-25 · S5: 抽公共层 tests/_platform.py（9 项自检含 3 负向；双平台逐行 diff 一致；含一次跨行正则事故的教训）*

---

## 28. ✅ S6 完成：T3 修复 + `_platform` 自检入门禁（2026-09-25）

### 28.1 🎯 发现：T3 的 preflight **必然失败**（**真缺口**）

```python
if KERNEL32.DebugActiveProcess(os.getpid()):     # <- **对自身附加**
```
**Windows 禁止进程调试自身** -> 探针**必然失败** -> `debug_ok=False`
-> **T3 永远 SKIP**（实测: Windows 27P/1S 与 Linux 同，那个 SKIP 就是 T3）。

**后果（真缺口）**：T3 是 e2e 里**唯一**验证
"被附加调试器能否检出（MSG_DBG + exit 0xDB）"的用例 ->
**该路径从未被 e2e 验证**（C-1 只覆盖 Linux 侧）。

### 28.2 修法：探针换对象（**保留原意**）

| 项 | 原实现 | 修改后 |
|----|--------|--------|
| 探针对象 | **自身**（`getpid()`）| **派生的无害子进程** |
| 语义 | 不成立（自附加被禁）| **更准**（真实能力 = 能附加**别的**进程）|
| 泄漏防护 | 注释声明"零子进程" | `try/finally` **必杀探针** |

### 28.3 🔍 决定性诊断：本环境**不允许**调试进程

```
① 探针子进程 pid=6620 -> 存活=False（timeout 在此环境立即退出）
② DebugActiveProcess(pid) -> 返回 0, **GetLastError=5 (拒绝访问)**
   FormatMessage: "拒绝访问。"
```
**=> 本环境（自动化壳/沙箱）不允许调试其他进程**
（`ERROR_ACCESS_DENIED`）—— 这是**环境能力限制**，非"代码写错"、非"未做"。

**处置**：保留 SKIP，但**原因串写准**（带错误码）：
```
SKIP: env denies process debugging (winerror 5/0x5); 保留 SKIP（环境限制，非未做）
```
> **为什么带错误码**：后人看到 `winerror 5` 即可判断"是环境还是代码"，
> **无需重跑诊断**。原串 "no debug session support in this env" 太笼统 ——
> 无法区分"环境限制"与"探针写错"。

### 28.4 附带修正：Linux 侧 T3 = **PLATFORM_NA**（**语义错位**修正）

加守卫前，Linux 侧会跑 **Windows 路径**（`cmd /c` 探针 + KERNEL32）
-> 报出 `winerror 5` —— **语义错位**（把 Windows 错误码当成 Linux 的原因）。

**正确处置**：
```
if _PLATFORM != 'win':
    T3 = PLATFORM_NA，并**指向** Linux 的真实覆盖:
      tests/attacks_linux.py 的**负向③**（ptrace 附加 -> debug_object=1）
```
> **不伪装成"跳过"** —— Linux 侧**本来就有覆盖**（C-1），
> 应该指向它，而不是留一个语义错位的 SKIP。

### 28.5 `_platform` 自检入门禁（第 **24** 项）

**为什么入门禁**：`tests/_platform.py` 现是 **e2e 与 attacks 的共同基础** ——
它若有缺陷，**两套测试同时失效**。其自检（**9 项含 3 负向**）随门禁常跑（只读、快）。

**门禁 23 -> 24 项**（`doccheck` 的对外数字已同步）。

### 28.6 ⚠️ 过程中的两次操作事故（**都与"改代码结构"有关**）

| # | 事故 | 根因 | 修复 |
|---|------|------|------|
| 1 | 守卫插到 `try:` **之后** -> `IndentationError` | **插入位置算错**（应在 try **之前**包住整个 try/except）| `git checkout` 回滚 + **行号区间**重做 |
| 2 | 替换锚点**按新文本写**（已回滚）-> 未匹配 | 回滚后文本回到**原版**，锚点却按 S6 版写 | 先**打印现状**再定锚点 |

> ### 🎯 教训（S5 事故的延续）
> 三次事故同一根源: **修改代码结构时的"位置/范围"判断出错**
> （跨行正则贪婪 / 插入点错 / 锚点与实际文本不符）。
> **统一对策**: 改结构前**先打印要改的区间**（`show` 一遍），
> 再按**行号**操作；替换锚点**必须取自当前实际文本**（不凭记忆）。

### 28.7 🔍 门禁 `mutate_check` 的"失败"结案（**再次确认**）

```
前次印象: 门禁 [X] mutate_check
本次实测: 门禁 **[ok] 检查器变异测试 (mutate_check)**
          （唯一失败 = git 工作区干净）
单独跑:   PASS（6 健康 / 0 盲）
受控实验: repro_check 与 example E1-E7 之后**均仍 PASS**（非触发项）
```
**=> 之前的失败是 §25 已记录的状态竞争**（我并发跑了 `ci_linux`），
**不是判据问题、也不是本阶段的改动引起**。已再次复现为通过。

### 28.8 验收

```
Windows 门禁: **23/24**（唯一失败 = git 未提交；**含 mutate_check [ok]**）
Linux ci_linux: 见下（串行）
e2e Linux:  **PASS 21 / FAIL 0 / SKIP 0 / NA 7**（T3 由 SKIP 转 PLATFORM_NA）
e2e Windows:**PASS 27 / FAIL 0 / SKIP 1 / NA 0**（T3 SKIP 原因已带错误码）
```

### 28.9 遗留

| 遗留 | 说明 |
|------|------|
| T3 在**有调试权限的环境**才能真跑 | 本环境 `winerror 5`；代码已就绪（探针语义正确）|
| Windows 调试检出路径**仍无自动化覆盖** | T3 是唯一入口，环境不允许 -> **真实边界**（非本次可解）|

---

*2026-09-25 · S6: T3 preflight 修复（探针换对象 + 错误码 + Linux PLATFORM_NA）+ _platform 自检入门禁（第 24 项）*

---

## 29. 📋 剩余边界**扩宽**分步计划（盘点驱动，2026-09-25，待确认）

### 29.1 边界的四条（来自 §28.9 / §23.5）

| # | 边界 | 性质 | 可扩宽? |
|---|------|------|--------|
| 1 | **6 项在线用例**（T22/T23/T25/T26/T27/T28）+ A12 未验证 | Linux **无 HTTP 能力** | ✅ 可（见 29.3）|
| 2 | **T3 真附加**（Windows 调试检出）| 环境 `DebugActiveProcess` = winerror 5 | ✅ **可**（见 29.2）|
| 3 | Windows 调试检出路径**无自动化覆盖** | 同 2 | ✅ 随 2 一并解决 |
| 4 | examples 的 flat 路径依赖 | §22.5「不做」| ⚠️ 独立范畴 |

### 29.2 🎯 盘点**新发现**: "创建即调试"在本环境**可行**（边界 2/3 可关）

**问题回顾**：`DebugActiveProcess(pid)`（附加**已有**进程）需 `SeDebugPrivilege`
-> 本环境返回 **winerror 5**。

**新发现（实验实测）**：
```
CreateProcess(cmd, ..., DEBUG_ONLY_THIS_PROCESS)
  -> **成功**（GetLastError=0），pid 正常
WaitForDebugEvent -> **收到 CREATE_THREAD(3) 事件**
=> **调试会话真的建立**，且**无需管理员**
```
**原理**：`DEBUG_ONLY_THIS_PROCESS` 是调试**自己的子进程** ——
子进程归调用者所有，**不需要** `SeDebugPrivilege`。

**=> T3 可以真正验证**（用"创建即调试"替代"附加"），
   而"Windows 调试检出路径无覆盖"**随之关闭**。

**待验证的最后一步（**这是计划的第一步，不预先假设**）**：
```
"创建即调试"时，demo 是否报 MSG_DBG + exit 0xDB？
```
  原型已确认会话建立，但**原型在喂 stdin 时挂起**（控制台输入句柄 + 继承句柄
  的组合问题）—— 那是**实现细节**，不是能力问题。
  **必须先证实"demo 会报"**，再决定是否改 T3（避免改完仍 SKIP）。

### 29.3 边界 1 的**关键技术判断**（**结论与 §22.5 不同**）

**§22.5 的原判断**：*"不用 libcurl（①不引入新依赖 ②诚实 ③可扩展）"*
-> 该判断**针对 libcurl 是对的**（第三方库）。

**但盘点发现**: Windows 侧用的是 **WinHTTP**（**系统组件**，非第三方）。
**对等的做法**是 Linux 用 **POSIX socket**（`<sys/socket.h>`，
**glibc 自带**，同样是系统组件）。
```
=> "用 POSIX socket 实现最小 HTTP" **不违背**原决策精神:
     · 不引入**第三方**依赖（与原决策一致）
     · 语义诚实（能实现就实现，不能则如实降级）
     · 与 Windows 的 WinHTTP **对等**（都是系统提供的网络能力）
```
**范围（**最小**）**：只需 demo 的两个用途 ——
`--check-url`（下载小 JSON 到内存）、`--blob-url`（下载 blob 到文件）。
```
支持: http://host:port/path 的 GET + Content-Length/Connection: close
不支持（如实降级）: https、重定向、分块传输、代理
```

### 29.4 分步计划（每步独立交付 + 独立验收）

| 步 | 内容 | 交付 | 验收 | 成本 |
|----|------|------|------|------|
| **W1** | **证实**"创建即调试"下 demo 报 MSG_DBG + 0xDB（原型，含 stdin 修法）| `tools/t3_dataprobe.py`（诊断脚本，非测试）| 打印 demo 的 exit code 与 MSG_DBG 命中情况 | 小 |
| **W2** | 若 W1 成立: e2e 的 **T3 改用"创建即调试"** | e2e 的 DebugAttacher 改造 | **T3 从 SKIP -> PASS**（真验证）；Linux 侧仍 NA（指向 C-1）| 中 |
| **W3** | Linux HTTP: `prot_platform_linux.c` 的 `prot_plat_http_get*` 用 **POSIX socket** 实现 | 平台层实现 + 单测 | `vm_unit`/契约测试绿；**Linux 侧 HTTP 可用**（本地 mock 验证）| **大** |
| **W4** | 在线用例**真跑**: e2e 的 6 项 + attacks A12 去 NA | — | **NA 7->0 / 1->0**；mock 服务器进 WSL（`tools/mock_http.py` **复活**）| 中 |
| **W5**（可选）| examples 的 flat 依赖适配（边界 4）| examples 改用平台路径 | example E1-E7 仍绿 + flat 目录可评估清理 | 中 |

**执行顺序**: W1 -> W2 -> W3 -> W4 ->（W5 视情况）
理由: W1/W2 先关掉"最小且已证实可行"的边界；W3 是**最大的**一项
（平台层新功能），单独做；W4 依赖 W3。

### 29.5 各步验收与总验收

| 项 | 当前 | 目标 |
|----|------|------|
| e2e（Linux）NA | **7**（T3 + 6 在线）| **0** |
| e2e（Windows）SKIP | **1**（T3）| **0** |
| attacks（Linux）NA | **1**（A12）| **0** |
| Windows 门禁 | 24/24 | **24/24**（每步后）|
| Linux ci_linux | 11/11 | **11/11**（每步后）|
| `_platform` / `check_state_platform` selftest | 9/9 / 6/6 | 不变 |

### 29.6 风险与**诚实边界**

| 风险 | 应对 |
|------|------|
| **W3 是平台层新功能**（不是测试改动）| 必须**含负向单测**（超时/超限/端口不可达 -> 如实报错）；**不得**为了"让测试通过"而放宽 HTTP 语义 |
| W1 可能证伪（demo 在"创建即调试"下不报）| 那 W2 **不做**，边界 2/3 **如实保留**（不强改判据）|
| W4 的 mock 服务器生命周期 | e2e 内 `try/finally` 确保 kill；每用例独立端口 |
| 并发状态争用（**已两次踩到**）| 验收**必须串行**（门禁与 ci_linux 不同时跑）|
| W3 违反"最小侵入"? | **不违反** —— POSIX socket 是 glibc 标准件（同 WinHTTP 的定位）；**仍不引入第三方库** |

**明确不做**（本计划范围外）：
· **https/TLS**（需 OpenSSL 的 TLS 栈 —— 那是**另一个量级**；`http://` 足够 demo 用途）
· **libcurl**（§22.5 的原决策保持）
· e2e/attacks **拆平台文件**（§22.5）

### 29.7 本计划与 §22 的关系

§22 是"**遗留项清理**"（把已实现的东西对齐/澄清）；§29 是"**能力扩宽**"
（新增平台能力 + 关闭真实验证边界）。**W3 是唯一的"新功能"**，
其余都是测试/澄清层面的对齐。

---

*2026-09-25 · §29: 剩余边界扩宽分步计划（W1-W5；关键发现: 创建即调试可行 + POSIX socket 不违背原决策）*

---

## 30. ⚠️ W1 结案：**证伪** —— 判据不成立，**W2 不做**（2026-09-25）

### 30.1 W1 的预期与实际

**§29.2 的乐观推断**（基于**会话建立**的实验）：
```
CreateProcess(DEBUG_ONLY_THIS_PROCESS) 成功 + 收到事件
=> "T3 可以真正验证"
```
**W1 的实测（`tools/t3_dataprobe.py`，**决定性**）**：
```
CreateProcess ok=True pid=26360 err=0
stdin 写入 19 字节
事件泵:
  [0.0s] #1 CREATE_PROCESS_DEBUG_EVENT (code=3) 
  [0.8s] no-event err=121 exit=259 out=0B
  ... （连续 25 秒，**0 个后续事件**）...
最终 exit=259 (0x103 STILL_ACTIVE)  事件数=**1**
stdout **0 字节** / stderr **0 字节**   <- 连启动横幅都没打印
```
**=> 判据（MSG_DBG + exit 0xDB）不成立**；进程**冻结在初始断点后不再推进**
（连 `CREATE_THREAD`/`LOAD_DLL` 事件都没有）。

### 30.2 结论：**本环境的调试能力不完整**（第二重证据）

| 证据 | 方式 | 结果 |
|------|------|------|
| ①（§28.3）| `DebugActiveProcess`（附加**已有**进程）| **winerror 5（拒绝访问）** |
| ②（W1）| `CreateProcess(DEBUG_ONLY_THIS_PROCESS)`（调试**自己的子进程**）| 会话**部分**建立（1 个事件）-> 进程**冻结** |

**=> 本环境（自动化壳/沙箱）的调试支持不完整** —— 不是"代码写错"，
也不是"没做"，而是**环境的真实限制**（两重独立证据）。

> ### 🎯 教训（**"部分成功"不等于"可用"**）
> 我在 §29.2 看到"CreateProcess 成功 + 收到事件"就推断"T3 可以真验证" ——
> **但那只证明"会话能建立一部分"**，不证明"**进程能正常跑**"。
> 正确的判据应是**端到端**的（"demo 能跑完并报出预期行为"），
> 而不是"能建立会话"。
> **这正是 W1 存在的意义** —— 计划里写明"**必须先证实，再决定改不改 T3**"，
> **避免了改完 T3 仍 SKIP 的返工**（以及"误判为环境不支持"的歧义）。

### 30.3 处置（**按计划的诚实纪律**）

| 项 | 处置 |
|----|------|
| **W2** | **不做**（W1 证伪）—— §29.4 已预先写明"If W1 成立才做" |
| **T3** | **保持 SKIP**，原因串已写准（`winerror 5`，§28.3）|
| 边界 2/3 | **如实保留**（环境限制，非可解项）|
| `tools/t3_dataprobe.py` | **保留**（**取证工具**）: 将来换环境时，跑它即可判断"W1 是否成立" |

### 30.4 边界 2/3 的**最终定性**

```
"Windows 调试检出路径无自动化覆盖"
  = **环境能力限制**（本环境不允许完整调试会话）
  · **不是**产品缺陷（demo 的检出自 0xDB/0xE4 等退出码与 C-1 已证有效）
  · **不是**测试缺口（T3 代码已就绪，换有调试权限的环境即真跑）
  · **已有替代覆盖**: C-1 负向③（Linux ptrace 附加 -> debug_object=1）
    —— 验证了**同一检出维度**（`debug_object`）
```

### 30.5 对 §29 计划的修订

| 原步 | 修订 |
|------|------|
| **W1** | ✅ 完成（**证伪**）|
| **W2** | ❌ **取消**（依赖 W1 成立）|
| W3-W5 | 不变（W3 是关掉 7 项 NA 的**唯一路径**）|

**=> 边界扩宽的重心落在 W3**（Linux HTTP）—— 那是**唯一能靠代码解**的边界。

---

*2026-09-25 · W1 结案: 证伪（判据不成立，W2 取消；边界 2/3 定性为环境限制）*

---

## 31. ✅ W3 完成：Linux HTTP（POSIX socket）+ 单测 + **T9 既有脆弱性**（2026-09-25）

### 31.1 交付：`prot_plat_http_get*` 的 **POSIX socket 实现**

**决策依据（§29.3 的关键判断）**：
```
§22.5 原决策: "不用 libcurl（不引入新依赖）" —— **针对 libcurl 是对的**（第三方库）
但 Windows 用 **WinHTTP**（**系统组件**）-> 对等做法 = Linux 用 **POSIX socket**
  （<sys/socket.h>，**glibc 自带**）
=> **不引入第三方依赖**（与原决策一致），且**与 Windows 对等**
```

**语义对齐（逐项对照 `prot_platform_win.c`）**：

| 项 | Windows（WinHTTP）| Linux（POSIX socket）|
|----|------------------|---------------------|
| 参数预检 | NULL -> `INVALID_ARG` | **同** |
| 大小上限 | `max_size` 或 **16 MiB** | **同** |
| 超限 | **删文件** + `INTERNAL` | **同** |
| 超时 | 3000ms | `SO_RCVTIMEO/SO_SNDTIMEO` **3s** |
| `get_mem` 边界 | `avail < cap` 才 OK | **同**（`body_len >= cap` -> `INTERNAL`）|
| https | 支持 | **`UNSUPPORTED`（如实，不假装成功）** |

**范围最小化**：只支持 `http://host[:port]/path` 的 GET；
**https / 重定向 / 分块 / 代理 -> 如实降级**（demo 的用途是内网 http）。

### 31.2 单测：`tests/http_platform_test.py`（2 正向 + **8 负向**）

```
ok P1 get_mem 正常下载（233 字节 JSON）      ok P2 get 下载到文件（字节一致）
ok N1/N1b https -> **如实 UNSUPPORTED**      ok N2 端口不可达 -> INTERNAL
ok N3/N3b 非法 scheme / 空 host -> INVALID_ARG
ok N4a-d NULL 参数 / cap=0 -> INVALID_ARG
ok N5/N5b 超 max_size -> INTERNAL + **文件已删**
ok N6 cap 过小 -> INTERNAL
```
**已接入 `ci_linux`（第 12 项）** —— 新能力必须有守护者。

### 31.3 🎯 永化单测**当场抓到**一个真实缺陷（**这就是它的价值**）

```
N6 cap 过小 -> INTERNAL   **原实现 got=OK**（want=INTERNAL）
```
**根因**：`get_mem` 在"**头已完整但体还没到**"的那次 `recv` 会算出
`body_len == 0`，而 `0 < cap` 成立 -> **报 OK 且内容为空**
-> **误报成功**（最危险的错误类型：调用方以为拿到了数据）。

**为什么临时脚本没抓到**：临时脚本的服务器把**头与体在同一次 TCP 段**发出
（本地、小体量）-> 一次 `recv` 同时拿到 -> `body_len > 0` -> 正常。
**永久化版本体更大（233B）且时序略不同** -> 分开到达 -> **暴露**。
> ### 🎯 教训（**"永久化"本身就是质量手段**）
> 临时脚本"跑过一次"**不等于**"被守护"。
> **把一次性验证变成常驻测试**这件事本身，就会**逼出隐藏缺陷**。

**修法（对齐 Windows 的 `avail < cap` 语义）**：`body_len == 0` **不算成功**，
继续 `recv`；连接结束仍无体 -> `INTERNAL`。

### 31.4 ⚠️ 顺带暴露并修掉 **T9 的既有脆弱性**（**非 W3 引入**）

**现象**：门禁里 `e2e` 失败 ->
```
T9 tamper-rdata  FAIL (exit=0)
```
**逐项排查**：
```
① e2e 单独            : PASS 27/28
② 门禁式构建后 e2e     : PASS（T9 exit=2989 = 0xBAD ✅）
③ repro_check 之后 e2e : **T9 FAIL（exit=0）**  <- 精确复现
④ 用 W3 **之前**的提交跑同一序列: **全绿** -> 一度判为"W3 引入"
```
**再查（关键数据）**：
```
门禁式构建 (-RecordSeeds): demo.exe **329080** 字节
repro_check (-SeedsFile) : demo.exe **327680** 字节（**布局不同**）
=> T9 的**固定偏移 +0x1000** 在布局 B 下落到了**未被 CRC 覆盖**的位置
```
**根因**：**T9 依赖固定经验偏移**（`+0x1000`）—— 而它与"CRC 覆盖范围"
**无必然关系**。W3 只改 `src/platform/prot_platform_linux.c`（**不参与
Windows 构建**），所以**不是 W3 的回归**，而是**既有脆弱性被暴露**
（W3 树上的构建布局恰好触发了它）。

> ### 🎯 教训（**"以前全绿"≠"现在没坏"**）
> 我用 worktree 跑"W3 之前的提交"得到全绿，就推断"W3 引入" ——
> **但那是单次采样的结论**。真正的原因是**布局敏感**:
> 同一份代码在不同构建布局下结果不同。
> **正确做法**: 判据**本身不能依赖布局**（见下）。

**修法（**两次**，第一次方向错）**：
| 尝试 | 做法 | 结果 |
|------|------|------|
| ① | 照搬 T4 的 `from_end=1`（翻 CRC 末字节）| ❌ **错**: `.rdata` CRC 末尾是 **IAT 名称表**（`"Heap"`/`"HeapSize"`/…**真实数据**）-> 翻转得 `0xC0000139`（**DLL 装载失败**）。T4 能用是因为 **`.text` 尾是 padding** |
| ② | **数据驱动**: `tamper_candidates()` 从 CRC **中段**向外扩散逐个试探，直到 demo 给 `0xBAD`；全失败则**如实 FAIL** | ✅ 两种布局均 PASS |

**验证（两种布局）**：
```
布局 A (-RecordSeeds): T9 PASS(2989)  T10 PASS(2989)
布局 B (repro 重建)  : T9 PASS(2989)  T10 PASS(2989)   <- 原失败条件已解
```
> **为什么不"放宽判据"**：`tamper_candidates` 全失败时**如实 FAIL**
> （暴露"该节无法被覆盖"的真问题），**不是**"改到过为止"。

### 31.5 验收

```
Windows 门禁: **23/24**（唯一失败 = git 未提交；**e2e/attacks/protchain 全绿**）
Linux ci_linux: **12/12**（新增第 12 项: HTTP 平台层单测）
e2e Windows: PASS 27 / FAIL 0 / SKIP 1（T9/T10 加固后两布局稳定）
```

### 31.6 诚实边界

| 边界 | 说明 |
|------|------|
| 只支持 `http://` | https 需 TLS 栈（**另一个量级**）-> 如实 `UNSUPPORTED` |
| 不支持重定向/分块/代理 | demo 用途不需；**不是**通用 HTTP 客户端 |
| `get_mem` 单次 `recv` 足够 | demo 的小 JSON 用途；大响应需扩展（**若 W4 需要再扩**）|
| `tamper_candidates` 最多 8 个候选 | 若布局极端，可能全部失败 -> **如实 FAIL**（不是 bug）|

---

*2026-09-25 · W3: Linux HTTP（POSIX socket）+ 12 项单测（含 8 负向）+ 顺带修掉 T9 既有脆弱性*

---

## 32. 🎯 W4 前置验证成功：Linux 在线路径**完全可用**（2026-09-25）

### 32.1 验证结果（**决定性**）

```
吊销当前 serial -> rc=228 (0xB1E4 低 8 位)  demo 输出: **online check: revoked** ✅
不吊销          -> rc=0                     demo 输出: **online check: ok**      ✅
服务端收到: REQ /v1/check?serial=DEMO-2026-ABCDEFGH&mid=183fb0e8a61eb2fa&tier=1&build=1.1.0
```
**=> W3 的 POSIX socket HTTP 真的在工作**（demo 的在线块执行了、
URL 构造正确、响应被解析、`revoked` 被识别）—— **7 项 NA 可以关**。

### 32.2 ⚠️ 过程中的关键教训（**环境变量跨不过 WSL 边界**）

**现象**：第一次验证时 demo 输出 `online check: **ok**`（服务端明明该吊销）。
```
服务端收到的路径: /v1/check?serial=DEMO-2026-ABCDEFGH&...   <- serial 就在路径里
但服务端判定: revoked = ('serial=%s' % REVOKE) in path
REVOKE 来自 **环境变量 W4_REVOKE** -> **没传进 WSL** -> None -> 永不吊销
```
**根因**：**Windows 的环境变量不会自动进入 WSL**（需 `WSLENV` 显式配置）
—— 我把 `W4_REVOKE` 塞进 `subprocess.Popen(env=...)`，那只影响
**`wsl.exe` 自己**，**不影响 WSL 内的进程**。

**修法**：改用**命令行参数**（`--revoke-serial <serial>`）—— 立即生效。

> ### 🎯 教训（**边界处要选最直接的通道**）
> 跨边界传参有三种通道: **①命令行参数 ②环境变量 ③文件**。
> · **命令行参数最可靠**（直接进 `wsl.exe` 的 argv -> WSL 内进程的 argv）
> · 环境变量**需额外配置**（`WSLENV`），**容易静默丢失**（且失败时无声）
> · 文件最通用但最重
> **与本项目既有教训同类**:
> · C-2/C-3「`bash -c` 会吞 stdin/退出码」-> **不经 shell 包装**
> · S1「服务器就绪 ≠ 被测程序会用它」-> **先确认通道两端都通**
> · **共同规律**: **边界处的通道选择是易错点，且失败往往静默** ——
>   要用**最直接**的通道，并在失败时**先怀疑通道**（而非怀疑被测逻辑）。

### 32.3 对 §29 计划的更新

| 步 | 状态 |
|----|------|
| W1 | ✅ 完成（**证伪**，W2 取消）|
| W2 | ❌ 取消（W1 证伪）|
| **W3** | ✅ 完成（POSIX socket HTTP + 12 项单测 + 修 T9 既有脆弱性）|
| **W4** | 🚧 **前置已验证成功，实施中**（复活 `mock_http.py` + 7 项去 NA）|
| W5 | ⬜ 待做 |

**W4 的确定方案**（基于本次验证）：
```
① `tools/mock_http.py` **复活**（WSL 内运行；**参数用命令行** —— 见 32.2）
   支持三类 handler（语义逐字复刻 e2e 的 start_*）:
     check / expect / blob
② e2e 的在线用例在 **linux** 侧改为: 起 WSL 内服务器 -> 用其 PORT 构造 URL
   -> demo（WSL 内）连接 -> 真验证
③ 删掉 `ONLINE_LABELS` 的 NA 机制（**NA 7 -> 0**）
④ attacks 的 A12 同法去 NA（**NA 1 -> 0**）
```

---

*2026-09-25 · W4 前置验证成功（Linux 在线路径可用 + "环境变量跨不过 WSL"的教训）*

---

## 33. ✅ W4 完成：在线用例**真跑**，NA 大幅归零（2026-09-25）

### 33.1 交付

| # | 改动 | 说明 |
|---|------|------|
| ① | **`tools/mock_http.py` 复活** | WSL 内运行；三类 handler（`check`/`expect`/`blob`），**语义逐字复刻** e2e 的 `_*Handler` |
| ② | 助手移入**公共层** `tests/_platform.py` | `WslMockServer` + `start_wsl_mock` —— **e2e 与 attacks 共用**（单一来源）|
| ③ | e2e 的 `start_*` **平台分派** | Linux 起 WSL 内 mock（同 loopback 才通）；调用方**零改动**（适配层吸收差异）|
| ④ | **删 `ONLINE_LABELS` + `_Results`** | 在线用例全过 -> NA 机制为空 -> **死代码删除**（不留失效判定逻辑）|
| ⑤ | attacks **A12 去 NA** | 改为真跑，与 Windows **同一判据**（无平台特例）|

### 33.2 烟测：三类 handler 全部正确（WSL 内 + 真 curl）
```
check(吊销)  -> {"status":"revoked","reason":"e2e"}
check(不吊销) -> {"status":"ok","tier":1}
expect(正确) -> {"status":"ok","tier":1,"expect1":"0x661a770a5c713b7e",...}（**复算**）
expect(错误) -> {"status":"ok","tier":1,"expect1":"0x1111111111111111",...}
blob        -> PROTVMB1...（真实 magic）
```

### 33.3 验收（**NA 归零**）

| 指标 | 之前 | 现在 |
|------|------|------|
| e2e（Linux）NA | **7** | **1**（仅 T3 = Windows 调试专用）|
| attacks（Linux）NA | **1** | **0** |
| e2e（Linux）PASS | 21 | **27**（6 项在线真跑）|

```
Linux e2e:   **PASS 27 / FAIL 0 / SKIP 0 / NA 1**
Windows e2e: PASS 27 / FAIL 0 / SKIP 1 / NA 0（零回归）
attacks:     **双平台 12 / 12 / NA 0**
门禁: **23/24**（唯一失败 = git 未提交）
ci_linux: **12/12**
```

**6 项在线用例真跑成功**（关键证据）：
```
T22 online-revoked   PASS (exit=228 = 0xB1E4 低 8 位)  <- **在线吊销真实生效**
T23 online-ok        PASS (exit=0)
T24 online-degrade   PASS
T25/T26 session      PASS (0 / 1)
T27/T28 online-blob  PASS (0 / 11)
```

### 33.4 过程中修的四处（**都是 NameError 类的接线问题**）

| # | 问题 | 根因 | 修 |
|---|------|------|----|
| 1 | `name 're' is not defined` | 我把 `start_wsl_mock` 写进 `_platform.py` 却没 `import re` | 补 import |
| 2 | `name 'to_wsl' is not defined` | **S5 正则事故**吞掉了 e2e 的 `to_wsl` 别名（当时 `_run_demo_wsl` 改走 `_plat` 未暴露）| 补别名 + 在 S5 记录基础上追加一笔 |
| 3 | `results = _Results()` 指向已删类 | 删机制后漏改调用点 | 改为 `[]` |
| 4 | A12 锚点用 `threading.Thread` 实际是 `_th.Thread` | **锚点没按实际文本写** | 按实际文本改 |

> ### 🎯 教训（**S5/S6 事故的第三次同类**）
> "改结构/删代码"时的**锚点与调用点**必须**同时更新** ——
> 本次四处都是**删/搬代码后残留引用**。
> **统一对策**（再次确认）: 改完立刻 `py_compile` + **grep 残留**（我做了，
> 但 `to_wsl` 那处漏在"靠 grep 已删符号"之外 —— 靠**运行时 NameError** 才暴露）。
> => **更可靠的一步**: 改完后**跑一次真实用例**（不只是编译）——
> NameError 类问题**编译发现不了**。

### 33.5 遗留

| 遗留 | 说明 |
|------|------|
| **T3 = 唯一 NA** | Windows 调试会话专用（本环境 `winerror 5`，§28.9 已定性为**环境限制**）|
| `mock_http` 与 e2e 的 handler 是两处实现 | 语义靠注释表格对齐；**以 e2e 为准**（判据来源）—— 若漂移，e2e 会先红 |

---

*2026-09-25 · W4: 在线用例真跑（NA 7->1 / 1->0）+ mock_http 复活 + 助手入公共层*

---

## 34. ✅ W5 完成：examples 适配 + **发现并修复 gen_padding 真实缺陷**（2026-09-25）

### 34.1 W5 的本职：examples 的 flat 依赖适配

| 位置 | 改动 | 结果 |
|------|------|------|
| `examples/tool_demo/build_example.ps1` | 5 处活跃（`license_pubkey` / `tool_check_blob` x3 / `strings.c`）| -> `demo\gen\win\`（**Windows 专用脚本**）|
| `tools/build_dotnet_gate.ps1` | 1 处活跃（`strings.c`）+ 错误提示文案 | -> `demo\gen\win\` |
| 注释同步 | 2 处 | 一致 |

**验收**：`example E1-E7` **ok**（门禁内实测）。

### 34.2 🚨 顺带发现并修复**真实缺陷**（**比 W5 本职更重要**）

**排查过程**（清点"谁还读 flat"）：
```
gen_padding 首选  dirname(--actual)/prot_sections.json -> build/ 与 build/linux/
                                       **两个都不存在**
回退        -> demo/gen/prot_sections.json（flat，**09-28 的 Windows 名字副本**）
=> **两平台构建都走回退** -> Linux 拿到 **Windows 的节名**（.gk9o791 等）
```

**后果（实测确证）**：
```
Linux 的 prot_padding.c 引用的节名 = **Windows 的名字**
-> gcc 把它们当**新节**创建 -> 真实的 protcrc/protcry/protpad **没有填充**
-> "尺寸归一化"对这些节**静默失效**
```

> ### 🎯 **判据盲区**（本节最重要的记录）
> 两道检查**都发现不了**这个问题：
> · `节名随机化` 查**产物**的节名（由 C 源 `PROT_SEC_*` 宏产生，
>   **与填充无关**）-> 照常通过
> · `文件大小统一` 只比 3 次构建**彼此**一致 —— **同样错 -> 同样一致**
>   -> 照常通过
>
> **教训**: "**自洽**" ≠ "**正确**"。当所有对象都以同一方式偏离时，
> 一致性检查**永远通过**。要发现这类缺陷，需要**独立的参照**
> （如"填充引用的节名 ⊆ 平台 json 的节名"）。

**修复**：
| # | 改动 |
|---|------|
| ① | `gen_padding` 加 `--sections-json`（**显式平台来源**）|
| ② | `build.sh` / `build.ps1` 传平台路径（`$GEN/prot_sections.json`、`$genDir\...`）|
| ③ | **移除 flat 回退** -> 缺失即 `return 2`（**响亮**，不静默、不猜）|
| ④ | `measure_sections` 的 flat 默认 -> `None`（调用方已传）|

**验证（字面量形式，实测）**：
```
win:   padding = .fzr44li/.hfp6u7x/.ih0oke8/.kn9ksuz = **本平台 4/4** ✅
linux: padding = .qae411j/.sv59d72/.xwdohuk         = 本平台 3 个
        （protxec 缺 = §21 已定: Linux 设计上无此节）✅
```

### 34.3 flat 目录的**评估结论**（§26.4 收尾）

```
可执行代码的活跃 flat 引用: **0 处**（default='demo/gen/...' 已全部移除）
仍存在的 11 处 = docstring / help 文本 / 注释（**不执行**）
`protchain.load_section_names` -> 用 `resolve_gen_paths`（**平台目录**）✅
与 win 的内容差异 = 仅少 `fptable` 键（S3 已移除）
```
**结论：flat 在可执行层面已死亡**（清理 = 删掉**旧的错误副本**，
避免重犯本节的缺陷）。

### 34.4 验收

```
Windows 门禁: **23/24**（唯一失败 = git 未提交；`example E1-E7` ok）
Linux ci_linux: **12/12**
Windows 构建 / Linux 构建: DONE（padding 用平台节名）
```

### 34.5 过程教训（**三次同类**）

| # | 事故 | 根因 | 教训 |
|---|------|------|------|
| 1 | 我从**截断的输出**拼锚点 -> 5 处不匹配 | 输出被 `[:84]` 截断 | **锚点必须取自文件本身**（读了再写）|
| 2 | `'--sections-json' in t` 判"已存在" -> 实际没加 | **注释里含该串** -> 子串假阳性（本项目第 3 次同类）| 判据要用**唯一结构形态**（`ap.add_argument('...`) |
| 3 | 三引号内嵌三引号 -> 脚本解析失败 | 嵌套字符串字面量 | 改用**小而精确的替换**（不整块写）|

> **共同规律**（贯穿 §27/§28/§34）: **"改代码结构"类操作的三重风险**
> —— 位置、范围、锚点。**对策**: 读了再改、按行号、改完立即
> `py_compile` + **跑真实用例**（NameError 类编译发现不了）。

### 34.6 ✅ flat 清理**已执行**（2026-09-29）

```
备份: %TEMP%/flat_backup_demo_gen_20260929_112707/  **38/38**
删除: 38 个 flat 文件
结果: demo/gen/ = ["linux", "win"]（**仅平台目录**）
```

**本轮共暴露 **2 处依赖**（**都是验证/运行抓住的，不是审计**）：

| # | 位置 | 现象 | 根因 |
|---|------|------|------|
| 1 | `tests/protchain_check.py` P4 | 门禁 `protchain P1-P6 [X]` | `join(REPO,'demo','gen','license_pubkey.c')` —— **分段拼接**（见下）|
| 2 | `tests/vmc_tests.py` | 清理后 flat **反复复活 2 个文件** | `GEN = join(REPO,'demo','gen')` 且 blob **唯一**写进它（其余 vmc 产物全在 BUILD）|

**修复**：
- P4 -> `resolve_gen_paths(_CURRENT_EXE)`（平台目录）
- vmc_tests: `GEN` -> 平台目录；blob_c/h -> **BUILD**（自包含）；
  编译补 `/I BUILD`（**MSVC 本会搜源文件目录所以测试本就过** ——
  补上是让**依赖显式**，防将来把 runner 挪走后静默失败）；顺带修 4 处
  `text=True` 的 `UnicodeDecodeError`（`cl` 中文输出 -> 读者线程崩溃；
  **既有问题**，改路径时首次看见 -> 修掉不留隐患）

**门禁抓到的依赖（验证救了它）**：
```
protchain P4 FAIL: license_pubkey.c missing
根因: os.path.join(REPO, 'demo', 'gen', 'license_pubkey.c')  <- **flat**
```

> ### 🎯 记名: **审计正则的盲区**
> 我的审计正则是 `demo[\\/]gen[\\/]<file>` —— **要求相邻斜杠**；
> 而 `join(REPO, 'demo', 'gen', x)` 是**分段** -> **未被捕捉**。
> => 审计报"活跃 0 处"，但实际还有 1 处。
> **同一问题有多种书写形态**，正则只能覆盖已知形态 ——
> **必须靠验证（门禁）兜底**。本次正是 `protchain P1-P6 [X]` 抓住的。
> （与 §17.2 "快照法找泄漏"同一教训的另一面: **机械工具覆盖面有限**，
>  **跑一次真实验证是不可省略的一步**。）

**修复**：`pub_path` -> `resolve_gen_paths(_CURRENT_EXE)`（平台目录）。

**验收**：门禁 **24/24** + ci_linux **12/12**（P4 `RSA-3072 verify ok`）。

---

*2026-09-25 · W5: examples 适配（活跃引用 6->0）+ 发现/修复 gen_padding 真实缺陷（判据盲区记名）*

---

## 35. 📋 下一阶段分步计划（D1–D4，2026-09-29，待确认）

### 35.1 现状盘点（**实测数据**，只读）

**① 代码卫生**
```
TODO/FIXME/XXX/HACK: **0 处**（代码行）
测试: 15 个文件（e2e 1152 行最大）
工具自检: **29 个**含 selftest
```

**② 门禁 vs ci 的覆盖不对称**（D1 的依据）
```
Windows 门禁 24 项  vs  Linux ci 14 项
未进 Linux 的关键项:
  · **mutate_check**     —— 检查器自证能抓错（**判据健康的验证**）
  · repro_check          —— 可复现构建
  · modcheck / conformance / attackcheck / skeleton_check /
    migration_gate / doccheck / comment_lint（7 个**纯逻辑**检查器）
探测结论: 这 7 个**不碰产物**（demo.exe 计数 0）-> **平台无关** ->
        **从未在 Linux 上验证过**（W3 的 HTTP 单测已证明这类补充能抓真缺陷）
```

**③ 反复出现的结构性问题**（D2/D3 的依据）
```
· **并发状态竞争**: 我已 **3 次**因并行跑门禁/ci 导致假失败（§25 已记 2 次）
· **判据盲区**: §34.2 的"padding 引用 Windows 节名"被两道检查**同时放过**
   （自洽 ≠ 正确）—— 根因已修，但**无守护**
· **flat 复活**: 清理后被 vmc_tests 复活 —— 根因已修，但**无守护**
```

**④ 攻防资产（D4 的依据）—— `docs/ATTACK_MATRIX.md`**
```
模块级统计（BLOCKED / PARTIAL / BREACHED / SKIP）:
  license    8 / 3 / **2** / 1     <- **2 处被突破**
  dbiguard   1 / 5 / **1** / 0     <- **1 处被突破**
  syscall    0 / 1 / **1** / 0     <- BLOCKED=0（**最弱**）
  antidebug  1 / 5 / 0 / 2
  integrity 10 / 5 / 0 / 0
  selfcrypt 10 / 4 / 0 / 0
  *(未映射)* 19 / 20 / 2 / 3 = 44 条攻击**未归模块**
合计: **3 处 BREACHED + 31 处 PARTIAL + 44 未映射**
```

### 35.2 分步计划（**顺序 = 流程基础 -> 判据加固 -> 覆盖补齐 -> 防护深化**）

| 步 | 内容 | 交付 | 验收 | 成本 |
|----|------|------|------|------|
| **D2** | **并发状态锁**：门禁与 ci 入口互斥（锁文件 + PID + 过期判定）| `tools/gate_lock.ps1`（或内联）+ 两侧接入 | ① 并发时**被拒绝并提示**（含持锁 PID）② 正常单跑 24/24 + 12/12 ③ 锁**不残留**（正常退出清理）| 小 |
| **D3** | **判据盲区固化为检查**（进 `check_state_platform`）| 2 个新检查 + **负向自检** | selftest **6 → 8**（每个新检查含 1 负向）；门禁仍 24 项 | 小 |
| **D1** | **Linux 侧检查器健康**：`mutate_check` 平台化 + 7 个纯逻辑检查器进 ci | mutate_check `--platform linux`（变异 `demo_linux`）+ ci 镜像 7 项 | ① Linux mutate_check **6 健康 / 0 盲**（**自证能抓错**，非"通过就完"）② ci 项数 14 → 21 ③ 双验收仍全绿 | 中 |
| **D4** | **攻防深化**：`BREACHED → BLOCKED`（3 处）+ PARTIAL 推进 | 每处: 复现 → 定位 → 修防护 → 回归 → 矩阵更新 | ① **3 处 BREACHED 全部转 BLOCKED**（或**定性为设计内边界**并记录）② 矩阵 `BLOCKED` 计数上升、`BREACHED` 归 0 ③ 双验收全绿 | 大 |

**执行顺序 D2 → D3 → D1 → D4**（理由: D2 先消除验证噪声 ——
我三次因并发把**真问题误判为状态竞争**；D2 之后所有测量才可信；
D3/D1 是小步加固；D4 最大且依赖可信的验证环境）。

### 35.3 各步的**关键设计**（要点，非细节）

**D2 并发锁**
```
· 锁位置: <repo>/build/.verify.lock（gitignored）
· 内容: PID + 启动时间 + 持有者（gate|ci）
· 过期: > 45 分钟视为 stale（陈旧锁自动清除，防死锁）
· 两侧入口: 拿不到锁 -> **明确报错**（含持锁者与已等待时长）而非排队
· 为什么"报错"而非"等待": 本项目要求**串行可预测** ——
  等待会把两个慢任务串成更慢的，且日志交错难读
```

**D3 两个新检查（+ 各 1 负向）**
```
① padding 节名 ⊆ 平台 json
   正向: demo/gen/<plat>/prot_padding.c 引用的自定义节名
        ⊆ demo/gen/<plat>/prot_sections.json 的生成名
   负向: 故意拿 **win 的 padding + linux 的 json** -> 必须 FAIL
        （这正是 §34.2 的缺陷形态）
② flat 目录无残留
   正向: demo/gen/ 根下**无文件**
   负向: 放一个假文件 -> 必须 FAIL（防"复活"回归）
```

**D1 mutate_check 平台化**
```
· `--platform linux`: mut 目标 -> build/demo_linux；cmd 加 `--platform linux`
  （protchain 另需 --exe 指向 demo_linux）
· **门禁与 ci 都调它**（同一工具，平台分派）
· 7 个纯逻辑检查器: 在 verify_linux_runtime 里**镜像**（与现有第 N 项同法）
```

**D4 的第一步 = **分类**（**先证实再改**，W1 纪律）**
```
3 处 BREACHED 必须先判定:
  (a) **真缺陷**（防护该挡而没挡）-> 修防护 + 回归
  (b) **设计内边界**（如"离线攻击本地文件本就不可防"）->
        如实写入矩阵的"已知边界"并说明**为什么在威胁模型内可接受**
分类错误的代价与 §30（W1 证伪）同 —— 不许直接改防护。
```

### 35.4 验收与总验收

| 项 | 当前 | 目标 |
|----|------|------|
| Windows 门禁 | 24/24 | **24/24**（每步后）|
| Linux ci 项数 | 14 | **21**（D1 后）|
| `check_state_platform` selftest | 6 | **8**（D3 后，含 4 负向）|
| ATTACK_MATRIX `BREACHED` | 3 | **0**（或全部定性为设计内边界）|
| 并发自测 | 无 | **D2 后: 并发被拒 + 无残留锁** |

### 35.5 风险与**不做什么**

| 风险 | 应对 |
|------|------|
| D2 锁**残留**导致后续全跑不了 | 过期判定 + `finally` 清理 + 自测含"锁不残留" |
| D1 的 mutate_check 在 Linux 上**改错字节位置** | ELF 段布局与 PE 不同（`0x2000` 未必是 .text）—— 按 `sections_of` 定位 .text 中部（**复用既有判据**）|
| D4 修防护**引入回归**（防护是核心）| 每处修完**立即**跑双验收 + 该模块既有用例全绿 |
| D4 分类可能长期"悬而未决" | 3 处有上限、逐条记名；**不因难解而跳过** |

**明确不做（本轮）**：
· https/TLS（**另一量级**）· libcurl · e2e/attacks 拆平台文件
· examples 的 Linux 化（`.ps1` + MSVC，独立范畴）
· flat 的 docstring 提及统一（低价值，随时可做）

---

*2026-09-29 · §35: D1-D4 分步计划（顺序: D2 锁 -> D3 判据加固 -> D1 覆盖补齐 -> D4 防护深化）*

---

## 36. ✅ D2 完成：并发状态锁（2026-09-29）

### 36.1 解决的问题（**3 次实测误判的根因**）

门禁（`release_check.ps1`）与 `ci_linux.ps1` **共享可变状态**
（`demo/gen/`、`build/`、`demo/vm_build.json`）—— 并发执行时互相污染 ->
**假失败**（把判据本身误报为坏的）。本项目已**3 次**因此误判
（§25 记录 2 次 + 后续 1 次）。

### 36.2 交付

| 组件 | 说明 |
|------|------|
| `tools/verify_lock.ps1` | **锁本体** + `-Selftest`（6 项，**3 负向**）|
| `release_check.ps1` | param 后 acquire + `try{...}finally{release}` |
| `ci_linux.ps1` | 同上 |

**语义**（实测 7 项全过）：
```
① 首次获取 rc=0            ② 并发获取 **rc=1** + 打印 持有者/PID/时长
③ 非持有者释放 **不动锁**   ④ 持有者释放后锁消失
⑤ 过期锁(46min)自动清除     ⑥ 释放后无残留  ⑦ 最终无残留
```

### 36.3 关键设计（**都是实测驱动的**）

**① 释放放 `finally`**（**先实测再定**）
```powershell
PowerShell 实测: finally 在 **`exit` / `throw` / 正常结束** 三种路径**都执行**
=> 释放**不依赖"记得释放"**（即使脚本 `exit 1` 也不漏）
```

**② 自检用**独立锁文件**（接入门禁前发现的隐患）
```
隐患: Selftest 第一句 `Remove-Item $LOCK`（干净起点）->
     若在**门禁运行中**执行 -> **删掉门禁自己的锁** -> 门禁中途**失锁**
     -> **互斥失效**（正是 D2 要防的）
修: 加 `-LockPath`，自检全程用 `build/.verify.lock.selftest`
```

**③ 加 `-Quiet`**（消除日志噪音）
```
现象: 自检的 T2「[lock] 拒绝」打进了**门禁输出**
     -> 读者会误以为**门禁被拒**
根因: `Write-Host` 走 PS 5.1 **宿主 UI 流** -> `| Out-Null` **捕获不到**
修: 信息行统一走 `Out-Lock`（受 `-Quiet` 控制），自检子调用加 `-Quiet`
```

**④ `finally` 跨行 `-f` 语法**（本项目"PowerShell 语法"的第 N 坑）
```powershell
     ('{0} 已占 {1:N1} 分钟'
      -f 'g', 1.5)          <- **Missing closing ')'**（实测）
根因: 换行续接要求上一 token 是**运算符**；引号字符串是完整表达式 ->
     新行的 `-f` 被当新语句
修: **-f 与格式串同行**
```

**⑤ `$MyInvocation.MyCommand.Path` 在**函数内为 null** -> 用 `$PSScriptRoot`**

### 36.4 验收

```
selftest:        **6 项（含 3 负向）PASS**，且**不动真锁**
真实并发互斥:    门禁运行中起 ci -> **rc=1**，消息含 持有者/PID/时长
锁生命周期:      门禁 获取 -> 运行 -> 释放 -> **无残留**
锁放 build/ 安全: 全仓**无整体清空 build/** 的代码（扫描 0 处）
门禁:            **25 项**（新增第 25 项「验证互斥锁自检」）
                 唯一失败 = git 未提交（预期）
自检噪音:        已消除（-Quiet）
```

### 36.5 本步修的 4 个接线问题（**都靠解析/实测抓住**）

| # | 问题 | 根因 |
|---|------|------|
| 1 | `Missing closing ')'` | 跨行 `-f`（见 36.3④）|
| 2 | `Missing closing '}'` | 我拼 finally 块时**漏了最后的闭合 `}`** |
| 3 | `$MyInvocation` null | 函数内不可用（见 36.3⑤）|
| 4 | param 列表缺逗号 | `$Quiet` 后**少一个逗号** |

> **共同对策**（本项目一贯纪律）: 每次改完**立即 `ParseFile` 校验**（而非
> 等门禁）—— 这 4 个都是**语法级**问题，parse 一步就抓到了。

### 36.6 遗留

| 遗留 | 说明 |
|------|------|
| 锁**不覆盖**直接跑 `build.sh`/`build.ps1` | 计划范围 = 门禁与 ci 两侧；裸构建并发仍无保护（**低概率**，已记） |
| 锁在 `build/` | 若未来出现"整体清空 build/"的脚本会被抹 —— 当前扫描 **0 处**（有检查即可随时发现）|

---

*2026-09-29 · D2: 并发状态锁（自检 6/6 含 3 负向；真实并发互斥实测；finally 释放；门禁 25 项）*

---

## 37. ✅ D3 完成：判据盲区固化为检查（2026-09-29）

### 37.1 解决的问题（**§34.2 的守护**）

§34.2 实测: Linux 的 `prot_padding.c` 引用 **Windows 的节名** ——
两道既有检查**同时放行**:
```
节名随机化  -> 查**产物**（由 C 源 PROT_SEC_* 宏产生，**与填充无关**）
文件大小统一 -> 只比 3 次构建**彼此**一致（**同样错 -> 同样一致**）
=> "**自洽 ≠ 正确**"（根因已修，但**无守护** -> 将来可静默复发）
```

### 37.2 交付（进 `tools/check_state_platform.py`）

| # | 检查 | 判据 |
|---|------|------|
| ① | **`check_padding_names`** | `prot_padding.c` 引用的节名 ⊆ **本平台 json ∪ 标准节**（`.text`/`.rdata`，与 `gen_padding.PADDABLE` 一致）|
| ② | **`check_flat_clean`** | `demo/gen/` 根下**无文件**（只有 `win/`、`linux/` 子目录）—— 防 §34.6 的"复活"回归 |

两者都 **抽成独立函数** -> 自检可直接喂任意路径（**不依赖仓库状态、不污染真目录**）。

**实跑输出**：
```
[win]   ok  4/4 section names applied; expect consistent; pad=ok; flat=ok
[linux] ok  3/4 section names applied; expect consistent; pad=ok; flat=ok;
          info: optional sections absent by design: protxec=.by9vyzs
[check_state_platform] PASS (2/2)
```

### 37.3 自检 **6 -> 8**（1 前置 + 1 正向 + **6 负向**）

```
T1 正向  linux 产物 + linux 生成物 -> PASS
T2 负向  linux 产物 + **win json**  -> FAIL（cross-platform mismatch）
T3 负向  win 产物 + linux json       -> FAIL
T4 负向  文件缺失                    -> FAIL（不崩溃）
T5 负向  expect 不一致               -> FAIL **且因 expect**（防"因错原因通过"）
T6 负向  **padding(win) + json(win)** -> FAIL
         detail: padding 引用**非本平台**节名: ['.9onmfzm', '.f3ha352', '.wwn4fl6']
T7 负向  **flat 出现文件**            -> FAIL
         detail: flat 文件复活... ['stray.c']
[check_state_platform-selftest] PASS: 1 前置 + 1 正向 + **6 负向**均可自证
```

> **T6 的构造刻意复刻 §34.2 的缺陷形态**（win 的 json + linux 的 padding）
> —— 这是"**用真实发生过的缺陷形态做负向**"，比造一个抽象错配更有力。
>
> **T7 在临时目录造**（**不碰真 demo/gen**）—— 否则自检中断会留污染。
> 这与 §34.6 清理时"先备份再删"是同一条纪律。

### 37.4 验收

```
selftest:   **8 项**（1 前置 + 1 正向 + 6 负向）
实跑:       PASS (2/2)，新输出含 `pad=ok; flat=ok`
门禁:       **25 项**（构建状态自检 ok；唯一失败 = git 未提交）
```

### 37.5 遗留

| 遗留 | 说明 |
|------|------|
| `check_state_platform` 只在**门禁**跑 | ci_linux 未含（其内容跨平台、门禁已覆盖双平台目录）—— **有意**，避免 ci 变长 |
| 标准节白名单 `STD_PAD_SECTIONS` | 若将来 `gen_padding.PADDABLE` 加新标准节，此处需同步（**不改会 FAIL-loud**，不会静默漏）|

---

*2026-09-29 · D3: 判据盲区固化（padding ⊆ json + flat 无残留；selftest 6->8 含 6 负向）*

---

## 38. ✅ D1 完成：Linux 侧检查器健康（2026-09-29）

### 38.1 解决的两个**覆盖缺口**

```
① 只跑 ci_linux 时，**7 个纯逻辑检查器完全不被验证**
   （modcheck / conformance / attackcheck / skeleton /
     doccheck / comment_lint / drills —— 此前只在 Windows 门禁跑）
② **Linux 侧的检查器从未自证能抓错**
   （"判据可能已变盲"没有守护 —— 与门禁侧的 mutate_check 不对称）
```

### 38.2 交付

| # | 改动 | 说明 |
|---|------|------|
| ① | `mutate_check --platform linux` | **Linux 侧变异表**（6 个: modcheck/drills/doccheck/**protchain/e2e/attacks**）|
| ② | `mut_demo_linux()` | 按 `sections_of` 定位 `.text`，取**非掩码**字节 |
| ③ | `ci_linux` 镜像段 | **7 个纯逻辑检查器** + 变异测试，**并入最终判定** |

**验收**：
```
mutate_check --platform linux: **健康 6 / 盲 0**  ✅
mutate_check（win）:            健康 6 / 盲 0     ✅（零回归）
ci_linux:                       **PASS**（运行时 12 + 镜像 7 + 变异 1）
门禁:                           24/25（仅 git 未提交；mutate/锁自检均 ok）
```

### 38.3 🔍 过程中**两次误判**（都靠受控实验纠正）

**误判 ①「掩码区」**（我先假设 `.text 中部` 落在掩码区被 P2 掩盖）
```
受控实验 A: 设 _CURRENT_EXE 后
  掩码区 = 5 个（0x63d0/0x8e20/0x7840/0x7920/0x7600，相对 .text 10704..22762）
  选非掩码 rel=17231 -> **P2 FAIL: .text crc 0xe2d05d6f != baked 0xd00df2a6** rc=1
  => **修复方向正确**（非掩码字节 = P2 的检测域）
```

**误判 ②「实验自身有缺陷」**
```
受控实验 B（我先前那次）打印"掩码区数=0" —— 错的：
  `selfcrypt_meta` 内部走 `cry_section_names()` -> 读 `_CURRENT_EXE` 决定的 json
  我**没设 `_CURRENT_EXE`** -> 读成 **Windows json** -> Linux 掩码算成 0
  而真正的 `mut_demo_linux` 里同样漏设 -> 选的"非掩码"字节 rel=17157
  **其实在 16160..17231 掩码区内** -> 被 P2 清零掩盖 -> **假报"盲"**
```
> **本步最核心的教训**
> **复用某模块的函数时，必须连同它的隐式上下文一起设**。
> `selfcrypt_meta(data, secs)` 看起来"纯数据驱动"，实际**隐含 `_CURRENT_EXE`**
> -> 同一函数在两个调用点**算出不同结果**（0 vs 5 个掩码）。
> 我因此被**自己的实验**误导了一轮（先下"掩码"结论、又发现"实验没设参"）。
> **对策**: 实验必须**与被测代码同路径**（我复用了函数，却漏了它的环境）。

### 38.4 变异目标的**域对齐**（为什么选"非掩码"字节不算作弊）

```
P2 的 CRC 计算: raw = .text -> **掩码区清零** -> crc32 -> 与烧录值比对
=> 静态 CRC **只承诺非掩码区**；掩码区的完整性由**运行期解密后**校验
（由 e2e/attacks 的域覆盖）
=> 变异打在掩码区 = **打到了检查器声明范围之外** = "域错配"，
   不是 protchain 缺陷。选非掩码字节 = **对齐其声明的范围**。
```

### 38.5 不镜像 `migration_gate` 的理由（**偏离计划并记录**）

```
实测: migration_gate **96s + 跑 2 次 Windows 构建**（demo.exe 引用=1）
=> 不是"纯逻辑"，与"Linux 端到端入口"定位不符
=> **已门禁第 22 项**覆盖；ci 不重复（计划 §35 列它为 7 项之一，此处**有意省略**）
```

### 38.6 遗留

| 遗留 | 说明 |
|------|------|
| `mutate_check --platform linux` 不覆盖 `vmc` | Linux 侧 vmc 检查器是 `tools/vmc_linux.py`（**不依赖 demo_linux**）→ 变异它无意义 |
| ci_linux 项数 | 12 运行时 + 7 镜像 + 1 变异 = **20**（计划预估 21；差异因 migration_gate 未镜像）|

---

*2026-09-29 · D1: Linux 检查器健康（mutate 6/0盲 双平台 + 镜像 7 项进 ci）*

---

## 39. ✅ D4 完成：攻防矩阵 BREACHED **逐条复核**（2026-09-29）

### 39.1 做法（**先分类，不直接改防护** —— §35.3 的 W1 纪律）

**6 条 BREACHED 逐条实测复核**（不是看文档，是**跑**）：

| id | 模块 | 复核方法 | 结论 |
|----|------|---------|------|
| **V3 台账注入** | unmapped | 用 `vmenc issue` 喂含换行/逗号/超长的 customer/note | **BLOCKED**：`_csv_safe` **5/5 拒绝**且**不写日志**；正常输入仍可用 |
| **S5 台账清洗** | unmapped | 读 `sdk_service/verify_ledger.py` | **PARTIAL**：`prev=sha256(上一行)` 哈希链已落地，**删/改中间行可检出**；残余 = 整文件删除（本机不可检）|
| L4 时钟回拨 | license | 查 `demo/main.c:468` | **BREACHED 确认**：只比本地时间；`monotonic_ns` **未用于过期判定** |
| L3 公钥替换 | license | 语义分析 | **边界**：文件可写 = 可自授权 = 离线授权**固有** |
| D5 DLL 劫持 | dbiguard | 语义分析 | **边界**：前提=目录可写 → **运营 ACL** |
| drill9.2 syscall | syscall | 语义分析 | **固有**：直调只规避用户态 hook |

### 39.2 🎯 关键发现：**矩阵记录会过时**

```
V3 的防御**早已落地** —— 同日提交:
  4553453 (2026-08-28) "feat(ledger-defense): landing D-D1/D-D2/**D-D4** from drill6"
函数 `vmenc._csv_safe` 的 docstring 就自述 "D-D4: 台账/license 字段卫生"
=> drill6 当日发现 -> **当日落地防御** -> **但表格没回填**
```
我起初以为 V3 是可修项，写了一段 `.replace('
','')` ——
**实测发现 `_csv_safe` 已先拒绝**（`raise VasmError`）->
我的修改成了**死代码** -> **已回滚**（不留死代码）。

> **教训（本条最有价值）**:
> **攻防矩阵是动态证据 —— 防御落地后必须同步回填**，
> 否则**持续低估自身能力**、并误导后续工作（我差点为此重复实现）。
> 与 §34.2「自洽 ≠ 正确」是**同一类**: 陈旧记录会掩盖真实状态。

### 39.3 结果（**6 → 4**）

```
更新为更好状态（回填实测）:  2 条
  · V3  BREACHED -> **BLOCKED**（_csv_safe 5/5 拒绝）
  · S5  BREACHED -> **PARTIAL** （哈希链可检出删改）
保持入册（实测确认仍为边界）: 4 条
  · L4 时钟回拨（**实测确认无单调防护**）
  · L3 公钥替换（离线授权固有）
  · D5 DLL 劫持（目录可写 = 运营 ACL 前提）
  · syscall（内核级攻击前无效，固有）
=> **符合 §35 目标**: "BREACHED 归 0 **或全部如实入册**"（余 4 条各有
   "为何在威胁模型内可接受"的**理由**，全部在册）
```

### 39.4 **不做**（有意，附理由）

| 项 | 理由 |
|----|------|
| 加固 **L4**（单调时钟）| 需引入 last-seen 持久化；**误报风险**（用户正常对时/NTP 校正会被拒）；当前**已作为威胁模型诚实边界入册**（文档 L27-28 明列）|
| 落地 **S5 整文件删除检测** | 需**外部锚点**（本机无法自证文件不存在）—— 属部署/运营层面，非代码 |
| 加固 **D5/L3/syscall** | 分别是运营 ACL / 离线授权固有 / 内核级固有 |

### 39.5 验收

```
矩阵: BREACHED 6 -> **4**（2 条回填为更好状态），4 条**全部入册**
drill6: 已加**指向**（不改写历史）
vmenc:  死代码已回滚（`issue --help` rc=0）
doccheck: PASS
```

---

*2026-09-29 · D4: BREACHED 6->4（V3→BLOCKED、S5→PARTIAL 实测回填；4 条如实入册）*

---

## 40. ✅ D4 续：PARTIAL 逐条实测复核（2026-09-29）

### 40.1 做法（延续 §39 的纪律：**实测复核，不轻信记录**）

盘点出 **13 条 PARTIAL**，逐条判定可推进性；对"残余问题明确"的
**V1/V2/S4** 做实测：

| id | 记录状态 | **实测结果** | 处置 |
|----|---------|------------|------|
| `drill6.V1` verify 工具 | PARTIAL（畸形公钥**崩溃**）| **已优雅**：`rc=1` + `vmenc: error: Expecting value...`，**无 Traceback** | **→ BLOCKED**（记录过时）|
| `drill6.S4` 重放 | PARTIAL（**无自动拦截**）| **`check_nonce_replay` 已落地**：同 nonce **默认拒绝**，`--allow-replay` 为显式逃生口 | **→ BLOCKED**（记录过时）|
| **`drill6.V2` vmenc 注入** | PARTIAL（负/超大 expires 未拒）| **确有缺陷**：`-1` / `10^30` / `4294967296` **全被接受并静默截断** | ✅ **已修** → **BLOCKED** |

### 40.2 V2 修复（**本轮唯一的真实修复**）

```
license_message: struct.pack('<I', expires & 0xFFFFFFFF)
  -1     -> 0xFFFFFFFF（2106 年）—— 签发者想设"已过期"，落盘是"2106 到期"
  10^30  -> 取低 32 位 —— 与意图无关
且**哈希链台账记的是原值**（未截断）-> **台账与产物不一致**（审计对不上）
```
**为什么算真缺陷**（drill6 记为"自伤"）：**授权语义错 + 审计不一致**，
不只是影响签发者自己。

**修法**（与 `_csv_safe`（D-D4）**同一模式**）：
```python
_expires_safe(v):  越界 [0, 4294967295] -> raise（**不截断**）
两个使用点都改（cmd_issue + cmd_sign）
```
**验收**：`-1`/`10^30`/`4294967296` → **rc=1 拒绝**；`0`/`2030` → 正常。

### 40.3 结果

```
PARTIAL 复核 3 条: 2 条记录过时（V1/S4 早已修）+ 1 条真缺陷（V2 已修）
=> 3 条全部 **→ BLOCKED**
门禁: 24/25（唯一失败 = git 未提交，**V2 修复零回归**）
```

### 40.4 未推进的 PARTIAL（**有意，附理由**）

| id | 为何不推进 |
|----|-----------|
| `L2` b64 鲁棒 | 已定性"**无安全影响**"（尾随垃圾<4 字符）→ 入册 |
| `S2` 伪造洪泛 / `S3` .req 篡改 | 记录即"**自损**"（绑假机器码 / 不产生有效授权）= **防御已成立** |
| `E5` VEH 覆盖 / `D3` | 环境受限或"无实际可利用性视为防御成立" |
| `R1-4` VM 模拟器还原 | **时间受限**（还原失败=成本高，本即 BLOCKED 语义）|
| `drill6.S5` 整文件删除 | 需**外部锚点**（非代码，运营层）|

---

*2026-09-29 · D4 续: PARTIAL 实测复核（V1/S4 记录过时、V2 真缺陷已修 -> 3 条 BLOCKED）*
