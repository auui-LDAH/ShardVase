# 下一阶段计划审查（2026-10-15）

> 口径：**33 份计划类文档逐条对代码/产物取证**（`build/_plan_audit.py` /
> `_next_stage{,2,3,4,5,6}.py` / `_spdx_gap.py`）。**不采信文档自述** ——
> 本仓库「陈旧状态行」是反复出现的缺陷类（§2.32 / §2.36 / §2.84 等第 21 例）。
> 用户 m37921 逐字：「继续推进，审查滚下一阶段计划」。
> ⚠️ **`hindsight_search_knowledge_pages` 不可达**（`ECONNREFUSED 127.0.0.1:9077`），
> 故本次审查**未使用记忆库**，结论全部来自现读。

---

## 0. 结论先行

**真正的「下一阶段」只有两项**（都在本仓库可闭环、都有可加的机器判据）：

| 序 | 项 | 依据 | 为什么是它 |
|---|---|---|---|
| **①** ✅ | **`docs/PILLAR2_OBSERVABILITY_PLAN.md` 阶段 4（完整性覆盖扩展）** — **已完成（2026-10-16）** | 阶段 1/2/3 + §15 已 ✅，**阶段 4/5 逐字 `⬜ 未做**（审查时）** | 第二支柱核心目标「让攻击者无法从产物静态判断这次开了哪些防护」**仍未达成**；阶段 4 是其中最有实质的一块 |
| **②** ✅ | **`tools/add_license_headers.py` 的 glob 缺口 + 一条 SPDX 门禁** — **已完成（commit d4f7a49）** | 实测 `.c`/`.h` **有 SPDX 41 / 缺 36**（审查时）；`release_check.ps1` 里 `SPDX` x0（审查时） | 缺的 36 个**几乎全是工具 glob 未覆盖的子目录**（一次改 glob 即可）；且**没有任何判据在看 SPDX** —— 与 §2.36.8 起的同型链条一致 |

**阶段 4 完成摘要（2026-10-16）**：基座 4 目标 + K∈[1,3] 每构建随机额外目标
（池 `{.rsrc,.reloc,protpad}`，排除 `.data`/`.protcry`/`.fptable`，理由在
`gen_sections.py` 注释）；变条目数经生成头三宏道；`check_crc_targets.py`
升至 18 判据 + 11 变异（M9-M11 新增）；A4 实测 20 种子 → 7 种覆盖集合。
链式 CRC（步 4.3，计划内可选）与**阶段 5** 仍 `⬜ 未做`。
SPDX 完成摘要：glob 递归化 + 95 文件补头 + 新 `spdx_check.py` 门禁
（三判据 + 9 自检，含 glob 缺口守卫），release_check 第 47 项。

**另有 3 处「陈旧状态行」需回填**（不是新工作，是记账纠偏）：§2 逐条列。

---

## 1. 候选逐条取证

### 1.1 ⬜ 真实未做，且本仓库可闭环

**A. PILLAR2 阶段 4 / 阶段 5**

`docs/PILLAR2_OBSERVABILITY_PLAN.md:697-702` 逐字：

| # | 项 | 状态 |
|---|---|---|
| 1 | 节名随机化 | ✅ 完成 |
| 2 | 组合归一化（节集合 + 尺寸填充）| ✅ 完成（文件尺寸**完全一致**）|
| 3 | 标注去自解释（magic 随机）| ✅ 完成 |
| **4** | **完整性覆盖扩展** | **⬜ 未做** |
| **5** | **检测项不可枚举（随机子集）** | **⬜ 未做** |
| §15 | 特征串归一化 | ✅ 完成 |

实证阶段 1 已生效：`build/demo.exe` 节名实测
`['.text','.pmp7vwb','.rdata','.data','.pdata','.okeebcb','.upnkt16','.pwayxsx','.fptable','.rsrc','.reloc']`。

**阶段 4 的验收（`:245` 逐字）**：

    A4: 未覆盖节数 = 0（或按随机策略 ≥N）；两次构建的覆盖集合不同

**阶段 4 的已知风险（`:251` 逐字）**：
「覆盖 `.protcry`（selfcrypt 密文区）会导致**自身改写触发误报** | 需排除
"运行期必然变化的区域"，或改为"校验后再解密"」
⇒ **这条风险本会话已有实测依据**（§2.80–§2.83 的 selfcrypt 驻留期密文态 +
`tools/selfcrypt_residency_check.py`），可直接复用。

**阶段 5 的做法（`:268-271`）**：`5.1 每构建随机选子集（如 12 项中选 7-10 项，
compile-time 随机）` / `5.2 等价变体（读 PEB / 系统调用 / 时序，随机选）` /
`5.3 伪装（未启用的检测项保留代码但返回固定值）` /
`5.4 子集与变体选择写入 demo/gen/prot_antidebug_sel.h`；
验收 `:275-276`「两次构建的启用项集合不同；产物中 12 项的实现代码**都存在**」；
风险 `:282`「**降低检测强度** → 设**下限**（如至少 8 项）；关键项
（`peb_being_debugged`）**强制启用**」。

⚠️ **阶段 4 的耦合面**（加第 5 个 CRC 目标会撞）：
`tools/hashpatch.py:47 MAGICS = (b'PROTCRCP', b'PROTCRCD', b'PROTCRDP', b'PROTCRCX')`
/ `:112 TARGET_NAMES = ('.text','.rdata','.pdata','.protxec')` /
`:183 ELF_TARGET_NAMES = ('.text','.rodata','.eh_frame')`；
`src/integrity.c` 的 `g_prot_baked_crc[4]` + 两处 `j < 4u` 循环；
**`tools/check_crc_targets.py`（440 行）本身是这条不变量的门禁** ——
其头部逐字「① `tools/hashpatch.py` MAGICS/TARGET_NAMES/TARGET_LOGICAL
② `src/integrity.c` `g_prot_baked_crc[]` 初始化顺序 + 两处 `j < Nu` 循环」，
且变异表**硬编码** `, b'PROTCRCX')`（`:358`）与 `g_prot_baked_crc[4]`（`:364`）
⇒ 加第 5 项须同步这三处。

**B. SPDX 头缺口（36 个 `.c`/`.h`）**

实测 `.c`/`.h`：**有 SPDX = 41 / 缺 = 36**。缺的几乎全是
`tools/add_license_headers.py:54-57` 的 glob **未覆盖的子目录**：

| 目录 | 缺 | 说明 |
|---|---|---|
| `tools/attacker/winpe_sympatcher` | 6 | glob 只收 `tools/*.py`（**单层**）|
| `tests/c2vasm_cases` | 6 | glob 只收 `tests/*.py`（单层）|
| `prot_sdk/skeleton` | 4 | glob 只收 `prot_sdk/**/*.py` |
| `tests` | 4 | `syscall_probe.c`/`vm_unit.c`/`vmc_case1_test.c`/`vmdetect_probe.c` |
| `examples/cross_platform/android` | 3 | |
| `tools/attacker/android_jniptrace` | 3 | |
| `examples/cross_platform` | 2 | |
| `tools/attacker/android_jniptrace/elfparse` | 2 | |
| `sdk_service/keys` | 2 | `pub-blob.c`/`pub-der.c` |
| `examples/tool_demo` / `prot_sdk/dotnet/Native` / `prot_sdk/showcase` | 各 1 | |
| **`include/protect`** | **1** | `prot_noise.h` —— **唯一在 glob 内却没加的** |

⚠️ `include/protect/prot_noise.h` 的 `SPDX` 偏移实测 **-1（完全不存在）**，
而它在 glob 内 ⇒ `add_c()` 应会加；dry-run 清单确实列着它。

`tools/add_license_headers.py` 现状：`C_FILES = glob('src/*.c') + glob('include/protect/*.h')`
（**只覆盖两层**）；`PY_FILES` 同（`tools/*.py` / `tests/*.py` 单层，
只 `examples/**` 与 `prot_sdk/**` 用了 `recursive=True`）。

dry-run 输出逐字：**合计 136 个文件，需添加 53**。

⭐ **且没有任何判据在看 SPDX**：`tools/release_check.ps1` 里
`SPDX` x**0** / `license-header` x**0**；46 个 `Check` 中含「许可/license」= **0 个**。
⇒ 与 §2.36.8 / §2.38 / §2.40 / §2.42 / §2.46 同型：**事实可得，但没有判据在用它**。

### 1.2 需外部条件 —— 本仓库无法闭环

| 位置 | 条数 | 阻塞条件 |
|---|---|---|
| `docs/HISTORY_REWRITE_PLAN.md:152-156` | 5 | **不可逆**（对真实仓库重写历史；`docs/OSS_TAIL_PLAN.md:28` 逐字标「**不可逆**」）|
| `docs/MEMPATCH_PLAN.md:105/107/108` | 3 | 需真机 root（`ptrace` 附加模式；`:107` 逐字「**代码就绪，真机未测**」）|
| `docs/DEFENSE_DEEPEN_PLAN.md:253` | 1 | 「回归：矩阵 + Defender + 真机闭环」需硬件 |
| `docs/PHASE2.md:123-130` | 8 | 真机验证项 |
| `docs/N1_PLAN.md:263` | 1 | 密文态 CRC（`PROTCRYP`）—— §2.37 已**定性为设计后果**（无密钥信任根的必然），非「忘了一个机制」|
| `docs/ANTIVIRUS_PLAN.md` | — | **VM 路线暂停**（用户手动接管安装）；下一步优先 **VirusTotal 手动上传静态矩阵（5 分钟，需人工）** |
| `docs/commercial/README.md:22-25` | 4 | 商务决策 |

⚠️ **`docs/OSS_TAIL_PLAN.md` ④「70 个源文件补 SPDX」标注「可逆」** ——
按 1.1-B 的取证，它**不是**需外部条件的项，应归入本仓库可闭环（只是工具 glob 要扩）。

### 1.3 陈旧状态行（**不是新工作**）

**C. `docs/GITHUB_PLAN.md:3` 写「规划完成，未开工」** —— 但步骤 2/3/4/5 的产物**已在**：

- `docs/marketing/` **12 个文件**：`landing.html`（7415 B）/
  `article-1-dump.md` / `article-2-license.md` / `article-3-integration.md` /
  `boundaries.md` / `attack-record.md` / `compat-av.md` / `LAUNCH_HANDBOOK.md` /
  `ISSUE_TEMPLATE_{consult,eval,security}.yml`
- `publish/` **8 个**；`.github/ISSUE_TEMPLATE/` **3 个**（bug/consult/security）
- `landing.html` 的 **8 个 `href` 全部指向真实仓库**：
  `github.com/auui-LDAH/ShardVase-demo/releases` /
  `…/ShardVase-docs` / `…/issues/new?template=eval.yml` /
  `…/issues/new?template=consult.yml` / `…/blob/main/boundaries.md`

⇒ 对应步骤 2（演示包）、3（Pages Landing）、4（Issues 模板）、5（3 篇文章）
**产物都在**；`docs/GITHUB_PLAN.md:80-83` 的 4 条 `[ ]` 未勾 = **陈旧**。
真正剩下的只有「**拍板 D1-D4**」与「**发布检查（红线）**」两件**人工**动作。

**D. `docs/WORKBENCH_ROADMAP.md` §30.8 的 L6 候选 —— 大部分已落地：**

| 候选 | 取证 |
|---|---|
| L6b Linux 构建链 | **`build.sh` exists=True（598 行 / B4 2026-09-25）**；头部逐字「保留 Python 工具步骤 + 把 MSVC 部分换成 gcc」|
| — 产物 | `build/linux/` 有 `vm.blob` 805 B / `license.txt` 619 B / `revoke_*.blob` 468 B / `section_baseline.json` 3545 B / `demo_tampered.exe` 108512 B |
| L6c 推送让 CI 实跑 | Linux job **已在** `.github/workflows/ci.yml:340 linux-portability`（**`ci-linux.yml` exists=False** —— 注释里提过它，实体是 job）|
| — 测试套件 | `tools/verify_linux_runtime.py` **14 个套件**（`Linux 产物就绪` / `构建 (build.sh)` / `vm_unit` / `平台层契约测试` / `端到端授权链` / `vmc` / `protchain` / `attacks_linux` / `attacks A1-A12` / `端到端 e2e T1-T30` / `HTTP 平台层单测 (W3)` / `节名随机化` / `文件大小统一`）|
| L6a 封装剩余 14 个 API | **需复核**：`include/protect/prot_platform.h` 声明 `prot_plat_*` = **40 个**（远超 §30.7 说的「14 个待封装」）|
| L6d `__readgsqword` Linux 重新设计 | 未见实现痕迹 |

**E. `docs/PLATFORM_ISOLATION_PLAN.md` 的 C-2/C-3 ⬜ 已过时**：
`tests/attacks.py:85 _PLATFORM = _plat.parse_platform(sys.argv)`、`:91 EXE = … if _PLATFORM=='win' else …`；`tests/e2e.py:93/99` 同、`:231-240` 委托 `_plat.run_demo_via_wsl`；`tests/_platform.py`（12972 B）含 `parse_platform`@`:53` / `to_wsl` / `norm_exit` / `norm_expect` / `fix_path_args` / `reap`@`:113` / `run_demo_via_wsl`@`:143` / `start_wsl_mock`@`:220`。
⇒ `:1005/1006/1100` 的 ⬜「C-2 attacks.py 移植 / C-3 e2e.py 全量移植」**已完成**。

**F. `docs/WORKBENCH_ROADMAP.md` §17.7（`:1410-1420`）写「W6 ⬜ 最后一项」**，
而 `§18`（`:1428`）标题逐字「W6 协议治理（2026-09-23 完成 —— 路线图最后一项）」
⇒ **同文件自相矛盾**，W6 已完成。

---

## 2. 推进顺序（第 3 项**已在本次审查中完成**）

1. **PILLAR2 阶段 4（完整性覆盖扩展）** —— 有实质防护收益；风险已本会话实测过
   （`.protcry` 误报）；须同步 `tools/check_crc_targets.py` 三处硬编码。**未开工**。
2. **SPDX：扩 `add_license_headers.py` 的 glob 到子目录 + 加一条门禁** ——
   一次改 glob 补齐 36 个缺口（`C_FILES`/`PY_FILES` 现为单层 glob）；门禁是
   「事实可得但无判据」链条的下一环。**未开工**。
3. ✅ **回填陈旧状态行 —— 本次已完成**（零代码风险，纯记账纠偏）：
   - `docs/WORKBENCH_ROADMAP.md:1420` W6 `⬜ 最后一项` ⇒ ✅（与本文件 `§18` 矛盾）
   - `docs/WORKBENCH_ROADMAP.md:2736-2741` §30.7 五条诚实边界 ⇒ 追加现读复核注
     （「未实现可运行的 Linux 产物」/「CI job 未实跑」已被推翻）
   - `docs/WORKBENCH_ROADMAP.md:2743-2747` §30.8 L6b/L6c ⇒ 标 ✅ 已落地
   - `docs/WORKBENCH_ROADMAP.md:3` 头部 ⇒ 追加现读复核注
   - `docs/GITHUB_PLAN.md:3` 状态行 ⇒ `v2 · 产物已就绪，剩人工决策`
   - `docs/GITHUB_PLAN.md:79-83` 待办清单 ⇒ 追加步骤 2/3/4/5 产物清单的注

**不建议我推进**：`docs/HISTORY_REWRITE_PLAN.md`（不可逆）、真机/root 类
（`docs/MEMPATCH_PLAN.md` / `docs/PHASE2.md` / `docs/DEFENSE_DEEPEN_PLAN.md`）、
商务类、以及 `docs/ANTIVIRUS_PLAN.md` 的 VM 段（用户已接管）。

---

## 3. 诚实边界

1. **本次审查未使用记忆库**（Hindsight 服务 `ECONNREFUSED 127.0.0.1:9077`）。
2. **「⬜/未做」的判读是两层的**：文档自述 + 代码取证。凡两者冲突，
   以**代码取证**为准（本文件全部结论均附文件路径与实测值）。
3. **未穷尽全部 33 份**：只对「有未勾 / 有未做标记 / 状态行含未开工待确认」的
   15 份做了取证；其余 18 份状态行为「✅ 全部完成」且无未勾，**未逐条复核其完成度**。
4. `docs/WORKBENCH_ROADMAP.md` §30.7 的「**只实现平台层，未移植模块**
   （14 个 API 待封装）」与 `prot_platform.h` 实测 **40 个** `prot_plat_*` 冲突 ——
   **本条只记名，未判定谁对**（需逐函数核对「已实现 vs 仅声明」）。
5. **阶段 4 未开工**：以上均为**审查结论**，未写任何代码。

---

*2026-10-15 · 33 份计划文档审查；证据脚本：`build/_plan_audit.py` /
`build/_next_stage{,2,3,4,5,6}.py` / `build/_spdx_gap.py` / `build/_todo_census.py`*
