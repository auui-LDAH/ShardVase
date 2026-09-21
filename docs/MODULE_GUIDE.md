# MODULE_GUIDE — 写一个模块（阶段5: 生态化）

> 面向想给 ShardVase **贡献新防御模块**的开发者。
> 读完本文你应当能独立完成一个模块并通过准入检查。
>
> 关联：`docs/MODULAR_ARCH.md`（架构与四条设计原则）、
> `modules.json`（模块注册表）、`tools/modcheck.py`（准入检查器）、
> `src/_template.c` + `include/protect/_template.h`（模板）。

---

## 0. 先明确：什么适合做成模块

**适合**：

- 一个新的**检测维度**（如：检测进程被页保护异常、检测特定调试器特征）
- 一套新的**保护机制**（如：新的代码变换、新的完整性算法）
- 一个新的**验证方式**（如：新的授权载体）

**不适合**（请先讨论）：

- 修改现有模块的内部实现 —— 那直接提 PR，不需要新模块
- 需要内核驱动的能力 —— 超出本项目用户态边界（见 `publish/06-诚实边界.md` B5）
- 只是为了"多一个检测项"而拆分 —— 低耦合是这个项目的优点，别为了拆而拆

---

## 1. 四条硬约束（架构原则的具象化）

来源：`docs/MODULAR_ARCH.md` §1。它们不是风格偏好，是项目**用事故换来的**。

### P1｜语义等价必须可验证，不能靠"看起来一样"

新增模块若改变了 `.text` 布局（几乎必然），必须重新生成 selfcrypt mask 与
三段 CRC。构建管线已自动化，但**你必须跑完整构建验证**，不能只看编译通过。

> 历史事故：一次"骨架一致"的整文件重建能编译，但 `e2e T1` 失败。

### P2｜页粒度与布局是硬约束

如果你的模块**会改写代码或数据**，必须在注册表里如实声明
（`modifies_text` / `verifies_text` / `page_align`）。

> 历史事故：`revoke` 因与 `main` **同页**，`VirtualProtect` 切 RW 会
> 禁执行 `main` 导致自伤 —— 至今**永久排除**在 selfcrypt 之外。

### P3｜门禁绕过路径会掩盖真实缺陷

新模块必须能被**独立验证**。不要依赖"整体门禁会跑到"。

> 历史事故：`build.ps1` 的 smoke 测试**必然失败**却被掩盖一个月，
> 因为所有自动门禁都带 `-SkipSmoke`。

### P4｜诚实边界是资产，不是弱点

注册表的 `known_limits` 是**强制字段**。你必须写下这个模块**挡不住什么**。

> 这不是自曝其短 —— `publish/06-诚实边界.md` 是本项目最有力的对外材料。

---

## 2. 五步落地

### 第 1 步：写代码

```powershell
copy src\_template.c              src\<your_module>.c
copy include\protect\_template.h  include\protect\<your_module>.h
```

然后改名为你的模块（如 `syscall2` → `prot_syscall2_*`）。

**命名约定**：

| 项 | 约定 | 例 |
|----|------|-----|
| 源文件 | `src/<模块名>.c` | `src/dbiguard.c` |
| 头文件 | `include/protect/<模块名>.h` | `include/protect/dbiguard.h` |
| 函数 | `prot_<模块名>_<动作>` | `prot_dbiguard_scan` |
| 报告结构 | `prot_<模块名>_report` | `prot_dbiguard_report` |

**函数形状**（三个检测器共用，你的模块也应遵循）：

```c
prot_status prot_<mod>_scan(prot_<mod>_report* out);      /* 采集, 永不失败 */
uint32_t    prot_<mod>_suspicious(const prot_<mod>_report*);  /* 判定 */
prot_status prot_<mod>_apply_policy(prot_policy pol);     /* 响应 (可选) */
```

> **咨询项模块请删掉 `apply_policy`** —— 参考 `dbiguard`/`vmdetect`：
> 它们只报告不阻断（误杀成本高）。

**依赖纪律**：头文件只 `#include "protect/protdef.h"`。
需要别的模块？在注册表 `deps` 里声明，而不是在头文件里互相包含。

### 第 2 步：登记到 `modules.json`

```json
"<your_module>": {
  "source": "src/<your_module>.c",
  "header": "include/protect/<your_module>.h",
  "caps": ["detect"],
  "phases": ["scan", "decide"],
  "deps": [],
  "exports": ["prot_<mod>_scan", "prot_<mod>_suspicious"],
  "page_align": false,
  "modifies_text": false,
  "verifies_text": false,
  "needs_writable_dir": false,
  "known_limits": ["必须写: 这个模块挡不住什么"],
  "evidence": "docs/<你的演练文档>.md"
}
```

字段含义（完整定义见 `docs/MODULAR_ARCH.md` §3.1）：

| 字段 | 取值 | 说明 |
|------|------|------|
| `caps` | `detect`/`prevent`/`conceal`/`verify`/`respond` | 能力位 |
| `phases` | `init`/`scan`/`decide`/`enforce`/`watch` | 参与阶段 |
| `deps` | 模块名数组 | 依赖的其它模块（须先就绪） |
| `modifies_text` | bool | **会改写 `.text`** → 与 `integrity` 冲突 |
| `verifies_text` | bool | 校验 `.text` → 与 `modifies_text` 模块冲突 |
| `page_align` | bool | 需独占页（防 P2 的 VP 自伤） |
| `needs_writable_dir` | bool | 要求安装目录可写（部署约束） |
| `known_limits` | 字符串数组，**不得为空** | 已知边界（P4） |

### 第 3 步：接入宿主

在**两个**宿主文件里加条件编译调用段：

- `demo/main.c`（演示程序）
- `prot_sdk/skeleton/app_main.c`（SDK 骨架）

```c
#ifdef PROT_MOD_<YOUR_MODULE>
    {
        prot_<mod>_report rep;
        prot_<mod>_scan(&rep);
        if (selftest) { /* 打印各项 */ }
        if (prot_<mod>_suspicious(&rep)) {
            /* 咨询项: 只提示; 关键项: 按策略 */
        }
    }
#endif /* PROT_MOD_<YOUR_MODULE> */
```

> ⚠️ **两个宿主都要加**。只改一个会导致另一个在排除该模块时链接失败
> —— 这正是我们在阶段 4 踩过的坑（`dbiguard` 主流程段未被包裹，
> `standard` 组合链接失败）。

### 第 4 步：补演练记录（准入要求）

**每个防御模块必须至少有一条 drill 记录**（阶段 3 准入纪律）。
在 `drills/` 下新增 JSON：

```json
{
  "drills": [{
    "id": "drillN.<序号>",
    "attack": "patch_function_head",
    "target_module": "<your_module>",
    "method": "具体手法 (可执行描述)",
    "prerequisite": "前置条件; 无则 null",
    "result": "BLOCKED",
    "result_detail": "实测说明",
    "severity": "low",
    "countermeasure": "生效的缓解机制; 无则 null",
    "known_limit": false,
    "evidence": "docs/<演练文档>.md §X",
    "date": "YYYY-MM-DD"
  }]
}
```

取值见 `drills/_schema.json`。`result` 必须是
`BLOCKED`/`PARTIAL`/`BREACHED`/`SKIP`；`attack` 须在 taxonomy 内。

> **如果你无法让攻击失败**：如实写 `BREACHED` 并给出 `prerequisite`。
> 一条诚实的 BREACHED 记录比一条假的 BLOCKED 有价值得多。

### 第 5 步：跑准入检查

```powershell
python tools\modcheck.py                    # 注册表漂移 + 演练覆盖
python tools\modcheck.py --compose standard # 你的模块加入组合后是否自洽
powershell -File build.ps1 -Config Release  # 完整构建
python tests\e2e.py; python tests\attacks.py
```

**准入门槛**（全绿才算完成）：

| # | 检查 | 命令 |
|---|------|------|
| 1 | 注册表与源码一致 | `python tools\modcheck.py` |
| 2 | 演练记录存在且合 schema | `python tools\drills.py lint` |
| 3 | 组合自洽 | `python tools\modcheck.py --compose standard` |
| 4 | 构建成功 | `build.ps1` |
| 5 | 回归全绿 | `e2e` + `attacks` + `release_check.ps1` |

---

## 3. 常见陷阱（本项目已踩过的）

| 陷阱 | 症状 | 处理 |
|------|------|------|
| **页冲突自伤** | 加密/改权限后进程崩 | 声明 `page_align`；确认不与 `main` 同页 |
| **布局敏感** | 间歇性 `0xBAD` | `.text` 变化后必须重建 mask/CRC（管线自动）；别手工改源文件顺序 |
| **只改一个宿主** | 某组合链接失败 | `demo/main.c` 与 `app_main.c` **都要**加 `#ifdef` |
| **静默吞错** | 检测失败当"没问题" | 检测函数返回 `PROT_OK`，但单项失败要保持 0 并**报告**，不能假装正常 |
| **声明与实现不符** | `modcheck` 报漂移 | 那是检查器在工作 —— 改注册表或改代码，别改检查器 |
| **`.ps1` 丢 BOM** | PS 5.1 报一堆语法错误 | 改完 `.ps1` 后确认首 3 字节是 `EF BB BF` |

---

## 4. 一个最小完整示例

最短的合规模块长这样（参照 `dbiguard`，共 4 个文件改动）：

```
src/mycheck.c                        # 实现: scan + suspicious
include/protect/mycheck.h            # 契约: report + 两个声明
modules.json                         # 登记一节
demo/main.c + app_main.c             # 各加一段 #ifdef
drills/drill8.json                   # 一条演练记录
```

参考实现：`src/dbiguard.c`（143 行）是最小的完整检测器模块
—— 只有 `scan` + `suspicious`，没有 `apply_policy`（咨询项）。

---

## 5. 设计问题该问什么

提交前自问（对应四条原则）：

1. **P1** 我改了 `.text` 吗？跑完整构建验证过吗（不只是编译通过）？
2. **P2** 我的模块会改代码/数据权限吗？注册表声明准确吗？会同页吗？
3. **P3** 我的模块能**独立**验证吗？还是只能靠"整体门禁"？
4. **P4** 我写的 `known_limits` 是真的吗？我知道它**挡不住什么**吗？

如果第 4 条你写不出东西来 —— 那通常意味着你还没真正测过它。

---

© ShardVase · 模块贡献指南 · 2026-09-20
