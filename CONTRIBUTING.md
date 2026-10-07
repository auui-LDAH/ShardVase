# 贡献指南（CONTRIBUTING）

> 本文件面向所有想给 ShardVase 提交改进的人。
> 如果你要**新增一个防御模块**，请先读 `docs/MODULE_GUIDE.md`（本文只讲流程）。

---

## 1. 这个项目看重什么

在提 PR 之前，请先理解本项目的三条基本立场 —— 它们决定了什么样的 PR 会被接受。

### 实证 > 声明

每条能力都要有可复现的证据（测试、演练记录、实测数字）。
**不要**提交"理论上可行"的功能 —— 那会被要求补证据，或者直接拒绝。

> 例：文档里"全程约 5 分钟"这种未实测的说法，后来被实测修正为
> "机器部分 17 秒，其余是人工"。

### 诚实边界 > 完美叙事

每个模块在注册表里都有 `known_limits`（**强制字段**）。
写"这个模块挡不住什么"不是自曝其短，而是这个项目最有力的资产。

> 对外材料 `publish/06-诚实边界.md` 列了 6 项边界与缓解路径。

### 工具强制 > 人工纪律

能做成检查器的，就不要写成"请注意"。
`tools/modcheck.py`（模块契约）、`tools/drills.py lint`（演练记录）
都在门禁内 —— 它们会自己发现问题。

> 例：一条"模块须有演练记录"的准入规则，首次运行就发现了
> `revoke` 与 `syscall` 缺少演练记录。

---

## 2. 提交流程

### 2.1 分支与提交

```powershell
git checkout -b <your-topic>
# ... 改动 ...
git commit -m "type(scope): 简述

详细说明: 改了什么、为什么、如何验证"
```

**type** 约定（沿用既有习惯）：

| type | 用于 |
|------|------|
| `feat` | 新功能 / 新模块 |
| `fix` | 修复缺陷 |
| `docs` | 仅文档 |
| `chore` | 构建 / 清理 / 工具 |
| `test` | 测试相关 |
| `refactor` | 重构（行为不变） |

**提交信息建议包含验证方式** —— 例如"实测 X 从 A 变为 B"。
这个项目的提交历史里大量引用实测数字，请延续。

### 2.2 必跑的门禁

```powershell
# 一键门禁（36 项，含模块契约与演练记录检查；发版前加 -With* 共 39 项）
powershell -ExecutionPolicy Bypass -File tools\release_check.ps1
```

单项也可以单独跑：

```powershell
python tools\modcheck.py                 # 模块契约漂移 + 组合自洽 + 演练覆盖
python tools\drills.py lint              # 演练记录 schema
python tests\e2e.py                      # 端到端 T1-T30
python tests\attacks.py                  # 攻击面 A1-A12
python tests\protchain_check.py          # 保护链静态断言 P1-P6
powershell -File build.ps1 -Config Release
```

**全绿才算完成。** 若某项失败，先判断是"你的改动引入的"还是"既有问题"
（后者可在 PR 中说明并单独开 issue）。

### 2.3 PR 描述模板

```markdown
## 改了什么
（1-3 句）

## 为什么
（问题 / 动机）

## 如何验证
- [ ] release_check 36/36 PASS（默认）
- [ ] （若适用）附实测数字或演练记录

## 诚实边界
（这个改动**没有**解决什么？若确实没有边界，写"无"）
```

最后一项不是形式主义 —— 项目的既有文档都遵循这个习惯。

---

## 3. 代码规范

### C 代码

- **C11**，MSVC，`/W4 /WX`（**警告即错误**）
- 头文件只 `#include "protect/protdef.h"`（低耦合是本项目的优点，别破坏）
- 函数命名 `prot_<模块>_<动作>`
- 模块实现文件放在 `src/`，契约头放 `include/protect/`
- **不要**引入第三方依赖（整个项目只用 C 标准库 + Windows API）

### Python 工具

- **只用标准库**（这是硬约束 —— `tools/` 下所有脚本都如此）
- Python 3.8+
- CLI 用 `argparse`，输出中文（与既有工具一致）

### PowerShell 脚本

- ⚠️ **必须保留 UTF-8 BOM**（首 3 字节 `EF BB BF`）
  PowerShell 5.1 读无 BOM 的 UTF-8 会按 GBK 解析，破坏中文字符串并产生
  **虚假语法错误**。编辑器保存时容易丢掉 BOM，改完 `.ps1` 请复查：

  ```powershell
  [System.IO.File]::ReadAllBytes('tools\xxx.ps1')[0..2]  # 应为 239 187 191
  ```

### 文档

- Markdown，中文
- 引用其它文件时用反引号包裹相对路径（便于 `modcheck` 之类工具核对）
- 涉及数字的断言请标注是**实测**还是**估算**

---

## 4. 新增模块的额外要求

见 `docs/MODULE_GUIDE.md`。摘要：

1. 从 `src/_template.c` + `include/protect/_template.h` 复制改名
2. 在 `modules.json` 登记（`known_limits` 不得为空）
3. 在 **两个**宿主（`demo/main.c` 与 `prot_sdk/skeleton/app_main.c`）
   加 `#ifdef PROT_MOD_<YOUR_MODULE>` 调用段
4. 补至少一条 `drills/` 演练记录
5. 跑 `python tools\modcheck.py` 确认无漂移

---

## 5. 已知的坑（请先看一眼，能省很多时间）

| 坑 | 现象 | 规避 |
|----|------|------|
| **`.ps1` 丢 BOM** | PS 5.1 报一堆莫名的语法错误 | 改完确认 BOM |
| **源文件顺序** | 加密函数数量变化 / 间歇 TAMPERED | 别改 `compose.py` 的 `SOURCE_ORDER`；新增模块**追加末尾** |
| **`.text` 布局** | 间歇性 `0xBAD` | 改 `.text` 相关代码后跑完整构建（重建 mask/CRC 是自动的） |
| **只改一个宿主** | 某组合链接失败 | 两个宿主都要加条件编译 |
| **注册表漂移** | `modcheck` 报错 | 那是检查器在工作 —— 改代码或注册表，别改检查器 |
| **解析 MSVC 输出** | 提取符号失败 | 中文 MSVC 输出的引号是**全角**的，别按英文写正则 |

---

## 6. 可以做什么

| 类型 | 例子 | 难度 |
|------|------|------|
| 新增检测维度 | 新的反调试 / 环境检测项 | 中 |
| 新增保护机制 | 新的代码变换 / 完整性算法 | 高 |
| 补演练记录 | 给 `revoke`/`syscall` 补 drill（**当前缺**） | 低 |
| 修文档错误 | 数字、链接、过时说明 | 低 |
| 扩充测试 | 新的攻击面用例 | 中 |
| 平台延伸 | Android **真机**验证（NDK 交叉编译已完成，见 `docs/EXTENSION_PLAN.md`） | 高 |

**当前最欢迎的两类**：

1. **补 `revoke` / `syscall` 的演练记录** —— `modcheck` 会持续提示
2. **把 `tests/attacks.py` 的 A1-A12 归一化进 `drills/`**
   （目前它们只是功能测试，未进入结构化攻防统计）

---

## 7. 不要做什么

| 不做 | 原因 |
|------|------|
| 承诺"不可破解" | 任何此类承诺都不可信 |
| 引入内核驱动 | 超出项目用户态边界（边界 B5） |
| 引入第三方运行时依赖 | 项目定位是零依赖、可审计 |
| 为了"多一个检测项"而拆模块 | 低耦合是优点，别为拆而拆 |
| 修改检查器以让检查通过 | 那是掩盖问题，不是解决问题 |

---

## 8. 有问题怎么办

- **架构问题** → 读 `docs/MODULAR_ARCH.md`（含四条设计原则的由来）
- **模块契约** → 读 `docs/MODULE_GUIDE.md` + `modules.json`
- **当前状态** → 读 `docs/HANDOVER.md`（交接文档，含已知限制）
- **路线图** → 读 `docs/BLUEPRINT.md`
- **实现细节** → 读 `docs/CONTRACT.md`（唯一事实来源）

---

© ShardVase · 贡献指南 · 2026-09-20
