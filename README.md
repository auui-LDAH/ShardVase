# ShardVase

> **攻防双侧、可组合、以实证为准绳**的反逆向保护框架（Windows x64 / C11）
>
> 不是"更强的壳"，而是一套**可验证、可组合、边界诚实**的代码保护与离线授权工具链。

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](LICENSE)
[![Commercial](https://img.shields.io/badge/license-commercial%20available-green.svg)](LICENSE.md)
[![Gate](https://img.shields.io/badge/release__check-34%2F34-brightgreen.svg)](#质量门禁)

---

## 这是什么

一个让你给 **Windows x64 C 程序**加上代码保护与离线授权的工作套件：

| 能力 | 做法 |
|------|------|
| **代码混淆** | 自定义 VM（47 条字节码指令）执行关键逻辑，业务函数可自动 VM 化 |
| **引擎自加密** | 关键函数原位 XOR 加密，运行时按组解密/重加密（`.protcry` 段） |
| **反调试** | 12 项多因子检测（关键项 7 + 咨询项 5），可配策略 |
| **完整性校验** | `.text`/`.rdata`/`.pdata` 三段 CRC + 看门狗周期复检 |
| **离线授权** | RSA-3072 签名，serial/tier/到期/机器码全部卷入签名载荷 |
| **可组合** | 13 个模块按拼装图取舍，未选模块**既不编译也不链接** |

**核心主张**：保护强度应当**可测量**。所以本项目自带攻防演练记录、
攻击面测试，以及一份**公开的诚实边界清单**。

---

## 三个与众不同的地方

### 1. 组合驱动构建（不只是"全都要"）

```powershell
powershell -File build.ps1 -Config Release -Composition minimal
```

四档拼装图，**未选中的模块不参与编译与链接**（不是空桩）：

| 拼装图 | 模块 | 产物 | 适用 |
|--------|------|------|------|
| `minimal` | 8（授权链） | ~221 KB | 已有外部保护 / 对启动开销敏感 |
| **`standard`** | 11（+反调试/完整性/自加密） | ~232 KB | **推荐默认** |
| `hardened` | 13（+DBI/VM 检测/间接化） | ~235 KB | 高价值软件 |
| `full` | 13（含已知冲突） | ~235 KB | 仅用于演示组合校验 |

实测：`full` → `minimal` 省 **14336 字节（6.3%）**，且三项保护层输出全部消失
（证明是真裁剪，不是体积变化）。

### 2. 攻防双侧，记录可查

**9 轮正式演练 + 4 组回归矩阵**，共 122 条结构化记录：

| 结果 | 数量 | 含义 |
|------|------|------|
| `BLOCKED` | 54 | 攻击被挡 |
| `PARTIAL` | 58 | 部分生效 / 有限制 |
| **`BREACHED`** | **5** | **显式破防（全部公开，附前置条件）** |
| `SKIP` | 5 | 基线用例（验证无误报） |

另有 `tests/attacks.py` 的 A1-A12 与模块演练记录（`drills/` 共 125 条，
含 65 BLOCKED / 48 PARTIAL / 6 BREACHED / 6 SKIP —— 口径含回归用例）。

> **我们不写"0 破防点"。** 那是模糊表述。5 项破防列在
> [攻防记录](publish/07-攻防记录.md)里，欢迎核验。
>
> 第 8/9 轮（`docs/ATTACK_DRILL8.md` / `docs/ATTACK_DRILL9.md`）分别覆盖
> 函数头 patch vs 跨构建布局随机化、判定点 patch + CRC 重算 vs 快照守卫；
> 后者的**守卫检查器自身不在段 CRC 覆盖内**已作为真漏洞公开，见
> [DRILL9 §5](docs/ATTACK_DRILL9.md)。

### 3. 边界诚实

[诚实边界清单](publish/06-诚实边界.md) 列出 6 项已知边界，每项附缓解路径：

- 到期依赖本地时钟（可回拨）——商业场景需在线时间锚点
- 安装目录可写时可换公钥自授权——部署时须 ACL 只读
- 用户态限制：无法防内核级攻击

**我们不承诺"永不破解"**——任何此类承诺都不可信。

---

## 快速开始

### 用现成工具保护你自己的程序（约 17 秒自动化）

```powershell
# 需要: Windows x64 + VS2022(C++ 工作负载) + Python 3.8+
python prot_sdk\wizard\prot_wizard.py
```

向导会生成骨架工程 → 你只改 `business_<app>.c` 写业务 → 构建：

```powershell
powershell -File <工程>\build_skeleton.ps1 -Project <工程>
```

完整教程见 **[prot_sdk/TUTORIAL.md](prot_sdk/TUTORIAL.md)**（含实测计时：
生成 0.03s + 构建 16s + 验证 0.6s）。

### 从源码构建本项目

```powershell
powershell -File build.ps1 -Config Release
powershell -File tools\release_check.ps1     # 39 项门禁（默认；共 42 项）
```

---

## 架构：三层模块化

```
L3  拼装图 (compositions/*.json)     ← 你选择要哪些能力
      ↓ tools/compose.py
L2  模块契约 (modules.json)          ← 13 模块，声明依赖/能力/边界
      ↓ 生成 prot_modconfig.h
L1  原语 (crc32 / vm_rekey)          ← 不可变的公共设施
```

每个模块在注册表里声明：能力位（`detect`/`prevent`/`conceal`/`verify`/`respond`）、
参与阶段、依赖、导出符号，以及**必填的 `known_limits`**。

**想写一个新模块？** 见 **[docs/MODULE_GUIDE.md](docs/MODULE_GUIDE.md)**
（含可直接复制的 `src/_template.c`，以及五步准入流程）。

---

## 质量门禁

`tools/release_check.ps1` 跑 **39 项**（默认；加 `-WithSkeleton`/`-WithMutation`/`-WithMigration`
后共 **42 项**），全绿才算通过。默认跑的全部 39 项：

```
[ok] git 工作区干净                        [ok] C 注释词法 (comment_lint)
[ok] 版本非占位                            [ok] mojibake 全库回归 (mojibake_check)
[ok] Release 构建 (build.ps1)              [ok] 平台层契约 (platform conformance)
[ok] 可复现 (repro_check)                  [ok] 攻击技契约 (attackcheck)
[ok] e2e T1-T30                            [ok] 构建状态自检 (check_state_platform)
[ok] attacks A1-A12                        [ok] 平台层自检 (_platform)
[ok] vm_unit                               [ok] 验证互斥锁自检 (verify_lock)
[ok] vmc                                   [ok] 文档断言一致性 (docclaim)
[ok] example E1-E7                         [ok] 部署加固自检 (deploy_harden)
[ok] protchain P1-P6                       [ok] 性能基准自检 (perf_baseline)
[ok] 加密封装窗口 (window_check)           [ok] 判定点快照校验自检 (guard_selftest)
[ok] 模块契约 (modcheck)                   [ok] 调试控制台自检 (prot_dbg)
[ok] 攻防记录 (drills lint)                [ok] 门禁日志自检 (gate_log)
[ok] 对外材料 (doccheck)                   [ok] 调试控制台活体自检 (prot_dbg live)
[ok] 签名 (Authenticode)                   [ok] 判定多副本等价性 (replica_check)
[ok] 协议兼容性 (conformance)              [ok] CRC 目标表一致性 (crc_targets)
[ok] Linux 编译覆盖 (linux_compile_check)  [ok] 静态未定义名审计 (undef_check)
                                           [ok] Android 交叉编译 (android_compile_check)
                                           [ok] selfcrypt 驻留期密文态 (selfcrypt_residency)
[ok] 休眠自检审计 (selftest_audit)
                                           [ok] Studio 契约 (studio)
                                           [ok] selfcrypt meta 布局四方一致 (selfcrypt_meta)
```

默认不跑的 3 项（各约 1-4 分钟，发版前用 `-With*` 启用）：
`检查器变异测试 (mutate_check)`、`骨架回归 (skeleton_check)`、`迁移成本 (migration_gate)`
—— 跳过时脚本会明确打印「未运行 —— **未验证 != 通过**」。

几个检查器本身值得一说：

- **`modcheck`** — 注册表与源码双向比对，防漂移；含"每个模块须有演练记录"准入
- **`doccheck`** — 对外材料数字不得与内部能力漂移（门禁项数/轮次/模糊表述/死链）
- **`repro_check`** — 同种子两次构建字节一致

> **纪律**：每个检查器都做过**负向测试**（注入问题确认能检出）。
> 一个只会 PASS 的检查器没有价值。

---

## 项目结构

```
src/            保护内核（16 文件，约 3900 行 C11）
include/        公共头文件
demo/           演示宿主（含条件编译接入示例）
prot_sdk/       接入 SDK：向导 / 骨架 / 教程
tools/          25 个构建与校验工具（纯 Python 标准库）
tests/          12 个测试：e2e / attacks / 单测 / 静态断言
compositions/   四档拼装图
drills/         125 条结构化攻防记录
docs/           设计与实现文档（BLUEPRINT / MODULAR_ARCH / CONTRACT ...）
publish/        对外材料（能力与边界）
```

---

## 设计原则

本项目有四条**用事故换来**的硬约束（详见
[MODULAR_ARCH](docs/MODULAR_ARCH.md)）：

| 原则 | 由来 |
|------|------|
| **P1** 语义等价必须可验证 | 一次"骨架一致"的整文件重建能编译，但 e2e 失败 |
| **P2** 页粒度与布局是硬约束 | `revoke` 因与 `main` 同页导致自伤，至今永久排除 |
| **P3** 门禁绕过路径会掩盖缺陷 | smoke 测试被 `-SkipSmoke` 绕过，缺陷藏了一个月 |
| **P4** 诚实边界是资产 | `known_limits` 是注册表必填字段，不是可选项 |

---

## 依赖与平台

- **构建**：MSVC（VS2022 BuildTools），`/W4 /WX`（警告即错误），C11
- **运行时**：仅 Windows API + bcrypt/winhttp/advapi32/user32，**无第三方依赖**
- **工具链**：Python 3.8+，**仅标准库**（不装任何包）
- **平台**：Windows x64

---

## 许可证

**AGPL-3.0 + 商业授权** 双许可。

- 开源使用：遵守 [AGPL-3.0](LICENSE)（改了并对网络用户提供服务时须开源改动）
- 闭源商用：需取得[商业授权](LICENSE.md)
- **你的业务代码不受影响** —— 用本项目编译产物不使你的代码成为衍生作品

详见 **[LICENSE.md](LICENSE.md)**。

---

## 贡献

欢迎贡献 —— 尤其是**补演练记录**与**新增检测维度**。

请先读 **[CONTRIBUTING.md](CONTRIBUTING.md)**（含本项目已知的坑），
新增模块见 **[docs/MODULE_GUIDE.md](docs/MODULE_GUIDE.md)**。

> 提交含代码贡献即视为同意你的贡献可用于本项目的商业授权版本
> （双许可模式所需，详见 LICENSE.md §5）。

---

## 安全与诚实

- 发现**边界之外的破防手法**？请开 Issue（`security` 模板），我们会更新记录
- **本项目是用户态保护**，不防御内核级攻击
- **不承诺零误报** —— 反调试类检测存在误报可能，咨询项已与关键项分离

---

*ShardVase · 机制公开，接受挑战*
