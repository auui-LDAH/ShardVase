# CHANGELOG

本项目变更日志。格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.0.0/)。
版本号规范见 `docs/RELEASE.md` §1。

## [Unreleased]

### Fixed
- Release 构建反调试误报 (0xDB 自杀): prot_antidebug_apply_policy 在 selfcrypt 解密窗口外调用被加密的 prot_antidebug_scan -> 密文执行误报。修复: main.c 将 apply_policy 调用包入 sc_ext_enter/leave。

## [1.1.0] - 2026-09-23

**主题**: 工作台路线图 W1→W6 全部落地 —— 从"防护模块集合"升级为
"**可验证的防护编排平台**"。

### Added

**W1 差异扩散**（跨构建差异 0.54% -> 67.85%）
- `tools/gen_padding.py`: 节填充（对齐基线 + 差异扩散，总量固定/分布随机）
- `tools/normalize_tail.py`: 文件尾精确填充（消除节对齐粒度残余）

**W1.6 每构建序言噪声**（保护函数特征命中 55.9% -> 5.9%）
- `include/protect/prot_noise.h`: `PROT_NOISE()` 宏（局部 volatile，实测
  `__nop()` 与 `static volatile` 两种写法均被 `/O2` 优化掉）
- `-DPROT_BUILD_SALT` 构建盐注入，34 个保护函数序言注入

**W5 验证框架**（**护城河**）
- `tools/observability.py`: 可观测性度量（跨构建差异 / 稳定核 / 熵剖面 /
  静态可识别性）+ 负向自检
- `tools/migration_cost.py`: 破解迁移成本度量（M1 地址复用 / M3 特征匹配）
- `tools/mutate_check.py`: 门禁检查器**变异测试**（6/6 自证能抓错）
- `tools/migration_gate.py`: 迁移成本门禁（阈值 12%）

**W2 协议形式化**（契约 12 -> 17 字段；W6 加 maturity 后为 18）
- `modules.json`: 新增 `abi_version` / `conflicts_with` / `ordering` /
  `consumes` / `produces`（13 模块 + 2 原语）
- `docs/MODULE_PROTOCOL_SPEC.md`: **开放规范 v1**（独立于实现）
- `tools/modcheck.py`: 新增校验规则 R10–R18（含 ordering 环检测）

**W3 编排器升级**（用户给策略，不再手写模块列表）
- `tools/compose.py`: `topo_order()`（Kahn 拓扑排序，替代硬编码
  `SOURCE_ORDER`）；`--profile` / `--plan-out`
- `tools/solve_profile.py`: 策略 -> 模块集求解 + 结构化构建计划
- `profiles/*.json`: 4 个参考策略（minimal-cost / balanced /
  hardened-threats / paranoid-analysis）

**W4 每用户唯一**（跨用户差异 93.04%）
- `tools/identity.py`: HKDF 分层派生（RFC 5869 测试向量验证）
- `build.ps1 -UserId`: 用户种子驱动全部随机维度

**W6 协议治理**
- `tools/conformance.py`: 兼容性套件（第三方**可自证兼容协议 v1**）
- `docs/PROTOCOL_GOVERNANCE.md`: 治理文档（版本化流程 / 核心扩展边界 /
  成熟度分级）
- `modules.json`: `maturity` 字段（experimental/community/verified/core）

### Changed
- `build.ps1`: 门禁项 14 -> 17（新增变异测试 / 协议兼容性 / 迁移成本）
- `build.ps1`: **签名时间戳改为可选**（默认关闭）—— 消除对公网
  `timestamp.digicert.com` 的依赖（该依赖会导致断网时构建失败，
  且 RFC3161 时间戳会破坏字节级可复现）
- `prot_sdk/skeleton/build_skeleton.ps1`: 同上
- `tools/modcheck.py`: `INFRA_HEADERS` 统一排除基础设施头
  （`protdef` / `prot_sections` / `prot_noise`）
- `modules.json`: `priority` 量纲统一（`SOURCE_ORDER index × 10`）；
  `selfcrypt` 的"万能声明"精简为语义必需的 `after: ['indirect']`

### Fixed
- **门禁严重失效**: `release_check.ps1` 的 `Check` 用 `$ok = & $cond`
  把命令输出赋给 `$ok` -> 非空数组恒为真 -> **7/13 项从未真正检查**。
  修: 只取末值 + 末值非布尔则判 FAIL（不静默通过）
- `tests/protchain_check.py`: 硬编码节名 -> 改读
  `demo/gen/prot_sections.json` 的**逻辑名映射**
- `tools/gen_padding.py`: 填充初值只给 64 个 + `, 0` 收尾 ->
  产生**大段零区**（熵低至 0.05，攻击者可一条熵扫描圈出全部填充区）。
  修: 初值改与 need 等长
- `build.ps1`: `$scDef`/`$resObj` 位于源文件**之后** -> `cl` 报
  `D9026`（选项作用于整个命令行）。修: 移到源文件之前
- `build.ps1`: `indirect` 用户种子分支嵌在 `if ($RecordSeeds)` 内部；
  `Get-SeedArgs` 未接用户种子 -> 同 UserId 两次构建**不可复现**
- `src/*.c`: 19 个检测项名原为裸字面量（`strings` 一次即知组合档位）
  -> 移入 strcrypt 加密表（14 -> 33 条）

### Security
- **每用户唯一**: 同策略的两个用户产物差异 **93.04%**
  （主密钥 -> HKDF 分层派生 -> 节名/盐/字符串密钥/间接表置换）
- **差异扩散**: 跨构建差异 **67.85%** 且分布均匀
  （此前 0.54% 且集中在 5 个块 -> 一次 diff 即定位全部 per-build 秘密）
- **迁移成本**: 保护函数特征命中 **5.9%**（此前 55.9% 可被字节特征
  跨构建定位）

### 说明（诚实边界）
- 迁移成本 M3 仍有 5.9% 残留（2/34 函数可匹配，可能因函数体极短）
- 序言噪声只覆盖函数**首部**（~15 字节），攻击者用更长特征仍可能匹配
- 跨用户差异 93% 非 100%（剩余为平台常量）
- `maturity` 分级如实反映证据: `integrity` 有 15 条 drill 但 **0 条
  BREACHED** -> 评为 `community` 而非 `core`（**未被证伪 ≠ 强**）

## [1.0.0] - 2026-08-15

### Added
- 授权吊销框架 (I1): 离线黑名单 `revoke.blob`（`vmenc.py revoke`）、客户端
  `src/revoke.c`、strict/warn 策略、退出码 `0xB1E4`（T15-T19）
- 发行加固 (I2): `version.h` 单一版本来源、`--version`、版本资源 `version.rc`、
  `-Config Release|Dev`（`/DEBUG:NONE /OPT:REF,ICF`）、自签证书 signtool 签名
- 可复现构建 (I3): `assemble --seed/--perm-seed`、`strgen --seed`、`-SeedsFile/
  -RecordSeeds`、`/Brepro`、`verify.ps1 -Reproducible`（无签名产物字节一致）
- 兼容骨架 (I4): `tools/osinfo.py`、manifest 记录 OS/工具链版本
- 交付/运营 (I5): `vmenc.py issue` 签发+只增日志、CHANGELOG、EULA 模板、
  客户台账模板

### Changed
- `build.ps1` 默认 `-Config Dev`（原 Release 占位未启用）

### Fixed
- `tests/unit_vm.vasm` Phase D 控制流: `storr32` 压栈顺序 ([off,val]) 与
  `callind` 返回路径 (`jmp p_d`) —— 干净重建必现的两个缺陷（随 DBI launcher 提交）

### Security
- 授权生命周期闭环: 签发-吊销-降级策略（I1）；密钥分级与轮换 SOP（`docs/OPS.md`）
