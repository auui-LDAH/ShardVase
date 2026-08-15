# CHANGELOG

本项目变更日志。格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.0.0/)。
版本号规范见 `docs/RELEASE.md` §1。

## [Unreleased]

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
