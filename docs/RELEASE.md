# 发布与交付工程 (RELEASE)

> 版本：2026-08-14 v1 · 归属：BUSINESS 阶段 I（I2/I3/I5）与发版相关事项的**可执行规格**。
> 目标：把"verify 全绿即可跑"升级为"可审计、可签名、可复现、可交付"的商业发布线。
> 每节格式：目标 → 方案（含命令/文件级细节）→ 验收（可测）→ 工作量估计。

## 1. 版本规范

### 1.1 版本号
- 语义化版本 `MAJOR.MINOR.PATCH`（如 `1.1.0`）+ 可选构建元数据 `-build.N`。
- 定义位置：单一事实来源 `include/protect/version.h`（本次新增）：
  ```c
  #define PROT_VERSION_MAJOR 1
  #define PROT_VERSION_MINOR 1
  #define PROT_VERSION_PATCH 0
  #define PROT_VERSION_STR   "1.1.0"
  ```
- 变更规则：破坏性接口/格式变化 → MAJOR；新能力（指令/检测项/格式兼容扩展）→ MINOR；
  缺陷修复 → PATCH。格式变化（license 载荷、blob 格式、demo_mem）必须升 MAJOR。
- **涉及文件**：`include/protect/version.h`（新）、`demo/main.c`（`--version`）。

### 1.2 --version 输出
- `demo.exe --version` 打印：`prot-demo <PROT_VERSION_STR> (build <SHA>, <timestamp>)`。
- 构建号/SHA/时间由 build.ps1 注入（见 §3 可复现构建的种子文件）。

## 2. I2 发行加固（Release 构建）

### 2.1 目标
发布产物：无调试信息、无 PDB、无可读符号、带版本资源、带数字签名。

### 2.2 符号与调试路径
- cl 加 `/DEBUG:NONE`（编译期不加调试信息）+ 链接 `/OPT:REF /OPT:ICF`（去冗余/合并相同函数）。
- PDB 不产生于 Release；`/Zi` 仅 dev 构建使用。
- 验证命令：
  ```
  dumpbin /headers build\demo.exe    # 无 Debug Directory (IMAGE_DIRECTORY_ENTRY_DEBUG 为空)
  dir build\*.pdb                    # 无 pdb
  dumpbin /symbols build\demo.exe    # 仅外部符号（导入），无内部函数符号
  ```
- **验收**：Release 构建下 dumpbin 三项检查全部通过；dev 构建不受影响。

### 2.3 版本资源（.rc）
- 新增 `demo/version.rc`：`VS_VERSION_INFO` 含 FileVersion/ProductVersion（读 version.h
  一致）、CompanyName/ProductName（占位，决策点 D1 后填）、LegalCopyright。
- build.ps1 Release 分支用 `rc.exe` 编译 → 链接进 demo.exe。
- **验收**：`powershell (Get-Item build\demo.exe).VersionInfo.FileVersion` 输出 `1.0.0`。

### 2.4 数字签名（自签证书，本地）
- 一次性：创建自签代码签名证书（PowerShell，`New-SelfSignedCertificate`）：
  ```powershell
  $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=PROT Demo Dev" `
      -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddYears(5)
  $pwd = ConvertTo-SecureString '<pass>' -AsPlainText -Force
  Export-PfxCertificate -Cert $cert -FilePath build\keys\codesign.pfx -Password $pwd
  ```
- 每次 Release：`signtool sign /fd SHA256 /f build\keys\codesign.pfx /p <pass> build\demo.exe`
  （signtool 位于 Windows SDK 工具链，vswhere 定位）。可选 `/tr <时间戳服务器>`（联网）。
- **验收**：`signtool verify /pa build\demo.exe` 成功；证书入 manifest。
- **注意**：自签证书面向"内部 v1.0"（D4）；正式对外销售建议商业证书（阶段 II 后决策）。

### 2.5 build.ps1 开关设计
- 新增 `-Config Release|Dev`（现有 `-Config` 保留扩展位，本项正式启用）：
  | 项 | Dev（默认） | Release |
  |----|------------|---------|
  | /Zi + PDB | ✅ | ❌ (/DEBUG:NONE) |
  | 版本资源 .rc | 不链接 | ✅ |
  | signtool 签名 | 不签 | ✅（有证书时） |
  | /Brepro（§3） | 不启用 | ✅ |
  | 种子注入（§3） | 随机 | 可选 -SeedsFile |
- **验收**：`build.ps1 -Config Release` 全链通过且满足 §2.2-2.4 全部检查；dev 构建行为不变。

### 2.6 部署要求：安装目录 ACL（WIN_ENHANCE W3，DLL 劫持缓解）
- **硬性要求**：安装目录 ACL 必须**只读于普通用户**（仅 Administrators/INSTALLER
  可写）。理由：Windows 同目录 DLL 优先加载，若目录可写则攻击者可植入同名
  `winhttp.dll` 等劫持（D5 攻防实证 BREACHED —— 环境约束，标准缓解即 ACL）。
- 实现：安装器以 `icacls <dir> /inheritance:r /grant "Users:RX" /grant "Administrators:F"`；
  运行时自检可加"目录可写检测"（可选）。
- 影响：防 DLL 盗用 + 在线校验篡改入口。

## 3. I3 可复现构建（审计用）

### 3.1 目标
给定相同输入（源码 + 种子文件），两次 Release 构建产出**字节一致**的产物
（PE 时间戳除外 → 用 `/Brepro` 消除），供审计与"客户 A 与客户 B 互异"之外的
可信度证明。

### 3.2 方案
1. **种子注入**：`vmenc.py assemble` 增加 `--seed <key0> --perm-seed <key1>` 确定性模式
   （缺省仍随机）；build.ps1 `-SeedsFile <json>` 读种子表（每镜像一组），
   `-RecordSeeds` 把本次种子写入 `build/seeds.json`（**入库？否——入 build/，随发布归档**）。
2. **/Brepro**：MSVC 链接器 `/Brepro` 使 PE 头时间戳/校验和可复现
   （配合 `/Brepro` 的确定性 COMDAT 顺序）。
3. **产物哈希**：`build/manifest.json` 增加 `release_seeds_sha256`、各产物 SHA-256。
4. 验证脚本 `verify.ps1 -Reproducible <seeds.json>`：同种子两次构建 → 比对
   demo.exe/vm.blob SHA-256 一致。

### 3.3 验收
- 同种子两次 Release 构建：demo.exe 与 vm.blob 的 SHA-256 完全一致；
- 不同种子（默认随机）：SHA-256 互异（随机化不被破坏）；
- `verify.ps1 -Reproducible` 在 verify-report.json 中记录比对结果。

### 3.4 工作量
约 0.5 天（vmenc.py 参数 + build.ps1 分支 + 验证脚本）。

## 4. I5 发版流程与交付物

### 4.1 发版 checklist（每次发版照做，形成 CHANGELOG 条目）
```
[ ] 1. git 状态干净；HANDOVER/PLAN 反映当前状态
[ ] 2. verify.ps1 -Rounds 3 全绿（发版 gate）
[ ] 3. build.ps1 -Config Release -RecordSeeds（归档 build/seeds.json）
[ ] 4. 符号/调试检查（§2.2 dumpbin）通过
[ ] 5. signtool 签名 + verify /pa 通过
[ ] 6. verify.ps1 -Reproducible（可选，审计时）通过
[ ] 7. 打包分发物（§4.2）+ 校验和
[ ] 8. 更新 CHANGELOG.md 与版本号（version.h）；打 git tag vX.Y.Z
```

### 4.2 分发打包规范
```
release-vX.Y.Z/
  demo.exe           (签名, Release)
  vm.blob            (与 exe 同构建)
  license.txt        (示例/模板)
  ReadMe.txt         (用途/序列号说明/校验和)
  SHA256SUMS         (全部文件哈希)
```
- 打包脚本 `tools/pack_release.ps1`（新）：执行 §4.1 的 3-7 步 + 生成 SHA256SUMS。
- **验收**：脚本一键产出上表目录；`Get-FileHash` 与 SHA256SUMS 一致。

### 4.3 CHANGELOG 规范
- `CHANGELOG.md`（新，仓库根）：按版本倒序；条目：Added/Changed/Fixed/Security，
  每条注明关联测试（T#/A#）与文档变更。

### 4.4 升级路径（每客户独立构建）
- 升级 = 重新构建（同客户种子库保持）+ 重新签发（旧 license 的 mid 不变则仍有效）。
- 种子库按客户归档：`build/seeds/<customer>/seeds.json`（I5 客户台账联动，见 OPS §4）。

## 5. 发布相关风险与注意事项

- **自签证书**：仅内部/演示；商业证书签名前，SmartScreen 会有警告——预期内，文档注明。
- **/Brepro 与随机化**：可复现 ≠ 所有客户同构；客户间必须用不同种子（每客户独立构建是
  商业底线，OPS §4）。
- **时间戳**：`/Brepro` 后 PE 时间戳为 0；如需真实时间戳（某些环境依赖），改用
  `--repro` 显式开关而非默认。
- **版本资源与 CI 解耦**：版本号只改 version.h，任何脚本不得二次硬编码。
- **WDAC 托管环境（2026-08-19 实测）**：启用 Application Control 策略的托管 VM 会
  按文件信誉拦截新构建产物（winerror 4551 / 偶发"license: 0"瞬态），表现为
  构建后立即运行不稳定、数分钟后趋于稳定。已做的韧性：build.ps1 签名全部产物
  （`build\keys\sign.pass` 口令文件，gitignore）+ WDAC 重试（延迟重跑/重编译）；
  verify.ps1 build 失败自动 90s 重试一次；e2e 篡改副本被拦记 SKIP。
  **结论：此类环境仅适合开发，验证 gate 应以无 WDAC 环境为准。**
