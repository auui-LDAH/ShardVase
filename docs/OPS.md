# 运营手册 (OPS)

> 版本：2026-08-14 v1 · 归属：BUSINESS 阶段 I（I1 吊销框架 / I5 运营 SOP）与
> 阶段 III（在线 API 规格预留）。目标：把"签发-分发-使用"变成**可记录、可撤销、
> 可审计**的授权生命周期。技术契约见 CONTRACT（license/blob 格式）。
> 每节格式：目标 → 方案/规格 → 验收 → 工作量。

## 1. I1 客户端吊销框架（离线优先，本地可做）

### 1.1 目标
- 授权可被**离线撤销**：黑名单文件随 vm.blob 分发渠道下发，客户端启动校验；
- 黑名单**版本化**：旧客户端只认 ≥ 自身支持最低版本的黑名单；
- **离线降级策略化**：黑名单缺失/过期时的行为可配置（默认：不阻断但本地告警）。

### 1.2 黑名单文件格式（规格）
- 文件名 `revoke.blob`，构建期由 `vmenc.py revoke` 子命令生成（新）：
  ```
  MAGIC "PROTREVK"(8) | VER u32 LE        # 黑名单版本号, 单调递增
  | COUNT u32 LE
  | 每条目: SERIAL[48] | TIER u32 | REVOKED_AT u64(UNIX)
  | BLOB_CRC u32 (prot_crc32 覆盖以上全部)
  ```
- 分发：与 vm.blob 同目录同渠道；**无黑名单文件 = 不阻断**（离线优先，不因
  分发疏漏锁死客户）。
- 命中语义：条目 serial 精确匹配 + tier 匹配（tier=0xFF 表示该 serial 全 tier 吊销）。
- 过期语义：VER 低于客户端支持的最低版本（`PROT_REVOKE_MIN_VER`）→ 按
  `PROT_REVOKE_POLICY` 处理（见 1.4）。

### 1.3 客户端实现（`src/revoke.c` + `include/protect/revoke.h`，新）
- `prot_status prot_revoke_check(const char* path, const char* serial,
  uint32_t tier, uint32_t* out_ver)`：
  - 文件缺失 → `PROT_REVOKE_NO_FILE`（不阻断路径）；
  - magic/CRC 坏 → `PROT_REVOKE_CORRUPT`（不阻断 + 告警）；
  - 命中 → `PROT_REVOKE_HIT`（返回条目 REVOKED_AT）；
  - 未命中 → `PROT_OK`（返回黑名单版本）。
- demo 接入：VM 装载（§9.1-6b）之后、license 验签之前调用；`--revoke-file F`
  （默认 `revoke.blob`）；命中 → 打印告警并 `exit(PROT_EXIT_REVOKED 0x1R0K? 见下)`。
- **退出码约定**（新增 `PROT_EXIT_REVOKED 0xB1E4`，与既有 0xDB/0xBAD/0xB10B 并列，
  加入 CONTRACT §9.3 与 protdef.h）。
- 策略（`PROT_REVOKE_POLICY`，`--revoke-policy strict|warn`）：
  - strict：命中 → 拒绝运行（默认）；
  - warn：命中 → 打印告警继续（评估/灰度用）。
- **涉及文件**：`src/revoke.c`、`include/protect/revoke.h`、`tools/vmenc.py revoke`、
  `demo/main.c`、`include/protect/protdef.h`、`docs/CONTRACT.md`。

### 1.4 验收（新 e2e）
| 用例 | 断言 |
|------|------|
| T15 revoke-hit | 生成含当前 serial 的黑名单 → demo 退出 0xB1E4（strict） |
| T16 revoke-clean | 黑名单不含 serial → 正常通过，退出 0 |
| T17 revoke-absent | 无黑名单文件 → 正常通过（离线优先不锁死） |
| T18 revoke-corrupt | 黑名单翻 1 字节 → 不阻断（warn 路径不误杀） |
| T19 revoke-warn | strict→warn 策略下命中 → 告警但继续 |

### 1.5 工作量
约 1 天（revoke.c + vmenc revoke + demo 接入 + T15-T19）。

## 2. 签发 SOP（脚本化，I5）

### 2.1 流程
```
客户档案(§4) -> 确认 serial/mid/tier -> vmenc.py issue(新) -> license.txt + 签发日志
```
- `vmenc.py issue --key <priv> --json <build.json> --tier N --customer <C> --note <..>`
  （新子命令）：与 `sign` 相同签名逻辑，但**强制写签发日志**
  `build/issue-log.csv`（追加行，CSV）：
  ```
  timestamp,serial,machine_id,tier,customer,note,license_sha256
  ```
- **验收**：两次 issue 生成两条日志；license_sha256 与产物一致；日志文件只增不改。

### 2.2 记录规范
- 日志只增（append-only）；月度归档 `build/issue-log-YYYYMM.csv`。
- 日志本身 gitignore（含 machine_id 客户数据）。

## 3. 密钥管理

### 3.1 分级
| 层级 | 用途 | 存储 | 备份 |
|------|------|------|------|
| 主密钥 | 生成签发密钥/轮换 | 离线介质（U 盘，断网机） | 双备份异地 |
| 签发密钥 | 日常签发（`build/keys/license_priv.json`） | 签发机，gitignore | 主密钥可再派生 |
| 代码签名证书 | 签 exe（RELEASE §2.4） | pfx + 强口令 | 与主密钥同策略 |

### 3.2 轮换与泄露响应
- 泄露迹象（异常签发量/日志异常/公开仓库泄露）→ 立即：
  1. 停用签发密钥；2. 生成新密钥对并重新嵌入公钥（构建基线变更 → MAJOR 版本）；
  3. 吊销受影响客户（§1 黑名单）；4. 全量重签发。
- 轮换频率建议：签发密钥 ≤ 12 个月；主密钥不轮换（泄漏才轮换）。

### 3.3 备份/恢复演练（验收）
- 文档化恢复步骤并在空目录演练：恢复私钥 → keygen（reuse）→ issue → demo 通过。

## 4. 客户台账（离线可用）

- 文件 `build/customers.csv`（gitignore，含客户数据），字段：
  ```
  id,customer_name,contact,serial_base,machine_id,seed_file,tier,issue_date,notes
  ```
- 与 RELEASE §4.4 种子库联动：`build/seeds/<id>/seeds.json`（每客户独立构建）。
- **验收**：一条模拟客户走完 台账→独立构建→签发→交付 全流程（I5 模拟发版）。

## 5. 吊销运营

- 流程：确定撤销对象（serial 或 serial+tier）→ `vmenc.py revoke --add <serial> [--tier N]
  --out build/revoke.blob`（读旧黑名单 + 追加，版本 +1）→ 随下次分发下发。
- 生效：客户端在**下次启动**即生效（黑名单为启动时校验；不强制联网）。
- **验收**：追加吊销后旧客户端（黑名单旧版本）仍接受新黑名单（VER 单调）；
  再吊销一条 → 版本再 +1。

## 6. 阶段 III 在线验证 API（规格预留，未实现）

- 接口（REST，TLS 必选）：
  ```
  GET /v1/check?serial=<s>&mid=<hex>&tier=<n>&build=<ver>
  -> 200 {"status":"ok","tier":1,"expires":"2027-01-01"}
  -> 200 {"status":"revoked","reason":"refund"}
  -> 404 {"status":"invalid"}
  ```
- 客户端集成点：`prot_revoke_check` 的 **online provider**（I1 框架预留接口，
  默认 offline 路径）：在线可达 → 查询；不可达 → 回退黑名单 + 本地告警。
- 服务端规格：单核 512MB VPS + Python（复用 vmenc 验签逻辑做服务端校验可选）；
  建议黑名单也由服务端版本化下发（统一渠道）。
- **决策点 D2 前不实现**；本文档即为实现规格。

## 7. 合规/法律（模板要点，I5 产出）

- **EULA 要点**（模板 `docs/templates/EULA.md`，新）：
  - 授权范围（单机/单用户、tier 对应功能边界）；
  - 保护强度声明边界（不承诺不可破解，仅提高成本）；
  - 禁止逆向/解除保护（在允许反逆向研究的司法辖区外）；
  - 吊销权利（欺诈/退款场景）；免责（误报导致的损失）。
- **出口合规提示**：反逆向工具在部分区域受管制；对外分发前咨询。
- **隐私**：machine_id 收集声明（本方案仅本地计算，不上传——在线验证（§6）如启用
  则需明示）。

## 8. 工作量汇总（阶段 I 相关）

| 项 | 工作量 |
|----|--------|
| I1 吊销框架（1.1-1.5） | ~1 天 |
| issue 子命令 + 签发日志（2.1） | ~0.5 天 |
| 恢复演练（3.3）+ 台账（4） | ~0.5 天 |
| 吊销运营验证（5） | ~0.25 天 |
| EULA 模板（7） | ~0.25 天 |
