# Blob 签名绑定 + 网络下发 — 完备实施计划 (BLOB_SIGN_PLAN)

> 版本：2026-08-22 v1 · 状态：**规划完成，未开工** · 关联：`docs/THREATMODEL.md` §6（注记）·
> `docs/PHASE3.md`（服务端）· `docs/HANDOVER.md` §4.3（待办）· `src/blob.c`（DBI launcher）·
> `src/license.c`（RSA 验签，A1）· `tools/vmenc.py`（pack/revoke/keygen/sign）。
> 本文档规划 DBI launcher 的可选升级：**blob 签名绑定**（防伪）+ **网络下发**（分发渠道）。

---

## 1. 背景与目标

### 1.1 现状
`vm.blob`（VM 镜像密文打包）由 `vmenc.py pack` 生成，装载时 `src/blob.c`
校验 **MAGIC + COUNT + 尾部 BLOB_CRC（CRC32）**。CRC 是**完整性**（防篡改），
**非防伪**——攻击者可以：
1. **自建 blob**：完全理解 VM 格式后，构造一个"看起来合法"的 blob（CRC 自己算）；
2. **替换镜像**：换掉某个镜像的内容（如把校验逻辑换成恒通过）；
3. **回滚**：拿旧版 blob（如有漏洞/已知期望值的版本）。

### 1.2 目标
- **blob 签名绑定**：blob 尾部加 RSA-2048 签名（复用 A1 私钥体系），
  装载时验签——**攻击者无法伪造合法 blob**（私钥离线）；
- **网络下发**（可选）：blob 经 `/v1/blob` 下发（复用 M3.1 在线渠道），
  离线回退本地文件（离线优先语义不变）。

### 1.3 与 A1（license 签名）的关系
| | A1 license.txt | blob 签名 |
|--|----------------|-----------|
| 私钥 | `build/keys/license_priv.json`（gitignore） | **同一把私钥**（复用，不新增密钥管理） |
| 消息 | serial‖mid‖PRODUCT‖tier‖expires | blob 全部字节（[0, size-sig)） |
| 算法 | RSA-2048 PKCS#1 v1.5 SHA-256（BCrypt） | **同算法**（BCrypt，代码可复用） |
| 验签端 | `src/license.c` prot_license_verify | `src/blob.c` 新增 prot_vm_blob_verify |

> **收益**：攻击者还原全部 VM 也造不出合法 blob（THREATMODEL §4 锚点
> 延伸到 blob 层）；"替换镜像/自建 blob"被断。

---

## 2. 技术路线

### 2.1 blob 格式扩展（版本化，向后兼容）

```
现有 (v0):
  MAGIC "PROTVMBL"(8) | COUNT u32 | [NAME16|CODE_LEN4|KEY0_8|KEY1_8|CRC4|CODE..]* | BLOB_CRC u32

扩展 (v1, 签名版):
  MAGIC "PROTVMB1"(8) | COUNT u32 | [同上]* | SIGNATURE_LEN u32 | SIGNATURE (256B) | BLOB_CRC u32
  - BLOB_CRC 覆盖 [0, size-4) (含 SIGNATURE_LEN + SIGNATURE, 与 v0 同规则)
  - SIGNATURE = RSA-2048 PKCS#1 v1.5 SHA-256 签名, 消息 = [0, sig_len_field_offset)
```

**兼容策略**（决策点 D1）：
- **D1a：强制 v1**——装载器只认 v1，老 blob 直接拒。简单，但升级部署需同时换 blob。
- **D1b：双模式**——先看 MAGIC 判定 v0/v1；v0 走 CRC-only（旧行为），v1 走签名。
  平滑升级，但保留 v0 弱点（旧 blob 仍可被伪造）。
- **推荐 D1a**（强制 v1）：blob 与 exe 同版本发布，无跨版本需求；
  防伪价值最大。revoke.blob 是否同样升级见 §4。

### 2.2 构建期（`tools/vmenc.py` 扩展）
- `pack` 增加 `--sign <key.json>`：
  1. 现有打包逻辑不变（生成 v0 字节）；
  2. 对 `[0, size)` 做 SHA-256（Python hashlib）→ RSA 私钥签名（PKCS1 v1.5）；
  3. 追加 `SIGNATURE_LEN u32 + SIGNATURE` + 重算尾部 BLOB_CRC。
- `keygen` 已产出 RSA 密钥（复用）。
- **sign 与 blob 分离**：`pack --sign` 一步完成；不另立子命令（少而清晰）。

### 2.3 运行期（`src/blob.c` + `include/protect/blob.h`）
- `prot_vm_blob_load` 扩展：
  1. MAGIC 检查 v1（`PROTVMB1`）；v0 → `PROT_ERR_BLOB_CORRUPT`（D1a）；
  2. BLOB_CRC 校验（现有逻辑，覆盖含签名）；
  3. **RSA 验签**：消息 = `[0, sig_len_field_off)`，与签名比对
     （复用 license.c 的 BCrypt 逻辑，抽公共函数或复制——见 §3.1）。
- 验签失败 → `PROT_ERR_BLOB_CORRUPT`（不泄漏原因，与现有错误语义一致）。

### 2.4 网络下发（可选，M3.1 渠道复用）
- `mock_server.py` / 生产服务端加 `GET /v1/blob?build=<ver>` → 返回 blob 字节；
- demo `--blob-url` 参数：启动时先尝试网络获取（有 `--check-url` 类似语义），
  失败/不可达 → 回退本地 `vm.blob`（离线优先）；
- **注意**：网络下发的 blob 同样必须验签（防中间人替换）——签名价值在此。
- e2e T27（在线 blob 获取 + 验签通过）、T28（在线 blob 篡改 → 拒）。

---

## 3. 实现要点

### 3.1 RSA 验签复用（关键）
`license.c` 已有完整 BCrypt 验签链路（`BCRYPT_RSAPUBLIC_BLOB` 导入 +
`BCryptVerifySignature` PKCS1 v1.5 SHA-256）。**两种选择**：
- **A：抽取公共模块** `src/rsa_verify.c`（license.c + blob.c 共用），
  改动 license.c（风险：A1 链路回归）；
- **B：blob.c 内复制一份**（公钥 blob 复用 `g_prot_license_pubblob`），
  license.c 零改动（风险低，代码重复 ~60 行）。
- **推荐 B**（原型阶段）：零回归风险；后续重构可再合并。

### 3.2 签名性能
- blob 大小 ~500B，RSA 验签 <1ms（BCrypt），启动无感。

### 3.3 与 N5/会话期望值的关系
- 在线会话下 blob 签名 + 服务端 expect 双重校验，互相独立，不冲突。

---

## 4. 决策点

| 编号 | 决策 | 选项 | 推荐 | 理由 |
|------|------|------|------|------|
| D1 | blob 版本兼容 | D1a 强制 v1 / D1b 双模式 | **D1a** | 防伪最大化；blob 与 exe 同发 |
| D2 | revoke.blob 是否也签名 | 同 blob / 维持 CRC-only | **同 blob**（一期同步） | 黑名单也是"可信下发内容"，同样可被伪造 |
| D3 | 验签代码复用 | A 抽公共模块 / B 复制 | **B** | license.c 零回归风险 |
| D4 | 网络下发 | 本期做 / 后续 | **本期做 mock 渠道**（离线优先） | 完整闭环；e2e 可测 |
| D5 | 私钥 | 复用 license 私钥 / 新建 | **复用** | 单一密钥管理 |

---

## 5. 实施步骤

| 步骤 | 内容 | 工作量 | 依赖 |
|------|------|--------|------|
| 1 | vmenc.py pack --sign（v1 格式 + 签名 + 版本化 MAGIC） | 0.5 天 | 无 |
| 2 | blob.c 验签（复制 license 逻辑 + 新 MAGIC + v0 拒绝） | 0.5-1 天 | 步骤 1 |
| 3 | revoke.blob 签名（vmenc.py revoke --sign + revoke.c 验签） | 0.5 天 | 步骤 1-2 |
| 4 | 网络下发 mock（/v1/blob + demo --blob-url + 回退） | 0.5-1 天 | 步骤 1-3 |
| 5 | e2e 新增 T27/T28（在线 blob 获取/篡改）+ 回归 | 0.5 天 | 全部 |
| 6 | 文档（CONTRACT/THREATMODEL/HANDOVER） | 0.5 天 | 全部 |
| **合计** | | **3-4 天** | |

## 6. 验收标准

1. 正常构建 → blob v1 签名 → demo 装载验签通过（T1 全链）；
2. **篡改 blob 任一字节** → 验签失败 → 0xB10B（T14 扩展覆盖签名层）；
3. **自建 blob**（重新 pack 不签名）→ v0 MAGIC → 拒；
4. **旧 v0 blob** → 拒（D1a）；
5. revoke.blob 签名同样验证（T15-T19 回归）；
6. 网络下发：`--blob-url` 在线获取验签通过；服务不可达回退本地（离线优先）；
7. e2e T1-T26 + 新增 T27/T28 全绿；Release 可复现；
8. 私钥不出库（gitignore 不变）。

## 7. 风险与回退

| 风险 | 等级 | 缓解 |
|------|------|------|
| blob.c 改动破坏 DBI 装载 | 高 | 验签失败只返回 BLOB_CORRUPT（错误语义不变）；T13/T14 回归 |
| license.c 复制逻辑不一致 | 中 | 单元测试：同一消息 Python 签名 → C 验签 |
| 网络下发引入新攻击面 | 中 | 验签兜底（中间人替换也过不了签名）；离线回退 |
| 部署兼容 | 低 | D1a 强制 v1：发布时 blob+exe 同版 |

**回退**：本期全部可选。若 blob.c 改动回归风险大，可先只做构建期签名 +
手动验证（跳过网络下发）；最坏情况 revert blob.c 改动（签名只是额外字节，
v0 装载器仍可读老 blob 逻辑保留在 git 历史）。

## 8. 待办清单

1. [ ] 拍板 D1-D5（§4）。
2. [ ] 步骤 1：vmenc.py pack --sign。
3. [ ] 步骤 2：blob.c 验签。
4. [ ] 步骤 3：revoke.blob 签名。
5. [ ] 步骤 4：网络下发 mock。
6. [ ] 步骤 5：e2e T27/T28 + 全量回归。
7. [ ] 步骤 6：文档更新。
