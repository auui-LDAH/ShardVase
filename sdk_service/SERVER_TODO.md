# 服务器侧部署记录（A-1 离线签发）

> 部署已完成（2026-08-27）。本节记录状态与长期运营纪律。

## 状态：已完成

- [x] 服务器：**签发机**（Ubuntu 26.04 LTS，1 核 2G，经 Tailscale 私有网络访问；主机名与内网地址已脱敏）
- [x] 清理：历史项目残留/docker/ddns-go/waf-guard/旧证书全部移除（磁盘 67G→8G，内存可用 1.3Gi）
- [x] 部署：`~/protsdk/`（`tools/vmenc.py` + `sdk_service/`），Python 3.14 + `python3-cryptography` 46.0.5
- [x] 正式私钥：`~/protsdk/sdk_service/keys/prot-priv.json`（chmod 600），**RSA-3072**（2026-08-27 升级），公钥导出 `pub-blob.c`（Windows）/`pub-der.c`（DER）
- [x] 首次实战签发：真机 `.req` → 服务器签发 → 双侧 `verify_license.py` VALID → 真机 `demo.exe` 验收**校验通过**
- [x] 正式 demo 构建：真机用服务器公钥构建（smoke PASS），license 只能由服务器签发通过
- [x] 备份：本机 `sdk_service/keys/prot-priv-backup.json`；建议再拷贝一份离线介质（U 盘）

## 部署结构（实录）

```
~/protsdk/
  tools/vmenc.py
  sdk_service/
    keys/prot-priv.json      # 私钥 600，gitignore，季度离线备份
    keys/pub-blob.c          # 公钥 BCRYPT blob（demo 构建嵌入）
    keys/pub-der.c           # 公钥 DER SPKI（跨平台/验签工具）
    reqs/                    # 收件 .req
    licenses/<客户>/license.txt
    issue-log.csv            # 签发台账（vmenc --log，只增不改）
    req_gen.py / issue_from_req.py / verify_license.py
```

## 日常签发操作（3 步）

1. 收到客户 `.req`，用另一渠道（电话/微信）核对客户报的 `MACHINE_ID` 与文件内一致
2. `cd ~/protsdk && python3 sdk_service/issue_from_req.py --key sdk_service/keys/prot-priv.json --req sdk_service/reqs/<xxx.req> --serial SN-订单号 --out sdk_service/licenses/<客户>/license.txt --log sdk_service/issue-log.csv`
3. 回执邮件模板：
   ```
   主题: [授权] SN-<订单号> license
   附件: license.txt
   正文: 请将附件 license.txt 放到程序目录后重启。序列号 <订单号> 已绑定当前机器，换机需重新申请。
   ```

## 注意事项（诚实记录）

- 服务器不必对公网开放任何服务——签发仅访问自身文件系统，**入站端口全关**（Tailscale 访问即可）
- 收到 `.req` 只是"申请通知"，签发权始终在私钥持有者手里；`.req` 被截获也无法自行获得 license
- 已发永久授权的吊销 = 只能靠不回发新授权，或未来引入 revoke 更新包（不在 A-1 范围内）
- `EXPIRES` 防"试用超期"而非"已授权永续"（与 THREATMODEL 边界一致）

## 遗留事项

- [x] D-D1 重放拦截 / D-D2 台账哈希链（verify_ledger.py）/ D-D4 字段卫生 —— 已落地（2026-08-28）
- [ ] 每季度：`keys/` + `issue-log.csv` 离线备份（服务器 → U 盘/加密盘）
- [ ] 正式客户端集成发布时：用服务器公钥重新构建（真机正式构建流程已示范）
- [ ] 时钟回拨在线锚点（L4 边界）——商业版路线，未做