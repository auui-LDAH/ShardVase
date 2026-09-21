# SDK 服务 — A-1 完全离线签发方案（定稿）

> 决策记录：客户端验证**完全离线**；授权签发由持有私钥方完成；
> 通信仅发生在"申请"与"回执"两个人工环节（邮件/网盘均可），
> 不存在运行期在线依赖，也不部署公网验证端点。

## 架构一句话

```
客户机器(离线)                    签发方(私钥持有者, 本机或 IPv6 VPS)
  req_gen.py ── .req 文件 ──>  人工发送(邮件/网盘) ──> issue_from_req.py
  验签/放行  <── license.txt <─ 人工回传(邮件/网盘) <── vmenc.py issue
    ↑ 全部本地                          ↑ 每次签发只做一次
```

- **客户端侧（目标机器）**：`req_gen.py` 算 machine_id 并生成 `.req` 申请文件；运行期验签全本地（现有 license_auth 链路，零网络）。
- **签发侧（你）**：`issue_from_req.py` 读 `.req` → 调 `vmenc.py issue`（`--machine-id` 取自申请文件）→ 产出 `license.txt` → 人工回传。
- **服务器（可选）**：如果你想把签发固定到 IPv6 VPS 上，只需把本目录 + `tools/vmenc.py` + 私钥放上去，流程完全相同。见 `SERVER_TODO.md`。

## 为什么这样防破解

| 破解路径 | 防御 | 状态 |
|---|---|---|
| 多机共用一份 license | `MACHINE_ID` 与目标机绑定，换机验签失败 | A1 已演练验证 |
| 伪造/篡改 license | RSA-2048 私钥离线保管，客户端用公钥验签 | 现有链路 |
| 截获/伪造申请文件 | 申请文件只是"通知你有人要授权"，不含任何密钥 | 无攻击价值 |
| 人工环节被代签/调包 | 请求方口头/文字**双通道**报 `MACHINE_ID`，签发人比对 `.req` | 流程纪律 |

已知边界（与 THREATMODEL 对齐，不掩盖）：拿到合法 `license.txt` 的机器可在离线状态下一直使用——**吊销只能靠不回发新授权/依赖到期时间**；`EXPIRES` 是防"试用超期"而非防"已授权永续"。

## 目录约定

```
sdk_service/
  keys/          私钥 JSON（gitignore，chmod 600，离线备份）
  reqs/          收到的 .req 申请（gitignore，归档留痕）
  licenses/      签发的 license.txt（gitignore，按客户分目录）
  issue-log.csv  签发日志（vmenc --log 追加写入）
```

## 实测闭环（2026-08-27，Windows 本机 ↔ 真机 Win11，已完成两轮）

已按真实流程跑通完整闭环（2048 首轮 + **3072 正式轮**）：

| 步骤 | 地点 | 动作 | 结果 |
|---|---|---|---|
| 1 申请 | 真机（客户机） | `req_gen.py --name ...` → `.req` | MACHINE_ID=`0x5e6bfd7560985c95` |
| 2 传输 | 模拟邮件 | scp 下载 `.req` 到签发机 + 取回签发私钥 | ✓ |
| 3 签发 | 签发机 | `issue_from_req.py --serial DEMO-2026-ABCDEFGH` | license.txt 绑定该机 |
| 4 回传 | 模拟邮件 | scp 上传 license.txt 到客户机 | ✓ |
| 5 验证 | 真机 | `demo.exe --license-file ... --vm-blob ...`，stdin 喂序列号 | **`校验通过，欢迎使用！(tier=1)`** |

关键结论：
- 客户机（真机）与签发机（服务器）的 Python/vmenc 版本可以不同——`req_gen`/`issue_from_req` 只依赖 `hostid()`/`LICENSE_PRODUCT` 两个稳定接口。
- license 的 `SERIAL` 字段 = 客户序列号本身（如 `DEMO-2026-ABCDEFGH`），**不是** 期望常量；期望常量（expect1/expect2）是 VM 内部校验值，绝不外发。
- 签发侧 Ubuntu Server 已实跑（Python 3.14 + cryptography 46.0.5），全程无 Windows API 依赖。

## 正式部署记录（2026-08-27，已完成）

目标 Ubuntu Server 已上线并走通正式授权链路：

| 环节 | 状态 |
|---|---|
| Ubuntu Server（签发机：主机名/内网地址已脱敏）| 已部署 `~/protsdk`（工具+私钥 `prot-priv.json` chmod 600）|
| 服务器清理 | 历史项目残留/docker/ddns-go/waf-guard 全部移除，磁盘 67G→8G |
| 正式密钥 | 服务器生成 RSA-3072（升级），公钥导出 `pub-blob.c`（Windows）/`pub-der.c`（DER）；私钥备份在本机 + 建议 U 盘 |
| 正式 demo 构建 | 真机（客户机形态）用服务器公钥构建 `demo.exe`，smoke PASS |
| 真实签发 | 服务器 `issue_from_req` 签发 SN=`DEMO-2026-ABCDEFGH` bound 真机 |
| 验收 | 真机 demo 完整启动：**校验通过，欢迎使用！(tier=1)**；服务器与本机 `verify_license` 均 VALID |

**RSA-3072 升级（2026-08-27，含一次排障）**：
- 密钥/签名尺寸：RSA-2048→3072（签名 256B→384B，SIGNATURE b64 512 字符）
- `SIGNATURE=` 行长度超过 license 解析缓冲 `line[512]` → **截断致验签失败**；已扩为 `line[1024]`（demo/main.c、examples/tool_demo/main.c、android/libprot.c）
- BCrypt 验签要求 PKCS1 时传 `BCRYPT_PKCS1_PADDING_INFO`（非 NULL）+ `BCRYPT_PAD_PKCS1`（src/license.c 原写法即正确）
- 升级后矩阵：本机/真机 smoke PASS + 真机验收 `license: 1`

台账：服务器 `~/protsdk/sdk_service/issue-log.csv`（只增不改），本机每轮签发后可取回存档。
颁证每季度离线备份 `keys/` + `issue-log.csv`。

## 本机图形化签发台（issue_console.py，已就绪）

简化日常运营，人只做"收 + 核 + 发"，无命令行：

```
客户(Tailnet)                         你(本机, issue_console.py)
  req_gen.py ──.req──► Taildrop ──► 打开"Taildrop 目录"取 .req
                                     界面显示 客户/机器码/nonce/时间
                                     输入客户口头报的 MACHINE_ID → 核对一致
                                     填 serial/tier/expires → [签发并生成回执]
                                     → license.txt 自动落到 licenses/<客户>/
                                       + 验签自检 VALID + 回执文本复制
  ◄──license.txt── Taildrop 拖回 ◄── 把 license.txt 拖入 Taildrop 发给客户
```

- 启动：`python sdk_service\issue_console.py`（或 `--req xxx.req` 启动即载入）
- 私钥用本机备份 `sdk_service/keys/prot-priv-backup.json`（界面可改路径）
- 台账仍然追加 `sdk_service/issue-log.csv`；签发动作与 GUI 解耦（`issue_direct`），已测 VALID
- Taildrop 落盘目录 = `~/Downloads`（Tailscale 桌面端），界面一键打开

## 台账防御（D-D1/D-D2/D-D4，2026-08-28 落地）

- **D-D1 重放拦截**：`issue_from_req` 检查历史台账，同 nonce 的 .req 拒签
  （`--allow-replay` 为逃生阀）；GUI 后同样生效
- **D-D2 台账哈希链**：每行追加 `prev=SHA256(上一行 body)`；校验用
  `python sdk_service\verify_ledger.py --log issue-log.csv`——
  改/删任意行即失配（篡改/删除可检测）；旧行视为 legacy 链起点可兼容
- **D-D4 字段卫生**：`serial ≤64 / customer ≤64 / note ≤512`，且拒绝
  `,`、CR、LF、TAB（csv 注入防护）；req_gen/issue 双侧校验

回归：13/13 PASS（注入拒绝 ×5、链条自洽 ×2、篡改/删行检测 ×2、
legacy 兼容 ×1、重放拦截 ×2、逃生阀 ×1）；服务器生产台账实测 OK。

## 完整流程（对客户/对你各 5 步）

**客户侧**
1. 拿到 `req_gen.py`（+ `tools/vmenc.py`，二者必须同版本目录结构）
2. 目标机器上运行：`python req_gen.py --name 公司名`
3. 得到 `.req` 文件；同时把屏幕打印的 `MACHINE_ID` **用另一渠道**（电话/微信）报给你
4. 把 `.req` 邮件/网盘发给你
5. 收到回传的 `license.txt`，放到程序目录 → 以后完全离线使用

**签发侧（你）**
1. 查收 `.req`，核对客户口头报的 `MACHINE_ID` 与文件内一致（双通道核对）
2. `python issue_from_req.py --key keys/prot-priv.json --req reqs/xxx.req --serial SN-订单号 --out licenses/<客户>/license.txt`
3. 检查输出的回执信息（serial / machine_id / tier / expires）
4. 把 `license.txt` 邮件/网盘回传
5. 签了多少、给谁、什么时候——都在 `issue-log.csv`（只增不改）

## 服务器侧（交给你处理）

见 `SERVER_TODO.md`：部署目录、私钥保管、依赖安装、回执模板。服务器装好后，签发流程与本机完全一致，**无需任何改动**。

## 依赖

- Python 3.8+（客户机与签发机）
- `pip install cryptography`（vmenc sign 所需）
- 客户机为 Windows（machine_id 依赖卷序列号/机器 GUID/磁盘物理序列号）

## 相关文件

- `req_gen.py` — 客户侧申请文件生成器
- `issue_from_req.py` — 签发侧：.req → license.txt
- `SERVER_TODO.md` — 服务器部署清单（你来处理的空位）
- `tools/vmenc.py` — 既有签发/验签工具链（keygen/sign/issue，本方案复用）