# ShardVase v1.2.0 发布公告（文案母版）

> 用途：GitHub Release 正文 / 公开渠道公告共用。文案只写**可复核**的事实——
> 每条都有门禁、归档或本公告内的校验步骤作依据（诚实边界见文末）。

---

**ShardVase v1.2.0 —— 反逆向保护 + 离线授权的可实证版本**

下载：[shardvase-demo-v1.2.0-win64.zip](https://github.com/auui-LDAH/ShardVase-demo/releases/tag/v1.2.0)（5 个文件，免安装）

## 这一版做了什么

- **4.3 链式 CRC**：完整性表不再各自独立——每一槽位的存储值 = crc32(本段原文 ‖ 前一槽位存储值)。
  改**任意一处**都必须重算整条链，静态改补从「改哪补哪」变成「改一处动全链」。
  判据 20 条 + 变异注入 13/13 全拦；Release 构建逐槽打印 `raw → chained` 对。
- **随机覆盖再加一层**：每构建在基座 4 组之上随机抽取额外 CRC 覆盖组
  （rsrc/reloc/protpad 池，K∈{1,3}），攻击者无法预知本轮覆盖布局。
- **门禁 47 项全绿（三开关全开）**：e2e 30 项 + 攻击面 12 项 + 可复现构建 +
  检查器变异测试 + 骨架回归 + 迁移成本（按工具链分档，MSVC 14.51 实测 M3=6.2%）。
- **工具链与工程**：MSVC 升级 14.51.36231（与 CI 同版）；`pack_release.ps1`
  一键发版（dumpbin 三查/签名/SHA256SUMS 自校验）；SPDX 覆盖 100%。
- Studio ST3-ST6、SDK 三步接入向导、离线签发体系（私钥留你服务器）。

## 下载后 5 分钟怎么验（本公告撰写时逐步实测）

```text
1) 解压 → 5 文件位于根层
2) sha256sum -c SHA256SUMS        → 4/4 全对
3) 直接运行 demo.exe              → 机器标识打印，授权通过（签发机上）
4) 错误序列号                      → "序列号无效。" exit=1
5) 改 license 一个字节             → license: 0，拒绝运行
6) signtool verify /pa demo.exe   → Successfully verified（自签证书）
```

在**非签发机**上首跑会看到 `license: 0` ——这不是包坏了，是机器绑定
**按设计工作**：运行会照常打印你的 `机器标识:0x...`，把它附到评估申请
Issue 即可签发绑定你机器的授权。

## 校验和（zip 与包内 SHA256SUMS）

```text
zip: 1F6591955677613be80d7088e78183cfd8b681ce42093cac05155287114d2a56  shardvase-demo-v1.2.0-win64.zip (209705 B)
demo.exe: 72ec11e45dc09aae5343fc245577eaa2ca0a648ad4a6ba97f5ccbc31ae9b71b8
vm.blob:  50165ba9fe61dd7cfd087b6cf26166ab7b9f5edde62c46740b5f7c9a2d41a27b
license.txt: 6f30c9b724dc94dc0acd996aa7cc1fdc0a2404a6807bb3a479d607ba56440001
ReadMe.txt:  ae4af16db723bb4a56be568ab4c311e3208fd4da7a76dfb075d2b6c142ecbbc6
```

源码 tag：`v1.2.0`（`bd4193b`，发行包 ReadMe 内「源码提交」与之一致）。

## 诚实边界（先读）

- 签名为自签证书（CN=PROT Demo Dev），SmartScreen/杀软提示属预期；
  信任链与发版流程见仓库 RELEASE.md。
- 我们**不写「0 破防」**：公开的 [5 项显式破防](https://github.com/auui-LDAH/ShardVase-docs/blob/main/attack-record.md)
  各带前置条件与缓解路径；[能力与边界](https://github.com/auui-LDAH/ShardVase-docs/blob/main/boundaries.md) 全文公开。
- 攻防累计（逐轮归档可复核）：BLOCKED 40 / PARTIAL 30 / 显式破防 5；
  第 6–9 轮（SDK）另计 51 PASS / 4 CHECK。

申请评估授权 / 提问：[开 Issue](https://github.com/auui-LDAH/ShardVase-docs/issues/new?template=eval.yml)（模板已附所需字段）。
