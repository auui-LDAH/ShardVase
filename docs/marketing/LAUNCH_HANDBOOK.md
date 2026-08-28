# 上线操作手册（ShardVase GitHub 公开面）

> 本手册给你（账号操作人）的 10 分钟上线清单。内容文件已在
> `docs/marketing/` 与 `build/release-staging/` 备齐，按下面步骤推。

## 一、创建组织（1 分钟，网页操作）
1. github.com → 右上头像 → Settings → Organizations → New organization；
2. 名称 `ShardVase`（品牌名），Account：Free；
3. 完成后你拥有 `ShardVase` 组织（你是 owner）。

## 二、创建公开仓库（3 分钟，网页或 gh CLI）
| 仓库 | 内容来源 |
|------|----------|
| `ShardVase/docs` | `docs/marketing/README.md`（首页）、`boundaries.md`、`attack-record.md`、`landing.html`、3 个 Issue 模板（放 `.github/ISSUE_TEMPLATE/`）|
| `ShardVase/demo` | `build/release-staging/hashcalc-demo-v1.zip` → Releases（v1.0）+ 包内 README 粘贴为仓库 README |
| `ShardVase/website`（可选）| `landing.html` → GitHub Pages（Settings → Pages → 主分支 /docs 或 root）|

用 gh 示例（docs 仓库）：
```
gh repo create ShardVase/docs --public --description "ShardVase docs: capabilities / honest boundaries / attack records" 
cd docs-public && git init && ...（复制内容文件后推送）
```
（仓库创建后，把对应文件推入；或网页上传也行——文件不多。）

## 三、Issue 模板生效
- 模板文件必须位于 `ShardVase/docs/.github/ISSUE_TEMPLATE/*.yml` 才会被
  Issues → New issue 识别（三个：eval/consult/security）。

## 四、演示包 Release
1. `ShardVase/demo` 仓库 → Releases → Draft new release；
2. Tag `v1.0.0`；附件上传 `hashcalc-demo-v1.zip`；
3. 公告正文用包内 README 的简介段。

## 五、Pages（可选，推荐做）
- `ShardVase/website` 或 `docs` 仓库 Settings → Pages → 分支 root /
  → 得到 `https://shardvase.github.io/website/`，把 README 的链接指过去。

## 六、邮箱路由（免费，复用 volga 域名）
1. Cloudflare Dashboard → 你的域名 → Email → Email Routing；
2. 添加规则：`shardvase@volga...` → 转发到你的个人邮箱；
3. 等 MX/DNS 生效（几分钟-几小时）；
4. 把 `shardvase@<域名>` 写进 README/landing 的联系位置。

## 七、发布前红线检查（每次发布执行）
- [ ] 目录里没有 `src/ include/ tools/` 内文件（保护内核）;
- [ ] 没有攻击工具脚本（vm_reduce/procdump/attack_drill*）;
- [ ] 没有私钥/台账/服务器地址；
- [ ] README/blog 里品牌/邮箱一致；
- [ ] 演示包 zip 内 `license_eval.txt` 的 expires 仍 > 今天。

## 八、发布节奏建议（内容面）
- 文章（docs/marketing/已备 3 篇初稿）每周 1 篇：知乎/掘金/V2EX/GitHub Discussions；
- 每次攻防/功能更新 → demo Release 小版本。

## 九、服务交付流程（收到咨询后）
1. Issue/邮件确认需求与栈；
2. 报报价（docs/commercial/PRICING.md 草案）；
3. 首笔=接入实施费 → 用 prot_sdk 接入 → 签发体系部署/托管；
4. 签收后按 SLA 提供服务。