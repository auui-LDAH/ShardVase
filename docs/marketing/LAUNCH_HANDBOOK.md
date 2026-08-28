# 上线操作手册（ShardVase 公开面 · 个人账号版）

> 方案变更记录（2026-08-28）：原计划"GitHub 组织"，因账号意愿与经济
> 考量，降级为**个人账号 + 前缀仓库（ShardVase-*）**——完全免费、
> 效果等效，后续想升级组织随时可迁。
> 内容文件已在 `docs/marketing/` 与 `build/release-staging/` 备齐。

## 一、个人账号创建公开仓库（3 分钟，网页或 gh CLI，全部免费）
| 仓库 | 内容来源 |
|------|----------|
| `<你的账号>/ShardVase-docs` | `docs/marketing/README.md`（首页）、`boundaries.md`、`attack-record.md`、`landing.html`、3 个 Issue 模板（放 `.github/ISSUE_TEMPLATE/`）|
| `<你的账号>/ShardVase-demo` | `build/release-staging/hashcalc-demo-v1.zip` → Releases（v1.0）+ 包内 README 作为仓库 README |
| `<你的账号>/ShardVase-website`（可选）| `landing.html` → GitHub Pages |

用 gh（示例，先在 `ShardVase-docs` 目录放好内容文件）：
```
gh repo create ShardVase-docs --public --description "ShardVase docs: capabilities / honest boundaries / attack records"
cd ShardVase-docs && git init -b main && git add . && git commit -m init && git push -u origin main
```
（或用网页 New repository 上传，文件不多。）

## 二、Issue 模板生效
模板文件位于 `<账号>/ShardVase-docs/.github/ISSUE_TEMPLATE/*.yml`
（eval/consult/security 三份）→ Issues → New issue 自动识别。

## 三、演示包 Release
`ShardVase-demo` 仓库 → Releases → Draft → Tag `v1.0.0` →
上传 `hashcalc-demo-v1.zip` → 公告粘贴包内 README 简介。

## 四、Pages（可选，推荐）
`ShardVase-website` → Settings → Pages → Deploy from branch → root →
得到 `https://<账号>.github.io/ShardVase-website/`，
README/landing 链接换成实际地址。

## 五、邮箱路由（免费，复用你的域名）
1. Cloudflare Dashboard → 域名 → Email → Email Routing；
2. 规则：`shardvase@<域名>` → 转发到个人邮箱；
3. 等 DNS 生效，把地址写进 README 联系位。

## 六、发布前红线检查（每次发布执行）
- [ ] 目录没有 `src/ include/ tools/` 内文件（保护内核）；
- [ ] 没有攻击工具（vm_reduce / procdump / attack_drill*）；
- [ ] 没有私钥/台账/服务器地址/真机地址；
- [ ] 品牌/邮箱一致；演示包 `license_eval.txt` 未过期。

## 七、内容节奏
- 每周 1 篇（docs/marketing/ 3 篇初稿可发）：知乎/掘金/V2EX/GitHub Discussions；
- 功能/攻防更新 → demo 小版本 Release。

## 八、服务交付流程（咨询 → 成交）
1. Issue/邮件确认需求与栈；
2. 报价（docs/commercial/PRICING.md 草案）；
3. 实施费 → prot_sdk 接入 → 签发部署；
4. 按 SLA 提供支持。