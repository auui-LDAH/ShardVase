# publish/ —— 博客发布素材（客户向展示内容）

本目录存放**面向客户/潜在合作方的展示内容**，用于发布到自建博客
（blog.qvorqio.cn，Halo）。均为公开安全内容，**不含**内部敏感信息
（密钥、私钥、攻击手法细节、内部文档引用等）。

---

## 内容清单与发布建议

| 文件 | 建议标题 | 类型 | 发布顺序 | 说明 |
|------|----------|------|----------|------|
| `01-关于ShardVase.md` | 关于 ShardVase | 页面（SinglePage） | 1 | 品牌介绍，放导航"关于" |
| `02-项目档案.md` | ShardVase 项目档案 | 文章（Post） | 2 | 完整技术档案（能力+实证+边界） |
| `03-攻防实录-01-dump.md` | 你的软件 30 秒就被 dump，然后呢？ | 文章 | 3 | 攻防实录系列第 1 篇 |
| `04-攻防实录-02-授权.md` | 授权不该一把密钥走天下 | 文章 | 4 | 攻防实录系列第 2 篇 |
| `05-攻防实录-03-接入.md` | 把保护做进产品：从 0 到受保护 exe | 文章 | 5 | 攻防实录系列第 3 篇 |
| `06-诚实边界.md` | 诚实边界（公开版） | 页面 | 6 | 6 项实证边界 + 缓解路径 |
| `07-攻防记录.md` | 攻防记录（公开摘要） | 页面 | 7 | 轮次总览 + 可对外结论 |

## 发布操作备忘（Halo 后台）

1. 登录 https://blog.qvorqio.cn/console（管理员账号）
2. **页面**：管理 → 页面 → 新建/编辑 → 粘贴 markdown 内容 → 填标题与别名（slug）
3. **文章**：管理 → 文章 → 新建 → 粘贴 markdown → 填标题与别名（slug）→ 发布
4. 建议 slug（与已上线保持一致）：
   - 关于页：`about-shardvase`
   - 项目档案：`shardvase-project-archive`（文章，URL 为 `/archives/shardvase-project-archive`）

## 已上线记录（2026-08-30）

以下两篇已通过 API 发布到博客，内容分别对应：
- 页面「关于 ShardVase」→ `https://blog.qvorqio.cn/about-shardvase`（源自 `01` 旧版/`docs/blog_project_overview.md`）
- 文章「ShardVase 项目档案」→ `https://blog.qvorqio.cn/archives/shardvase-project-archive`（源自 `02` 旧版/`docs/部署档案-ShardVase.md`）

> 后续更新以本目录文件为准；如内容有更新，重新粘贴即可。

## 素材来源（只读引用，勿改）

- 营销文案底稿：`docs/marketing/`（article-1/2/3、README、landing.html）
- 边界与攻防：`docs/marketing/boundaries.md`、`docs/marketing/attack-record.md`
- 完整技术档案（内部版）：`docs/部署档案-ShardVase.md`（含更多内部细节，发布时按需删减）
