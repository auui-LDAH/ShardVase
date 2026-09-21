# 演示包 — 批量哈希校验工具 (showcase)

> 对评估者：这是一个**被完整保护的真实小工具**样例，用于评估保护套件的
> 效果与授权流程。它演示：授权门、机器绑定、分级授权、试用期控制、
> 防篡改/防伪造——全部是真实运行中的能力，不是截图或文档宣称。

## 这是什么
`hashcalc`：批量文件 SHA-256 校验工具（示例业务，代码见
`business_hash.c`，可运行可编译）。

## 怎么试用
1. 交付物（签发方提供）：`hashcalc.exe` + `vm.blob` + `license_eval.txt`
   + 序列号（当前演示用固定 `DEMO-2026-ABCDEFGH`）
2. 首次运行：
   ```
   hashcalc.exe --license-file license_eval.txt --vm-blob vm.blob
   ```
   输入序列号 → 应看到：
   ```
   license: 1 (tier=1 expires=17xxxxxx)
   == 批量哈希校验工具 (正式版) ==
   机器绑定: 0x.... [Tier 1]
   ```
   （`license_eval.txt` 为 7 天评估授权，到期后自动拒绝）
3. 分级展示：Tier2（高级版）license 下发后，自动启用目录递归扫描
   （`--scan` 语义），观察功能分级随 license 变化。

## 你能亲手验证的效果
| 试一下 | 预期 |
|--------|------|
| 删除 / 改 license.txt 任意字段 | `license: 0`，拒绝运行 |
| 把 license 拷到另一台机器 | 拒绝（机器绑定在签名内）|
| 替换 vm.blob 为伪造版本 | `VM 镜像装载失败`（blob 签名强制）|
| 到期后再运行（把系统时间改到 expires 之后）| 拒绝（试用期控制；注：本地时钟可知）|
| 用调试器附加 / 常见投 dump | 反调试多维扫描 + 完整性自检拦截 |

## 授权流程（签发方视角，见 sdk_service/ + docs/PACKAGING_PLAN.md）
```
客户机: req_gen.py 生成 .req（含机器码）
签发方: 核对机器码 → 服务器 issue_from_req 签发 license.txt（tier/expires 可配）
        → 补签 vm.blob（blob 与 license 同私钥，防替换）
客户机: 放入 license.txt → 离线永久使用（到期/换机/篡改全拒）
```

## 构建复现（开发商）
`business_hash.c` → prot_sdk 向导生成工程（pub 模式）→ 构建 →
签发方补签 blob + 发 license → 验收。全程见 `prot_sdk/QUICKSTART.md`。

## 诚实边界（同 THREATMODEL）
- EXPIRES 依赖本地时钟（回拨可绕过；商业版需在线时间锚点）
- 安装目录须防写（否则攻击者能换公钥重签）
- 本示例业务函数体未被 VM 化（授权判定链已 VM 保护；业务 VM 化是扩展项）

## 部署说明（维护者）

本目录是**开发者向**的说明。对外发布的 `ShardVase-demo` 仓库 README 有
**三个来源**，各有不同受众，部署时需注意不要互相覆盖：

| 文件 | 受众 | 用途 |
|------|------|------|
| `prot_sdk/showcase/README.md`（本文件） | 仓库开发者 | 构建复现与边界说明 |
| `build/release-staging/hashcalc-demo/README.md` | **下载包用户** | 随 zip 交付，讲怎么运行/续期 |
| `auui-LDAH/ShardVase-demo` 仓库 README | 仓库访客 | 摘要 + 指向 Releases 与 docs 库 |

> **2026-09-21 教训**：曾计划用下载包版本**覆盖**仓库 README，
> 那会丢失仓库版里的 `能力与边界：[ShardVase-docs]` 交叉链接与
> "下载 Releases 里的 zip" 引导 —— 仓库访客看到的应是"怎么获取"，
> 而非"解压后怎么跑"。正确做法是**合并**（保留仓库版的头部引导 +
> 追加下载包的正文细节），见 commit 记录。
>
> 注：`build/` 被 `.gitignore` 覆盖，故下载包 README 不在版本库内，
> 仅由打包流程使用。修改它不会进入 git 历史。