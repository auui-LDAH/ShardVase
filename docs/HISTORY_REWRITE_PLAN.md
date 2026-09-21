# 历史重写方案（开源前必做）

> **状态**：方案已验证，**待执行**（不可逆操作，需确认）
> **日期**：2026-09-21
> **原因**：完全开源将公开全部 156 个提交；审计发现历史中含个人与基础设施信息

---

## 1. 为什么必须重写历史

**工作区清理无法清除历史。** 我在工作区删除了这些字符串，但它们仍存在于
早期提交的 blob 中 —— 一旦推送，**任何人 `git log -S` 就能取回**。

实测（`git log -S`）确认 5 个提交含泄露：

| 字符串 | 性质 | 所在提交 |
|--------|------|----------|
| `issuer-host` | 签发机主机名 | `b9b83ef` `e9fa597` `fa2a5f6` |
| `test-host` | 测试机主机名 | `220c120` |
| `DEV-MACHINE` | 开发机 Windows 机器名 | `fa2a5f6` |
| `devuser` / `devuser` / `devuser~1` | 用户名（3 种写法） | `220c120` `e2d4ad0` |
| `100.x.x.x` / `100.x.x.x` | Tailscale 内网 IP | `b9b83ef` `220c120` |

**另有提交身份泄露**（`--replace-text` 不处理）：

```
author/committer: jurecoasertkrockt777 <jurecoasertkrockt777@users.noreply.github.com>    ← 个人 QQ 邮箱
```

对照：现有三个公开仓库用的是
`jurecoasertkrockt777 <jurecoasertkrockt777@users.noreply.github.com>`（GitHub
noreply）—— 说明**一贯做法是隐藏真实邮箱**，本仓库是个例外。

### 风险等级评估（诚实说明）

| 项 | 实际可达性 |
|----|-----------|
| Tailscale CGNAT IP（100.64.0.0/10） | **公网不可路由**，仅 tailnet 内可达 |
| MagicDNS 主机名 | **公网不可解析** |
| 机器名 / 用户名 | 可用于 OSINT 与凭证填充，属**中度**风险 |
| 个人 QQ 邮箱 | 已公开在提交元数据中，可直接被爬取 |

即使当前可达性有限，**"永久可检索"本身就是不该有的暴露面**。且推送后
撤销代价极高（需 force-push + 联系 GitHub 清缓存 + 已被 fork 则无解）。

---

## 2. 方案（已在克隆上完整验证）

```bash
# 1. 内容替换（replacements.txt 见下）
git filter-repo --replace-text replacements.txt --mailmap .mailmap --force
```

`replacements.txt`：

```
issuer-host==>issuer-host
test-host==>test-host
DEV-MACHINE==>DEV-MACHINE
devuser==>devuser
devuser~1==>devuser
devuser==>devuser
100.x.x.x==>100.x.x.x
100.x.x.x==>100.x.x.x
```

`.mailmap`（统一身份到与既有公开仓库一致）：

```
jurecoasertkrockt777 <jurecoasertkrockt777@users.noreply.github.com> <jurecoasertkrockt777@users.noreply.github.com>
jurecoasertkrockt777 <jurecoasertkrockt777@users.noreply.github.com> jurecoasertkrockt777
```

### 工具

`git-filter-repo` 2.47.0（本次安装；`git filter-branch` 亦可但慢且易错）。

---

## 3. 验证结果（在克隆上实测）

| 验证项 | 结果 |
|--------|------|
| 11 个敏感字符串历史残留 | **全部 0** ✓ |
| 全历史 blob 内容扫描（1258 对象） | **0 命中** ✓ |
| 提交身份 | 已统一为 noreply ✓ |
| 提交数 | 156（未丢失）✓ |
| 内容完好（src/vm.c 等 7 文件） | 字节一致 / 行数正常 ✓ |
| **构建** | `build.ps1` **EXIT=0** ✓ |
| **完整门禁** | **12/13 PASS**（唯一失败=测试产生的构建产物使工作区不干净）✓ |
| Python 工具语法 | 4/4 ✓ |

**结论：重写是无损的。**

---

## 4. 副作用：docs 中的 SHA 引用会失效

文档里用 `` `f0aa393` `` 这类形式引用提交。重写后 SHA 变化 → 引用变成死链。

**已用真实 commit-map 实测**（`tools/update_sha_refs.py`）：

| 方案 | commit-map | 需更新 |
|------|-----------|--------|
| 仅 `--replace-text` | 156 条，108 变化 / **48 不变** | 部分保留 |
| **`+ --mailmap`（推荐）** | 156 条，**156 变化 / 0 不变** | **全部需更新** |

> **修正**：本文初稿写"3 个天然保留、23 个需更新" —— 那是**只做内容替换**
> 时的结果。加上 `--mailmap`（为隐藏个人邮箱，推荐做法）后，
> **每一个提交的身份都被改写 → 所有 SHA 都变**。

实际待更新量（`tools/update_sha_refs.py` 在真实 commit-map 上测得）：
**65 处引用，涉及 6 个文件**。

受影响文件：

```
docs/BLUEPRINT.md            30 处
docs/HANDOVER.md             12 处
docs/迁移核验-2026-09-20.md   10 处
docs/MODULAR_ARCH.md          2 处
docs/N1_PHASE2_PLAN.md        1 处
（其余为同文件内重复引用）
```

**自动化**：`tools/update_sha_refs.py --map <commit-map> [--apply]`
读 `filter-repo` 生成的 old→new 映射并批量替换（默认 dry-run）。

---

## 5. 执行清单

- [x] 全量备份（目录副本 + `git bundle`，含完整历史）
- [x] 克隆上验证方案（泄露清零 + 可构建 + 门禁通过）
- [ ] **人工确认后**对真实仓库执行
- [ ] 用 tools/update_sha_refs.py --map <commit-map> --apply 更新 65 处 SHA 引用
- [ ] 重跑完整门禁（须 14/14）
- [ ] 再跑一次广义泄露扫描（确认工作区 + 历史双清零）
- [ ] 推到公开仓库

### 备份位置

```
D:\specifically for development and work\Reverse Engineering-backup-prehistory\
%TEMP%\rf-backup2.bundle      (含完整历史，可 git clone 恢复)
```

---

## 6. 若决定不重写

替代方案与代价：

| 方案 | 代价 |
|------|------|
| 不重写，直接开源 | 上述字符串与个人邮箱**永久公开**，`git log -S` 可检索 |
| 丢弃历史（`--depth 1` 重新初始化） | 丢失全部提交历史与"150 次迭代"这个可信度资产 |
| 只改邮箱不改内容 | 主机名/用户名/内网 IP 仍公开 |

**建议重写**：它是无损的（已实测），且一次做对胜过事后补救。

---

*本文件在重写完成后应更新状态或移除。*
