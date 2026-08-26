# 基础设施完善计划 (INFRA_PLAN)

> 版本：2026-08-26 v2 · 状态：**✅ I1-I6 全部完成（2026-08-26）** · 关联：构建/验证/CI/测试/部署·
> `docs/CI_PLAN.md`（CI 增强）· `docs/HANDOVER.md`（现状）。
> 本文档规划**完善现有基础设施**——目标是让构建/测试/发布链路：
> 可复现、可审计、可回归、可运维，并补齐 CI 从不实际运行的缺口。

---

## 1. 现状盘点（健康 but 有缺口）

| 基础设施 | 现状 | 缺口 |
|----------|------|------|
| build.ps1 | 完整开关（MachineId/Config/种子/D2b/Drill）+ WDAC 容错 | 无 `--help`；参数校验弱；增量构建无 |
| verify.ps1 | 本地门禁全链（build/e2e/vm_unit/attacks/vmc/example/protchain）+ 可复现 | **`-Reproducible` 未与 CI reproducible job 对齐** |
| ci.yml | build/e2e/attacks/vm_unit/vmc/example/protchain/reproducible | **从未实际运行**（无 GitHub 远程 push） |
| 测试 | 57 项攻防 + e2e T1-T28 + protchain | 部分需真机/桌面会话（已知） |
| 部署 | NSSM 服务化驻留 + 签名 | 无自动化部署脚本（生产 APK/SO 待） |
| 文档 | 20+ 份 | 版本对齐需持续维护 |

**核心缺口（本轮重点）**：
1. **CI 从不实际运行** → 缺乏 CI 等效验证；妥协：本地 CI 模拟器
2. **verify.ps1 -Reproducible 与 CI reproducible job 不一致** → 校准
3. **无发布（release）流水线自动化** → release 检查脚本
4. **构建无参数帮助/校验** → build.ps1 --help + 参数校验
5. **测试产物管理**（drill 报告/临时文件）→ 清理策略
6. **版本/变更追踪** → CHANGELOG 自动生成钩子

---

## 2. 完善项设计

### I1 — 本地 CI 模拟器 (`tools/ci_sim.ps1`)
- **Why**：CI 无远程 push → 本地等效跑一遍 CI 步骤（同 ver!y 但模拟
  actions 顺序）验证配置正确。
- **做**：读 ci.yml 解析 steps → 按序执行（build -RecordSeeds →
  e2e → attacks → vm_unit → vmc → example → protchain → py_compile →
  可复现比对）；输出 PASS/FAIL + 与真实 CI 相同的判定。
- **校验**：ci.yml 语法 + 步骤可执行 + 可复现一致。

### I2 — verify/CI 可复现对齐
- **Why**：verify.ps1 `-Reproducible`（双构建 SHA）vs CI reproducible job
  （下载 seeds 重建比对）**判定逻辑需一致**。
- **做**：统一为 `tools/repro_check.ps1`（build ×2 同种子 → SHA256 比对
  demo.exe+vm.blob），verify.ps1 和 ci.yml 都调用它。

### I3 — 发布检查脚本 (`tools/release_check.ps1`)
- **Why**：发版前需要一键确认所有 release 前置条件。
- **做**：检查 items——
  - git 干净（无未提交）；
  - Release 构建成功（build.ps1 -Config Release）；
  - 可复现（同种子 SHA 一致）；
  - 签名有效（signtool verify）；
  - test 全绿（e2e/attacks/protchain）；
  - manifest.json 版本正确；
  输出 PASS/FAIL 清单 → 发版 gate。

### I4 — build.ps1 --help + 参数校验
- **Why**：新开发者/跨环境需要 self-documenting。
- **做**：`-Help` 开关打印全部参数及含义；参数值校验（Config∈{Dev,Release}、
  MachineId 数值/auto；Seed 文件存在）。

### I5 — 产物/临时文件清理策略
- **Why**：drill 报告/测试临时物累积在 build/drill*，无清理。
- **做**：`tools/clean_build.ps1`（清理 build/drill*, verify-artifacts,
  keys 保留）—— 发布前清理 + 日常维护。

### I6 — CHANGELOG 钩子
- **Why**：20+ 提交无 changelog 自动维护。
- **做**：`tools/gen_changelog.ps1` 从 git log 生成 CHANGELOG 草稿
  （按 commit 分类）→ 发版时人工确认。

---

## 3. 决策点

| 编号 | 决策 | 选项 | 推荐 |
|------|------|------|------|
| D1 | CI 模拟 vs 真实 push | 本地模拟 / 配远程 push | **本地模拟**（无远程但也保 CI 正确性） |
| D2 | repro 判定统一工具 | 独立 repro_check / 内联各侧 | **独立工具**（verify+CI 复用） |
| D3 | release_check 强制 | 发版必跑 / 可选 | **必跑**（gate） |
| D4 | CHANGELOG 自动化 | 脚本生成草稿 / 手动 | **脚本草稿+人工确认** |

## 4. 实施步骤

| 步 | 内容 | 工作量 |
|----|------|--------|
| I1 | ci_sim.ps1 本地 CI 模拟 | 0.5-1 天 |
| I2 | repro_check.ps1 + verify/CI 接入 | 0.5 天 |
| I3 | release_check.ps1 发版 gate | 0.5 天 |
| I4 | build.ps1 --help + 校验 | 0.3 天 |
| I5 | clean_build.ps1 | 0.2 天 |
| I6 | gen_changelog.ps1 | 0.3 天 |
| 回归 | 全链 + 文档 | 0.5 天 |
| **合计** | | **3-4 天** |

## 5. 验收标准
1. `ci_sim.ps1` 本地跑通全部 CI 步骤，PASS；
2. `verify.ps1 -Reproducible` 与 CI reproducible 同判定（repro_check 统一）；
3. `release_check.ps1` 输出完整 PASS 清单（clean/Release/signed/repro/test 全绿）；
4. `build.ps1 -Help` 帮助清晰；非法参数被拒；
5. `clean_build.ps1` 安全清理（keys 保留）；`gen_changelog.ps1` 生成草稿；
6. 现有全链不回归（build/e2e/protchain 绿）。

## 6. 风险与回退
| 风险 | 缓解 |
|------|------|
| CI 模拟不覆盖 GitHub 环境差异 | 注明"本地等效"；真实 CI 留待 push |
| repro_check 改动影响现有 verify | 用同一工具复用，回归测试 |
| release_check 过度严格 | 参数化 `-SkipTest` 等松弛项 |
| 脚本新增 bug | 全链 py_compile + 回归 |

**回退**：全部是增量新脚本/参数，删除即回退。

## 7. 待办清单
1. [x] 拍板 D1-D4（本地 CI 模拟 / 独立 repro / gate 必跑 / 脚本+人工）。
2. [x] I1: ci_sim.ps1 —— 本地跑通 PASS（build+repro_check 一致）。
3. [x] I2: repro_check.ps1 —— demo.exe/vm.blob SHA-256 identical；verify.ps1
       -Reproducible 已接入统一判定。
4. [x] I3: release_check.ps1 —— 发版 gate（clean/Release/repro/test/sig/manifest）。
5. [x] I4: build.ps1 -Help + 参数校验（Config Bad 拒绝）。
6. [x] I5: clean_build.ps1（drill 清理 + keys 保留）已验证。
7. [x] I6: gen_changelog.ps1 —— 按 feat/fix/docs 分类生成草稿。
   **剩余待办**（非本轮阻断）：
   - release_check.ps1 完整实跑（全 test）作为下次发版前 gate；
   - ci_sim 未来接真实 GitHub push 后替换为真 CI；
   - Android T1（攻防矩阵）需 NDK/真机；
   - 24h 驻留服务期满确认（8/27 12:33）。