# verify 门禁增强 + 收口计划 (VERIFY_PLAN)

> 版本：2026-08-22 v2 · 状态：**✅ 全部完成（2026-08-22 落地）** · 关联：`verify.ps1`（发版门禁）·
> `tests/protchain_check.py`（保护链断言 P1-P6，CI_PLAN 产物）· `tests/attacks.py`（A1-A12）·
> `docs/CI_PLAN.md` / `docs/ATTACK_PLAN.md` / `docs/HANDOVER.md`（剩余事项）。
> 本文档规划：**verify.ps1 同步保护链断言**（本地门禁 = CI 门禁）+ 剩余事项收口盘点。
> v2 记录落地结果 + 附带修复（example 适配 BLOB_SIGN）。

---

## 1. 背景与目标

### 1.1 现状
`verify.ps1`（本地发版门禁）覆盖：build + e2e + vm_unit + syscall_probe +
attacks + vmc + example。**缺口**：
- `protchain_check.py`（P1-P6 保护链断言，CI_PLAN 产物）**未纳入 verify**——
  本地发版不检查保护链完整性；
- `attacks.py` 已扩展到 A1-A12，verify 跑的是 attacks（全量，自动含 A8-A12）✓；
- 环境限制项（T3/双机/N1 真机/D2b）与阶段 III（按 D2 不启动）无法本地推进。

### 1.2 目标
1. verify.ps1 纳入 `protchain_check.py`（P1-P6），本地门禁与 CI 一致；
2. 破坏性验证：去掉保护 → verify 必须 FAIL；
3. 收口盘点：确认全部本地可做事项完成，剩余全部为环境/决策限制项。

---

## 2. verify.ps1 增强设计

### 2.1 改动点
- `Invoke-Once` 增加 `protchain` 步骤：
  ```
  Write-Step "round $i/$tot : python tests\protchain_check.py"
  $pc = @(& $py tests\protchain_check.py 2>&1)
  $rcP = $LASTEXITCODE
  if ($rcP -ne 0) { $ent.protchain = 'FAIL'; $ent.log = $pc }
  else { $ent.protchain = 'PASS' }
  ```
- 报告行 `r{i}: build=.. e2e=.. vm_unit=.. syscall_probe=.. attacks=.. vmc=.. example=.. protchain=..`；
- `$roundBad` 加入 protchain（任一 FAIL → 轮次 FAIL）；
- 汇总统计加 protchain。

### 2.2 顺序
protchain 是静态断言（不依赖进程、无 WDAC 干扰），放在 build 后、e2e 前
（失败即中止本轮，快速暴露保护链问题）。

### 2.3 与 CI 一致
CI（ci.yml）已跑 protchain；verify 补上后本地/远程门禁完全一致。

---

## 3. 剩余事项收口盘点（2026-08-22）

| 事项 | 状态 | 本地可做？ | 解锁条件 |
|------|------|-----------|----------|
| T3 真机调试 | 环境限制 | ❌ | 交互桌面会话 |
| 硬件绑定双机 | 环境限制 | ❌ | 第二台机器 |
| N1 D2b 真机复核（杀软） | 环境限制 | ❌ | 交互桌面会话 |
| A8/A9/A12 进程确认 | 待 CI/真机 | ❌（本机 WDAC） | CI 远程运行 / 真机 |
| CI 远程运行回填 | 待 push | ❌ | GitHub 远程 |
| 阶段 III 服务端（M3.2/M3.3） | 按 D2 不启动 | ✅（可做但决策不启动） | 业务决策 |
| **verify.ps1 同步 protchain** | **本次推进** | ✅ | 无 |
| demo\license_vm.vasm 清理 | 保留作参考 | ✅（但保留） | 无 |

**结论**：本计划（verify 同步）是当前最后一个**本地可做且有价值**的事项；
完成后项目进入"环境/决策待办"状态。

---

## 4. 决策点

| 编号 | 决策 | 选项 | 推荐 | 理由 |
|------|------|------|------|------|
| V1 | protchain 是否纳入 verify | 纳入 / 仅 CI | **纳入** | 本地门禁 = CI 门禁，发版前必查 |
| V2 | protchain 失败是否中止本轮 | 中止 / 仅标记 | **标记 FAIL 不中止** | 与现有步骤一致（各步骤独立跑，汇总判定） |
| V3 | license_vm.vasm 清理 | 删 / 保留 | **保留** | 历史参考（现状已是"保留"） |

## 5. 实施步骤

| 步骤 | 内容 | 工作量 | 依赖 |
|------|------|--------|------|
| 1 | verify.ps1 加 protchain 步骤 + 报告字段 | 0.5 天 | 无 |
| 2 | 破坏性验证（去保护 → verify FAIL） | 0.5 天 | 步骤 1 |
| 3 | 全量回归（verify -Minimal） | 0.5 天 | 步骤 1-2 |
| **合计** | | **1.5 天** | |

## 6. 验收标准

1. `verify.ps1 -Minimal` 含 protchain 步骤且 PASS；
2. 破坏性测试：临时改坏 selfcrypt（如跳过加密）→ verify protchain FAIL；
3. 报告 JSON 含 protchain 字段；
4. 其余步骤零回归（e2e/attacks/vm_unit/vmc/example 全绿）。

## 7. 风险与回退

| 风险 | 等级 | 缓解 |
|------|------|------|
| verify 改动破坏现有流程 | 低 | 纯增量（新步骤 + 新字段） |
| protchain 在 WDAC 环境误报 | 低 | 静态断言不启动进程，无 WDAC 依赖 |
| 全量 verify 时长增加 | 低 | protchain 秒级 |

**回退**：verify.ps1 移除 protchain 步骤即回退（纯增量）。

## 8. 待办清单

1. [x] 拍板 V1-V3（§4）——纳入 verify / 标记 FAIL 不中止 / license_vm.vasm 保留。
2. [x] 步骤 1：verify.ps1 加 protchain（ent 字段 + build 后步骤 + roundBad + 报告行）。
3. [x] 步骤 2：破坏性验证（改密文为序言 → P1 FAIL，断言有效）。
4. [x] 步骤 3：全量回归（verify -Minimal 全绿 PASS：build/e2e/vm_unit/
      syscall_probe/attacks/vmc/example/protchain）。
   **附带修复**：example 适配 BLOB_SIGN——.protcrypt 容器从 demo/main.c 移到
   src/selfcrypt.c（example 链接不缺符号）；build_example.ps1 pack/revoke 加
   --sign（blob.c/revoke.c 强制 v1）；test_example.py E5 revoke --sign。
