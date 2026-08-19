# 阶段 II — 真机验证执行计划 (PHASE2)

> 版本：2026-08-19 v1 · 归属：BUSINESS 阶段 II · 前置：阶段 I 全部落地（I1-I6 完成，
> verify 单机全绿，WDAC 环境限制已记录于 COMPAT §7 / RELEASE §5）。
> 本文件是**执行计划**（怎么测、顺序、验收）；技术细节/风险清单见 `docs/COMPAT.md`
> （测什么、为什么）；`docs/OPS.md` §5 提供吊销运营流程。
> 执行前提：**一台普通 Windows 10/11 真机**（非沙箱、无 WDAC 或策略放行）。

## 1. 目标与范围

- **目标**：在真实用户会话（可 attach 调试器、无 Application Control 拦截、
  普通网络）上完成全部自动化用例 + 兼容矩阵 + 硬件绑定 + 长期稳定性验证，
  把"单机全绿"升级为"目标环境全绿"，产出 `docs/compat-matrix.csv` 记录。
- **范围**：T1-T19 全量、attacks A1-A7、syscall_probe、vm_unit、24h 驻留、
  8 开并发、双机绑定、吊销真机行为、可复现构建交叉验证、签名 SmartScreen 记录。
- **不在范围**：阶段 III（服务端，见 PHASE3.md）、32 位/ARM 支持（决策点 D7）。

## 2. 前置条件

| 项 | 规格 | 用途 |
|----|------|------|
| 真机 A（必须） | Windows 10 22H2 或 Windows 11 22H2+，x64，普通用户会话，4GB+ 内存 | 主验证机 |
| 真机 B（建议） | 任意 Windows 10/11，x64 | 硬件绑定换机验证 |
| 克隆 VM（可选） | 真机 A 的 VM 克隆 | hostid 克隆绕过评估（COMPAT §5） |
| Python 3.8+ | 仅 stdlib | 跑 tests/ |
| 仓库拷贝 | git 仓库（含 build/keys 私钥与 codesign.pfx，安全通道） | 构建/签发 |

## 3. 准备清单（真机 A 上执行一次）

```powershell
# 1. 环境确认
git status                                  # 干净
python tools\osinfo.py --json               # 记录 OS 版本 (COMPAT §6)
python -c "import ctypes; print('wdac-probe')"  # 无需; 直接跑 demo 验证可执行

# 2. 构建 + 单机回归 (冒烟应通过; 若 WDAC 拦截按 COMPAT §7 处理)
powershell -ExecutionPolicy Bypass -File build.ps1
powershell -ExecutionPolicy Bypass -File verify.ps1 -Minimal

# 3. 记录基线
#    若 T3 仍 SKIP -> 说明会话仍受限, 先解决"普通交互会话"问题
python tests\e2e.py
```

## 4. 执行步骤（按顺序，每步独立可验收）

### P2-1 环境基线与 T3 真机调试（最高优先）
- **用例**：`python tests\e2e.py` 的 T3（DebugActiveProcess 附加 demo --wait-ms 4000）。
- **期望**：T3 从 SKIP 转 **PASS**（退出 0xDB + MSG_DBG 文本）。
- **若 FAIL**：记录退出码/输出到 matrix；检查是否被调试器策略/杀软拦截；
  这是"置信度"验证，FAIL 不等于保护失效（见 COMPAT §2 咨询项说明）。
- **验收**：T3 PASS 或如实记录 FAIL 原因（不允许静默 SKIP 过关）。

### P2-2 兼容矩阵（每台目标系统各一轮）
- **目标系统**：Win10 21H2 / 22H2、Win11 21H2 / 22H2 / 23H2 / 24H2、
  Windows Server 2022（决策点 D6 决定优先级）。
- **每台执行**（写 `docs/compat-matrix.csv` 一行）：
  ```
  python tests\e2e.py          # T1-T19 (T3 应 PASS)
  python tests\attacks.py      # A1-A7
  powershell verify.ps1 -Minimal
  build\demo.exe --selftest    # 干净环境全 0 (反调试零误报专项)
  ```
- **验收**：e2e+attacks+verify 全绿；`--selftest` 全部字段 0；
  任何 FAIL/异常 → 记录 os_build + 现象 + 版本，按 §6 异常处理。

### P2-3 反调试专项（每台）
- `build\demo.exe --selftest`：全部 10 个字段必须 0（干净会话）。
- 可选加测：任务管理器/DebugView 等常见工具运行时是否误报（记录）。
- **验收**：全 0；误报项记录并评估（咨询项可静默，关键项需版本适配）。

### P2-4 长期驻留（真机 A，后台）
- **24h 驻留**：`build\demo.exe --wait-after 86400000 --license-file build\license.txt`
  后台运行 24h：零退出（无 0xBAD/0xDB/0xB1E4）、内存稳定（任务管理器观察，
  允许 ±5% 抖动无持续增长）。
- **8 开并发**：8 个实例并行 10 分钟全部正常退出 0。
- **验收**：两项通过；记录内存峰值/均值到 matrix。

### P2-5 硬件绑定（需真机 B）
| 用例 | 步骤 | 期望 |
|------|------|------|
| 换机拒绝 | A 签发 license → B 运行 | license: 0，退出 1 |
| 同机续用 | A 重新运行 | license: 1 |
| 克隆 VM | 克隆 A → 运行 | 记录是否通过（触发决策点 D5） |
| 因子审计 | 两台 `--selftest` 的 machine_id 对比 genserial | 记录差异 |
- **验收**：换机拒绝成立；克隆行为记录并触发 D5 决策。

### P2-6 吊销真机行为
- 真机 A：生成含 A 的 serial 的黑名单 → demo 退出 0xB1E4（strict）；
  warn 策略 → 告警继续；删除黑名单 → 恢复。
- **验收**：T15-T19 语义在真机复现 PASS。

### P2-7 可复现构建交叉验证
- 真机 A：`build.ps1 -Config Release -RecordSeeds` →
  `verify.ps1 -Reproducible build\seeds.json`（无签名产物字节一致）。
- **验收**：reproducible OK；签名产物记录差异属预期（RELEASE §5）。

### P2-8 签名与 SmartScreen 记录
- 真机 A 首次运行签名 exe：记录 SmartScreen 提示（自签证书预期有警告，
  商业证书后应消失）；`signtool verify /pa` 通过。
- **验收**：记录观察结果（供 D4 发版决策）。

## 5. 记录模板（docs/compat-matrix.csv）

```
os_build,arch,date,verify,e2e_t3,selftest_clean,24h_ok,concurrent_ok,bind_ok,notes
"Win11 24H2","x64","2026-xx-xx","PASS","PASS","0/0","PASS","PASS","N/A","..."
```

## 6. 异常处理（某版本 FAIL 时）

| 现象 | 处置 |
|------|------|
| 反调试咨询项误报（nt_global_flag/kernel_debugger/debug_heap_flags/int3_honey） | 静默（只报告不触发）；记录版本；不阻塞 |
| 关键项误报（being_debugged/debug_port/flags/object/hw_breakpoints/timing） | 需版本适配：加版本分支 → 升 MINOR；记录矩阵 |
| SSN 提取失败（syscall_probe FAIL） | 直调回退 API 路径（架构已保证）；记录版本 |
| 完整性误报（T4/T9/T10 FAIL） | hashpatch/integrity 掩码规则需按工具链复验；记录 cl 版本 |
| WDAC 拦截（托管环境） | 按 COMPAT §7 识别；真机不应出现 |
| 24h 驻留误杀 | 看门狗策略调整（咨询项改静默）；记录 |

## 7. 验收标准汇总（阶段 II 完成定义）

- [ ] T3 真机 PASS（或记录真实 FAIL 原因）
- [ ] 兼容矩阵 ≥ 4 个系统全绿（Win10/11 主力 + 目标 Server）
- [ ] --selftest 全部关键字段 0（每台）
- [ ] 24h 驻留零误杀 + 内存稳定；8 开并发通过
- [ ] 换机拒绝成立；克隆行为已记录并触发 D5
- [ ] 吊销/可复现/签名行为真机复现
- [ ] `docs/compat-matrix.csv` 完整填写
- [ ] D5/D6 决策完成（硬件因子是否补充、矩阵优先级）

## 8. 时间估计

| 步骤 | 估计 |
|------|------|
| P2-1 环境基线 + T3 | 0.5 天 |
| P2-2 兼容矩阵（每系统） | 0.5 天/系统 |
| P2-3 反调试专项 | 0.5 天 |
| P2-4 24h 驻留（含 8 开） | 1 天（24h 并行） |
| P2-5 硬件绑定（双机） | 0.5 天 |
| P2-6/7/8 吊销/可复现/签名 | 0.5 天 |
| 矩阵填写 + 决策 | 0.5 天 |

> 总计约 3-4 个工作日（不含系统准备）。
