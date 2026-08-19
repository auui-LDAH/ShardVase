# 兼容性计划 (COMPAT)

> 版本：2026-08-14 v1 · 归属：BUSINESS 阶段 II（真机验证）。目标：在商业化之前
> 建立 **Windows 版本兼容矩阵**、**反调试误报风险清单**与**实机验证用例**，
> 把"本机全绿"升级为"目标环境全绿"。阶段 II 依赖 1 台普通 Windows 真机
> （或非沙箱 Win VM）；本文档同时给出现阶段 I 可做的"兼容骨架"（I4）。

## 1. 目标与范围

- **支持目标**：Windows 10 21H2 / 22H2、Windows 11 21H2 / 22H2 / 23H2 / 24H2、
  Windows Server 2022，x64。Windows 10 1809 及更早按需评估（不承诺）。
- **验收判据**：每台机器 `verify.ps1 -Minimal` 全绿（T3 除外按环境 SKIP/PASS）+ attacks 全绿。
- 兼容性 ≠ 仅"能跑"：含反调试**零误报**、完整性与 blob 校验正常、授权正常。

## 2. 检测项跨版本风险清单（阶段 I 就位，阶段 II 实机验证）

| 检测/机制 | 依赖的版本敏感点 | 风险 | 缓解 |
|-----------|------------------|------|------|
| PEB 直读（0x02/0xBC/0x30/0x74） | PEB 布局自 Win10 起稳定，但非文档化 | 中低 | 仅咨询项用 0xBC/0x74；实机矩阵确认 |
| NtQueryInformationProcess 直调（A6） | **SSN 运行时提取**（不硬编码）→ 无版本依赖 | 低 | syscall_probe 每构建自验（build.ps1 内） |
| 计时检测（QPC+Sleep） | 高精度计时可用性/节流 | 低 | 5 轮采样 + 咨询项策略 |
| int3 VEH 蜜罐 | VEH 行为一致 | 低 | 咨询项 |
| debug_heap_flags（ForceFlags 0x74） | 堆布局偏移非文档化 | 中 | 咨询项只报告；矩阵确认 |
| 完整性 IAT/重定位掩码（A3） | PE 布局随编译器版本/链接器变化 | 中 | hashpatch/integrity 两侧同规则；新工具链需重跑 T4/T9/T10 |
| vm.blob 装载（DBI launcher） | 纯文件 I/O，无版本依赖 | 低 | T13/T14 每构建自验 |
| RSA/BCrypt 验签 | Windows CNG 版本 | 低 | T8/T12 每构建自验 |

**结论**：架构上已消除"硬编码 syscall 号"等最大版本依赖；剩余风险集中在
PEB/堆偏移的**非文档化布局**，全部为咨询项或可降级路径，靠真机矩阵兜底。

## 3. 真机验证用例（阶段 II，按机器执行）

对每台目标机器执行：

```
# 1. 常规回归
python tests\e2e.py        # T1-T14（T3 应 PASS 或如实记录）
python tests\attacks.py    # A1-A6
powershell verify.ps1 -Minimal

# 2. 反调试专项（干净环境必须零误报）
build\demo.exe --selftest  # 全部字段 0

# 3. 调试附加专项（T3 的完整形态）
python tests\e2e.py        # 确认 T3 从 SKIP 转 PASS/FAIL 并记录
```

结果记录到下表（`docs/compat-matrix.csv`，新）：

```
os_build,arch,date,verify,e2e_t3,selftest_clean,notes
"Win10 22H2","x64","2026-xx-xx","PASS","PASS","..."
```

## 4. 长期驻留与资源稳定性（阶段 II）

- **24h 驻留**：`demo.exe --wait-after 86400000`（看门狗每 3-7s 复查）：
  - 零误报（无 0xBAD/0xDB 退出）；
  - 内存稳定（任务管理器观察，允许 ±5% 抖动，无持续增长）；
  - VM blob 缓冲驻留（密文）不泄漏（进程退出时正常回收）。
- **多开并发**：8 个实例并行运行 10 分钟 → 全部通过且无资源耗尽。
- 记录到 compat-matrix.csv。

## 5. 硬件绑定验证（阶段 II，需第二台机器/克隆 VM）

| 用例 | 步骤 | 期望 |
|------|------|------|
| 换机拒绝 | 机器 A 签发 license → 机器 B 运行 | license: 0，退出 1 |
| 同机续用 | 机器 A 重新运行 | license: 1 |
| 克隆 VM 对比 | 克隆 A → 运行 | 若 hostid 因子（卷序列号/计算机名）相同则通过——**记录差异，评估是否需补充因子** |
| 因子审计 | `--selftest` 打印 machine_id，对比 `vmenc.py genserial --print` | 一致 |

> 若克隆 VM 出现"克隆即通过"，说明当前 hostid 因子不足（卷序列号+计算机名），
> 商业绑定需评估补充因子（如主板 UUID、TPM、磁盘序列号）——**决策点 D5**。

## 6. 阶段 I 可先做的"兼容骨架"（I4，本地）

- **版本检测工具**：`tools/osinfo.py`（新，stdlib）输出
  `osver/build/arch/edition`，供矩阵记录与回归脚本用。
- **API 可用性降级路径**：审计现有调用点（BCrypt/VEH/QPC 等）确认全部有失败回退
  （无崩溃路径）；补缺（若发现）。
- **构建工具链版本记录**：manifest.json 记录 cl/link 版本
  （`cl /?` 第一行解析），兼容矩阵按工具链版本归档。
- **验收**：osinfo.py 正确输出；代码审查清单勾完；manifest 含工具链版本。

## 7. 风险与决策点

| 项 | 说明 | 决策 |
|----|------|------|
| 非文档化布局（PEB/堆） | 若某版本布局变化导致误报 | 咨询项可静默；关键项需补版本适配 → 记录于矩阵 |
| hostid 因子不足（克隆通过） | 换机语义被克隆绕过 | **D5：是否补充硬件因子** |
| Server 版本优先级 | 若面向企业分发，Server 2022 优先于 Win10 | **D6：兼容矩阵优先级** |
| 32 位/ARM 支持 | 当前 x64 only | **D7：是否扩展（影响面大，建议不扩展）** |
| **WDAC/托管环境（2026-08-17 实测）** | 启用代码完整性策略的托管 VM 会按文件信誉拦截**新副本**（winerror 4551）：构建产物（已签名/信誉良好）可跑，篡改测试副本被拦 → e2e T4/T9/T10 记 SKIP；解决方案：build.ps1 签名全部测试产物 + 测试识别 4551 转 SKIP | 真机/无 WDAC 环境自动恢复 PASS |
