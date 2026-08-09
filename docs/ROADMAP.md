# 反逆向保护套件 — 商业级路线图 (ROADMAP)

> 定位：把当前"演示级存活性验证"提升到"商业级"的分阶段路线。
> 前提：商业保护 = 显著提高破解成本，不存在不可破解。核心策略 =
> 关键逻辑进 VM + 多层干扰 + 服务器端兜底。
> 每一阶段都以 `tests/e2e.py` 及新增攻击模拟用例验收。

## Phase 1 — VM 抗静态分析
目标：让"离线静态还原逻辑"的成本远超 2 个小时的劳动力价值。

| 任务 | 状态 | 验收 |
|------|------|------|
| 1a 每次构建随机化 opcode 置换 | ✅ 2026-08-08 | 连续两次构建输出字节不同、e2e 全绿 |
| 1b 调度间接化：dispatch 表 + 上下文 hash，消除单一调度循环特征 | ✅ 2026-08-08 | 两次构建的调度代码几乎不相似 |
| 1c 等价 handler 多样性（mul/add/shl 多条实现路径随机） | ✅ 2026-08-08 | 反汇编无法稳定构成"标准操作序列" |
| 1d 指令集扩充：`nop`、`push/pop`、条件寄存器、间接 call | ✅ 2026-08-08 | 新增指令有测试用例、回归绿 |

## Phase 2 — VM 加密与多样性
- ✅ 多 VM 上下文：序列校验逻辑拆成 3 个独立小 VM（FNV-1a 哈希 / GOLDEN 混合 /
  期望值校验），各自独立密钥 + 置换/槽位 + 滑动窗口，通过共享 `demo_mem`
  中间区衔接（已落地，2026-08-09）。
- ✅ 加密态执行：指令按 64 字节滑动窗口按需解密、用后即焚（`vm_wprune` 丢弃
  已消费字节），CRC 改用流式接口（`prot_crc32_init/step/done`）逐字节预检，
  全程无 malloc、堆上不留全明文（已落地，2026-08-09）。
- 运行时语义随机化（等价变形），重放失败（✅ 已落地：`vm_ctx_seed` TSC/QPC/栈
  熵播种 ctx → vm_var 每实例选不同等价路径，2026-08-09）。
- 综合：内存转储无法得到完整明文汇编。

## Phase 3 — 反调试/反探测立体化
- 现有：PEB / DebugPort / Flags / Object / 硬件断点 / 计时。
- ✅ 多轮 QPC/timing 采样（5 轮 × 20ms，抗调度抖动误报，2026-08-09）。
- ✅ int3 VEH 蜜罐（可执行存根 + VEH，不破坏完整性，2026-08-09）。
- ✅ 调试堆特征检测（PEB.ProcessHeap ForceFlags，2026-08-09）。
- 待办：direct syscall 绕过 ntdll hook；线程隐藏 + 反附加定时器。
- 看门狗 → 周期全量自检 + 随机间隔。

## Phase 4 — 授权与分发（商业价值核心）
- ✅ machine_id 真实绑定（卷序列号 + 计算机名多因子 FNV-1a，C/Python 两则一致，
  2026-08-09）。
- 离线段签发 CLI（vmenc 扩展）：FNV/xorshift → RSA 签名 license。
- 分级授权（试用/正式/增值），验证核心放进 VM，私钥离线。
- 在线验证 + 吊销（可选），失败降级 + 本地告警而非崩溃。

## Phase 5 — 交付线同化
- 每客户独立构建（种子/密钥/随机化），成品互异。
- signtool 签名、剥离符号、关闭调试路径。
- 完整性扩展到 `.rdata`/`.pdata`；`PROTCRCP` 标记多态化。
- ✅ 基础设施（2026-08-09）：Git 基线 + `.gitignore/.gitattributes` +
  `verify.ps1`（N 轮随机重建 + e2e(T1-T7) + 攻击 A1-A4 + py_compile →
  `verify-report.json`）+ CI（`.github/workflows/ci.yml`，MSVC x64）+ 
  `build.ps1 -MachineId/-Config` + `build\manifest.json` 产物清单 +
  攻击模拟 `tests/attacks.py`。
- 攻击面复盘表 + 每层量化验收指标（待补）。

---

## 当前里程碑（2026-08-08）
- [x] 全链路构建 + T1/T2/T4 e2e 通过
- [x] 修复：密钥流顺序 / CRC 长度 / /O2 常量折叠 / VASM 栈下溢
- [x] 契约同步（CONTRACT §3、§5.4）+ PLAN 清理项
- [x] Phase 1a VM opcode 构建期随机化
- [x] Phase 1b 调度间接化（函数指针路由 + key[1] 派生槽位 + ctx 上下文散列）
- [x] Phase 1c 等价 handler 多样性（add/sub/mul/xor/and/or/not/shl/shr 多路径，
  构建期基准 + ctx/ip 运行时刻再折叠 → 同一 opcode 在同一次运行中走多条实现；
  连续 6 次重建 e2e 全绿验证不同变体组合）
- [x] Phase 1d 指令集扩充（域 0x00..0x2A：nop/lea/pushr/popr/setcon/pushcon/
  callind；opcode 域 0x24→0x2B 同步；tests/unit_vm.vasm 驱动 vm_unit.exe 单测，
  build.ps1 每构建执行）
- [x] Phase 2b 加密态执行（win[64] 环形滑动窗口按需解密、`vm_wprune` 用后即焚、
  回跳重绕密钥流；流式 CRC 预检；完全去除全明文 malloc 缓冲；连续 3 次重建
  e2e 全绿，2026-08-09）
- [x] Phase 2a 多 VM 上下文（拆成 hash/mix/verify 3 个独立小 VM，各自密钥/
    置换/槽位/窗口，共享 `demo_mem` 中间态衔接；连续 3 次重建 e2e 全绿，
    2026-08-09）
- [x] Phase 2c 运行时语义随机化（`vm_ctx_seed` 给 ctx 播种 TSC/QPC/栈地址熵 →
  每次执行走不同等价路径、重放失败；连续 3 次重建 e2e 全绿，2026-08-09）
- [x] Phase 3a 反调试立体化：int3 VEH 蜜罐 + 调试堆特征 + 多轮 QPC；selftest
  报告新增字段（连续 3 次重建 e2e 全绿，2026-08-09）
- [x] Phase 4 machine_id 真实绑定：`src/hostid.c` 与 `vmenc.py hostid()` 同算法
  多因子 FNV-1a（卷序列号 + 计算机名），genserial 自动写回，demo 运行期读取
  （连续 3 次重建 e2e 全绿，2026-08-09）
- [ ] T3 真机验证（沙箱 SKIP 待补）