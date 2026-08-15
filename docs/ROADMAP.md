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
| 1d-A4 二次扩充：`brk` 断言陷阱 / `move` / 寄存器索引寻址 | ✅ 2026-08-14 | unit_vm + unit_vm_brk 单测覆盖、连续 8 轮重建全绿 |

## Phase 2 — VM 加密与多样性
- ✅ 多 VM 上下文：序列校验逻辑拆成 3 个独立小 VM（FNV-1a 哈希 / GOLDEN 混合 /
  期望值校验），各自独立密钥 + 置换/槽位 + 滑动窗口，通过共享 `demo_mem`
  中间区衔接（已落地，2026-08-09）。
- ✅ 加密态执行：指令按 64 字节滑动窗口按需解密、用后即焚（`vm_wprune` 丢弃
  已消费字节），CRC 改用流式接口（`prot_crc32_init/step/done`）逐字节预检，
  全程无 malloc、堆上不留全明文（已落地，2026-08-09）。
- ✅ **镜像外部装载（DBI launcher，技术债 #3）**：VM 密文打包 `vm.blob`
  （`vmenc.py pack`，NAME/KEY/CRC + BLOB_CRC），launcher（`src/blob.c`）
  启动时装载校验；exe 不再静态嵌入 VM 逻辑；T13/T14 缺失/篡改 → 0xB10B
  （2026-08-14）。
- 运行时语义随机化（等价变形），重放失败（✅ 已落地：`vm_ctx_seed` TSC/QPC/栈
  熵播种 ctx → vm_var 每实例选不同等价路径，2026-08-09）。
- ✅ **引擎语义随构建变异（A2）**：`sem=[sem0,sem1]` 由 `key[1]` 随机流派生 —
  操作数字节序 LE/BE-SWAP + 折叠公式 4 选 1，生成/执行两侧同位置复算，
  语义逐位一致（已落地，2026-08-14，THREATMODEL 债 #2 结清）。
- 综合：内存转储无法得到完整明文汇编。

## Phase 3 — 反调试/反探测立体化
- 现有：PEB / DebugPort / Flags / Object / 硬件断点 / 计时。
- ✅ 多轮 QPC/timing 采样（5 轮 × 20ms，抗调度抖动误报，2026-08-09）。
- ✅ int3 VEH 蜜罐（可执行存根 + VEH，不破坏完整性，2026-08-09）。
- ✅ 调试堆特征检测（PEB.ProcessHeap ForceFlags，2026-08-09）。
- ✅ 反附加定时器（A5）：看门狗内周期重跑 `prot_antidebug_scan` + 间隔 ±40%
  抖动，驻留期附加不再只有启动一次检测（2026-08-14）。
- ✅ direct syscall 反 hook（A6）：`NtQueryInformationProcess`/
  `NtQuerySystemInformation` 关键信息类运行时提取 SSN + 内存生成 12B stub
  直调进内核，失败回退 API 路径；`syscall_probe` 单测断言直调==API 路径
  （2026-08-14，Phase 3 剩余项结清）。

## Phase 4 — 授权与分发（商业价值核心）
- ✅ machine_id 真实绑定（卷序列号 + 计算机名多因子 FNV-1a，C/Python 两则一致，
  2026-08-09）。
- ✅ 离线段签发 CLI（vmenc 扩展）：FNV/xorshift → RSA 签名 license（A1，
  2026-08-10）。
- ✅ 分级授权（试用/正式/增值）：`sign --tier 0|1|2` 参与签名载荷
  （serial‖mid‖PRODUCT‖tier），license.txt `TIER=` 行，demo 验签后
  `license: 1 (tier=N)`；篡改 TIER 行 → 验签失败（T12 全绿，2026-08-14）。
- 在线验证 + 吊销（可选），失败降级 + 本地告警而非崩溃。

## Phase 5 — 交付线同化
- 每客户独立构建（种子/密钥/随机化），成品互异。
- signtool 签名、剥离符号、关闭调试路径。
- ✅ 完整性扩展到 `.rdata`/`.pdata`（A3，2026-08-14：`.protcrc` 专用段 3 组
  marker + IAT/重定位掩码两侧一致；T9/T10 篡改检测全绿）。
- ✅ 基础设施（2026-08-09）：Git 基线 + `.gitignore/.gitattributes` +
  `verify.ps1`（N 轮随机重建 + e2e(T1-T8) + 攻击 A1-A4 + py_compile →
  `verify-report.json`）+ CI（`.github/workflows/ci.yml`，MSVC x64）+ 
  `build.ps1 -MachineId/-Config` + `build\manifest.json` 产物清单 +
  攻击模拟 `tests/attacks.py`。
- 攻击面复盘表 + 每层量化验收指标（✅ 已在 `docs/THREATMODEL.md` 建立 v1：
  威胁模型/成本矩阵/RSA 上限分析/技术债，2026-08-09；后续随各阶段更新）。
- 实施清单（✅ 已在 `docs/PRODUCTION.md` 拆分：A 区可立即实施 A1-A6 /
  B 区需真机后延 B1-B4，2026-08-09）。

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
- [x] A2 引擎语义随构建变异（sem0 操作数序 + sem1 折叠公式，2026-08-14，
  连续 8 轮重建全绿）
- [x] A3 完整性扩 .rdata/.pdata（.protcrc 段 + IAT/重定位掩码，T9/T10 全绿，
  2026-08-14）
- [x] A4 指令集二次扩充（brk/move/loadr32/storr32，unit_vm_brk 陷阱单测，
  2026-08-14）
- [x] A5 反附加定时器（看门狗周期 antidebug 复查 + 间隔抖动，2026-08-14）
- [x] A6 direct syscall 反 hook（SSN 运行时提取 + 内存 stub，syscall_probe
  单测，2026-08-14）
- [x] Phase 4 分级授权（试用/正式/增值）：tier 参与 RSA 签名载荷 + TIER 行，
  T12 防篡改全绿（2026-08-14）
- [x] 技术债 #3 DBI launcher：vm.blob 外部装载，exe 无 VM 逻辑，T13/T14 全绿
  （2026-08-14）
- [ ] T3 真机验证（沙箱 SKIP 待补）