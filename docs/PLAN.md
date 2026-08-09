# 反逆向保护套件 — 开发计划 / 状态 (PLAN)

> 本文档是对 docs/CONTRACT.md 的配套执行计划与状态跟踪。
> CONTRACT.md 是唯一事实来源；本文档记录"进行到哪了、修了什么、下一步做什么"。

## 1. 项目目标

Windows x64 原生 C 反逆向保护套件 + 演示程序。四路并行实现：

| Lane | 模块 | 交付物 | 状态 |
|------|------|--------|------|
| A | VM 解释器 + CRC32 | `src/vm.c` `src/crc32.c` | ✅ 完成 |
| B | 反调试 / 完整性 / 字符串 / 机器标识 | `src/antidebug.c` `src/integrity.c` `src/strcrypt.c` `src/hostid.c` | ✅ 完成 |
| C | 汇编器 / 加密器 / 烧录 | `tools/vmenc.py` `tools/strgen.py` `tools/hashpatch.py` | ✅ 完成 |
| D | 演示 + 构建 + 测试 / 验证 / CI / 产物 | `demo/main.c` `demo/strings.txt` `build.ps1` `verify.ps1` `.github/workflows/ci.yml` `tests/e2e.py` `tests/attacks.py` | ✅ 完成 |
| ├ | 基础设施（2026-08-09） | Git 基线 + .gitignore/.gitattributes + verify.ps1 + CI + build.ps1(-MachineId/-Config/manifest) + 攻击模拟 A1-A4 | ✅ 完成 |

## 2. 当前交付验证结果

一键构建 `build.ps1`（genserial → 汇编加密 → 字符串加密 → cl 编译 → CRC 烧录）全绿。
一键验证 `verify.ps1`（N 轮随机重建 + e2e + vm_unit + 攻击模拟 + py_compile，JSON 报告）:
`tests/e2e.py`：

| 用例 | 结果 |
|------|------|
| T1 正确序列号 → 退出码 0 / 显示"校验通过" | ✅ PASS |
| T2 错误序列号 → 退出码 1 / 显示"序列号无效" | ✅ PASS |
| T3 调试器附加 → 退出码 0xDB | ⚠️ 沙箱无法驱动调试会话记 SKIP，需真机验证 |
| T4 篡改 .text → 退出码 0xBAD / 显示完整性失败 | ✅ PASS |
| T5 VM 指令集单测 | ✅ PASS |
| T6 多实例稳定（Phase 2c 随机化不得改变结果，8 连跑全过） | ✅ PASS |
| T7 --selftest 干净环境（含 debug_heap_flags/int3_honey）全 0 | ✅ PASS |

`tests/attacks.py`（非真机攻击模拟，Lane D 基础设施）：A1 本机 machine_id 绑定通过 /
A2 VM 密文高熵非明文 / A3 构建镜像指纹（跨轮互异）/ A4 --selftest 干净全 0

## 3. 本次会话修复记录（2026-08-08）

这轮把"能编译但不能跑"的演示修到全部跑通。四个根因，均为契约双方不一致或编译器优化坑：

| # | Bug | 表现 | 根因 | 修复 |
|---|-----|------|------|------|
| 1 | 字符串乱码 | BANNER/提示全是乱码 | `vm.c` `strcrypt.c` 密钥流"先输出后更新"，与 `vmenc.py` `strgen.py`"先更新后输出"差一字节 | C 侧改为先 `k=k*MUL+ADD` 再取 `k>>56`（对齐契约 §3） |
| 2 | 完整性恒失败 | 未篡改也退出 0xBAD | `hashpatch.py` 用整段 `SizeOfRawData` 算 CRC，`integrity.c` 按契约 `min(VirtualSize, SizeOfRawData)`，长度不一致 | hashpatch 改用 `min(...)`，与运行时完全一致 |
| 3 | /O2 常量折叠 | 内存里已有烧录值，但比较总是 0 | `const` 全局 `g_prot_baked_crc` 初始 0，编译器把 `crc` 折叠成立即数，`hashpatch.py` 改的是文件字节，编译器不知道 | 新增 `read_baked_crc()` 用 `volatile` 指针读取 |
| 4 | VM 栈下溢 | 正确序列号也报错 5 | `license_vm.vasm` xorshift 三段只 dup 一次 x，第二次 `shr` 会吃掉 x | 三段变换各补一个 `dup`（算法与 genserial 完全一致） |

### 契约偏差声明

`demo/license_vm.vasm` 在 CONTRACT.md 中标记为"不可改"，但它原有程序必然栈下溢（永远 exit 1）。
已修正 xorshift 的 dup 缺失——**这是唯一超出契约文件的改动，用户已确认接受**。
后续如需恢复一致性，建议在 CONTRACT.md 补充说明处加上该变更。

## 4. 剩余工作（按优先级）

- [ ] **P0｜真实调试检测验证**：在普通交互终端跑 `python tests\e2e.py`，确认 T3 真实走通（附加调试器 → 0xDB）。
- [x] P1｜健全性收尾（2026-08-08 完成）：清理根目录 10 个散落 `.obj` 与 `build\demo_mincrc.exe`；`build.ps1` 末尾新增 `*.obj` 清理步骤，重建后验证根目录 0 残留。
- [x] P1｜契约同步（2026-08-08 完成）：CONTRACT.md §3 明确密钥流"先更新后取字节"；新增 §5.4 记录 `license_vm.vasm` 的 dup 修复。
- [x] **Phase 1a｜VM 构建期 opcode 随机化（2026-08-08 完成，见 `docs/ROADMAP.md`）**：
  `vmenc.py make_opcode_permutation`（xorshift64+Fisher-Yates）每次构建生成置换并烧进
  `key[1]`；`vm.c vm_build_keymaps` 从 `key[1]` 确定性重建逆表，取指后还原规范 opcode。
  验证：连续构建字节码 SHA-256 互异；e2e 全绿。契约 §4.2/§5.2 已同步。
- [x] **Phase 1b｜调度间接化（2026-08-08 完成，见 `docs/ROADMAP.md`）**：
  移除 switch/跳转表，改为 `g_routes[]` 函数指针路由 + `key[1]` 同流续派生
  `slot[op]` 槽位，运行时灌入 `dt[]` 间接调用；新增 `ctx` 上下文散列
  （GOLDEN 乘加）。`vmenc.py make_opcode_keymaps` 侧镜像。e2e 全绿。
- [x] **Phase 1c｜等价 handler 多样性（2026-08-08 完成，见 `docs/ROADMAP.md`）**：
  `vm_kr_add/sub/mul/xor/and/or/not/shl/shr` 等价路径（全加器循环、农夫乘法、
  De Morgan、无进位恒等式等）；`vm_build_keymaps` 第三段流抽取 `var[op]` 基准，
  `vm_var()` 叠加 ctx/ip 折叠实现运行时刻多路径。连续 6 次重建 e2e 全绿。
- [x] **Phase 1d｜指令集扩充（2026-08-08 完成，见 `docs/ROADMAP.md`）**：
  规范 opcode 域 0x00..0x23 → 0x00..0x2A，新增 nop/lea/pushr/popr/setcon/
  pushcon/callind（vmenc `INSTRUCTIONS` 表 + `labs` 操作数类型）；
  `vmenc.py --name` 支持多镜像导出。新增 `tests/unit_vm.vasm` →
  `tests/vm_unit.c` 单测并纳入 build.ps1 与 e2e（T5），连续 3 次重建全绿。
- [x] **Phase 2b｜加密态执行（2026-08-09 完成，见 `docs/ROADMAP.md`）**：
  `vm.c` 去除"解密到 malloc 缓冲"方案，改为 64 字节环形滑动窗口 `win[64]`
  按需解密当前取指窗口；`vm_wprune` 每取完一条指令就把 ip 之前已消费字节弃出
  窗口（用后即焚）；回跳/远跳按 `img->key[0]` 重绕密钥流。CRC 预检查改用流式
  接口 `prot_crc32_init/step/done`（新加于 `src/crc32.c` + `protdef.h`）
  逐字节解密校验、明文不入内存。全程无 malloc/free，状态全在栈上。
  连续 3 次重建 e2e 全绿。
- [x] **Phase 2a｜多 VM 上下文（2026-08-09 完成，见 `docs/ROADMAP.md`）**：
  原单一 `demo/license_vm.vasm` 校验拆分 3 个独立小 VM，各自独立密钥/置换/
  槽位/滑动窗口：`demo/license_hash.vasm`（FNV-1a）→ `demo/license_mix.vasm`
  （GOLDEN 混合）→ `demo/license_verify.vasm`（比对 EXPECT1/2），经共享
  `demo_mem` 中间区衔接，demo/main.c 依次执行。已同步 build.ps1、
  `vmenc.py --name` 多镜像、CONTRACT §5.5/§9.2、ROADMAP。连续 3 次重建全绿。
- [x] **Phase 2c｜运行时语义随机化（2026-08-09 完成，见 `docs/ROADMAP.md`）**：
  `vm.c` 新增 `vm_ctx_seed()`：用 `__rdtsc` ⊕ `QueryPerformanceCounter` ⊕
  栈地址折叠每实例熵，播种 `rt.ctx`，使 `vm_var()` 在同一次执行/不同次执行
  中随机选等价路径（重放/前后两次运行执行轨迹不同），最终结果语义不变。
  CONTRACT §4.2 补充说明，连续 3 次重建 e2e 全绿。
- [x] **Phase 3a｜反调试立体化（2026-08-09 完成，见 `docs/ROADMAP.md`）**：
  `antidebug.c` 新增：多轮 QPC 计时（5×20ms 抗抖动，替换单轮 150ms）、
  int3 VEH 蜜罐（自研 `VirtualAlloc {0xCC,0xC3}` 存根探测）、调试堆特征检测
  （PEB.ProcessHeap ForceFlags）。`antidebug.h` 报告新增 `debug_heap_flags` /
  `int3_honey`（均为咨询项），demo `--selftest` 输出新增两行。CONTRACT §6.1/6.2
  已同步。连续 3 次重建 e2e 全绿、selftest 新增项在干净环境全 0（无误报）。
- [x] **Phase 4｜machine_id 真实绑定（2026-08-09 完成，见 `docs/ROADMAP.md`）**：
  新增 `src/hostid.c` + `include/protect/hostid.h` `prot_hostid_get()`，与
  `tools/vmenc.py hostid()`（ctypes 调 GetVolumeInformationW/GetComputerNameW）
  同一多因子 FNV-1a 算法（卷序列号 + 计算机名 + 高位折叠）。genserial 在
  `machine_id` 缺失/0/"auto" 时自动回填 hostid，demo 运行期同函数计算；
  `hostid.c` 接入 build.ps1 cl 行。构建与运行不同机器时 T1 会失败（体现绑定）。
  连续 3 次重建 e2e 全绿。
- [ ] P2｜生产增强（演示可扩展方向，非契约内）：
  - 离线段 RSA 签名 license（后续接入 genserial）
  - VM 指令集再扩充（brk、move、寄存器索引寻址等）
  - integrity 覆盖 `.rdata`/`.pdata`（当前只校验 `.text`）
  - 加壳/外部文件装载（demo_mem 从栈扩容或独立 blob）
  - direct syscall 反 hook、线程隐藏 + 反附加定时器（Phase 3 剩余项）

### 4.1 基础设施（2026-08-09 完成，本会话）

| 项 | 说明 | 验证 |
|----|------|------|
| Git 版本控制 | `git init` 基线提交，`.gitignore`（build/ demo/gen/ obj exe pdb __pycache__ 等）+ `.gitattributes`（*.c/*.h/*.py 定 LF） | 首次提交 0b33a95 |
| verify.ps1 一键验证 | 多轮随机重建 + e2e(T1-T7) + vm_unit + attacks(A1-A4) + py_compile → `verify-report.json`（时间戳/每轮种子/SHA/结果表）；`-Minimal` 单轮冒烟 | 3 轮全绿 PASS |
| CI 流水线 |`.github/workflows/ci.yml`：`ilammy/msvc-dev-cmd` 起 MSVC x64 → build.ps1 → e2e → attacks → vm_unit → py_compile → upload build 产物/清单 | 待推远程后生效 |
| 构建/产物规范化 | `build.ps1 -MachineId <dec/h0x/auto> -Config`；末尾写 `build\manifest.json`(机器标识/VM 种子指纹/Git SHA/exe SHA256/时间戳)；`verify-artifacts\` 按轮留档（`-KeepArtifacts`） | manifest 正确生成 |
| 攻击模拟（不需真机） | `tests/e2e.py` 扩 T6 多实例稳定/T7 selftest 干净；新 `tests/attacks.py` A1 machine-bind / A2 VM 密文高熵 / A3 构建指纹 / A4 selftest 干净 | 全 PASS |
| machine-id 覆盖 | `vmenc.py genserial --machine-id`（十进制/0x/auto），`build.ps1 -MachineId` 贯通;异机绑定用 `-MachineId 42` 复现 T1 拒绝（已实测） | 手动实测 FAIL 正确 |

> 注意：T3（真机调试附加）仍待真机；CI 未推远程因此本地以 verify.ps1 全绿为准。

## 5. 关键文件速查

| 文件 | 说明 |
|------|------|
| `docs/CONTRACT.md` | 契约（算法、指令表、VM 拆分、进程布局、退出码） |
| `docs/PLAN.md` | 本文档（状态 + 计划） |
| `docs/ROADMAP.md` | 商业级路线图（Phase 1-5 进度） |
| `demo/license_hash.vasm` | VM#1: FNV-1a 哈希（Phase 2a） |
| `demo/license_mix.vasm` | VM#2: GOLDEN 混合（Phase 2a） |
| `demo/license_verify.vasm` | VM#3: 期望值校验（Phase 2a） |
| `demo/vm_build.json` | 序列号 + machine_id + expect1/expect2（构建时由 genserial 重算） |
| `src/hostid.c` | machine_id 运行时计算（Phase 4） |
| `demo/main.c` | 演示入口，流程见契约 §9 |
| `tests/e2e.py` | 端到端测试（T1–T7） |
| `tests/attacks.py` | 非真机攻击模拟（A1–A4） |
| `verify.ps1` | 一键验证（多轮重建 + 全套测试 + JSON 报告） |
| `build.ps1` | 一键构建（-MachineId/-Config + manifest.json） |
| `.github/workflows/ci.yml` | CI 流水线（MSVC + build + verify + 上传报告） |