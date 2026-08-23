# 高级能力强化路线图 2 (ADVANCED2)

> 版本：2026-08-20 v1 · 定位：在 ADVANCED.md（M1-M3 已完成）之后，针对
> **"正版授权 + dump/逆向"** 路径的第二阶段强化——把破解成本继续抬高直到
> 放弃。**明确不做多层 VM 嵌套**（收益/复杂度比低，用户已排除）。
> 关联：`docs/ADVANCED.md`（第一阶段：反 VM/vmc/平坦化）· `docs/BUSINESS.md`（总纲）·
> `docs/THREATMODEL.md`（威胁模型）。

## 1. 背景与目标

**威胁路径**：破解者合法购买授权 → 程序正常运行 → dump 内存/动态逆向 →
还原算法或做定制 patch。此路径无 100% 技术防御，目标是把成本拉到远高于收益。

**五项强化**（按价值排序，N4/N5 为可选）：

| 编号 | 项 | 针对的缺口 | 价值 | 工作量 |
|------|----|-----------|------|--------|
| N1 | **运行时自变形**（VM 引擎关键段运行时解密） | dump 抓完整引擎/静态反汇编宿主代码 | 高 | 3-5 天 |
| N2 | **反 DBI 检测**（Frida/Detours 等） | 高级破解者的动态插桩工具 | 中高 | 1-2 天 |
| N3 | **数据完整性层**（关键数据多重冗余+校验） | 单点内存 patch（改 flag/result） | 中高 | 1-2 天 |
| N4 | **函数级间接化**（宿主 C 层间接调用/跳板） | 直接 call 关系静态可见 | 中 | 2-3 天（可选） |
| N5 | **服务器端兜底**（可选，离线优先增强） | 纯本地逻辑最终可被完整还原 | 高但依赖服务端 | 按 PHASE3 |

## 2. N1 — 运行时自变形（VM 引擎关键段解密执行）

### 2.1 目标
VM 引擎（`src/vm.c` 的解释循环、`vm_build_keymaps`、窗口解密等）**静态是密文**，
运行时解密执行，执行后立即重新加密——dump 时抓不到完整引擎，静态反汇编
看不到解释器逻辑。

### 2.2 技术路线
- 构建期：`tools/vmenc.py` 新增对**宿主函数**的加密支持——
  `protect 函数体` 标记（如 `PROT_SELFCRYPT` 宏包裹的关键函数），
  生成"密文段 + 解密密钥"。
- 运行期（`src/selfcrypt.c` + `include/protect/selfcrypt.h`）：
  1. 启动时定位密文段（专用节 `.protcrypt`，类似 `.protcrc` 的做法）；
  2. `VirtualProtect` 改 RWX → 解密 → `FlushInstructionCache` → 改 RX；
  3. **执行后重新加密**（看门狗周期或函数返回时，`volatile` 防优化）。
- 约束：
  - 解密窗口最小化（仅在调用时解密，调用返回即重加密）；
  - 与现有 `.text`/`.rdata`/`.pdata` CRC **兼容**：密文段不进 CRC 覆盖区
    （专用节，或 CRC 对"已加密形态"校验）；
  - x64 下用 `VirtualProtect` 改页属性（DEP 兼容）。

### 2.3 验收
- 静态 dump 中 VM 引擎函数为密文（无 `mov r10,rcx` 等引擎特征码）；
- 运行时正常执行（引擎解密→运行→重加密），e2e T1-T24 不回归；
- 引擎函数在运行间隙重新加密（内存转储验证）；
- 完整性校验在加密/解密两种形态下均不误报。

## 3. N2 — 反 DBI 检测（动态插桩对抗）

### 3.1 目标
检测 Frida / Detours / DynamoRIO / Intel Pin 等动态插桩工具，检测到后
**行为异常**（输出垃圾/在特定路径崩溃/静默降级），提高高级破解者成本。

### 3.2 技术路线
- 新文件 `src/dbiguard.c` + `include/protect/dbiguard.h`（咨询项+可选策略）：
  - **Frida 特征**：扫描已加载模块中的 `frida-agent-*.dll` / `gum-js-loop`
    / `frida` 相关导出；检查 `NtQueryVirtualMemory` 的可疑注入区域；
  - **Detours 特征**：检查常用 API（`GetProcAddress`/`NtQueryInformationProcess`）
    入口前 5-16 字节是否被改写为 `jmp`（inline hook 检测——与 A6 direct
    syscall 互补）；
  - **调试/插桩痕迹**：`PAGE_EXECUTE_READWRITE` 的堆区域异常增多、线程
    数异常、`TLS` 回调异常；
  - **时序**：插桩工具通常显著增加关键路径耗时（QPC 采样对比基线）。
- 行为策略：检测到 → 按配置：`PROT_POLICY_CONTINUE`（静默记录）/
  `FAKE`（返回垃圾结果）/ `EXIT`（退出）；默认 CONTINUE + 报告（避免误杀）。

### 3.3 验收
- 干净环境 T7/selftest 不误报（新增字段全 0 或记录）；
- 手工注入 Frida/Detours 的测试环境能检测到（≥1 项命中）；
- e2e/attacks 不回归。

## 4. N3 — 数据完整性层（关键数据多重冗余）

### 4.1 目标
授权状态/关键 flag（`license_ok`/`result`/tier）**多重冗余存储 + 校验和**，
单点内存 patch 立即失效（改一个副本，其他副本+校验和检测不一致）。

### 4.2 技术路线
- 扩展 `demo_mem`/tool_mem：关键字段 3 份冗余 + 每份带局部校验和；
- VM#4 门控改为"多数一致 + 校验和通过"才判定；
- 看门狗周期校验冗余一致性，不一致 → 按策略（EXIT/FAKE）；
- 关键判定值（`result`）由 VM 写入多个副本（不同偏移），宿主读取时
  取多数一致值。

### 4.3 验收
- 修改任意单副本 → 判定失败（T 系列新增用例）；
- 修改校验和字段 → 判定失败；
- 正常路径零误报（T1-T24 回归）。

## 5. N4 — 函数级间接化（宿主 C 层）

### 5.1 目标
宿主关键函数（license 校验/VM 装载入口）**间接调用化**：直接 `call` 改为
经跳板/调用表，调用关系静态不可直接读。

### 5.2 技术路线（2026-08-22 落地）
- `tools/indirect.py`：从种子（`-SeedsFile`/`-RecordSeeds`，I3 可复现）派生
  **槽位置换** `perm[fn_id]`（xorshift64 + Fisher-Yates，与 vmenc 同构），
  生成 `demo/gen/indirect_table.c`：
  - `s_fn[]` 静态表存规范顺序函数指针（同 vm.c g_routes）；
  - `s_perm[]` 槽位（每次构建随机，跨构建不可复用 patch）。
- `include/protect/indirect.h` + `src/indirect.c`：
  - `prot_indirect_resolve(fn_id)` = `s_fn[s_perm[fn_id]]`，`__declspec(noinline)`
    防 /O2 内联；
  - 调用点宏 `PROT_INDIRECT_CALL(fn_id, sig, ...)`。
- 接入的 4 个关键函数：`prot_vm_run`（VM 执行）、`load_and_verify_license`
  （RSA 验签）、`prot_revoke_check`（吊销）、`prot_hostid_get`（机器标识）。
- 构建管线：build.ps1 步骤 4c 生成表 + 编译 `src/indirect.c` + `indirect_table.c`；
  seeds.json 记录 `indirect` 种子。

### 5.3 验收（实测 2026-08-22）
- 静态反汇编：4 个函数**零直接 call**（`E8 rel32` 扫描 0 命中），调用点形态为
  `call prot_indirect_resolve` + `call rax`（间接调用）；
- 功能不回归：e2e T1-T24 / attacks A1-A7 全绿；
- Release 可复现：同种子两次构建 demo.exe SHA-256 一致。

## 6. N5 — 服务器端兜底（可选, 离线优先增强）

### 6.1 目标
纯本地逻辑最终可被完整还原——增强：**关键数据由服务器下发**，每会话/每启动
不同，破解者无法"一次还原，永久有效"。

### 6.2 技术路线（2026-08-22 落地）
- 复用 PHASE3 M3.1 的在线 provider：`/v1/check` 响应中携带**会话级期望值**
  `expect1/expect2`（服务端用与 vmenc.py 一致的 `compute_expect` 对请求的
  serial+mid 复算）；
- 客户端 VM#3（verify）期望值不再烧录立即数，改为读 demo_mem +112/+120
  （宿主填：在线=服务端下发值，离线=构建期默认 `g_prot_expect_default`，
  build.ps1 从 vm_build.json 生成）；
- 离线回退：无网络时用本地默认值（降级不锁死，离线优先不变）；
- 注意：这是"在线增强"而非"在线强制"——保持 D2 离线优先语义。

### 6.3 验收（实测 2026-08-22）
- 在线会话中 VM 期望值随服务端响应变化（T25 正确值通过 / T26 错误值拒绝）；
- 离线降级路径零回归（T1-T24、T17 等全绿）。

## 7. 风险与边界（诚实面）

| 项 | 说明 | 缓解 |
|----|------|------|
| N1 自变形与完整性冲突 | 密文段若进 CRC 区会导致误报 | 专用节 `.protcrypt`（仿 `.protcrc`），CRC 不覆盖 |
| N1 性能 | 每次调用解密+加密有开销 | 窗口最小化；仅引擎关键段（非全部） |
| N1 杀软/EDR 误报 | 运行时自修改代码可能触发 AV | 保持节只读+短暂 RWX 窗口；文档注明 |
| N2 DBI 误杀 | 正常工具（杀软注入）可能被当成插桩 | 默认 CONTINUE + 报告；特征谨慎选择 |
| N3 冗余开销 | 内存+代码复杂度增加 | 仅关键字段（≤5 个）冗余 |
| 整体 | 无法绝对防住"合法运行+dump" | 目标是成本 > 收益（与 THREATMODEL 一致） |

## 8. 实施顺序与里程碑

| 里程碑 | 内容 | 工作量 | 依赖 |
|--------|------|--------|------|
| N1 | 运行时自变形（vmenc 宿主函数加密 + selfcrypt.c + 专用节） | 3-5 天 | 无 |
| N2 | 反 DBI 检测（dbiguard.c + selftest 接入） | 1-2 天 | 无 |
| N3 | 数据完整性层（冗余+校验和） | 1-2 天 | 无 |
| N4 | 函数级间接化（可选） | 2-3 天 | N1 优先 |
| N5 | 服务器端兜底（可选） | 1-2 天 | PHASE3 M3.1（已完成） |

> 顺序：N1 → N2 → N3（主线，全部本地可做可测）；N4/N5 按需后置。

## 9. 状态跟踪

| 里程碑 | 状态 | 完成日期 |
|--------|------|---------|
| N1 运行时自变形 | ✅ **完成（一期 + 二期全部，2026-08-22）**：方案 B 原位加密（方案 C 搬移证伪——函数内 E8 rel32 错位）；`tools/selfcrypt_proto.py` + `src/selfcrypt.c` + D1b 掩码；**二期**：解密态 CRC（meta 20B + 篡改→0xBAD）、调用级解密 D2b（enter/leave + SRWLock + `-D2b` 开关，默认 D2a）、4 函数覆盖（prot_vm_run/keymaps/wb/var）；静态密文；e2e/attacks/vm_unit/vmc 零回归；Release 可复现。计划见 `docs/N1_PLAN.md` / `docs/N1_PHASE2_PLAN.md` | 2026-08-22 |
| N2 反 DBI 检测 | ✅ 完成（inline hook/frida 模块/RX+RW 区/线程数；咨询项接入 selftest；本机实测检测到系统 hook） | 2026-08-20 |
| N3 数据完整性层 | ✅ 完成（gate VM 写 3 份冗余+校验和，宿主多数一致+校验和检查；模拟器验证写回正确，e2e 零回归） | 2026-08-20 |
| N4 函数级间接化（可选） | ✅ 完成（tools/indirect.py 槽位随机化表 + src/indirect.c 运行时 resolve + 调用点宏；静态反汇编 4 关键函数零直接 call，实测 call resolve + call rax 间接形态；种子可复现） | 2026-08-22 |
| N5 服务器端兜底（可选） | ✅ 完成（/v1/check 下发会话级期望值，VM#3 改读 demo_mem +112/+120；离线用构建期默认；e2e T25/T26 在线正确/错误期望值验证） | 2026-08-22 |
