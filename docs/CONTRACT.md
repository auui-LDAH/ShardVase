# 反逆向保护套件 — 实现契约 (CONTRACT)

本文件是全部实现工作的唯一事实来源。所有 lane 先读本文件 + `include/protect/*.h`，再动手。
任何与本文件冲突的实现都是 bug。**只写自己负责的文件，禁止改动契约文件与头文件。**

## 1. 目标与约束

- Windows x64 原生 C 保护库 + 演示程序。编译器: MSVC cl (VS2022 BuildTools)。
- 所有 C 源码必须 `/W4 /WX` 零警告通过（cl 编译命令见 §12）。
- 所有 Python 工具必须 `python -m py_compile` 通过；文件 I/O 一律显式 `encoding="utf-8"`；
  控制台避免输出非 ASCII（或 `sys.stdout.reconfigure(encoding="utf-8")`）。
- 命名：库函数一律 `prot_*`；内部静态函数 `static`；常量 `PROT_*`。

## 2. 目录与文件归属

```
include/protect/   protdef.h vm.h antidebug.h integrity.h strcrypt.h   [已存在, 契约, 勿改]
docs/CONTRACT.md   [本文件]
src/vm.c           [Lane A]  VM 解释器
src/crc32.c        [Lane A]  prot_crc32 实现
src/antidebug.c    [Lane B]  反调试
src/integrity.c    [Lane B]  完整性校验 + 看门狗
src/strcrypt.c     [Lane B]  prot_str_decrypt 实现
src/license.c      [A1]      RSA-2048 授权验签 (BCrypt, 公钥)
include/protect/license.h     [A1]  license 契约 (常量/函数声明; 与 vmenc.py 一致)
tools/vmenc.py     [Lane C]  VASM 汇编器 + 加密 + genserial + keygen/sign (A1)
tools/strgen.py    [Lane C]  字符串加密生成器
tools/hashpatch.py [Lane C]  PE .text CRC 烧录
demo/license_hash.vasm    [Phase 2a] VM#1: FNV-1a 哈希
demo/license_mix.vasm     [Phase 2a] VM#2: GOLDEN 混合
demo/license_verify.vasm  [Phase 2a] VM#3: 期望值校验
demo/license_gate.vasm    [A1]      VM#4: result &= license_ok 门控
demo/vm_build.json   [已存在, 契约, 不可改]   序列号/机器标识/期望常量
demo/main.c        [Lane D]  演示入口
demo/strings.txt   [Lane D]  字符串清单
build.ps1          [Lane D]  一键构建
tests/e2e.py       [Lane D]  端到端测试
demo/gen/          [构建产物] vm_hash_blob.* vm_mix_blob.* vm_verify_blob.*, strings.c
build/             [构建产物] demo.exe
```

## 3. 公共常量与算法（所有模块必须一致）

> 防护设计意图/威胁模型/每层成本评估见 `docs/THREATMODEL.md`（非契约，规划类）。

- **滚动密钥流**：`k = k * 0x5851F42D4C957F2D + 0x14057B7EF767814F`（uint64 回绕）。
  对输入流的**每个**字节：**先更新 `k`，再取 `(k >> 56) & 0xFF`** 作为该字节密钥；
  加密 `cipher = plain ^ keybyte`，解密同式。注意：第一个字节用的是一次更新后的
  `k`，**不是初始种子**。C 侧常量 `PROT_KS_MUL` / `PROT_KS_ADD` 已在 protdef.h，
  `vm.c` 与 `strcrypt.c` 均按"先更新后取字节"实现。
- **CRC32**：标准（poly 0xEDB88320，init 0xFFFFFFFF，final xor），
  必须与 Python `zlib.crc32` 一致。测试向量 `"123456789"` → `0xCBF43926`。
- **FNV-1a 64**：offset `14695981039346656037`，prime `1099511628211`。
- **xorshift64**：`x ^= x<<13; x ^= x>>7; x ^= x<<17`（uint64 回绕）。
- **常量**：`0x9E3779B97F4A7C15`（黄金比例）。
- **烧录标记**：8 字节 `"PROTCRCP"` + uint32 crc + uint32 reserved（LE），
  位于 `integrity.c` 的 `const prot_baked_crc g_prot_baked_crc`。

## 4. VM (src/vm.c) — 实现 prot_vm_run

### 4.1 执行流程
1. 参数校验：img/code/mem_base 非空，`0 < code_len <= 1<<20`，`mem_size > 0`。
2. **流式 CRC 预检（Phase 2b）**：用 `img->key[0]` 作种子，按 §3 滚动密钥流
   对 `code[0..code_len)` 逐字节解密，**明文只喂给流式 CRC**
   （`prot_crc32_init` → 每字节 `prot_crc32_step` → `prot_crc32_done`），
   不在内存中驻留完整明文。结果 `!= img->crc` → 返回 `PROT_ERR_VM_CRC`。
3. **加密态执行（Phase 2b）**：不再一次性解密到 malloc 的全明文缓冲。解释器维护
   64 字节滑动窗口 `win[64]`（环形，掩码 `& 0x3F`）：按需解密以 IP 为当前读位置
   的指令窗口；每取完一条指令即把 ip 之前已消费字节弃出窗口（用后即焚，
   `vm_wprune`）；回跳时按 `img->key[0]` 从头重绕密钥流。全程无 malloc/free，
   堆上不存在虚拟机明文。
4. 解释执行（见步骤 2 的窗口取指）。IP 从 0 开始，逐字节取指令；任何越界/非法
   指令/栈错误立即返回对应错误码（结果区保持原样）。返回前 `win[64]` 清零。

### 4.2 指令集（1 字节 opcode + 可选操作数，小端）

> **构建期随机化（ROADMAP Phase 1a）**：字节码中的 opcode 数值不再是固定的 0x00–0x2A，
> 而是每次构建在 `img->key[1]` 种子下用 xorshift64（§3）+ Fisher-Yates 派生的置换。
> 语义仍以本表为准：`vm.c` 先用 `img->key[1]` 重建逆表把取到的字节还原成规范 opcode，
> 再进入下面的调度。操作数字节不作置换。
> 生成侧（`vmenc.py make_opcode_permutation`）与执行侧（`vm.c vm_build_keymaps`）
> 必须产出完全相同的置换，保证两遍一致。
>
> **调度间接化（ROADMAP Phase 1b）**：解释器没有 switch/跳转表，改为**函数指针路由**。
> `vm.c` 定义规范顺序的路由表 `g_routes[op]`，运行时再从同一条 xorshift64 流
> （`img->key[1]` 的延续）派生第二个置换 `slot[op]`（规范 opcode → 分发表槽位），
> 按 `dt[slot[op]] = g_routes[op]` 灌入局部分发表 `dt[]`，取指后经
> `dt[slot[canon]](rt)` 间接调用。每次构建 `key[1]` 变化 → 两个置换与分发表布局
> 全部不同。同时维护 64 位上下文散列 `ctx = ctx*GOLDEN + canon`（每取指一次），
> 为 Phase-3 完整性自检/ Phase-2 加密联动预留。
> 生成侧镜像为 `vmenc.py make_opcode_keymaps`（先派生取指置换，其 rng 状态直接
> 续派生槽位置换），两遍必须逐字节一致。
>
> **等价实现多样性（ROADMAP Phase 1c）**：下列 op 有 ≥2 条**语义完全相同**、
> 结构各异的等价实现路径（`vm.c` 的 `vm_kr_*` 系列，`volatile` 防折叠）：
> add/sub/mul/xor/and/or/not/shl/shr。构建期在 `img->key[1]` 流第三次派生时，
> 按 op 字序为每个有变体的 op 抽取基准变体 `var[op]`（进入同上 `var[]` 数组）；
> 运行时每次执行再叠上随指令时刻变化的 ctx/ip 折叠值，使同一 opcode 在同一次
> 运行的不同时刻可能走不同实现，反汇编构不成"标准操作序列"。所有路径必须与
> 本表语义逐字节一致（模 2^64 回绕、除数左零、移位低 6 位）。
>
> **运行时语义随机化（ROADMAP Phase 2c）**：`prot_vm_run` 进入时用实例熵播种
> 上下文 `ctx`（`vm_ctx_seed`：TSC `__rdtsc` ⊕ `QueryPerformanceCounter` ⊕ 栈地址
> 折叠）。`ctx` 只驱动 `vm_var` 的等价路径选择，不参与语义，因此同一次执行的
> 不同轮次/AI 次运行会走不同等价路径（重放同一个二进制/传同一序列号，执行轨迹
> 逐次不同），但最终校验结果始终一致。entropy 失败（如缺 invokeCPU）时自然回落
> 回确定路径，不影响正确性。
>
> **指令集扩充（ROADMAP Phase 1d）**：规范 opcode 域从 0x00..0x23 扩到
> 0x00..0x2A，新增 7 条：`nop`/`lea`/`pushr`/`popr`/`setcon`/`pushcon`/`callind`
> （见下表）。`vm.c` `PROT_VM_OP_COUNT` 与 `vmenc.py OPCODE_SLOTS` 必须同步为
> 0x2B(43)，置换/槽位/变体派生自动覆盖新域。每组新指令以 `tests/unit_vm.vasm`
> → `tests/vm_unit.c` 单测覆盖，`build.ps1` 每构建执行，失败即中止。
| op | 助记符 | 语义 |
|----|--------|------|
| 0x00 | halt | 正常结束, 返回 PROT_OK |
| 0x01 | push32 imm32 | 压入零扩展的 imm32 |
| 0x02 | push64 imm64 | 压入 imm64 |
| 0x03 | dup | 复制栈顶 |
| 0x04 | drop | 弹栈丢弃 |
| 0x05 | swap | 交换栈顶两元素 |
| 0x06 | add | pop b, pop a, push a+b |
| 0x07 | sub | pop b, pop a, push a-b |
| 0x08 | mul | pop b, pop a, push a*b (回绕) |
| 0x09 | divu | pop b, pop a, push a/b (b==0 → PROT_ERR_INTERNAL) |
| 0x0A | modu | pop b, pop a, push a%b (b==0 → PROT_ERR_INTERNAL) |
| 0x0B | xor | pop b, pop a, push a^b |
| 0x0C | and | pop b, pop a, push a&b |
| 0x0D | or | pop b, pop a, push a\|b |
| 0x0E | not | pop a, push ~a |
| 0x0F | shl | pop b, pop a, push a<<(b&63) |
| 0x10 | shr | pop b, pop a, push a>>(b&63) (逻辑右移) |
| 0x11 | cmpeq | pop b, pop a, push (a==b)?1:0 |
| 0x12 | cmpne | pop b, pop a, push (a!=b)?1:0 |
| 0x13 | cmpltu | pop b, pop a, push (a<b)?1:0 (无符号) |
| 0x14 | cmpleu | pop b, pop a, push (a<=b)?1:0 |
| 0x15 | cmpgtu | pop b, pop a, push (a>b)?1:0 |
| 0x16 | cmpgeu | pop b, pop a, push (a>=b)?1:0 |
| 0x17 | jmp rel32 | ip += (int32)rel32 |
| 0x18 | jz rel32 | pop c; c==0 则跳转 |
| 0x19 | jnz rel32 | pop c; c!=0 则跳转 |
| 0x1A | call rel32 | push 返回地址(绝对 ip), 再 ip += rel32 |
| 0x1B | ret | pop → ip |
| 0x1C | load8 | pop addr; 读 mem_base[addr] 1 字节, push 零扩展 |
| 0x1D | load32 | pop addr; 读 4 字节 LE |
| 0x1E | load64 | pop addr; 读 8 字节 LE |
| 0x1F | store8 | pop val, pop addr; 写 1 字节 |
| 0x20 | store32 | pop val, pop addr; 写 4 字节 LE |
| 0x21 | store64 | pop val, pop addr; 写 8 字节 LE |
| 0x22 | setbase | pop → BR (基址寄存器, 初始 0) |
| 0x23 | pushbase | push BR |
| 0x24 | nop | 空操作 (Phase 1d) |
| 0x25 | lea imm32 | push 绝对地址 (label/符号的绝对 ip, 供间接 call/表) (Phase 1d) |
| 0x26 | pushr | push 通用寄存器 R (初始 0) (Phase 1d) |
| 0x27 | popr | pop → R (Phase 1d) |
| 0x28 | setcon | pop; CON = (v!=0)?1:0 (条件寄存器, 初始 0) (Phase 1d) |
| 0x29 | pushcon | push CON (Phase 1d) |
| 0x2A | callind | pop 目标绝对地址; push 返回地址(绝对 ip); ip = 目标 (Phase 1d) |

- 内存访问：`addr` 为相对 BR 的无符号偏移；`addr + 宽度 > mem_size` → `PROT_ERR_VM_OUT_OF_BOUNDS`。
- 栈：`uint64_t stk[512]`；push 时满 → `PROT_ERR_VM_STACK_OVERFLOW`；pop 时空 → `PROT_ERR_VM_STACK_UNDERFLOW`。
- 取指越界（ip >= code_len）→ `PROT_ERR_VM_BAD_OPCODE`。
- 所有算术用 `uint64_t` 回绕。

### 4.3 src/crc32.c
标准查表 CRC32，`uint32_t prot_crc32(const void* data, size_t len)`，与 zlib 一致。
另有流式三件套（Phase 2b 供 VM 逐字节校验不入内存）：
`uint32_t prot_crc32_init(void)` / `uint32_t prot_crc32_step(uint32_t crc, uint8_t byte)` /
`uint32_t prot_crc32_done(uint32_t crc)`；`init -> 若干 step -> done` 与整段
`prot_crc32` 完全等价。声明在 `include/protect/protdef.h`。

## 5. VASM 汇编器 (tools/vmenc.py)

### 5.1 语法
- 行注释 `;`。标签 `name:` 独占一行。
- 指令：`助记符 [操作数]`。数字：十进制 / `0x` 十六进制 / `0b` 二进制（均按 uint64 解析）。
- 符号 `EXPECT1` / `EXPECT2` 从 `vm_build.json` 的 `expect1` / `expect2`（十六进制字符串）解析。
- 跳转/调用操作数：标签名（汇编器计算 rel32）。

### 5.2 CLI
```
python tools/vmenc.py assemble <in.vasm> <vm_build.json> <out.c> <out.h>
python tools/vmenc.py genserial --json <vm_build.json> [--print]
python tools/vmenc.py keygen --key-out <priv.json> --blob-out <pub.c>   (A1)
python tools/vmenc.py sign --key <priv.json> --json <vm_build.json> --out <license.txt>  (A1)
```
- `assemble`：两遍汇编（先收集标签）→ 明文字节 → 随机 64 位种子 key → 按 §3 加密 →
  输出 `out.c`（含 `static const uint8_t s_code[]`、`const prot_vm_image <name>`）与
  `out.h`（`#pragma once; #include "protect/vm.h"; extern const prot_vm_image <name>;`）。
  `<name>` 由 `--name` 指定（默认 `g_vm_image`），用于同一目录导出多个独立镜像
  （Phase 2a: demo 用 3 个镜像 `g_vm_hash_image` / `g_vm_mix_image` / `g_vm_verify_image`）。
  `g_vm_image = { s_code, LEN, { KEY, 0 }, CRC }`，CRC 为明文 `zlib.crc32`。
  `KEY`(key[0]) 为加密种子；`key[1]` 为构建期 opcode 置换种子（§4.2 上方说明），
  两者每次构建都随机生成。
- `genserial`：读 json 的 `serial`/`machine_id`，按 §3 算法计算 `expect1`/`expect2`
  （十六进制字符串）写回 json；`--print` 时打印人类可读结果。
- `machine_id`（Phase 4，默认 auto）：json 中 `machine_id` 缺失/为 `0`/为 `"auto"`
  时，`genserial` 自动用 `hostid()` 计算本机机器标识（见 §5.6）写回 json；显式
  给非零整数则原样使用。运行期 `demo` 由 `src/hostid.c` `prot_hostid_get()` 计算
  同一算法，保证构建期烧录的 EXPECT 与运行期读取的 machine_id 一致。
- 算法（与 demo/license_verify.vasm、tools/vmenc.py `compute_expect` 完全一致）：
  ```
  h = 14695981039346656037
  for b in serial.encode('ascii'): h ^= b; h = (h * 1099511628211) & M64
  x = h ^ machine_id
  x ^= (x << 13) & M64; x ^= x >> 7; x ^= (x << 17) & M64
  total = (x + 0x9E3779B97F4A7C15) & M64
  expect1 = h; expect2 = total
  ```

### 5.3 自检
`assemble` 后：用 Python 复算解密（同密钥流）应还原明文；`zlib.crc32(明文) == 输出 CRC`。

### 5.4 变更记录（2026-08-08）
- `demo/license_vm.vasm`（契约标记"不可改"）：修正 xorshift 三段式实现——原程序
  只在第一段变换前 dup 一次 x，第二次 `shr` 会消费掉唯一的 x，第三次 `xor` 必然
  `PROT_ERR_VM_STACK_UNDERFLOW`。现每段变换前补一个 `dup`（算法不变，与
  `genserial` 一致）。该改动已获项目负责人接受（2026-08-09 起随 Phase 2a
  整体重构为三个独立小 VM，见 §5.5 / §9.1）。

### 5.5 多 VM 上下文（ROADMAP Phase 2a，2026-08-09）
- 原单一 `demo/license_vm.vasm` 序列号校验逻辑拆成 **3 个独立小 VM**，
  各自独立的加密密钥 `key[0]`、opcode 置换/槽位种子 `key[1]`、滑动窗口：
  | 镜像 | 源文件 | 职责 | 中间值 |
  |------|--------|------|--------|
  | `g_vm_hash_image` | `demo/license_hash.vasm` | FNV-1a(serial) | 写 `h` @ mem+64 |
  | `g_vm_mix_image` | `demo/license_mix.vasm` | xorshift(GOLDEN 混合) | 写 `total` @ mem+72 |
  | `g_vm_verify_image` | `demo/license_verify.vasm` | 比对 EXPECT1/EXPECT2 | 写 `result` @ mem+52 |
- 三者以宿主共享内存 `demo_mem` 的中间区衔接（§9.2），按固定顺序依次执行
  （`demo/main.c` §9.1-9）：哈希 → 混合 → 校验。任一返回非 PROT_OK → 输出
  MSG_FAIL 并 exit(1)。
- 攻击者即使 dump 出某一个镜像的明文，也只拿到 1/3 的校验逻辑；要完整理解
  必须同时还原 3 个镜像并追踪中间区数据流，无法通过单镜像静态还原出整个算法。

### 5.6 机器标识（ROADMAP Phase 4，2026-08-09）
- `src/hostid.c` `prot_hostid_get()` 与 `tools/vmenc.py` `hostid()` 用**完全一致**
  的算法计算 64 位 machine_id：多因子 FNV-1a 折叠——
  1. `GetVolumeInformationW(C:\)` 的卷序列号/最大组件长度/文件系统标志
  2. `GetComputerNameW` 的每个宽字符
  3. 末尾 `h ^= h >> 32` 高位折叠
  常量同 FNV-1a64（basise `0xCBF29CE484222325`，prime `0x100000001B3`）。
- 任何一侧改动必须同步（两侧均以注释/docstring 互指），否则构建期烧录的
  EXPECT 与运行期 demo 读取的 machine_id 对不上 → T1 直接失败。
- 演示中作为"绑定到这台机器"的简化：换机器后同一 serial 无法通过。生产可
  换成永久性签名/加密机制，接口形状不变。

## 6. 反调试 (src/antidebug.c)

实现 `prot_antidebug_scan` / `detected` / `apply_policy` / `fake_active` / `hide_thread`。

### 6.1 检测项（x64）
| 字段 | 实现 |
|------|------|
| peb_being_debugged | `__readgsqword(0x60)` 取 PEB，`*(uint8_t*)(peb+0x02)` |
| peb_nt_global_flag | `*(uint32_t*)(peb+0xBC)` 与 `0x70` 相与非 0（咨询项） |
| debug_port | `NtQueryInformationProcess(pid, 7, &port, 8, NULL)`，port != 0 |
| debug_flags | `NtQueryInformationProcess(pid, 31, &flags, 4, NULL)`，flags != 1 |
| debug_object | `NtQueryInformationProcess(pid, 30, &h, 8, NULL)`，h != NULL（成功后 CloseHandle） |
| hardware_breakpoints | `OpenThread(THREAD_GET_CONTEXT, FALSE, GetCurrentThreadId())` + `GetThreadContext`（ContextFlags=CONTEXT_DEBUG_REGISTERS），Dr0-3 != 0 或 (Dr7 & 0xFF) != 0 |
| timing_suspicious | 多轮 QPC 计时（Phase 3b）：5 轮 × `Sleep(20)`，任一轮耗时 < 5ms 则可疑（抗调度抖动误报） |
| kernel_debugger | `NtQuerySystemInformation(0x23, &info, 2, NULL)`，`info.DebuggerEnabled != 0`（咨询项） |
| debug_heap_flags | PEB 偏移 `0x30` 取 ProcessHeap，`*(uint32_t*)(heap+0x74)`（ForceFlags）非 0（Phase 3a，咨询项） |
| int3_honey | int3 VEH 蜜罐：`VirtualAlloc` 2 字节可执行存根 `{0xCC,0xC3}`，`AddVectoredExceptionHandler(1,...)` 后调用；VEH 未接管 → 有外部断点拦截者（Phase 3a，咨询项） |

- 注意：多轮计时常量 `PROT_AD_TIMING_ROUNDS 5` / `PROT_AD_TIMING_SLEEP_MS 20` /
  `PROT_AD_TIMING_MIN_MS 5`；int3 蜜罐用 `VirtualAlloc` 存根而非改 `.text`，
  避免破坏 §7 完整性校验；VEH 捕获后 `Rip += 1` 续跑。

### 6.2 策略
- 关键项 = {being_debugged, debug_port, debug_flags, debug_object, hardware_breakpoints, timing_suspicious}。
- 咨询项 = {nt_global_flag, kernel_debugger, debug_heap_flags, int3_honey}（只报告，不触发策略）。

- ntdll 函数用 `GetProcAddress(GetModuleHandleW(L"ntdll.dll"), L"...")` 解析一次（static 缓存），
  函数指针类型用 `NTSTATUS (NTAPI*)(...)`。`#include <winternl.h>` 可选，常量自行定义：
  `PROT_PID_DEBUG_PORT 7`、`PROT_PID_DEBUG_OBJECT_HANDLE 30`、`PROT_PID_DEBUG_FLAGS 31`、
  `PROT_THREAD_HIDE_FROM_DEBUGGER 17`、`PROT_SYS_KERNEL_DEBUGGER_INFO 0x23`。
- 任何 API 调用失败 → 该项记 0（不误报）。
- `hide_thread`：`NtSetInformationThread(GetCurrentThread(), 17, NULL, 0)`，返回 PROT_OK。

### 6.2 策略
- 关键项 = {being_debugged, debug_port, debug_flags, debug_object, hardware_breakpoints, timing_suspicious}。
- 咨询项 = {nt_global_flag, kernel_debugger}（只报告，不触发策略）。
- `detected`：任一关键项非 0 → 返回 1。
- `apply_policy`：detected 时 EXIT → `TerminateProcess(GetCurrentProcess(), PROT_EXIT_DEBUG_DETECTED)`；
  FAKE → 置 `static volatile uint32_t g_fake = 1`；CONTINUE → 无操作。返回 PROT_OK。
- `fake_active`：返回 g_fake。

## 7. 完整性 (src/integrity.c)

### 7.1 烧录结构
```c
typedef struct prot_baked_crc { uint8_t magic[8]; uint32_t crc; uint32_t reserved; } prot_baked_crc;
const prot_baked_crc g_prot_baked_crc = { {'P','R','O','T','C','R','C','P'}, 0, 0 };
```
（hashpatch.py 在构建期把 .text 的 CRC32 写入 `crc` 字段。）

### 7.2 check_self
- `GetModuleHandleW(NULL)` → 基址；解析 DOS/PE 头（`IMAGE_DOS_HEADER`/`IMAGE_NT_HEADERS`，
  `#include <winnt.h>` 已有），遍历节表找 `.text`。
- 对 `base + VirtualAddress` 处 `min(SizeOfRawData, VirtualSize)` 字节做 `prot_crc32`。
- 与 `g_prot_baked_crc.crc` 比较：相等 → PROT_OK，否则 → PROT_ERR_INTEGRITY。

### 7.3 看门狗
- `start_watchdog(pol, interval_ms)`：`CreateThread` 后台线程，循环 `Sleep(interval)` →
  `check_self()` 失败时按 pol 处理（EXIT → `TerminateProcess(PROT_EXIT_TAMPERED)`；
  FAKE → 置 g_fake；CONTINUE → 计数）。线程句柄 + `volatile LONG` 停止标志。
- `stop_watchdog`：置标志，`WaitForSingleObject` 等待线程退出（幂等）。

## 8. 字符串 (src/strcrypt.c + tools/strgen.py)

- `strcrypt.c` 实现 `prot_str_decrypt`（§3 密钥流，`out[len]=0`）。
- `strgen.py`：`python tools/strgen.py demo/strings.txt demo/gen/strings.c`
  - 清单格式：每行 `NAME|text`（UTF-8，不含 `|` 与换行），NAME 必须是
    `prot_str_id` 枚举成员名，顺序与枚举一致。
  - 输出 `strings.c`：每个字符串随机 64 位密钥 + 加密字节数组；
    实现 `prot_str_get`：首次调用时全部解密到 `static char s_bufs[PROT_STR_COUNT][128]`，
    之后直接返回；id 非法返回 NULL。

## 9. 演示程序 (demo/main.c)

### 9.1 流程
1. `SetConsoleOutputCP(65001)` / `SetConsoleCP(65001)`。
2. 解析参数：`--selftest`（打印每项检测结果）、`--wait-ms N`（扫描前 Sleep N 毫秒）。
3. 打印 `PROT_STR_BANNER`。
4. `prot_antidebug_scan` → 打印一行摘要（`反调试扫描: 通过` 或 `反调试扫描: 发现可疑`）；
   `--selftest` 时逐项打印 `字段名: 0/1`。`prot_antidebug_apply_policy(PROT_POLICY_EXIT)`；
   若 detected → 打印 `PROT_STR_MSG_DBG` 并 `exit(PROT_EXIT_DEBUG_DETECTED)`。
5. `prot_integrity_check_self()` 失败 → 打印 `PROT_STR_MSG_TAMPER` 后 `exit(PROT_EXIT_TAMPERED)`。
6. `prot_integrity_start_watchdog(PROT_POLICY_EXIT, 5000)`。
7. 打印 `PROT_STR_MSG_HWID` + 机器标识（`prot_hostid_get()`，16 位十六进制，Phase 4）。
8. 打印 `PROT_STR_PROMPT_SERIAL`，`fgets` 读入，去掉换行，长度上限 47。
9. 构造 `demo_mem`（见下），依次执行 3 个独立 VM（Phase 2a，见 §5.5）：
   `prot_vm_run(&g_vm_hash_image, ...)` → `g_vm_mix_image` → `g_vm_verify_image`；
   任一返回非 PROT_OK → 打印 `PROT_STR_MSG_FAIL` + 错误码，`exit(1)`。
10. 授权验签（A1，§9.4）：`--license-file F` → 验签设 `mem.license_ok`；未传 → 1。
11. 执行 VM#4 门控 `g_vm_gate_image`：`result &= license_ok`（§9.4）。
12. `prot_antidebug_fake_active()` 为真 → `mem.result ^= 1`。
13. `mem.result` 非 0 → 打印 `PROT_STR_MSG_OK`，`exit(0)`；否则打印 `PROT_STR_MSG_FAIL`，`exit(1)`。

### 9.2 demo_mem 布局（VM 程序依赖，勿改）
```c
typedef struct demo_mem {
    char     serial[48];   /* +0  */
    uint32_t serial_len;   /* +48 */
    uint32_t result;       /* +52 */
    uint64_t machine_id;   /* +56 */
    uint64_t vm_h;         /* +64 (VM#1 写, VM#2/3 读: FNV-1a h) */
    uint64_t vm_total;     /* +72 (VM#2 写, VM#3 读: GOLDEN 混合 total) */
    uint64_t vm_scratch;   /* +80 (VM#1 内部循环计数器, 宿主无需初始化) */
    uint32_t license_ok;   /* +88 (宿主 RSA 验签结果, 0/1; VM#4 门控) */
    uint32_t _pad;         /* +92 */
} demo_mem;                /* 总 96 字节 */
```
`machine_id`（Phase 4）由 `prot_hostid_get()` 在运行期计算（= `vm_build.json` 中
genserial 自动写入的 `hostid()`，见 §5.6）。演示为"绑定本机"简化：换机器后同一
serial 无法通过。

### 9.4 授权验签（A1, 2026-08-10）
- 流程（§9.1 第 8 步之后）：`demo --license-file F` 传授权文件；未传时
  `license_ok=1`（与旧行为兼容）。传了则：
  1. 逐行解析 `F`：`SERIAL=` / `MACHINE_ID=0x..` / `PRODUCT=` / `SIGNATURE=<base64 344B>`
     （`SIGNATURE` 在前，`SERIAL`/`MACHINE_ID` 可能在后，供顺序收集）。
  2. `PRODUCT != PROT_LICENSE_PRODUCT` 或 `SERIAL` 与用户输入不一致 → 拒。
  3. base64 解码签名（自定义解码器，`\r\n`/空格忽略），长度必须 256。
  4. `prot_license_build_message(serial, serial_len, machine_id, msg, cap)`
     = `serial || LE64(machine_id) || "PROT-DEMO-2026"`（与 `vmenc.py license_message` 逐字节一致）。
  5. `prot_license_verify(msg)`：BCrypt SHA-256 → `BCryptImportKeyPair`（公钥 blob
     嵌入 `demo/gen/license_pubkey.c`）→ `BCryptVerifySignature`，**必须传**
     `BCRYPT_PKCS1_PADDING_INFO{B CRYPT_SHA256_ALGORITHM}`（传 NULL 返回 0xc000000d）。
  6. 过 → 打印 `license: 1` 且 `mem.license_ok=1`；任何一步失败 → 打印 `license: 0`
     （不泄漏原因），`exit(1)`。
- **门控进 VM**（防宿主调用点被 patch）：验签通过仅设 `license_ok`；由 VM#4
  （`demo/license_gate.vasm`，`g_vm_gate_image`）在宿主 VM#1-3 之后执行，
  对 `mem.result`（+52）与 `mem.license_ok`（+88）逐位 AND 写回 +52。
  攻击者必须还原并修改 VM 判定逻辑才可绕过。
- BCrypt 句柄/对象均在函数内即开即关，失败路径统一归 0。

### 9.5 授权签发（离线, tools/vmenc.py, A1）
- `vmenc.py keygen --key-out build/keys/license_priv.json --blob-out demo/gen/license_pubkey.c`：
  生成/reuse RSA-2048（e=65537，纯 Python Miller-Rabin）；私钥只写
  `build/keys/`（gitignore），二进制只嵌公钥 blob。
- 公钥 blob 为 **BCRYPT_RSAPUBLIC_BLOB**：16 字节头 `<IIII` LE
  （magic `'RSA1'`/bitlen/cbExp/cbMod）+ **8 字节零填充** + exponent BE + modulus BE
  （实测：无 8 字节填充时 `BCryptImportKeyPair` 返回 0x80090005）。
- `vmenc.py sign --key <priv.json> --json demo/vm_build.json --out build/license.txt`：
  读 json 的 serial/machine_id，载荷 = `license_message`（同 §9.4-4），
  EMSA-PKCS1-v1_5(SHA-256) 填充 → RSA 私钥签名 → base64 344B 写
  `build/license.txt`。

### 9.3 退出码
0 成功 / 1 序列号无效 / 0xDB 调试环境 / 0xBAD 被篡改。

## 10. 构建管线 (build.ps1)

```powershell
$ErrorActionPreference = 'Stop'
$vcvars = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
# 1. 若 demo\vm_build.json 不存在 → 写默认 {"serial":"DEMO-2026-ABCDEFGH","machine_id":0}
# 2. python tools\vmenc.py genserial --json demo\vm_build.json   (machine_id=0/缺省 -> 自动 hostid)
# 2.5 python tools\vmenc.py keygen --key-out build\keys\license_priv.json --blob-out demo\gen\license_pubkey.c   (首次; 之后复用库)
#    python tools\vmenc.py sign --key build\keys\license_priv.json --json demo\vm_build.json --out build\license.txt
# 3. python tools\vmenc.py assemble demo\license_hash.vasm demo\vm_build.json demo\gen\vm_hash_blob.c demo\gen\vm_hash_blob.h --name g_vm_hash_image
#    python tools\vmenc.py assemble demo\license_mix.vasm demo\vm_build.json demo\gen\vm_mix_blob.c demo\gen\vm_mix_blob.h --name g_vm_mix_image
#    python tools\vmenc.py assemble demo\license_verify.vasm demo\vm_build.json demo\gen\vm_verify_blob.c demo\gen\vm_verify_blob.h --name g_vm_verify_image
#    python tools\vmenc.py assemble demo\license_gate.vasm demo\vm_build.json demo\gen\vm_gate_blob.c demo\gen\vm_gate_blob.h --name g_vm_gate_image
# 4. python tools\strgen.py demo\strings.txt demo\gen\strings.c
# 5. cmd /c "`"$vcvars`" >nul 2>&1 && cl /nologo /O2 /W4 /WX /std:c11 /utf-8 /I include /I demo\gen /Fe:build\demo.exe src\vm.c src\crc32.c src\antidebug.c src\integrity.c src\strcrypt.c src\hostid.c src\license.c demo\main.c demo\gen\strings.c demo\gen\vm_hash_blob.c demo\gen\vm_mix_blob.c demo\gen\vm_verify_blob.c demo\gen\vm_gate_blob.c demo\gen\license_pubkey.c /link /SUBSYSTEM:CONSOLE bcrypt.lib
# 6. python tools\hashpatch.py build\demo.exe
# 7. 打印 DONE
```
- 每步失败即中止并打印明确错误。`demo\gen` 目录不存在则先创建。
- 注意：`vm_build.json` 每次构建都会用 genserial 重算 expect1/expect2 与 machine_id
  （machine_id=0/缺失时自动绑定本机 hostid，见 §5.6）。

## 11. 端到端测试 (tests/e2e.py)

- 用 `subprocess` 运行 `build\demo.exe`（相对脚本目录 `..\build\demo.exe`），
  `encoding="utf-8"` 捕获输出。读 `demo\vm_build.json` 取正确序列号。
- 测试 1（正常通过）：输入正确序列号 → 输出含 `PROT_STR_MSG_OK` 文本，退出码 0。
- 测试 2（错误序列号）：输入 `WRONG-SERIAL-0000` → 输出含 `PROT_STR_MSG_FAIL` 文本，退出码 1。
- 测试 3（调试检测）：`demo.exe --wait-ms 4000` 启动，1 秒后 `ctypes` 调
  `kernel32.DebugActiveProcess(pid)`；若 attach 失败 → 标记 SKIP；否则期望输出含
  `PROT_STR_MSG_DBG` 文本且退出码 0xDBG。
- 测试 4（篡改检测）：复制 `build\demo.exe` 到 `build\demo_tampered.exe`，用 PE 解析
  （`struct.unpack_from`）找到 `.text` 的 `PointerToRawData`，翻转其中 1 字节，
  运行 → 输出含 `PROT_STR_MSG_TAMPER` 文本且退出码 0xBAD。
- 测试 5（VM 单测）：`tests/vm_unit.c` 编译为 `build\vm_unit.exe` 运行，Phase 1d
  新增指令全覆盖。
- 测试 6（稳定性）：同轮构建 8 次重启 demo（正确序列号）都应先输出
  `license: 1` 再过校验（A1 起）——`key[0]/key[1]` 逐轮随机，但结果必须稳定。
- 测试 7（自检）：`--selftest` 输出种各检测项全部 0，退出码 0。
- 测试 8（license-forge）：把 `SIGNATURE=` 行 base64 改 1 位 → demo 必须输出
  `license: 0` 且退出码 1（RSA 防伪造）。
- 输出每项 `PASS/FAIL/SKIP`，任一 FAIL → `sys.exit(1)`。
- 测试 3/4 的期望文本从 `demo\strings.txt` 读取（避免硬编码中文）。
- T1-T8 传 `--license-file build\license.txt`（A1 起），避免把"无授权文件"误判。

## 8. 提交前自检清单

- [ ] 只写了归属自己的文件
- [ ] C 文件 `cl /c /W4 /WX` 零警告（Lane A/B 必须实际编译验证）
- [ ] Python 文件 `python -m py_compile` 通过（Lane C/D）
- [ ] 与 §3 常量、§4 指令表、§9 布局完全一致