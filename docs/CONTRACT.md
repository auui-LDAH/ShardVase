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
- **烧录标记**：**3 组** 16 字节 marker（`magic[8] + crc u32 + reserved u32`，LE），
  位于专用只读段 `.protcrc`（`#pragma section` + `__declspec(allocate)`，不被任何
  段 CRC 覆盖，避免自引用）：
  `PROTCRCP`(.text) / `PROTCRCD`(.rdata) / `PROTCRDP`(.pdata)。
  下标顺序与 `tools/hashpatch.py` 的 `MAGICS` 完全一致。运行期经
  `integrity.c` 的 `g_prot_baked_crc[3]` 读取（volatile 防 /O2 常量折叠）。

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
> **引擎语义随构建变异（A2，2026-08-14）**：在 `key[1]` 随机流的 slot 派生之后、
> var 派生之前（生成侧 `vmenc.py make_opcode_keymaps` 与执行侧 `vm.c
> vm_build_keymaps` 在**同一流位置**）继续取两步 xorshift，抽出 2 个构建期
> **语义微变开关** `sem`：
> - `sem[0]` = 操作数字节序：0=LE（现行），1=BE 高位在前。生成侧
>   `assemble_source(sem0)` 把 imm32/imm64/rel32/labs 操作数字节反转写出，
>   执行侧 `vm_wfetch32/64` 同步反转读回 —— 语义逐位一致，但跨构建字节布局
>   完全不同（还原器不能"一次通吃所有构建"）。
> - `sem[1]` = `vm_fold` 折叠公式 0..3（`vm_var` 里 ctx/ip/op 的折叠写法多选）。
>   只影响"走哪条等价实现路径"，不参与语义。
> 约束：生成/执行两侧派生顺序必须逐字节一致（perm → slot → sem → [C 私有 var]）。
>
> **指令集扩充（ROADMAP Phase 1d / A4, 2026-08-14）**：规范 opcode 域从 0x00..0x23
> 扩到 0x00..0x2E，Phase 1d 新增 7 条（`nop`/`lea`/`pushr`/`popr`/`setcon`/
> `pushcon`/`callind`），A4 追加 4 条：`brk`/`move`/`loadr32`/`storr32`
> （见下表）。`vm.c` `PROT_VM_OP_COUNT` 与 `vmenc.py OPCODE_SLOTS` 必须同步为
> 0x2F(47)，置换/槽位/变体派生自动覆盖新域。新增指令以 `tests/unit_vm.vasm`
> + `tests/unit_vm_brk.vasm` → `tests/vm_unit.c` 单测覆盖（含 brk 陷阱路径），
> `build.ps1` 每构建执行，失败即中止。
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
| 0x2B | brk | CON!=0 → PROT_ERR_VM_BREAKPOINT; CON==0 继续 (A4 断言陷阱) |
| 0x2C | move imm32 | R = 零扩展 imm32 (A4) |
| 0x2D | loadr32 | pop off; push mem32[BR + R + off] (A4 寄存器索引寻址) |
| 0x2E | storr32 | pop val, pop off; mem32[BR + R + off] = val (A4; 压栈序 [off, val], 与 store32 一致) |

- **压栈序约定（A4）**：`storr32`/`store32` 均为**先压地址后压值**
  （栈顶为值，`pop val` 先于 `pop off/addr`）。VASM 中写
  `push32 off; push32 val; storr32`。

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

### 4.4 VM blob 装载器（DBI launcher, 技术债 #3, 2026-08-14）
- 动机：VM 镜像密文**不再静态嵌入 exe**，由构建期 `vmenc.py pack` 打包为
  独立 `build\vm.blob`，launcher（`src/blob.c` `prot_vm_blob_load`）启动时
  装载进内存再交给 `prot_vm_run`——静态拿到 exe 拿不到任何 VM 逻辑
  （"断源"：必须同时拿到分发 blob）。
- blob 格式（与 `vmenc.py pack` 一致）：
  ```
  MAGIC "PROTVMBL"(8) | COUNT u32 LE
  | 每镜像: NAME[16] | CODE_LEN u32 | KEY0 u64 | KEY1 u64 | CRC u32
    | CODE[CODE_LEN] (原 key[0] 滚动密钥流加密)
  | BLOB_CRC u32 (prot_crc32 覆盖以上全部, 防篡改)
  ```
  镜像 `name` 由 `assemble --bin-name` 指定（≤15 字节，demo 请求
  `hash/mix/verify/gate`）。
- 状态码：`PROT_ERR_BLOB_MISSING`（文件缺失）/ `PROT_ERR_BLOB_CORRUPT`
  （magic/CRC/长度）/ `PROT_ERR_BLOB_NAME`（缺镜像）。退出码
  `PROT_EXIT_BLOB_MISSING 0xB10B`。
- 装载缓冲是**密文**；VM 解释器仍按活动窗口解密 + 用后即焚，明文语义不变。
- 构建：`assemble --bin-out X --bin-name N` → `vmenc.py pack --out build\vm.blob X...`；
  `demo.exe` 不再链接 `vm_*_blob.c`（仅 `vm_unit.exe` 单测仍静态链接）。

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
python tools/vmenc.py sign --key <priv.json> --json <vm_build.json> --out <license.txt> [--tier 0|1|2]  (A1 + Phase 4)
```
- `assemble`：两遍汇编（先收集标签）→ 明文字节 → 随机 64 位种子 key → 按 §3 加密 →
  输出 `out.c`（含 `static const uint8_t s_code[]`、`const prot_vm_image <name>`）与
  `out.h`（`#pragma once; #include "protect/vm.h"; extern const prot_vm_image <name>;`）。
  `<name>` 由 `--name` 指定（默认 `g_vm_image`），用于同一目录导出多个独立镜像
  （Phase 2a: demo 用 3 个镜像 `g_vm_hash_image` / `g_vm_mix_image` / `g_vm_verify_image`）。
  `g_vm_image = { s_code, LEN, { KEY, 0 }, CRC }`，CRC 为明文 `zlib.crc32`。
  `KEY`(key[0]) 为加密种子；`key[1]` 为构建期 opcode 置换种子（§4.2 上方说明），
  两者每次构建都随机生成。`assemble` 同时从 `key[1]` 流派生 A2 语义微变
  `sem=[sem0,sem1]`（§4.2：操作数字节序 / 折叠公式），打印在输出行里。
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

### 6.3 direct syscall 反 hook（A6, 2026-08-14）
- 动机：攻击者 inline hook ntdll 导出 stub 入口（改前 5~12 字节跳走）时，
  `GetProcAddress` 拿到的地址指向被改写的代码。关键信息类查询
  （DebugPort/DebugFlags/DebugObjectHandle/SystemKernelDebuggerInformation）
  改为**绕过 stub 直接 syscall 进内核**。
- 实现（`src/syscall.c` + `include/protect/syscall.h`，纯 C，无 MASM）：
  1. `GetProcAddress` 定位导出函数（只读地址，与 hook 无关）；
  2. 在其字节码窗口内扫描 `0F 05`（syscall），向前找最近的 `B8 <imm32>`
     （mov eax, SSN）提取 **SSN**（不硬编码，跨 Win10/11 版本稳定；
     inline hook 只改入口字节，syscall 指令仍在后半，不受影响）；
  3. `VirtualAlloc` 生成 12 字节直调 stub
     （`mov r10,rcx; mov eax,SSN; syscall; ret`，x64 第 1 参须移入 r10，
     第 5+ 参由调用者压栈）→ `FlushInstructionCache` →
     `VirtualProtect(PAGE_EXECUTE_READ)`。二进制中无固定 syscall 代码
     （运行时生成，反静态分析加分）；CFG 未启用（无 /guard:cf），
     函数指针调用 stub 不受影响；
  4. 任何失败（SSN 提取失败/分配失败）→ 返回 `STATUS_UNSUCCESSFUL`，
     `antidebug.c` 回退 GetProcAddress 路径——与现状等价，不新增误报面。
- 接入：`antidebug.c` 的 debug_port/debug_flags/debug_object/kernel_debugger
  四项优先直调，`st < 0` 时回退 `s_pNtQueryInformationProcess` 等。
- 验收：`tests/syscall_probe.c`（build.ps1 5c/7.1 步编译运行）断言
  `prot_sys_available()==1` 且直调结果与 API 路径逐项一致；T7 selftest-clean
  不退化。

## 7. 完整性 (src/integrity.c)

### 7.1 烧录结构（A3, 2026-08-14）
```c
typedef struct prot_baked_crc { uint8_t magic[8]; uint32_t crc; uint32_t reserved; } prot_baked_crc;
/* 专用只读段 .protcrc: 不被任何段 CRC 覆盖 (避免自引用) */
#pragma section(".protcrc", read)
__declspec(allocate(".protcrc"))
const prot_baked_crc g_prot_baked_crc[3] = {
    { {'P','R','O','T','C','R','C','P'}, 0, 0 },  /* 0: .text  */
    { {'P','R','O','T','C','R','C','D'}, 0, 0 },  /* 1: .rdata */
    { {'P','R','O','T','C','R','D','P'}, 0, 0 },  /* 2: .pdata */
};
```
（hashpatch.py 在构建期把各段的 CRC32 写入对应 `crc` 字段；下标顺序与
`tools/hashpatch.py` 的 `MAGICS` 一致。）

### 7.2 check_self（A3）
- `GetModuleHandleW(NULL)` → 基址；解析 DOS/PE 头（`IMAGE_DOS_HEADER`/
  `IMAGE_NT_HEADERS`），遍历节表：对 `.text`/`.rdata`/`.pdata` 各取
  `min(SizeOfRawData, VirtualSize)` 字节做 CRC32（流式接口），与烧录值比对。
  任一不匹配 → `PROT_ERR_INTEGRITY`；目标节缺失 → 跳过；`.text` 必须存在。
- **重定位/IAT 掩码**：ASLR 下 loader 会改写 `.rdata` 中两类字节，文件与
  运行内存不一致，因此两侧（hashpatch.py ↔ integrity.c `build_reloc_mask`）
  用**同一规则**把下列字节归零后再算 CRC：
  1. 基址重定位字段：type 10 (DIR64) 8 字节 / type 3 (HIGHLOW) 4 字节
     （遍历 `DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]` 块表）；
  2. IAT 全段（`DataDirectory[12]`，loader 启动时写入导入地址）。
  `.text`/`.pdata` 无重定位命中，掩码为空。

### 7.3 看门狗
- `start_watchdog(pol, interval_ms)`：`CreateThread` 后台线程，循环
  `Sleep(interval ± 40% 抖动)`（A5：xorshift 派生自 QPC，防周期可预测）→
  `check_self()` 失败时按 pol 处理（EXIT → `TerminateProcess(PROT_EXIT_TAMPERED)`；
  FAKE → 置 g_fake；CONTINUE → 计数）。
- **A5 反附加周期复查**：同线程每次醒来后重跑 `prot_antidebug_scan`，
  命中关键项时按同一 pol 处理（EXIT → `PROT_EXIT_DEBUG_DETECTED`），
  驻留期附加不再只有启动一次检测。
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
2. 解析参数：`--selftest`（打印每项检测结果）、`--wait-ms N`（扫描前 Sleep N 毫秒）、
   `--wait-after N`（看门狗启动后驻留 N 毫秒，A5 长驻留回归钩子，e2e T11 用）、
   `--license-file F`（A1 授权文件）、`--vm-blob F`（VM blob 路径，默认 `vm.blob`，
   DBI launcher）、`--revoke-file F`（吊销黑名单，默认 `revoke.blob`，I1）、
   `--revoke-policy strict|warn`（吊销命中策略，默认 strict）、`--version`
   （打印 `prot-demo <PROT_VERSION_STR>` 后退出，RELEASE §1.2）。
3. 打印 `PROT_STR_BANNER`。
4. `prot_antidebug_scan` → 打印一行摘要（`反调试扫描: 通过` 或 `反调试扫描: 发现可疑`）；
   `--selftest` 时逐项打印 `字段名: 0/1`。`prot_antidebug_apply_policy(PROT_POLICY_EXIT)`；
   若 detected → 打印 `PROT_STR_MSG_DBG` 并 `exit(PROT_EXIT_DEBUG_DETECTED)`。
5. `prot_integrity_check_self()` 失败 → 打印 `PROT_STR_MSG_TAMPER` 后 `exit(PROT_EXIT_TAMPERED)`。
6. `prot_integrity_start_watchdog(PROT_POLICY_EXIT, 5000)`。
6b. 装载 VM blob（DBI launcher，§4.4）：`prot_vm_blob_load` 抽出
    hash/mix/verify/gate 四个镜像；失败 → 打印 MSG_BLOB，`exit(PROT_EXIT_BLOB_MISSING)`。
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
    uint32_t license_tier; /* +92 (Phase 4: 授权等级 0/1/2, 参与签名不可篡改) */
} demo_mem;                /* 总 96 字节 */
```
`machine_id`（Phase 4）由 `prot_hostid_get()` 在运行期计算（= `vm_build.json` 中
genserial 自动写入的 `hostid()`，见 §5.6）。演示为"绑定本机"简化：换机器后同一
serial 无法通过。

### 9.4 授权验签（A1, 2026-08-10; Phase 4 tier, 2026-08-14）
- 流程（§9.1 第 8 步之后）：`demo --license-file F` 传授权文件；未传时
  `license_ok=1`（与旧行为兼容）。传了则：
  1. 逐行解析 `F`：`SERIAL=` / `MACHINE_ID=0x..` / `PRODUCT=` / `TIER=<0|1|2>`
     （缺省视为 1=正式，向后兼容）/ `SIGNATURE=<base64 344B>`
     （`SIGNATURE` 在前，`SERIAL`/`MACHINE_ID`/`TIER` 可能在后，供顺序收集）。
  2. `PRODUCT != PROT_LICENSE_PRODUCT` 或 `SERIAL` 与用户输入不一致 → 拒。
  3. base64 解码签名（自定义解码器，`\r\n`/空格忽略），长度必须 256。
  4. `prot_license_build_message(serial, serial_len, machine_id, tier, msg, cap)`
     = `serial || LE64(machine_id) || "PROT-DEMO-2026" || tier(1B)`
     （与 `vmenc.py license_message` 逐字节一致）。
  5. `prot_license_verify(msg)`：BCrypt SHA-256 → `BCryptImportKeyPair`（公钥 blob
     嵌入 `demo/gen/license_pubkey.c`）→ `BCryptVerifySignature`，**必须传**
     `BCRYPT_PKCS1_PADDING_INFO{B CRYPT_SHA256_ALGORITHM}`（传 NULL 返回 0xc000000d）。
  6. 过 → 打印 `license: 1 (tier=N)` 且 `mem.license_ok=1`、`mem.license_tier=N`；
     任何一步失败 → 打印 `license: 0`（不泄漏原因），`exit(1)`。
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
  `build/license.txt`。`--tier 0|1|2`（Phase 4，默认 1=正式）参与载荷与
  `TIER=` 行；0=试用 / 1=正式 / 2=增值（`vmenc.py LICENSE_TIER_*`）。
- `vmenc.py issue ...`（OPS §2）：同 sign 签名逻辑，但**强制追加签发日志**
  `build/issue-log.csv`（timestamp,serial,machine_id,tier,customer,note,
  license_sha256；只增不改，gitignore）。

### 9.6 授权吊销（I1, 2026-08-15）
- 黑名单 `revoke.blob` 随 vm.blob 渠道分发；格式（`src/revoke.c` 与
  `vmenc.py revoke` 一致）：
  ```
  MAGIC "PROTREVK"(8) | VER u32 LE | COUNT u32 LE
  | 每条目: SERIAL[48] (NUL 填充) | TIER u32 (0xFF=全 tier) | REVOKED_AT u64
  | BLOB_CRC u32 (prot_crc32 覆盖以上全部)
  ```
- 客户端 `prot_revoke_check(path, serial, tier, out_ver)`：命中
  `PROT_REVOKE_HIT`；文件缺失 `NO_FILE`、损坏 `CORRUPT`（均不阻断，离线优先）；
  版本号单调递增，旧客户端接受新黑名单。
- demo 接入：license 验签（§9.1-9b）之后、VM#4 门控之前（§9.1-9c）；
  strict（默认）命中 → 打印 MSG_REVOKED，`exit(PROT_EXIT_REVOKED 0xB1E4)`；
  warn → 告警继续。黑名单缺失/损坏 → 不阻断 + 告警。
- 生成：`vmenc.py revoke --out build\revoke.blob [--base 旧] --add <serial>
  [--tier N]`（版本自动 +1）。

### 9.3 退出码
0 成功 / 1 序列号无效 / 0xDB 调试环境 / 0xBAD 被篡改 / 0xB10B VM blob 缺失或损坏 /
0xB1E4 授权被吊销（I1 黑名单）。

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
  找到 `.text` 的 `PointerToRawData`，翻转其中 1 字节，运行 → 输出含 `PROT_STR_MSG_TAMPER`
  文本且退出码 0xBAD。**托管环境启用 WDAC（代码完整性策略）时，新复制的篡改副本
  可能被信誉拦截（winerror 4551）→ 记 SKIP（真机无 WDAC 时正常验证）。**
- 测试 9/10（A3 篡改扩展）：翻转 `.rdata`（+0x1000 处，避开段首 IAT）/ `.pdata`
  各 1 字节 → 退出码 0xBAD（`.rdata` 被篡改时 MSG_TAMPER 解密即乱码，只断言退出码）。
- 测试 11（A5 看门狗长驻留）：`--wait-after 14000` 驻留 14s，期间看门狗周期
  复查（完整性 + 反调试）多次触发，干净环境必须零误报：退出码 0 且 `license: 1`。
- 测试 12（Phase 4 分级授权防篡改）：把 `TIER=` 行改为不同值 → 载荷与签名
  不匹配 → demo 必须输出 `license: 0` 且退出码 1。
- 测试 13/14（DBI launcher）：`--vm-blob` 指向不存在文件 / 复制 vm.blob 翻
  转 1 字节 → 退出码 0xB10B（消息可能乱码，只断言退出码）。
- 测试 15-19（I1 吊销）：命中 → 0xB1E4；干净黑名单 → 0；无黑名单文件 →
  不阻断；损坏黑名单 → 不阻断；warn 策略命中 → 告警但退出 0。
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