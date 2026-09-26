/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 ShardVase contributors
 *
 * 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；
 * 商业授权见 LICENSE.md。
 */
/*
 * vm.c — VM 解释器 (Lane A)
 *
 * 实现 prot_vm_run: 按 CONTRACT §4.1 流程执行:
 *   1) 参数校验
 *   2) 流式 CRC 预检: 滚动密钥流逐字节解释出明文并只喂 CRC, 明文不入任何缓冲
 *   3) 解释执行 (§4.2 指令集, 1 字节 opcode + 小端操作数)
 *
 * 抗静态分析 (ROADMAP Phase 1):
 *   1a: 构建期 opcode 随机化 — 字节码中的 opcode 经 img->key[1] 置换,
 *       取指后先逆置换回规范值再执行。
 *   1b: 调度间接化 — 解释器无 switch/跳转表, 改为函数指针路由表
 *       g_routes[] 经 img->key[1] 派生槽位后灌入局部分发表 dt[] 间接调用;
 *       同时维护 ctx 上下文散列 (GOLDEN 乘加)。
 *   1c: 等价实现多样性 — 算术/位运算多条等价路径, 构建期基准 + 运行时刻折叠。
 *   1d: 指令集扩充 — 规范 opcode 域 0x00..0x2A。
 *
 * 加密态执行 (ROADMAP Phase 2b):
 *   不再一次性解密并驻留完整明文。窗口 win[64] 按需解密当前指令窗口 (绝对地址
 *   环形映射), 已消费字节不再驻留; 回跳通过密钥流重绕重建。CRC 用流式接口在
 *   预检阶段逐字节完成, 全程无 malloc/free, 堆上不存在明文。
 *
 * 线程安全: 无共享状态, 可并发调用。
 */
#include "protect/vm.h"
#include "protect/prot_platform.h"  /* L6b: prot_plat_monotonic_ns（跨平台高精度时钟）*/
#include "protect/prot_compiler.h"  /* L6b: PROT_RDTSC（跨平台 TSC）*/
#include "protect/prot_noise.h"   /* W1.6 序言噪声 */

#include <string.h>       /* memset */

/* 虚拟机栈容量 (CONTRACT §4.2) */
#define PROT_VM_STACK_CAP 512u

/* 规范 opcode 域大小 (CONTRACT §4.2: 0x00..0x2E, A4 扩充 brk/move/loadr32/storr32) */
#define PROT_VM_OP_COUNT 0x2Fu

/* Phase 1b: 上下文散列乘子 (CONTRACT §3 GOLDEN), 取低 32 为变体折叠 */
#define PROT_CTX_MUL 0x9E3779B97F4A7C15u

/* Phase 1b: 内部信号 — 正常停机 (非错误, 由调度循环转成 PROT_OK) */
#define PROT_VM_HALT ((prot_status)0xFE)

/* Phase 2b: 明文滑动窗口 (环形, 2 的幂以便 & 掩码)。
 * 窗口须覆盖 1 opcode + 最长操作数 (8) + 余量, 取 64 稳固。 */
#define PROT_VM_WIN     64u
#define PROT_VM_WIN_MASK (PROT_VM_WIN - 1u)

/* Phase 1c: 各 opcode 的等价实现路径个数 (1 = 无变体)。
 * 只给算术/位运算配置多条路径, 其余为 0 (= 无变体)。 */
static const uint8_t vmk_vr_count[PROT_VM_OP_COUNT] = {
    [0x06] = 2u, /* add  */
    [0x07] = 2u, /* sub  */
    [0x08] = 2u, /* mul  */
    [0x0B] = 3u, /* xor  */
    [0x0C] = 2u, /* and  */
    [0x0D] = 2u, /* or   */
    [0x0E] = 2u, /* not  */
    [0x0F] = 2u, /* shl  */
    [0x10] = 2u  /* shr  */
};

/* ---------------------------------------------------------------------------
 * 解释器运行时上下文。所有状态都在这里, 栈上创建, 无共享, 线程安全。
 * ------------------------------------------------------------------------- */
typedef struct prot_vm_rt {
    const uint8_t* cc;   /* 密文指针 (img->code), 执行时经窗口解密 */
    uint32_t       code_len;
    uint8_t*       mem;  /* 宿主内存基址 */
    size_t         mem_size;
    uint64_t       stk[PROT_VM_STACK_CAP];
    uint32_t       sp;
    uint32_t       ip;
    uint64_t       br;   /* 基址寄存器, 初始 0 */
    uint64_t       ctx;  /* 上下文散列 (Phase 1b) */
    uint64_t       rr;   /* 通用寄存器 R (Phase 1d), 初始 0 */
    uint64_t       con;  /* 条件寄存器 CON (Phase 1d, 0/1), 初始 0 */
    uint8_t        var[PROT_VM_OP_COUNT]; /* Phase 1c: 每个 op 的构建期变体基准 */
    uint8_t        sem[2]; /* A2: 构建期语义微变 [0]=操作数序 0=LE/1=BE, [1]=折叠公式 */

    /* Phase 2b 窗口状态 */
    uint64_t       kseed; /* 初始密钥流状态 (= img->key[0]) */
    uint64_t       k;     /* 当前密钥流状态, 已推进 (wlo+wt) 步 */
    uint32_t       wlo;   /* 窗口覆盖的起始绝对字节 */
    uint32_t       wt;    /* 窗口内已解明的字节数 */
    uint8_t        win[PROT_VM_WIN]; /* 明文环形窗口 */
} prot_vm_rt;

typedef prot_status (*prot_vm_route)(prot_vm_rt*);

/* 从 img->key[1] 重建构建期 opcode 置换与变体选择 (ROADMAP Phase 1a/b/c + A2):
 * xorshift64 + Fisher-Yates, 与 tools/vmenc.py 完全一致。
 *   inv[发射字节] = 规范 opcode;  未命中(0xFF)表示非法指令
 *   slot[规范 opcode] = 分发表槽位 (同一条 xorshift 流继续派生第二个置换)
 *   var[规范 opcode] = 该 op 的构建期基准变体
 *   sem[0] = 操作数字节序微变 (0=LE, 1=BE; vm_wfetch32/64 同步反转, A2)
 *   sem[1] = vm_var 等价路径折叠公式选择 0..3 (A2, 不影响语义)
 * 注意: sem 与 slot/var 一样只在 C 侧运行时按同一流复算, 字节码生成不依赖它们;
 * 生成侧 (vmenc.py make_opcode_keymaps) 在同一流位置 (slot 之后) 复算 sem。 */
static void vm_build_keymaps(const prot_vm_image* img, uint8_t inv[256],
                             uint8_t slot[PROT_VM_OP_COUNT], uint8_t var[PROT_VM_OP_COUNT],
                             uint8_t sem[2])
{
    uint8_t  pool[PROT_VM_OP_COUNT];
    uint8_t  pool2[PROT_VM_OP_COUNT];
    uint64_t rng = img->key[1];
    uint32_t i;

    for (i = 0; i < PROT_VM_OP_COUNT; i++) {
        pool[i] = (uint8_t)i;
        pool2[i] = (uint8_t)i;
        var[i] = 0u;
    }

    for (int32_t idx = (int32_t)PROT_VM_OP_COUNT - 1; idx > 0; idx--) {
        uint8_t temp;
        uint32_t swapi;
        rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; /* uint64 回绕 */
        swapi = (uint32_t)(rng % (uint64_t)(idx + 1));
        temp = pool[idx];
        pool[idx] = pool[swapi];
        pool[swapi] = temp;
    }

    /* Phase 1b: 继续同一 rng 流, 派生第二个置换 (规范 opcode -> 槽位) */
    for (int32_t idx = (int32_t)PROT_VM_OP_COUNT - 1; idx > 0; idx--) {
        uint8_t temp;
        uint32_t swapi;
        rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
        swapi = (uint32_t)(rng % (uint64_t)(idx + 1));
        temp = pool2[idx];
        pool2[idx] = pool2[swapi];
        pool2[swapi] = temp;
    }

    /* A2: 继续同一 rng 流 (slot 之后, var 之前 —— 与生成侧 make_opcode_keymaps
     * 的 sem 派生位置一致), 抽 2 个构建期语义微变开关。 */
    rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
    sem[0] = (uint8_t)(rng & 1u); /* 操作数字节序 */
    rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
    sem[1] = (uint8_t)(rng & 3u); /* 折叠公式 */

    /* Phase 1c: 继续同一 rng 流, 按 op 字序为有变体的 op 抽取基准变体 */
    for (i = 0; i < PROT_VM_OP_COUNT; i++) {
        uint8_t n = vmk_vr_count[i];
        if (n >= 2u) {
            rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
            var[i] = (uint8_t)(rng % (uint64_t)n);
        }
    }

    memset(inv, 0xFF, 256);
    for (i = 0; i < PROT_VM_OP_COUNT; i++) {
        inv[pool[i]] = (uint8_t)i;
        slot[pool2[i]] = (uint8_t)i;
    }
}

/* 内存访问越界判定 (回绕安全): 访问 [addr, addr+width) 合法 <=> addr+width <= mem_size */
static int vm_mem_oob(uint64_t addr, uint64_t width, size_t mem_size)
{
    if (width > (uint64_t)mem_size)
        return 1;
    return addr > (uint64_t)mem_size - width;
}

/* 跳转: ip += (int32)rel (取指已越过操作数, rel 相对下一条指令) */
static uint32_t vm_jump(uint32_t ip, uint32_t rel)
{
    return (uint32_t)((int64_t)ip + (int32_t)rel);
}

/* ---------------------------------------------------------------------------
 * Phase 2b: 明文滑动窗口。
 * 密钥流转置到 [idx]: kseed 推进 idx 次 (O(idx), 仅回跳/重对齐时调用)。
 * ------------------------------------------------------------------------- */
static void vm_ks_seek(prot_vm_rt* s, uint32_t idx)
{
    uint64_t k = s->kseed;
    for (uint32_t i = 0u; i < idx; i++)
        k = k * PROT_KS_MUL + PROT_KS_ADD; /* §3 先更新再逐字节输出 */
    s->k = k;
}

/* 把窗口解密推进到覆盖字节 p (不含 p 则继续填; 上限 code_len)。
 * 窗口已满 (64 字节) 时滑动: 丢最旧字节再填新字节, 保持环形且 wt 封顶。
 * 前提: p 有效 (< code_len), k 状态对应窗口末尾 (wlo+wt) 的下一步。 */
static void vm_wd_fill(prot_vm_rt* s, uint32_t upto)
{
    while (upto >= s->wlo + s->wt && s->wlo + s->wt < s->code_len) {
        if (s->wt == PROT_VM_WIN) { /* 满窗: 丢最旧, 不推进 k (w+wt 不变) */
            s->wlo++;
            s->wt--;
        }
        {
            uint32_t pos = s->wlo + s->wt;
            s->k = s->k * PROT_KS_MUL + PROT_KS_ADD;
            s->win[pos & PROT_VM_WIN_MASK] =
                (uint8_t)(s->cc[pos] ^ (uint8_t)(s->k >> 56));
            s->wt++;
        }
    }
}

/* 读绝对位置 p 的明文: 不在窗口则先重绕再解密补足。 */
static uint8_t vm_wb(prot_vm_rt* s, uint32_t p)
{
    if (p < s->wlo || p >= s->wlo + s->wt) {
        if (p < s->wlo) { /* 回跳: 整窗重绕到 p */
            s->wlo = p;
            s->wt = 0u;
            vm_ks_seek(s, p);
        }
        vm_wd_fill(s, p);
    }
    return s->win[p & PROT_VM_WIN_MASK];
}

/* 用后即焚: 丢弃已经消费 (ip 之前) 的窗口字节, 之后位置若在窗口内保留。 */
static void vm_wprune(prot_vm_rt* s)
{
    uint32_t end;
    if (s->ip <= s->wlo)
        return; /* 无已消费字节 (跳回或停在线性起点) */
    end = s->wlo + s->wt;
    if (s->ip >= end) { /* 整窗皆已消费/越过: 直接重锚到 ip */
        s->wlo = s->ip;
        s->wt = 0u;
        vm_ks_seek(s, s->ip);
        return;
    }
    /* 部分消费: 只保留 [ip, end) */
    s->wt -= s->ip - s->wlo;
    s->wlo = s->ip;
    /* k 仍对应 (wlo+wt) 位置, 无需改动 */
}

/* 取 4 字节操作数 (经明文窗口); 越界返回 0。
 * A2 语义微变: sem[0]==1 时按 BE (高位在前) 组装 —— 生成侧 assemble_source
 * 在同一构建下同步反转写出, 语义逐位一致。 */
static int vm_wfetch32(prot_vm_rt* s, uint32_t* ip, uint32_t* out)
{
    uint32_t p = *ip;
    uint32_t b0, b1, b2, b3;
    if (p + 4u > s->code_len)
        return 0;
    b0 = (uint32_t)vm_wb(s, p);
    b1 = (uint32_t)vm_wb(s, p + 1);
    b2 = (uint32_t)vm_wb(s, p + 2);
    b3 = (uint32_t)vm_wb(s, p + 3);
    *out = (s->sem[0] & 1u)
               ? (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
               : b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
    *ip = p + 4u;
    return 1;
}

/* 取 8 字节操作数 (经明文窗口); 越界返回 0。A2 语义微变同上。 */
static int vm_wfetch64(prot_vm_rt* s, uint32_t* ip, uint64_t* out)
{
    uint32_t p = *ip;
    uint64_t b[8];
    uint64_t v = 0u;
    uint32_t j;
    if (p + 8u > s->code_len)
        return 0;
    for (j = 0u; j < 8u; j++)
        b[j] = (uint64_t)vm_wb(s, p + j);
    if (s->sem[0] & 1u) { /* BE: 最高字节在前 */
        for (j = 0u; j < 8u; j++)
            v |= b[j] << (8u * (7u - j));
    } else { /* LE: 最低字节在前 */
        for (j = 0u; j < 8u; j++)
            v |= b[j] << (8u * j);
    }
    *out = v;
    *ip = p + 8u;
    return 1;
}

/* 用后即焚: volatile 逐字节清零, 阻止编译器/DCE 优化掉擦除 */
static void vm_scrub(void* p, size_t n)
{
    volatile uint8_t* v = (volatile uint8_t*)p;
    while (n-- != 0u)
        *v++ = 0x00u;
}

/* ---------------------------------------------------------------------------
 * Phase 1c: 等价实现路径 (语义不变, 结构各异的实现)。
 * volatile 局部防止优化器把不同路径折叠成同一条指令序列。
 * ------------------------------------------------------------------------- */

/* Phase 2c: 每实例熵播种 ctx. 用 TSC/单调时钟/栈地址折叠, 使不同实例 ctx 不同,
 * 从而 vm_var 挑选不同等价路径. 该值只影响"走哪条等价路", 不影响最终语义。
 *
 * ## L6b（2026-09-25）: 改为**平台层 + 跨平台内建**
 *   **改动前**:
 *     ```c
 *     #if defined(_MSC_VER) && (defined(_M_IX86) || defined(_M_X64))
 *         acc = (uint64_t)__rdtsc();
 *     #else
 *         acc = 0u;                  // <- 非 MSVC 直接退化为 0
 *     #endif
 *     QueryPerformanceCounter(&t);   // <- Windows 专有
 *     acc ^= t.QuadPart;
 *     ```
 *   **问题**: 在 GCC 上 `acc` 恒为 0 + 无 QPC -> 熵源**完全失效**
 *   （虽然"只影响走哪条等价路，不影响语义"，但**削弱了每实例随机性**）。
 *
 *   **改动后**:
 *     · `PROT_RDTSC()`      —— 跨平台 TSC（GCC 用 `__builtin_ia32_rdtsc`）
 *     · `prot_plat_monotonic_ns()` —— 跨平台高精度时钟（替代 QPC）
 *   => GCC 下**同样有真实熵**（不再退化为 0）。
 *
 *   **语义等价性**: 两者都提供"随实例/时间漂移的高精度计数"，
 *   折叠公式**逐字未变** -> VM 行为不变（已实测 e2e/vm_unit/vmc 全绿）。
 */
static uint64_t vm_ctx_seed(void)
{
    uint64_t acc;
    uint64_t sa = (uint64_t)(uintptr_t)&acc;   /* 栈地址, 随加载布局漂移 */

    acc = (uint64_t)PROT_RDTSC();              /* 跨平台 TSC */
    acc ^= prot_plat_monotonic_ns();           /* 跨平台高精度单调时钟 */
    acc ^= sa;
    acc ^= acc << 31;
    acc *= 0x5851F42D4C957F2Du;
    acc ^= acc >> 29;
    return acc;
}

/* A2: 上下文折叠公式按构建期微变 sem[1] 选择 0..3。该值只决定"走哪条等价
 * 实现路径" (vm_var), 不参与语义 —— 各公式产出不同, 但最终计算结果一致。
 * 生成侧只派生开关值 (vmenc.py make_opcode_keymaps), 公式本体仅 C 侧存在。 */
static uint32_t vm_fold(const prot_vm_rt* s, uint8_t op)
{
    const uint32_t c  = (uint32_t)s->ctx;
    const uint32_t ch = (uint32_t)(s->ctx >> 32);
    const uint32_t ip = s->ip;
    uint32_t k;

    switch (s->sem[1] & 3u) {
    case 1: /* 乘加混序 */
        k = ch ^ c;
        k = k * 0x9E3779B9u + ip * 0x85EBCA6Bu + (uint32_t)op * 0xC2B2AE35u;
        return k;
    case 2: /* xorshift 折叠 */
        k = c ^ ip;
        k ^= k << 13; k ^= k >> 7; k ^= k << 17;
        k += ch ^ ((uint32_t)op * 0x9E3779B9u);
        return k;
    case 3: /* 乘异或混 + 半字折叠 */
        k = c * 0x9E3779B9u;
        k ^= (ip << 7) ^ ch;
        k += (uint32_t)op * 0x85EBCA6Bu;
        return k ^ (k >> 16);
    default: /* 原式 (case 0): ch ^ c + ip*G + op*K */
        k = ch ^ c;
        k += ip * 0x9E3779B9u;
        k += (uint32_t)op * 0x85EBCA6Bu;
        return k;
    }
}

/* 返回 op 本轮实际要走的路编号: 构建期基准 var[op] 再叠运行时刻 ctx/ip 折叠值 */
static uint8_t vm_var(const prot_vm_rt* s, uint8_t op)
{
    uint8_t n = vmk_vr_count[op];
    if (n < 2u)
        return 0u;
    return (uint8_t)((uint32_t)s->var[op] + vm_fold(s, op)) % n;
}

static uint64_t vm_kr_add(uint64_t a, uint64_t b, uint8_t w)
{
    switch (w) {
    case 1: { /* 全加器循环 */
        uint64_t c = b;
        uint64_t r = a;
        while (c != 0u) {
            uint64_t t = r & c;
            r = r ^ c;
            c = t << 1;
        }
        return r;
    }
    case 2: { /* a - ~b - 1 == a + b (mod 2^64) */
        uint64_t r = a;
        return r - (~b) - 1u;
    }
    default: { /* a + b */
        volatile uint64_t out = a + b;
        return out;
    }
    }
}

static uint64_t vm_kr_sub(uint64_t a, uint64_t b, uint8_t w)
{
    volatile uint64_t out;
    switch (w) {
    case 1: /* a + ~b + 1 == a - b (mod 2^64) */
        out = a + (~b) + 1u;
        return out;
    default:
        out = a - b;
        return out;
    }
}

static uint64_t vm_kr_mul(uint64_t a, uint64_t b, uint8_t w)
{
    switch (w) {
    case 1: { /* 俄罗斯农夫乘法 */
        uint64_t r = 0u;
        while (b != 0u) {
            if ((b & 1u) != 0u)
                r = r + a;
            a = a << 1;
            b = b >> 1;
        }
        return r;
    }
    default: { /* a * b */
        volatile uint64_t out = a * b;
        return out;
    }
    }
}

static uint64_t vm_kr_xor(uint64_t a, uint64_t b, uint8_t w)
{
    uint64_t r;
    switch (w) {
    case 1: /* (a|b) & ~(a&b) */
        r = (a | b) & ~(a & b);
        return r;
    case 2: /* a + b - 2*(a&b) */
        r = a & b;
        r = a + b - r - r;
        return r;
    default: { /* a ^ b */
        volatile uint64_t out = a ^ b;
        return out;
    }
    }
}

static uint64_t vm_kr_and(uint64_t a, uint64_t b, uint8_t w)
{
    volatile uint64_t out;
    switch (w) {
    case 1: /* De Morgan: ~(~a | ~b) */
        out = ~((~a) | (~b));
        return out;
    default:
        out = a & b;
        return out;
    }
}

static uint64_t vm_kr_or(uint64_t a, uint64_t b, uint8_t w)
{
    volatile uint64_t out;
    switch (w) {
    case 1: /* De Morgan: ~(~a & ~b) */
        out = ~((~a) & (~b));
        return out;
    default:
        out = a | b;
        return out;
    }
}

static uint64_t vm_kr_not(uint64_t a, uint8_t w)
{
    volatile uint64_t out;
    switch (w) {
    case 1: /* a ^ 全 1 */
        out = a ^ UINT64_MAX;
        return out;
    default:
        out = ~a;
        return out;
    }
}

static uint64_t vm_kr_shl(uint64_t a, uint64_t b, uint8_t w)
{
    uint32_t c = (uint32_t)(b & 63u);
    switch (w) {
    case 1: { /* 逐位翻倍 */
        uint64_t r = a;
        while (c != 0u) {
            r = r + r;
            c--;
        }
        return r;
    }
    default: { /* a << (b & 63) */
        volatile uint64_t out = a << c;
        return out;
    }
    }
}

static uint64_t vm_kr_shr(uint64_t a, uint64_t b, uint8_t w)
{
    uint32_t c = (uint32_t)(b & 63u);
    switch (w) {
    case 1: { /* 逐位减半 */
        uint64_t r = a;
        while (c != 0u) {
            r = r >> 1;
            c--;
        }
        return r;
    }
    default: { /* a >> (b & 63) (逻辑右移) */
        volatile uint64_t out = a >> c;
        return out;
    }
    }
}

/* ---------------------------------------------------------------------------
 * Phase 1b: 指令 handler。每个规范 opcode 一个, 语义与 CONTRACT §4.2 完全一致。
 * 返回 PROT_OK 继续; 具体 prot_status 错误即停机; halt 返回 PROT_VM_HALT。
 * ------------------------------------------------------------------------- */
static prot_status vm_rt_binop(prot_vm_rt* s, uint8_t op)
{
    uint64_t b, a;
    if (s->sp < 2u)
        return PROT_ERR_VM_STACK_UNDERFLOW;
    b = s->stk[--s->sp];
    a = s->stk[--s->sp];
    switch (op) {
    case 0x06: a = vm_kr_add(a, b, vm_var(s, 0x06)); break;
    case 0x07: a = vm_kr_sub(a, b, vm_var(s, 0x07)); break;
    case 0x08: a = vm_kr_mul(a, b, vm_var(s, 0x08)); break;
    case 0x09:
        if (b == 0u) return PROT_ERR_INTERNAL;
        a = a / b; break;
    case 0x0A:
        if (b == 0u) return PROT_ERR_INTERNAL;
        a = a % b; break;
    case 0x0B: a = vm_kr_xor(a, b, vm_var(s, 0x0B)); break;
    case 0x0C: a = vm_kr_and(a, b, vm_var(s, 0x0C)); break;
    default:   a = vm_kr_or(a, b, vm_var(s, 0x0D)); break;
    }
    s->stk[s->sp++] = a;
    return PROT_OK;
}

static prot_status vm_rt_cmp(prot_vm_rt* s, uint8_t op)
{
    uint64_t b, a;
    int c;
    if (s->sp < 2u)
        return PROT_ERR_VM_STACK_UNDERFLOW;
    b = s->stk[--s->sp];
    a = s->stk[--s->sp];
    switch (op) {
    case 0x11: c = (a == b); break;
    case 0x12: c = (a != b); break;
    case 0x13: c = (a <  b); break;
    case 0x14: c = (a <= b); break;
    case 0x15: c = (a >  b); break;
    default:   c = (a >= b); break;
    }
    s->stk[s->sp++] = (c != 0) ? 1u : 0u;
    return PROT_OK;
}

/* 0x00 halt */
static prot_status vm_h_halt(prot_vm_rt* s) { (void)s; return PROT_VM_HALT; }

/* 0x01 push32 imm32 (零扩展) */
static prot_status vm_h_push32(prot_vm_rt* s)
{
    uint32_t v;
    if (!vm_wfetch32(s, &s->ip, &v))
        return PROT_ERR_VM_BAD_OPCODE;
    if (s->sp >= PROT_VM_STACK_CAP)
        return PROT_ERR_VM_STACK_OVERFLOW;
    s->stk[s->sp++] = (uint64_t)v;
    return PROT_OK;
}

/* 0x02 push64 imm64 */
static prot_status vm_h_push64(prot_vm_rt* s)
{
    uint64_t v;
    if (!vm_wfetch64(s, &s->ip, &v))
        return PROT_ERR_VM_BAD_OPCODE;
    if (s->sp >= PROT_VM_STACK_CAP)
        return PROT_ERR_VM_STACK_OVERFLOW;
    s->stk[s->sp++] = v;
    return PROT_OK;
}

/* 0x03 dup */
static prot_status vm_h_dup(prot_vm_rt* s)
{
    if (s->sp == 0u)
        return PROT_ERR_VM_STACK_UNDERFLOW;
    if (s->sp >= PROT_VM_STACK_CAP)
        return PROT_ERR_VM_STACK_OVERFLOW;
    s->stk[s->sp] = s->stk[s->sp - 1u];
    s->sp++;
    return PROT_OK;
}

/* 0x04 drop */
static prot_status vm_h_drop(prot_vm_rt* s)
{
    if (s->sp == 0u)
        return PROT_ERR_VM_STACK_UNDERFLOW;
    s->sp--;
    return PROT_OK;
}

/* 0x05 swap */
static prot_status vm_h_swap(prot_vm_rt* s)
{
    uint64_t t;
    if (s->sp < 2u)
        return PROT_ERR_VM_STACK_UNDERFLOW;
    t = s->stk[s->sp - 1u];
    s->stk[s->sp - 1u] = s->stk[s->sp - 2u];
    s->stk[s->sp - 2u] = t;
    return PROT_OK;
}

/* 0x06..0x0D 二元运算: 见 vm_h_* 系列路由表入口 */
static prot_status vm_h_add(prot_vm_rt* s)  { return vm_rt_binop(s, 0x06); }
static prot_status vm_h_sub(prot_vm_rt* s)  { return vm_rt_binop(s, 0x07); }
static prot_status vm_h_mul(prot_vm_rt* s)  { return vm_rt_binop(s, 0x08); }
static prot_status vm_h_divu(prot_vm_rt* s) { return vm_rt_binop(s, 0x09); }
static prot_status vm_h_modu(prot_vm_rt* s) { return vm_rt_binop(s, 0x0A); }
static prot_status vm_h_xor(prot_vm_rt* s)  { return vm_rt_binop(s, 0x0B); }
static prot_status vm_h_and(prot_vm_rt* s)  { return vm_rt_binop(s, 0x0C); }
static prot_status vm_h_or(prot_vm_rt* s)   { return vm_rt_binop(s, 0x0D); }

/* 0x0E not */
static prot_status vm_h_not(prot_vm_rt* s)
{
    if (s->sp == 0u)
        return PROT_ERR_VM_STACK_UNDERFLOW;
    s->stk[s->sp - 1u] = vm_kr_not(s->stk[s->sp - 1u], vm_var(s, 0x0E));
    return PROT_OK;
}

/* 0x0F shl / 0x10 shr */
static prot_status vm_h_shl(prot_vm_rt* s)
{
    uint64_t a, b;
    if (s->sp < 2u)
        return PROT_ERR_VM_STACK_UNDERFLOW;
    b = s->stk[--s->sp];
    a = s->stk[--s->sp];
    s->stk[s->sp++] = vm_kr_shl(a, b, vm_var(s, 0x0F));
    return PROT_OK;
}

static prot_status vm_h_shr(prot_vm_rt* s)
{
    uint64_t a, b;
    if (s->sp < 2u)
        return PROT_ERR_VM_STACK_UNDERFLOW;
    b = s->stk[--s->sp];
    a = s->stk[--s->sp];
    s->stk[s->sp++] = vm_kr_shr(a, b, vm_var(s, 0x10));
    return PROT_OK;
}

/* 0x11..0x16 比较 */
static prot_status vm_h_cmpeq(prot_vm_rt* s)  { return vm_rt_cmp(s, 0x11); }
static prot_status vm_h_cmpne(prot_vm_rt* s)  { return vm_rt_cmp(s, 0x12); }
static prot_status vm_h_cmpltu(prot_vm_rt* s) { return vm_rt_cmp(s, 0x13); }
static prot_status vm_h_cmpleu(prot_vm_rt* s) { return vm_rt_cmp(s, 0x14); }
static prot_status vm_h_cmpgtu(prot_vm_rt* s) { return vm_rt_cmp(s, 0x15); }
static prot_status vm_h_cmpgeu(prot_vm_rt* s) { return vm_rt_cmp(s, 0x16); }

/* 0x17 jmp rel32 */
static prot_status vm_h_jmp(prot_vm_rt* s)
{
    uint32_t rel;
    if (!vm_wfetch32(s, &s->ip, &rel))
        return PROT_ERR_VM_BAD_OPCODE;
    s->ip = vm_jump(s->ip, rel);
    return PROT_OK;
}

/* 0x18 jz rel32 */
static prot_status vm_h_jz(prot_vm_rt* s)
{
    uint32_t rel;
    uint64_t c;
    if (!vm_wfetch32(s, &s->ip, &rel))
        return PROT_ERR_VM_BAD_OPCODE;
    if (s->sp == 0u)
        return PROT_ERR_VM_STACK_UNDERFLOW;
    c = s->stk[--s->sp];
    if (c == 0u)
        s->ip = vm_jump(s->ip, rel);
    return PROT_OK;
}

/* 0x19 jnz rel32 */
static prot_status vm_h_jnz(prot_vm_rt* s)
{
    uint32_t rel;
    uint64_t c;
    if (!vm_wfetch32(s, &s->ip, &rel))
        return PROT_ERR_VM_BAD_OPCODE;
    if (s->sp == 0u)
        return PROT_ERR_VM_STACK_UNDERFLOW;
    c = s->stk[--s->sp];
    if (c != 0u)
        s->ip = vm_jump(s->ip, rel);
    return PROT_OK;
}

/* 0x1A call rel32 */
static prot_status vm_h_call(prot_vm_rt* s)
{
    uint32_t rel;
    if (!vm_wfetch32(s, &s->ip, &rel))
        return PROT_ERR_VM_BAD_OPCODE;
    if (s->sp >= PROT_VM_STACK_CAP)
        return PROT_ERR_VM_STACK_OVERFLOW;
    s->stk[s->sp++] = (uint64_t)s->ip; /* 返回地址 = 下一条指令的绝对地址 */
    s->ip = vm_jump(s->ip, rel);
    return PROT_OK;
}

/* 0x1B ret */
static prot_status vm_h_ret(prot_vm_rt* s)
{
    if (s->sp == 0u)
        return PROT_ERR_VM_STACK_UNDERFLOW;
    s->ip = (uint32_t)s->stk[--s->sp];
    return PROT_OK;
}

/* 0x1C load8 */
static prot_status vm_h_load8(prot_vm_rt* s)
{
    uint64_t addr;
    if (s->sp == 0u)
        return PROT_ERR_VM_STACK_UNDERFLOW;
    addr = s->stk[--s->sp];
    if (vm_mem_oob(addr, 1u, s->mem_size))
        return PROT_ERR_VM_OUT_OF_BOUNDS;
    s->stk[s->sp++] = (uint64_t)s->mem[addr];
    return PROT_OK;
}

/* 0x1D load32 / 0x1E load64 */
static prot_status vm_h_load32(prot_vm_rt* s)
{
    uint64_t addr, v = 0u, j;
    if (s->sp == 0u)
        return PROT_ERR_VM_STACK_UNDERFLOW;
    addr = s->stk[--s->sp];
    if (vm_mem_oob(addr, 4u, s->mem_size))
        return PROT_ERR_VM_OUT_OF_BOUNDS;
    for (j = 0u; j < 4u; j++)
        v |= (uint64_t)s->mem[addr + j] << (8u * j);
    s->stk[s->sp++] = v;
    return PROT_OK;
}

static prot_status vm_h_load64(prot_vm_rt* s)
{
    uint64_t addr, v = 0u, j;
    if (s->sp == 0u)
        return PROT_ERR_VM_STACK_UNDERFLOW;
    addr = s->stk[--s->sp];
    if (vm_mem_oob(addr, 8u, s->mem_size))
        return PROT_ERR_VM_OUT_OF_BOUNDS;
    for (j = 0u; j < 8u; j++)
        v |= (uint64_t)s->mem[addr + j] << (8u * j);
    s->stk[s->sp++] = v;
    return PROT_OK;
}

/* 0x1F store8 / 0x20 store32 / 0x21 store64 */
static prot_status vm_store_h8(prot_vm_rt* s)
{
    uint64_t val, addr;
    if (s->sp < 2u)
        return PROT_ERR_VM_STACK_UNDERFLOW;
    val = s->stk[--s->sp];
    addr = s->stk[--s->sp];
    if (vm_mem_oob(addr, 1u, s->mem_size))
        return PROT_ERR_VM_OUT_OF_BOUNDS;
    s->mem[addr] = (uint8_t)val;
    return PROT_OK;
}

static prot_status vm_store_h32(prot_vm_rt* s)
{
    uint64_t val, addr, j;
    if (s->sp < 2u)
        return PROT_ERR_VM_STACK_UNDERFLOW;
    val = s->stk[--s->sp];
    addr = s->stk[--s->sp];
    if (vm_mem_oob(addr, 4u, s->mem_size))
        return PROT_ERR_VM_OUT_OF_BOUNDS;
    for (j = 0u; j < 4u; j++)
        s->mem[addr + j] = (uint8_t)(val >> (8u * j));
    return PROT_OK;
}

static prot_status vm_store_h64(prot_vm_rt* s)
{
    uint64_t val, addr, j;
    if (s->sp < 2u)
        return PROT_ERR_VM_STACK_UNDERFLOW;
    val = s->stk[--s->sp];
    addr = s->stk[--s->sp];
    if (vm_mem_oob(addr, 8u, s->mem_size))
        return PROT_ERR_VM_OUT_OF_BOUNDS;
    for (j = 0u; j < 8u; j++)
        s->mem[addr + j] = (uint8_t)(val >> (8u * j));
    return PROT_OK;
}

/* 0x22 setbase / 0x23 pushbase / Phase 1d 指令 */
static prot_status vm_h_setbase(prot_vm_rt* s)
{
    if (s->sp == 0u)
        return PROT_ERR_VM_STACK_UNDERFLOW;
    s->br = s->stk[--s->sp];
    return PROT_OK;
}

static prot_status vm_h_pushbase(prot_vm_rt* s)
{
    if (s->sp >= PROT_VM_STACK_CAP)
        return PROT_ERR_VM_STACK_OVERFLOW;
    s->stk[s->sp++] = s->br;
    return PROT_OK;
}

static prot_status vm_h_nop(prot_vm_rt* s) { (void)s; return PROT_OK; }

static prot_status vm_h_lea(prot_vm_rt* s)
{
    uint32_t v;
    if (!vm_wfetch32(s, &s->ip, &v))
        return PROT_ERR_VM_BAD_OPCODE;
    if (s->sp >= PROT_VM_STACK_CAP)
        return PROT_ERR_VM_STACK_OVERFLOW;
    s->stk[s->sp++] = (uint64_t)v;
    return PROT_OK;
}

static prot_status vm_h_pushr(prot_vm_rt* s)
{
    if (s->sp >= PROT_VM_STACK_CAP)
        return PROT_ERR_VM_STACK_OVERFLOW;
    s->stk[s->sp++] = s->rr;
    return PROT_OK;
}

static prot_status vm_h_popr(prot_vm_rt* s)
{
    if (s->sp == 0u)
        return PROT_ERR_VM_STACK_UNDERFLOW;
    s->rr = s->stk[--s->sp];
    return PROT_OK;
}

static prot_status vm_h_setcon(prot_vm_rt* s)
{
    if (s->sp == 0u)
        return PROT_ERR_VM_STACK_UNDERFLOW;
    s->con = (s->stk[--s->sp] != 0u) ? 1u : 0u;
    return PROT_OK;
}

static prot_status vm_h_pushcon(prot_vm_rt* s)
{
    if (s->sp >= PROT_VM_STACK_CAP)
        return PROT_ERR_VM_STACK_OVERFLOW;
    s->stk[s->sp++] = s->con;
    return PROT_OK;
}

static prot_status vm_h_callind(prot_vm_rt* s)
{
    uint64_t target;
    if (s->sp == 0u)
        return PROT_ERR_VM_STACK_UNDERFLOW;
    target = s->stk[--s->sp];
    if (s->sp >= PROT_VM_STACK_CAP)
        return PROT_ERR_VM_STACK_OVERFLOW;
    s->stk[s->sp++] = (uint64_t)s->ip; /* 返回地址 = 下一条指令的绝对地址 */
    s->ip = (uint32_t)target;
    return PROT_OK;
}

/* 0x2B brk — 断言陷阱 (A4): CON != 0 -> PROT_ERR_VM_BREAKPOINT; CON == 0 继续。
 * 用途: setcon 后接 brk, 让"校验失败"在 VM 内部直接停机, 不给宿主 patch 点。 */
static prot_status vm_h_brk(prot_vm_rt* s)
{
    if (s->con != 0u)
        return PROT_ERR_VM_BREAKPOINT;
    return PROT_OK;
}

/* 0x2C move imm32 — R = 零扩展 imm32 (A4: 免栈流操作寄存器) */
static prot_status vm_h_move(prot_vm_rt* s)
{
    uint32_t v;
    if (!vm_wfetch32(s, &s->ip, &v))
        return PROT_ERR_VM_BAD_OPCODE;
    s->rr = (uint64_t)v;
    return PROT_OK;
}

/* 0x2D loadr32 — 寄存器索引寻址 (A4): pop off; 读 mem[BR + R + off] 4 字节 LE 压栈 */
static prot_status vm_h_loadr32(prot_vm_rt* s)
{
    uint64_t off, addr, v = 0u, j;
    if (s->sp == 0u)
        return PROT_ERR_VM_STACK_UNDERFLOW;
    off = s->stk[--s->sp];
    addr = s->br + s->rr + off; /* 基址寄存器 + 索引寄存器 + 栈上位移 */
    if (vm_mem_oob(addr, 4u, s->mem_size))
        return PROT_ERR_VM_OUT_OF_BOUNDS;
    for (j = 0u; j < 4u; j++)
        v |= (uint64_t)s->mem[addr + j] << (8u * j);
    s->stk[s->sp++] = v;
    return PROT_OK;
}

/* 0x2E storr32 — 寄存器索引寻址 (A4): pop val, pop off; 写 mem[BR + R + off] 4 字节 LE */
static prot_status vm_h_storr32(prot_vm_rt* s)
{
    uint64_t val, off, addr, j;
    if (s->sp < 2u)
        return PROT_ERR_VM_STACK_UNDERFLOW;
    val = s->stk[--s->sp];
    off = s->stk[--s->sp];
    addr = s->br + s->rr + off;
    if (vm_mem_oob(addr, 4u, s->mem_size))
        return PROT_ERR_VM_OUT_OF_BOUNDS;
    for (j = 0u; j < 4u; j++)
        s->mem[addr + j] = (uint8_t)(val >> (8u * j));
    return PROT_OK;
}

/* 规范顺序的路由表 (Phase 1b: 运行时按 key[1] 派生槽位, 灌入 dt[] 后间接调用) */
static const prot_vm_route g_routes[PROT_VM_OP_COUNT] = {
    vm_h_halt,     /* 0x00 */
    vm_h_push32,   /* 0x01 */
    vm_h_push64,   /* 0x02 */
    vm_h_dup,      /* 0x03 */
    vm_h_drop,     /* 0x04 */
    vm_h_swap,     /* 0x05 */
    vm_h_add,      /* 0x06 */
    vm_h_sub,      /* 0x07 */
    vm_h_mul,      /* 0x08 */
    vm_h_divu,     /* 0x09 */
    vm_h_modu,     /* 0x0A */
    vm_h_xor,      /* 0x0B */
    vm_h_and,      /* 0x0C */
    vm_h_or,       /* 0x0D */
    vm_h_not,      /* 0x0E */
    vm_h_shl,      /* 0x0F */
    vm_h_shr,      /* 0x10 */
    vm_h_cmpeq,    /* 0x11 */
    vm_h_cmpne,    /* 0x12 */
    vm_h_cmpltu,   /* 0x13 */
    vm_h_cmpleu,   /* 0x14 */
    vm_h_cmpgtu,   /* 0x15 */
    vm_h_cmpgeu,   /* 0x16 */
    vm_h_jmp,      /* 0x17 */
    vm_h_jz,       /* 0x18 */
    vm_h_jnz,      /* 0x19 */
    vm_h_call,     /* 0x1A */
    vm_h_ret,      /* 0x1B */
    vm_h_load8,    /* 0x1C */
    vm_h_load32,   /* 0x1D */
    vm_h_load64,   /* 0x1E */
    vm_store_h8,   /* 0x1F */
    vm_store_h32,  /* 0x20 */
    vm_store_h64,  /* 0x21 */
    vm_h_setbase,  /* 0x22 */
    vm_h_pushbase, /* 0x23 */
    vm_h_nop,      /* 0x24 */
    vm_h_lea,      /* 0x25 */
    vm_h_pushr,    /* 0x26 */
    vm_h_popr,     /* 0x27 */
    vm_h_setcon,   /* 0x28 */
    vm_h_pushcon,  /* 0x29 */
    vm_h_callind,  /* 0x2A */
    vm_h_brk,      /* 0x2B (A4) */
    vm_h_move,     /* 0x2C (A4) */
    vm_h_loadr32,  /* 0x2D (A4) */
    vm_h_storr32,  /* 0x2E (A4) */
};

prot_status prot_vm_run(const prot_vm_image* img, void* mem_base, size_t mem_size)
{
    PROT_NOISE();   /* W1.6 序言噪声 */
    /* §4.1 第 1 步: 参数校验 */
    if (img == NULL || img->code == NULL || mem_base == NULL ||
        img->code_len == 0u || img->code_len > (1u << 20) || mem_size == 0u)
        return PROT_ERR_INVALID_ARG;

    /* §4.1 第 2 步 (Phase 2b 流式 CRC): 逐字节解密仅过 CRC, 明文不入缓冲。
     * 与整段明文 crc32 完全等价。CRC 失败=密文被篡改。 */
    {
        uint32_t crc = prot_crc32_init();
        uint64_t kk = img->key[0];
        for (uint32_t i = 0u; i < img->code_len; i++) {
            kk = kk * PROT_KS_MUL + PROT_KS_ADD;
            crc = prot_crc32_step(crc, (uint8_t)(img->code[i] ^ (kk >> 56)));
        }
        if (prot_crc32_done(crc) != img->crc)
            return PROT_ERR_VM_CRC;
    }

    /* §4.1 第 3 步: 解释执行 (Phase 1a/1b/1c + Phase 2b 窗口解密 + A2 语义微变) */
    uint8_t op_inv[256];
    uint8_t slot[PROT_VM_OP_COUNT];
    uint8_t vr[PROT_VM_OP_COUNT];
    uint8_t sem[2];
    prot_vm_route dt[PROT_VM_OP_COUNT];
    vm_build_keymaps(img, op_inv, slot, vr, sem);
    for (uint32_t c = 0u; c < PROT_VM_OP_COUNT; c++)
        dt[slot[c]] = g_routes[c]; /* 按构建期槽位随机灌表 */

    prot_vm_rt rt;
    rt.cc = img->code;
    rt.code_len = img->code_len;
    rt.mem = (uint8_t*)mem_base;
    rt.mem_size = mem_size;
    memset(rt.stk, 0, sizeof(rt.stk));
    memcpy(rt.var, vr, sizeof(vr));
    memcpy(rt.sem, sem, sizeof(sem)); /* A2: 构建期语义微变开关 */
    rt.sp = 0u;
    rt.ip = 0u;
    rt.br = 0u;
    /* Phase 2c: 运行时语义随机化. 用实例熵播种 ctx, 使 vm_var 每次运行取不同
     * 等价路径 (重放/指纹前后两次相同二进制无法复用); 因各路径语义等价,
     * 计算最终结果始终一致. */
    rt.ctx = vm_ctx_seed();
    rt.rr = 0u;
    rt.con = 0u;
    rt.kseed = img->key[0];
    rt.k = rt.kseed;
    rt.wlo = 0u;
    rt.wt = 0u;
    memset(rt.win, 0, sizeof(rt.win));

    prot_status rc = PROT_OK;
    for (;;) {
        if (rt.ip >= rt.code_len) {
            rc = PROT_ERR_VM_BAD_OPCODE;
            break;
        }
        vm_wprune(&rt); /* Phase 2b: 用后即焚, 丢弃已消费字节 */
        {
            const uint8_t canon = op_inv[vm_wb(&rt, rt.ip)];
            rt.ip++;
            if (canon == 0xFFu) {
                rc = PROT_ERR_VM_BAD_OPCODE;
                break;
            }

            /* Phase 1b 上下文散列: 每取一条指令累加 */
            rt.ctx = rt.ctx * PROT_CTX_MUL + (uint32_t)canon;

            rc = dt[slot[canon]](&rt);
            if (rc == PROT_VM_HALT) {
                rc = PROT_OK;
                break;
            }
            if (rc != PROT_OK)
                break;
        }
    }

    /* Phase 2b 用后即焚: 明文窗口清零 */
    vm_scrub(rt.win, sizeof(rt.win));
    return rc;
}