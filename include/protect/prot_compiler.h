/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 ShardVase contributors
 *
 * 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；
 * 商业授权见 LICENSE.md。
 */
/*
 * prot_compiler.h — 编译器/平台无关的属性宏（L2）
 *
 * ## 为什么需要（L2 目标）
 *   纯逻辑模块应**不含编译器专有语法** —— 否则换编译器/平台就要改源码。
 *   实测（2026-09-23）发现的耦合:
 *     · `src/indirect.c` 用 `__declspec(noinline)`（**MSVC 专有**）
 *     · GCC/Clang 用 `__attribute__((noinline))`
 *
 * ## 设计
 *   把编译器差异**集中到一个头文件** —— 模块只写 `PROT_NOINLINE`。
 *   这是 L1 平台抽象层（运行期能力）的**编译期对应物**。
 *
 * ## 诚实边界
 *   · 本头只覆盖**已发现的**差异（noinline / used / align）
 *   · 新增属性时须同步本文件（同 INFRA_HEADERS 的教训）
 *   · **不改变任何现有行为** —— MSVC 下展开与原来**逐字相同**
 */

#ifndef PROT_COMPILER_H
#define PROT_COMPILER_H

/* ------------------------------------------------------------------ *
 * 编译器标识
 * ------------------------------------------------------------------ */

#if defined(_MSC_VER)
#  define PROT_COMPILER_MSVC 1
#elif defined(__GNUC__)
#  define PROT_COMPILER_GCC 1
#elif defined(__clang__)
#  define PROT_COMPILER_CLANG 1
#else
#  define PROT_COMPILER_UNKNOWN 1
#endif

/* ------------------------------------------------------------------ *
 * 属性宏
 *
 * **用法**: 替换模块里的编译器专有写法。
 * ------------------------------------------------------------------ */

/* 禁止内联 —— 保持函数体的**独立存在**（间接化/加密依赖此性质）。
 *
 * MSVC:   __declspec(noinline)
 * GCC:    __attribute__((noinline))
 *
 * 注: 两者语义一致（都禁止内联），且都可用在函数定义前。 */
#if defined(PROT_COMPILER_MSVC)
#  define PROT_NOINLINE __declspec(noinline)
#elif defined(PROT_COMPILER_GCC) || defined(PROT_COMPILER_CLANG)
#  define PROT_NOINLINE __attribute__((noinline))
#else
#  define PROT_NOINLINE
#endif

/* 强制保留符号（防止链接器/优化器丢弃未被引用的函数）。 */
#if defined(PROT_COMPILER_MSVC)
#  define PROT_USED
#elif defined(PROT_COMPILER_GCC) || defined(PROT_COMPILER_CLANG)
#  define PROT_USED __attribute__((used))
#else
#  define PROT_USED
#endif

/* ------------------------------------------------------------------ *
 * CPU 内建指令的**兼容层**（L6b，2026-09-25）
 *
 * ## 为什么需要
 *   实测 Linux 编译: `vmdetect` 与 `vm` 卡在 `<intrin.h>` 的
 *   `__cpuid` / `__rdtsc` —— 它们是 **MSVC 专有内建**，
 *   GCC/Clang 用**不同的形式**（内建函数或内联汇编）。
 *
 *   这两个模块的**平台依赖最轻**（只有 CPU 内建），故优先封装。
 * ------------------------------------------------------------------ */

/* CPUID 指令。
 *
 * MSVC:  `__cpuid(int regs[4], int leaf)`（intrin.h）
 * GCC :  内联汇编（**不用 cpuid.h** —— 避免额外依赖，
 *        且 cpuid.h 的 `__get_cpuid` 在部分环境下不可用）
 *
 * **用法**: int regs[4]; PROT_CPUID(regs, 1);
 *           之后 regs[0]=EAX, regs[1]=EBX, regs[2]=ECX, regs[3]=EDX
 *
 * **顺序契约**: MSVC 的 `__cpuid` 也是 EAX,EBX,ECX,EDX 顺序
 *   （与 x86 `cpuid` 指令的**物理寄存器顺序**不同 —— 指令是 EAX,EBX,ECX,EDX）。
 */
#if defined(PROT_COMPILER_MSVC)
#  include <intrin.h>
#  define PROT_CPUID(regs, leaf) __cpuid((regs), (leaf))
#elif defined(PROT_COMPILER_GCC) || defined(PROT_COMPILER_CLANG)
#  define PROT_CPUID(regs, leaf)                                           \
        __asm__ __volatile__("cpuid"                                       \
            : "=a"((regs)[0]), "=b"((regs)[1]),                            \
              "=c"((regs)[2]), "=d"((regs)[3])                             \
            : "a"((leaf)))
#else
#  define PROT_CPUID(regs, leaf)                                           \
        do { (regs)[0] = (regs)[1] = (regs)[2] = (regs)[3] = 0; } while (0)
#endif

/* 读时间戳计数器（TSC）。
 *
 * MSVC:  `__rdtsc()`（intrin.h）
 * GCC :  `__builtin_ia32_rdtsc()`（x86 内建，无需头文件）
 *
 * **注意（x86 专有）**: 本封装假定 x86/x64。
 *   在 ARM64 上应另有实现（如 CNTVCT_EL0）—— **本轮不支持**（如实标注）。
 */
#if defined(PROT_COMPILER_MSVC)
#  define PROT_RDTSC() __rdtsc()
#elif defined(PROT_COMPILER_GCC) || defined(PROT_COMPILER_CLANG)
#  if defined(__x86_64__) || defined(__i386__)
#    define PROT_RDTSC() __builtin_ia32_rdtsc()
#  else
#    define PROT_RDTSC() 0ull   /* 非 x86: 无 TSC（如实退化为 0）*/
#  endif
#else
#  define PROT_RDTSC() 0ull
#endif

/* ------------------------------------------------------------------ *
 * 自定义节（C2，2026-09-25）
 *
 * ## 为什么需要
 *   `selfcrypt.c` 用 MSVC 专有语法建自定义节:
 *     `#pragma section(".protcry", read, write)`
 *     `__declspec(allocate(".protcry")) uint8_t blob[N];`
 *   GCC/Clang 用 `__attribute__((section(".protcry")))`。
 *
 * ## 用法（**属性必须是标识符，不加引号**）
 *   ```c
 *   PROT_SECTION_BEGIN(PROT_SEC_CRY, read, write)
 *   PROT_ALLOCATE(PROT_SEC_CRY) uint8_t g_blob[16384];
 *   ```
 *
 * ## ⚠️ 实测踩坑（2026-09-25）
 *   初版把属性写成**字符串**: `PROT_SECTION_BEGIN(sec, "read, write")`
 *   -> MSVC 报 **C4081（应输入"标识符"；找到"字符串"）** -> `/WX` 失败。
 *   MSVC 的 `__pragma(section(...))` 要的是**标识符**。
 *   故改用**可变参数** `...`，让两侧各自展开。
 *
 * ## 诚实边界
 *   · MSVC 的 `#pragma section` 影响**其后所有** `__declspec(allocate)`
 *   · GCC 的属性是**逐变量**的 -> **该宏在 GCC 上展开为空**
 *     （节归属由 `PROT_ALLOCATE` 的属性表达）
 * ------------------------------------------------------------------ */

/* MSVC: `__pragma(section(NAME, ATTRS...))`；GCC: 空（属性随变量走） */
#if defined(PROT_COMPILER_MSVC)
#  define PROT_SECTION_BEGIN(sec, ...) __pragma(section(sec, __VA_ARGS__))
#  define PROT_ALLOCATE(sec) __declspec(allocate(sec))
#else
#  define PROT_SECTION_BEGIN(sec, ...)   /* GCC: 属性随变量走 */
#  define PROT_ALLOCATE(sec) __attribute__((section(sec)))
#endif

/* ------------------------------------------------------------------ *
 * MSVC 专有 API 的**兼容层**（L6b，2026-09-25 编译测试发现）
 *
 * ## 为什么需要
 *   实测在 Linux 上编译 18 个源文件，只有 3 个通过。失败原因中
 *   **有一类是"MSVC 专有写法"而非"平台依赖"** —— 可统一抽象:
 *     · `fopen_s(&f, path, mode)`（MSVC 安全版）
 *     · `#pragma code_seg(...)`（MSVC 段控制）
 *   这些**改一处即可跨平台**，不该散落在各模块里。
 * ------------------------------------------------------------------ */

/* 安全打开文件（统一调用形式）。
 *
 * MSVC:  `fopen_s(&fp, path, mode)`（返回 errno_t，0 为成功）
 * POSIX: `fp = fopen(path, mode)` -> 转为同样的 errno_t 语义
 *
 * **用法**:
 *   FILE* f = NULL;
 *   if (PROT_FOPEN_S(&f, path, "rb") != 0) { ... }
 *
 * **语义等价性（关键）**:
 *   两者都保证"失败时 *fpp 为 NULL"，故调用方判 `err != 0` 即可。
 */
#if defined(PROT_COMPILER_MSVC)
#  define PROT_FOPEN_S(fpp, path, mode) fopen_s((fpp), (path), (mode))
#else
#  include <stdio.h>
#  include <errno.h>
#  define PROT_FOPEN_S(fpp, path, mode)                     \
        ( (*(fpp) = fopen((path), (mode))) != NULL          \
          ? 0 : (errno ? errno : EIO) )
#endif

/* 段控制（MSVC）。其它平台**忽略** —— 段布局是 PE 概念。
 *
 * ## 诚实说明
 *   在 Linux 上忽略此指令 -> `crc32` 表不会被放到特定节。
 *   **这不影响功能**（该指令用于"防止 crc 表被单独定位"的加固），
 *   但**加固效果在 Linux 上不存在**（如实记录为平台差异）。
 */
#if defined(PROT_COMPILER_MSVC)
#  define PROT_CODE_SEG(name) __pragma(code_seg(name))
#  define PROT_CODE_SEG_END() __pragma(code_seg())
#else
#  define PROT_CODE_SEG(name)   /* 无对应：PE 段布局是平台概念 */
#  define PROT_CODE_SEG_END()
#endif

/* 空操作指令（编译器无关）。
 *
 * ## 为什么需要（L6b，2026-09-25 编译测试发现）
 *   `include/protect/prot_noise.h` 的 `PROT_NOISE()` 用了 `__nop()`
 *   —— **MSVC 专有**内建。GCC/Clang **不认识**它 ->
 *   **8 个"纯逻辑"模块**在 Linux 上编译失败（`implicit declaration
 *   of function '__nop'`）。
 *
 *   **这是 L2 的遗漏**: L2 只处理了 `indirect.c` 的 `__declspec`，
 *   而扫描维度里的关键词表**没列 `__nop`** -> 静态清单漏了它。
 *
 * ## 语义
 *   · 目的: 给"永不执行"的分支一个**真实的指令**，
 *     使编译器**不能把整个分支优化掉**（PROT_NOISE 的核心机制）
 *   · MSVC:   `__nop()`  -> 展开为 `0x90`（x64）
 *   · GCC:    `__asm__ __volatile__("nop")`
 *   · 其它:   退化为空语句（噪声效果减弱，但**语义仍恒等**）
 *
 * ## 跨平台语义差异（**如实**）
 *   MSVC 的 `__nop()` 与 x86 的 `nop` 在 x64 上都是 `0x90` ——
 *   但 **ARM64 上 `__nop()` 是不同编码**。
 *   故此处按编译器的**内建**选，而非硬编码 `0x90`：
 *   让编译器产生它自己平台上正确的 NOP。
 */
#if defined(PROT_COMPILER_MSVC)
#  define PROT_NOP() __nop()
#elif defined(PROT_COMPILER_GCC) || defined(PROT_COMPILER_CLANG)
#  define PROT_NOP() __asm__ __volatile__("nop")
#else
#  define PROT_NOP() ((void)0)
#endif

/* 调用约定：Windows 常见 __cdecl/__stdcall；其它平台无此概念。 */
#if defined(PROT_COMPILER_MSVC)
#  define PROT_CALL __cdecl
#else
#  define PROT_CALL
#endif

/* 结构体对齐（用于与文件格式对接的结构）。 */
#if defined(PROT_COMPILER_MSVC)
#  define PROT_PACKED
#  define PROT_PACK_PUSH __pragma(pack(push, 1))
#  define PROT_PACK_POP  __pragma(pack(pop))
#else
#  define PROT_PACKED __attribute__((packed))
#  define PROT_PACK_PUSH
#  define PROT_PACK_POP
#endif

/* ------------------------------------------------------------------ *
 * 编译器能力探测（模块可据此降级）
 * ------------------------------------------------------------------ */

/* 是否支持 C11 `_Static_assert`（MSVC 2019+ / GCC 4.6+ 均支持）。
 * 项目用 /std:c11，故此处仅作显式记录。 */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#  define PROT_HAS_C11 1
#else
#  define PROT_HAS_C11 0
#endif

#endif /* PROT_COMPILER_H */
