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
