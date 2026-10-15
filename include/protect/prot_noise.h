/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 ShardVase contributors
 *
 * 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；
 * 商业授权见 LICENSE.md。
 */
/* prot_noise.h — 每构建序言噪声（W1.6）
 *
 * ## 为什么需要（W5.6 实测依据 2026-09-23）
 *   `tools/migration_cost.py` 实测：**55.9%（19/34）的保护函数**其前 32 字节
 *   在两个构建间**完全相同** -> 攻击者取字节特征做**模式扫描**即可跨构建
 *   定位同一函数 -> 复用已开发的绕过 -> **迁移成本低**。
 *
 *   根因：此前的每构建随机化只作用于**数据**（节名/magic/期望值/密钥/掩码/
 *   填充区），不作用于**代码**。真实函数体的机器码与种子无关。
 *
 * ## 本宏做什么
 *   在函数序言插入一段**语义恒等**但**会生成机器码**的代码，
 *   其立即数由构建系统注入的 `PROT_BUILD_SALT` 决定 ->
 *   不同构建的同名函数首部字节不同 -> 特征匹配失效。
 *
 * ## 为什么用"局部 volatile"（三次实测迭代后确定）
 *   | 写法 | 唯一字节序列 | 判定 |
 *   |------|-------------|------|
 *   | `PROT_NOP()` 序列 | —— | ✗ **被 /O2 完全优化掉** |
 *   | `static volatile` + 分支 | 2/5 | ✗ 碰撞（见下）|
 *   | **局部 `volatile`** | **6/6** | ✅ **采用** |
 *   | 直接用 salt 做分支条件 | 2/6 | ✗ 碰撞 |
 *
 *   **根因（逐字节定位）**：`static volatile uint32_t s_ = SALT;` 把变量
 *   放进 **.data**，函数体里只有**取它的地址**（`8b 05 <disp32>`）——
 *   而该地址是否随 salt 变化取决于**链接布局**，不可控。
 *   实测 `0x11111111` 与 `0xAAAAAAAA` 生成了**完全相同**的机器码。
 *
 *   改用**局部** `volatile` 后，编译器生成
 *       `c7 44 24 08 <imm32>`   (mov dword [rsp+8], imm32)
 *   —— salt 作为**函数体内立即数** -> 任意 salt 都改变机器码 ✓
 *
 * ## 安全性
 *   · 语义恒等：`v_` 只用于一个**永不成立**的条件（0xDEADBEEF），
 *     不改变任何返回值/状态。即使分支被误判成立，执行的也只是 `PROT_NOP()`。
 *   · 无 I/O、无内存写入（栈上局部）、无异常 -> 不引入新的失败模式。
 *   · 开销：一次栈写 + 一次栈读 + 一次比较（亚纳秒级，且不在循环内）。
 *
 * ## 诚实边界
 *   · 这**只**提高"跨构建特征匹配"的成本，**不**阻止单构建内的分析。
 *   · 只覆盖函数**首部**（约 15 字节）。攻击者若用**函数中部/尾部**的更长
 *     特征仍可能匹配 —— **已知局限**，需在 migration_cost 度量中复核。
 *   · 注入位置规律（都在序言）本身是可学习的模式；攻击者可"跳过前 N 字节"
 *     再匹配 —— 这会降低（但不消除）本宏的效果。
 */

#ifndef PROT_NOISE_H
#define PROT_NOISE_H

#include "protect/prot_compiler.h"   /* L6b: PROT_NOP() 跨平台 */

#include <stdint.h>

/*
 * 构建盐：由构建系统以 -DPROT_BUILD_SALT=0x... 注入（每构建不同）。
 * 未定义时退化为 0（独立构建 如 骨架/示例/单测 不受影响）。
 */
#ifndef PROT_BUILD_SALT
#define PROT_BUILD_SALT 0u
#endif

/*
 * 序言噪声：语义恒等，机器码随 PROT_BUILD_SALT 变化。
 *
 * 关键: 用**局部** volatile（非 static）—— 让 salt 成为函数体内的
 * 立即数（`mov dword [rsp+N], imm32`），而非全局变量的地址引用。
 */
#define PROT_NOISE()                                                       \
    do {                                                                   \
        volatile uint32_t prot_k_ = PROT_BUILD_SALT;                       \
        uint32_t prot_v_ = prot_k_;                                        \
        if (prot_v_ == 0xDEADBEEFu) { PROT_NOP(); }                           \
        (void)prot_v_;                                                     \
    } while (0)

/*
 * 盐驱动惰性填充步（R3.2-c 位置抖动，2026-10-04）。
 *
 * 语义恒等：只对局部 volatile 做读-改-写，结果丢弃。
 * 与 PROT_NOISE 的区别：PROT_NOISE 让**立即数**随构建变化；本宏由调用方
 * 用 `#if` 阶梯控制**语句条数**，于是机器码**长度**随构建变化。
 *
 * ## 为什么需要（实测缺口）
 *   R3.2-c 的副本都在 `src/antidebug.c` 一个编译单元里，其相互距离由编译器
 *   在该 TU 内的函数排布决定，**与链接顺序（--shuffle-seed）无关**。
 *   实测 3 个不同 shuffle seed 下，副本相对本体的偏移恒为
 *   `+208 / +416 / +480 / +688` —— 攻击者定位到任一副本后，用固定偏移即可
 *   找到其余副本。把填充量绑定到**每构建都变**的 PROT_BUILD_SALT，相对偏移
 *   就不再是常量（详见 tools/replica_check.py 判据 5）。
 *
 * ## ⚠️ 为什么必须用 `#if` 阶梯（而不是 switch / 循环）
 *   · `switch` 的**所有 case 体都会被编译出来** —— 执行走哪条分支不影响
 *     代码长度，机器码长度恒定，起不到作用；
 *   · 常量界循环是否展开由优化器决定 —— 不可控，不能作为不变量；
 *   · 只有**预处理期**的条件编译才真正改变"被编译的代码量"。
 *
 * 为什么不会被优化掉：每次操作都是对局部 volatile 的读-改-写；volatile
 * 访问是副作用，编译器不得消除或合并。
 */
#define PROT_PAD_STEP()                                                    \
    do {                                                                   \
        volatile uint32_t prot_pad1_ = 0u;                                 \
        volatile uint32_t prot_pad2_ = (PROT_BUILD_SALT);                  \
        prot_pad1_ += prot_pad2_;                                          \
        (void)prot_pad1_;                                                  \
    } while (0)

/*
 * R3.2-c 位置抖动的**位分解阶梯**：把 3 个 bit 分解成 4+2+1，恰好给出 0..7 步。
 * 位分解（而非 8 段 `#if` 阶梯）让调用点只有 3 个条件块：
 *     #if ((PROT_BUILD_SALT) >> N) & 4u
 *         PROT_PAD_4();
 *     #endif
 *     #if ((PROT_BUILD_SALT) >> N) & 2u
 *         PROT_PAD_2();
 *     #endif
 *     #if ((PROT_BUILD_SALT) >> N) & 1u
 *         PROT_PAD_1();
 *     #endif
 * 每个调用点取**不同**的位段 N，使各函数的尺寸扰动互相独立。
 */
#define PROT_PAD_4()  do { PROT_PAD_STEP(); PROT_PAD_STEP(); PROT_PAD_STEP(); PROT_PAD_STEP(); } while (0)
#define PROT_PAD_2()  do { PROT_PAD_STEP(); PROT_PAD_STEP(); } while (0)
#define PROT_PAD_1()  do { PROT_PAD_STEP(); } while (0)

/*
 * 加强版：让 salt 参与两条独立的立即数（扩大敏感面，抗"部分位碰撞"）。
 * 用于**非热路径**的关键检测函数。
 */
#define PROT_NOISE_STRONG()                                                \
    do {                                                                   \
        volatile uint32_t prot_k_ = (PROT_BUILD_SALT ^ 0x9E3779B9u);       \
        volatile uint32_t prot_m_ = (PROT_BUILD_SALT * 0x01000193u);       \
        uint32_t prot_v_ = (prot_k_ ^ prot_m_);                            \
        if (prot_v_ == 0x1234ABCDu) { PROT_NOP(); }                           \
        (void)prot_v_;                                                     \
    } while (0)

#endif /* PROT_NOISE_H */
