/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 ShardVase contributors
 *
 * 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；
 * 商业授权见 LICENSE.md。
 */
/*
 * indirect.c — 函数级间接化 (N4)
 *
 * 静态表 s_fn[] 存规范顺序指针 (同 vm.c g_routes), 生成侧 (tools/indirect.py)
 * 派生出槽位置换 s_perm 嵌入表文件。
 *
 * 取用: 指针 = s_fn[ s_perm[fn_id] ]
 *   - 静态反汇编: 调用点只有 "call prot_indirect_resolve" + "call rax",
 *     无直接 call 目标 (调用方无法静态读到最终函数地址);
 *   - 每次构建 seed 变化 -> perm 全变, 跨构建无法复用 patch。
 *
 * PROT_NOINLINE: 防止 /O2 把 resolve 内联进调用点 (保持间接形态)。
 *
 * L2（2026-09-23）: 由 `__declspec(noinline)`（**MSVC 专有**）
 *   改为 `PROT_NOINLINE`（见 protect/prot_compiler.h）——
 *   本模块因此**不含编译器专有语法**，换编译器无需改源码。
 *   MSVC 下该宏**展开为完全相同的 `__declspec(noinline)`**，
 *   故产物行为不变（已实测门禁全绿 + 可复现性保持）。
 */
#include "protect/indirect.h"
#include "protect/prot_compiler.h"  /* L2: 编译器无关属性宏 */
#include "protect/prot_noise.h"   /* W1.6 序言噪声 */

#include <stdint.h>

PROT_NOINLINE
prot_indirect_fnp prot_indirect_resolve(prot_indirect_fn fn_id)
{
    PROT_NOISE();   /* W1.6 序言噪声 */
    const prot_indirect_fnp* tab = prot_indirect_table();
    const uint8_t* perm = prot_indirect_perm();

    if (fn_id < 0 || fn_id >= PROT_INDIRECT_COUNT)
        return NULL;
    return tab[perm[(uint32_t)fn_id]];
}
