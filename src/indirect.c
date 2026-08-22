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
 * __declspec(noinline): 防止 /O2 把 resolve 内联进调用点 (保持间接形态)。
 */
#include "protect/indirect.h"

#include <stdint.h>

__declspec(noinline)
prot_indirect_fnp prot_indirect_resolve(prot_indirect_fn fn_id)
{
    const prot_indirect_fnp* tab = prot_indirect_table();
    const uint8_t* perm = prot_indirect_perm();

    if (fn_id < 0 || fn_id >= PROT_INDIRECT_COUNT)
        return NULL;
    return tab[perm[(uint32_t)fn_id]];
}
