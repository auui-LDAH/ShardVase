/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 ShardVase contributors
 *
 * 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；
 * 商业授权见 LICENSE.md。
 */
/*
 * indirect.h — 函数级间接化 (N4)
 *
 * 目标: 宿主关键函数 (VM 执行/授权校验/吊销检查/机器标识) 不再直接 call,
 * 改为经**构建期随机化槽位**的函数指针表间接调用 —— 静态反汇编看不到
 * 直接 call 目标, 每次构建槽位/掩码不同, 跨构建无法复用 patch。
 *
 * 与 VM Phase 1b 调度间接化同构 (g_routes + 运行时槽位重排):
 *   - 静态表 s_fn[] 按规范顺序存函数指针 (demo/gen/indirect_table.c 生成);
 *   - 运行期 prot_indirect_resolve(fn_id) 按派生槽位取指针, 经掩码混淆;
 *   - 生成侧 tools/indirect.py 与执行侧 src/indirect.c 用同一 xorshift64 流
 *     (CONTRACT §3) 派生 perm/mask/salt, 两遍逐字节一致。
 */
#ifndef PROT_INDIRECT_H
#define PROT_INDIRECT_H

#include "protect/protdef.h"

/* 规范顺序函数 ID (与 tools/indirect.py _fn_order_from_header 一致, 勿改) */
#ifdef __cplusplus
extern "C" {
#endif

typedef enum prot_indirect_fn {
    PROT_INDIRECT_VM_RUN,      /* prot_vm_run: VM 解释执行核心 */
    PROT_INDIRECT_LICENSE,     /* load_and_verify_license: RSA 验签 (demo) */
    PROT_INDIRECT_REVOKE,      /* prot_revoke_check: 吊销黑名单 */
    PROT_INDIRECT_HOSTID,      /* prot_hostid_get: 机器标识 */
    PROT_INDIRECT_COUNT
} prot_indirect_fn;

/* 泛型函数指针 (间接表统一存储类型) */
typedef void (*prot_indirect_fnp)(void);

/* 生成侧导出的静态表 (demo/gen/indirect_table.c) */
const prot_indirect_fnp* prot_indirect_table(void);
const uint8_t* prot_indirect_perm(void);

/*
 * 取第 fn_id 个函数的运行时指针 (经槽位派生)。
 * 返回泛型函数指针; 调用方转回具体签名 (函数指针互转在 C 标准下
 * 实现定义, MSVC 允许且 /W4 无告警)。
 */
prot_indirect_fnp prot_indirect_resolve(prot_indirect_fn fn_id);


#ifdef __cplusplus
}   /* extern "C" */
#endif
#endif /* PROT_INDIRECT_H */
