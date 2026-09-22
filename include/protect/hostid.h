/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 ShardVase contributors
 *
 * 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；
 * 商业授权见 LICENSE.md。
 */
/*
 * hostid.h — 机器标识 (Phase 4: 真实硬件绑定)
 *
 * 由 C 运行时与 tools/vmenc.py(hostid) 用同一算法计算, 保证构建期 genserial
 * 烧录的 EXPECT 与运行期 demo 读取的 machine_id 一致。任何一侧改动必须同步。
 */
#ifndef PROT_HOSTID_H
#define PROT_HOSTID_H

#include "protect/protdef.h"

/* 机器标识: 卷序列号 + 计算机名 多因子 FNV-1a 折叠 (64 位) */
#ifdef __cplusplus
extern "C" {
#endif

uint64_t prot_hostid_get(void);


#ifdef __cplusplus
}   /* extern "C" */
#endif
#endif /* PROT_HOSTID_H */
