/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 ShardVase contributors
 *
 * 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；
 * 商业授权见 LICENSE.md。
 */
/*
 * prot_sections.h — 保护节的名称与 magic（**默认值 + 可覆盖**）
 *
 * ## 为什么需要这一层（设计教训，2026-09-21）
 * 阶段1（第二支柱）要让节名"每构建随机"，以消除 .protcrc/PROTCRCP 这类
 * 自解释线索。但若让 src 下的 .c 直接 include 生成的头（demo/gen/prot_sections.h），
 * 就会**要求所有使用者都走 build.ps1** —— 而 skeleton / examples / tests
 * 等独立构建并没有 demo/gen 的 include 路径，于是全部 C1083 失败
 * （门禁实测抓到）。
 *
 * 故改为**两层**:
 *   · 本文件提供**默认节名**（与历史一致）-> 独立构建无需任何生成步骤
 *   · 若构建定义了 PROT_USE_GENERATED_SECTIONS 且 -I 指向生成目录，
 *     则由生成头覆盖（build.ps1 走这条）
 *
 * 这样"随机节名"是**可选强化**，而不是对所有使用者的硬性要求。
 *
 * ## 约束（实测）
 * PE 节名上限 **8 字节**，超出被静默截断
 * （源码曾写 ".protcrypt"(10) 而产物为 ".protcry"(8)）。
 * 故生成器产 "." + 7 字符，正好 8。
 */
#ifndef PROT_SECTIONS_H
#define PROT_SECTIONS_H

/* 默认节名（历史值；独立构建与未启用随机化时使用） */
#ifndef PROT_SEC_XEC
#define PROT_SEC_XEC  ".protxec"
#endif
#ifndef PROT_SEC_CRC
#define PROT_SEC_CRC  ".protcrc"
#endif
#ifndef PROT_SEC_CRY
#define PROT_SEC_CRY  ".protcry"
#endif
#ifndef PROT_SEC_PAD
#define PROT_SEC_PAD  ".protpad"
#endif
/* ## `PROT_SEC_FPT` 已移除（S3, 2026-09-25）—— 不要加回来
 *
 *   它曾有默认值 `.fptable`，但**全库无任何使用者**（死宏）。
 *   产物里那个 `.fptable` 段的**生产者是 CRT**
 *   （`?function_pointers` @ `libucrt:winapi_thunks.obj`，
 *   见 `build/demo.map`）—— **不是本项目代码**。
 *
 *   本项目的随机化自定义节只有四个:
 *     `PROT_SEC_XEC` / `PROT_SEC_CRC` / `PROT_SEC_CRY` / `PROT_SEC_PAD`
 *   详见 `tools/gen_sections.py` 的 NAMES 表注释。
 */

/* 默认 magic（历史值；见 tools/hashpatch.py 的 marker 布局） */
#ifndef PROT_MAGIC_TEXT
#define PROT_MAGIC_TEXT   "PROTCRCP"
#endif
#ifndef PROT_MAGIC_RDATA
#define PROT_MAGIC_RDATA  "PROTCRCD"
#endif
#ifndef PROT_MAGIC_PDATA
#define PROT_MAGIC_PDATA  "PROTCRDP"
#endif

/* magic 的**字节数组形式**（供聚合初始化用）。
 * C 不允许用字符串字面量初始化 uint8_t[8] 成员，故展开为字节表。
 * 生成头（PROT_USE_GENERATED_SECTIONS 时）会用随机值覆盖。 */
#ifndef PROT_MAGIC_TEXT_BYTES
#define PROT_MAGIC_TEXT_BYTES \
    { 'P', 'R', 'O', 'T', 'C', 'R', 'C', 'P' }
#endif
#ifndef PROT_MAGIC_RDATA_BYTES
#define PROT_MAGIC_RDATA_BYTES \
    { 'P', 'R', 'O', 'T', 'C', 'R', 'C', 'D' }
#endif
#ifndef PROT_MAGIC_PDATA_BYTES
#define PROT_MAGIC_PDATA_BYTES \
    { 'P', 'R', 'O', 'T', 'C', 'R', 'D', 'P' }
#endif

/* 可选覆盖: 由 build.ps1 定义 PROT_USE_GENERATED_SECTIONS 并 -I 生成目录。
 * 生成头里的 #define 会覆盖上面的默认值（因为默认值带 #ifndef 保护）。 */
#ifdef PROT_USE_GENERATED_SECTIONS
#include "prot_sections_generated.h"
#endif

#endif /* PROT_SECTIONS_H */
