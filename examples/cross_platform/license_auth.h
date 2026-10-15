/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 ShardVase contributors
 *
 * 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；
 * 商业授权见 LICENSE.md。
 */
/*
 * license_auth.h — 跨平台授权验签 SDK (EXTENSION_PLAN C1)
 *
 * 平台无关接口: Windows(BCrypt) / Android(JCA) / iOS(SecKey)。
 * 每个平台提供 license_auth_impl.c 实现 4 个函数; 消息构建/解析/分级
 * 逻辑在 license_auth_common.c (纯 C, 跨平台字节级一致)。
 *
 * 依赖: 公钥 (DER SPKI, vmenc.py keygen --blob-out-der 导出)。
 */
#ifndef LICENSE_AUTH_H
#define LICENSE_AUTH_H

#include <stddef.h>
#include <stdint.h>

/* 产品标识 (与 vmenc.LICENSE_PRODUCT / Windows PROT_LICENSE_PRODUCT 一致) */
#define PROT_PRODUCT "PROT-DEMO-2026"

/* 分级授权 tier */
#define PROT_TIER_TRIAL   0
#define PROT_TIER_FULL    1
#define PROT_TIER_PREMIUM 2

/*
 * 构建签名载荷: serial || LE64(machine_id) || PRODUCT || tier(1B) || expires(LE32)。
 * 与 vmenc.license_message / Windows prot_license_build_message 字节级一致。
 * 返回载荷长度; 失败 (buf 太小) 返回 0。
 */
size_t prot_auth_build_message(const char* serial,
                               uint64_t machine_id,
                               uint32_t tier,
                               uint32_t expires,
                               uint8_t* out_buf, size_t out_cap);

/*
 * 验签 (RSA-3072 + PKCS1 v1.5 + SHA-256)。
 *   msg     : prot_auth_build_message 的输出
 *   msg_len : 载荷长度
 *   sig     : 384 字节 RSA 签名
 * 返回 1 有效; 0 无效/内部失败 (不泄漏原因)。
 */
int prot_auth_verify(const uint8_t* msg, size_t msg_len,
                     const uint8_t* sig, size_t sig_len);

/* 解析 license.txt 行 (跨平台, 供各平台适配器复用) */
void prot_auth_strip_crlf(char* s);

#endif /* LICENSE_AUTH_H */