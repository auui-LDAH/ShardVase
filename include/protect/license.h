/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 ShardVase contributors
 *
 * 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；
 * 商业授权见 LICENSE.md。
 */
/*
 * license.h — RSA 授权验签 (A1): 公钥验签, 私钥离线签发
 *
 * 定位: docs/PRODUCTION.md A1 / docs/THREATMODEL.md §4 —— 让"伪造合法校验值"
 * 从可计算函数 (FNV/xorshift) 变成 RSA 私钥才能签出 (防伪造)。私钥只存在于
 * 签发侧 (tools/vmenc.py keygen/sign, build/keys/license_priv.json, gitignore),
 * 二进制只嵌公钥 BCRYPT_RSAPUBLIC_BLOB (demo/gen/license_pubkey.c)。
 *
 * 关键判定位仍进 VM: demo 在宿主先算出 license_ok, 再由 VM#4 把它与 result
 * 逐位判定相结合 (见 demo/license_gate.vasm), 不依赖单一宿主调用点可 patch。
 */
#ifndef PROT_LICENSE_H
#define PROT_LICENSE_H

#include <stddef.h>
#include <stdint.h>

/* 产品标识, 参与签名载荷 —— 与 tools/vmenc.py LICENSE_PRODUCT 必须一致 */
#ifdef __cplusplus
extern "C" {
#endif

#define PROT_LICENSE_PRODUCT "PROT-DEMO-2026"

/* 分级授权 (Phase 4): tier 参与签名载荷, 与 vmenc.py LICENSE_TIER_* 一致 */
#define PROT_LICENSE_TIER_TRIAL   0
#define PROT_LICENSE_TIER_FULL    1
#define PROT_LICENSE_TIER_PREMIUM 2

/* 公钥 blob (BCRYPT_RSAPUBLIC_BLOB, 由 tools/vmenc.py keygen 生成) */
extern const uint8_t g_prot_license_pubblob[];
extern const size_t g_prot_license_pubblob_len;

/* ## 平台公钥选择（C 阶段，2026-09-25 —— AG5 发现的兑现）
 *
 * **问题**: `g_prot_license_pubblob` 是 **BCRYPT_RSAPUBLIC_BLOB**
 *   （Windows 专有: 魔数 + BitLength + exp/mod），
 *   而 Linux 密码学层用 **DER/SPKI**（`d2i_PUBKEY`）解析
 *   -> 收到 BCRYPT 格式必然失败 -> 验签失败
 *   -> 实测: VM blob 被判 **CORRUPT（code=11）**。
 *
 * **修法**: 按平台选公钥缓冲 —— 两者由 `vmenc.py keygen`
 *   **从同一把私钥**同时导出（数学等价）。
 *
 * **为什么编译期选**: 两者都是编译期常量数组 -> **零开销、无歧义**。
 *   密码学路径**不应有"试两种格式"的试探**（那会引入模糊语义）。
 *
 * **诚实边界**: 若只生成了一种（旧构建）-> 另一平台**链接失败**
 *   （显式失败，而非静默用错格式）。
 */
#if defined(PROT_PLATFORM) && PROT_PLATFORM == PROT_PLATFORM_WINDOWS
#  define PROT_LICENSE_PUB     g_prot_license_pubblob
#  define PROT_LICENSE_PUB_LEN g_prot_license_pubblob_len
#else
extern const uint8_t g_prot_pubkey_der[];
extern const size_t  g_prot_pubkey_der_len;
#  define PROT_LICENSE_PUB     g_prot_pubkey_der
#  define PROT_LICENSE_PUB_LEN g_prot_pubkey_der_len
#endif

/*
 * 构建签名载荷 = serial(ascii) || machine_id(LE64) || PRODUCT(ascii) || tier(1B)
 *             || expires(4B LE, unix; 0=永久)。
 * 与 tools/vmenc.py license_message 完全一致。
 */
size_t prot_license_build_message(const char* serial, size_t serial_len,
                                  uint64_t machine_id, uint32_t tier,
                                  uint32_t expires,
                                  uint8_t* out_msg, size_t out_cap);

/*
 * 验签 (RSA-3072 + PKCS#1 v1.5 + SHA-256):
 *   msg:    prot_license_build_message 的结果
 *   msg_len: 载荷长度
 *   sig:    384 字节 RSA 签名 (base64 解码后)
 * 返回 1 签名有效, 0 无效/参数错误/内部失败。
 */
int prot_license_verify(const uint8_t* msg, size_t msg_len,
                        const uint8_t* sig, size_t sig_len);


#ifdef __cplusplus
}   /* extern "C" */
#endif
#endif /* PROT_LICENSE_H */