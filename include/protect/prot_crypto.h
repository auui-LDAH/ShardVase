/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 ShardVase contributors
 *
 * 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；
 * 商业授权见 LICENSE.md。
 */
/*
 * prot_crypto.h — 密码学抽象层（L2）
 *
 * ## 为什么需要（L2 目标）
 *   `src/license.c`（**授权链**，14 条 drill）此前**直接调用 BCrypt**
 *   （Windows CNG）做 SHA-256 与 RSA 验签 -> 整个授权链**不可移植**。
 *
 *   但密码学**本身是纯算法** —— SHA-256 与 RSA PKCS#1 v1.5 验签
 *   在任何平台都有等价实现（OpenSSL / mbedTLS / 内置）。
 *   故把平台差异**限制在本层**:
 *     · `license.c` -> 只做**消息构造与流程**（纯逻辑，可移植）
 *     · 本层       -> 只做**密码学原语**（平台实现）
 *
 * ## 设计原则
 *   · 本接口**只暴露算法语义**，不暴露平台类型
 *     （不用 `BCRYPT_*` / `NTSTATUS` / `PUCHAR`）
 *   · 公钥以**不透明 blob + 长度**传入 —— 具体编码由实现决定
 *     （Windows 用 `BCRYPT_RSAPUBLIC_BLOB`；其它平台可换标准格式）
 *   · 所有函数**不抛出、不 longjmp**，用返回值表达成败
 *
 * ## 诚实边界
 *   · 本层**只覆盖授权链实际用到的两个原语**（SHA-256 / RSA 验签）
 *   · 未接入其它算法（对称加密、KDF 等仍各自为政）
 *   · **不改变任何现有行为** —— Windows 实现委托到原来的 BCrypt 调用
 */

#ifndef PROT_CRYPTO_H
#define PROT_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ *
 * 摘要
 * ------------------------------------------------------------------ */

#define PROT_SHA256_DIGEST_LEN 32

/* 计算 SHA-256 摘要。
 *
 * 成功返回 1，失败返回 0。**失败不泄漏原因**（与验签路径的约定一致）。
 */
int prot_crypto_sha256(const uint8_t* data, size_t len,
                       uint8_t out[PROT_SHA256_DIGEST_LEN]);

/* ------------------------------------------------------------------ *
 * RSA 验签（PKCS#1 v1.5 + SHA-256）
 * ------------------------------------------------------------------ */

/* 授权签名长度（RSA-3072 = 384 字节）。**协议常量，非平台相关**。 */
#define PROT_SIG_LEN 384u

/* 用公钥验证 RSA 签名（PKCS#1 v1.5 填充 + SHA-256 摘要）。
 *
 * ## 参数
 *   pub / pub_len   公钥 blob（**不透明**，编码由实现决定）
 *   msg / msg_len   被签名的消息（**原始消息，非摘要**）
 *   sig / sig_len   签名（`sig_len` 必须 == `PROT_SIG_LEN`）
 *
 * ## 返回
 *   1 = 验签通过；0 = 验签失败（**含任何内部错误**，不区分原因）
 *
 * ## 为什么把"错误"与"验签失败"都返回 0
 *   授权验证路径**不应向调用方**（乃至攻击者）泄漏"是格式错还是签名错"
 *   —— 这会成为 oracle。故统一返回 0。
 */
int prot_crypto_rsa_verify_sha256(const void* pub, size_t pub_len,
                                  const uint8_t* msg, size_t msg_len,
                                  const uint8_t* sig, size_t sig_len);

/* ------------------------------------------------------------------ *
 * 能力查询
 * ------------------------------------------------------------------ */

#define PROT_CRYPTO_HAS_SHA256  (1u << 0)
#define PROT_CRYPTO_HAS_RSA     (1u << 1)

/* 本平台密码学实现支持的能力（返回 PROT_CRYPTO_HAS_* 的位或）。 */
uint32_t prot_crypto_capabilities(void);

/* ------------------------------------------------------------------ *
 * 实现约定
 *
 * Windows: src/platform/prot_crypto_win.c（BCrypt / CNG）
 * 其它平台: **未实现** —— 见 docs/PORTABILITY_ASSESSMENT.md §6
 * ------------------------------------------------------------------ */

#ifdef __cplusplus
}
#endif

#endif /* PROT_CRYPTO_H */
