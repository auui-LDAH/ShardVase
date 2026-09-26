/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 ShardVase contributors
 *
 * 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；
 * 商业授权见 LICENSE.md。
 */
/*
 * prot_crypto_linux.c — 密码学层的 **Linux/OpenSSL 实现**（B1，2026-09-25）
 *
 * ## 对应关系
 *   本文件是 `src/platform/prot_crypto_win.c`（BCrypt 实现）的**平台对等物**。
 *   两者实现**同一份接口**（`include/protect/prot_crypto.h`）:
 *     · `prot_crypto_sha256`            -> int（1 成功 / 0 失败）
 *     · `prot_crypto_rsa_verify_sha256` -> int（1 通过 / 0 失败）
 *     · `prot_crypto_capabilities`      -> 能力位
 *
 *   **返回值约定（契约"实现约定"）**:
 *     失败**不泄漏原因** —— 不区分"格式错"与"签名错"（防 oracle）。
 *     => 本实现严格遵循：所有失败路径**统一返回 0**。
 *
 * ## 公钥格式的**关键差异**（AG5 发现，M1 阶段）
 *   | 平台 | 格式 | 生成者 |
 *   |------|------|--------|
 *   | Windows | `BCRYPT_RSAPUBLIC_BLOB`（`"RSA1"` + BitLength + exp/mod）| `demo/gen/license_pubkey.c` |
 *   | **Linux** | **DER / SPKI**（X.509 SubjectPublicKeyInfo）| **`demo/gen/prot_pubkey_der.c`** |
 *
 *   **`tools/vmenc.py` 已同时生成两者**（`rsa_pub_spki_der()`）——
 *   故 Linux 侧**无需新工具**，直接用现成 DER 即可。
 *
 * ## 为什么用 EVP 高层接口
 *   OpenSSL **3.0 弃用了大量低层 API**（`RSA_*` / `SHA256_Init` 等）——
 *   用它们产生 `-Wdeprecated-declarations` 警告，
 *   而本项目用 **`-Werror`** -> **编译失败**。
 *   => 用 **EVP_PKEY / EVP_DigestVerify**（OpenSSL 3.0 推荐路径）。
 *
 * ## 诚实边界
 *   · 依赖 **libcrypto**（构建 `-lcrypto`；运行需 `libcrypto.so.3`）
 *   · **只验签不签名**（与 Windows 侧一致 —— 签名在构建期用私钥完成）
 *   · 若目标环境无 OpenSSL -> 需换 mbedTLS 或自实现（**本阶段未做**）
 */

#include "protect/prot_crypto.h"

#include <string.h>

#include <openssl/evp.h>
#include <openssl/x509.h>

/* ------------------------------------------------------------------ *
 * SHA-256
 * ------------------------------------------------------------------ */
int prot_crypto_sha256(const uint8_t* data, size_t len,
                       uint8_t out[PROT_SHA256_DIGEST_LEN])
{
    unsigned int out_len = 0u;

    if (out == NULL)
        return 0;
    if (data == NULL && len != 0u)
        return 0;

    /* ## 为什么用 `EVP_Digest`（一次性接口）
     *   内部完成 init/update/final，**无状态** -> 线程安全
     *   （每次调用用独立的内部 ctx）。
     *   与 Windows 侧的 `BCryptHashData` 一次性调用**语义对应**。
     */
    if (EVP_Digest(data, len, out, &out_len, EVP_sha256(), NULL) != 1)
        return 0;

    /* SHA-256 固定 32 字节 —— 不符说明库异常 */
    if (out_len != PROT_SHA256_DIGEST_LEN)
        return 0;

    return 1;
}

/* ------------------------------------------------------------------ *
 * RSA 验签（PKCS#1 v1.5 + SHA-256）
 * ------------------------------------------------------------------ */
int prot_crypto_rsa_verify_sha256(const void* pub, size_t pub_len,
                                  const uint8_t* msg, size_t msg_len,
                                  const uint8_t* sig, size_t sig_len)
{
    const unsigned char* der = (const unsigned char*)pub;
    EVP_PKEY* pkey;
    EVP_MD_CTX* ctx;
    int rc;

    /* ## 参数预检（**统一返回 0**，不泄漏原因）
     *   签名长度必须 == PROT_SIG_LEN（RSA-3072 = 384 字节）——
     *   不符则**直接失败**，不进 OpenSSL（与 Windows 侧预检一致）。
     */
    if (pub == NULL || msg == NULL || sig == NULL)
        return 0;
    if (sig_len != PROT_SIG_LEN)
        return 0;

    /* DER/SPKI -> EVP_PKEY。
     *
     * ## 与 Windows 的格式差异（**如实标注**）
     *   Windows 的 blob 是**裸的 (exp, mod)** + 头部；
     *   DER/SPKI 是**自描述结构**（含算法 OID）。
     *   两者由 `vmenc.py` 从**同一把 RSA 私钥**导出 -> **数学上等价**。
     */
    pkey = d2i_PUBKEY(NULL, &der, (long)pub_len);
    if (pkey == NULL)
        return 0;

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        EVP_PKEY_free(pkey);
        return 0;
    }

    /* ## 为什么 `EVP_DigestVerifyInit` 默认就是 PKCS#1 v1.5
     *   `EVP_DigestVerify*` 对 RSA 的**默认 padding 就是 PKCS#1 v1.5**
     *   （PSS 需显式 `EVP_PKEY_CTX_set_rsa_padding(RSA_PKCS1_PSS_PADDING)`）。
     *   本项目与 Windows 侧的约定也是 v1.5（见 license.c 注释）
     *   -> **无需显式设置**，保持与 Windows 行为一致。
     *
     *   `EVP_DigestVerify` 接受**原始消息**（内部自己做摘要）——
     *   与接口契约"msg 是原始消息，非摘要"**一致**。
     */
    rc = EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey);
    if (rc == 1)
        rc = EVP_DigestVerify(ctx, sig, sig_len, msg, msg_len);

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    /* 契约: 只有 1 表示"通过"；0 与负数（库错误）**统一返回 0** */
    return (rc == 1) ? 1 : 0;
}

/* ------------------------------------------------------------------ *
 * 能力查询
 * ------------------------------------------------------------------ */
uint32_t prot_crypto_capabilities(void)
{
    /* OpenSSL 提供 SHA-256 与 RSA 验签 -> 两项能力都有。
     *
     * ## 为什么不用编译期探测
     *   本项目**明确依赖 libcrypto**（构建时 `-lcrypto`）——
     *   若库缺失则**链接失败**（构建期即暴露），
     *   故运行期无需再探测。返回常量是**准确的**（非乐观假设）。
     */
    return PROT_CRYPTO_HAS_SHA256 | PROT_CRYPTO_HAS_RSA;
}
