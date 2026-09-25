/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 ShardVase contributors
 *
 * 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；
 * 商业授权见 LICENSE.md。
 */
/*
 * prot_crypto_win.c — 密码学抽象层（Windows / BCrypt 实现）
 *
 * ## 来源
 *   本文件是 `src/license.c` 中 `sha256_digest()` 与
 *   `prot_license_verify()` 的**原 BCrypt 代码**——
 *   L2（2026-09-23）**逐字迁移**到本层，使 `license.c`
 *   得以摆脱平台依赖。
 *
 * ## 为什么"逐字迁移"很重要
 *   授权链有 **14 条 drill**，且验签失败会直接影响授权判定。
 *   重写密码学调用 = 引入真实风险。故此处**不改逻辑**，
 *   只把代码从 `license.c` **搬到**平台层，并换成接口签名：
 *     · 返回值语义保持一致（1=通过 / 0=失败）
 *     · 错误路径保持一致（任何一步失败都返回 0）
 *   => 行为**逐字等价**（已实测: 门禁全绿 + 可复现性保持）
 *
 * ## 公钥 blob 的编码
 *   `pub` 参数直接传给 `BCryptImportKeyPair` 的
 *   `BCRYPT_RSAPUBLIC_BLOB` —— 故 Windows 下调用方传入的就是
 *   原来的 `g_prot_license_pubblob`（**未改变编码**）。
 *   其它平台实现可要求不同编码 —— 故接口把它当作**不透明 blob**。
 */

#include "protect/prot_crypto.h"
#include "protect/prot_platform.h"

#if PROT_PLATFORM == PROT_PLATFORM_WINDOWS

#include <windows.h>
#include <bcrypt.h>
#include <string.h>

int prot_crypto_sha256(const uint8_t* data, size_t len,
                       uint8_t out[PROT_SHA256_DIGEST_LEN])
{
    BCRYPT_ALG_HANDLE halg = NULL;
    BCRYPT_HASH_HANDLE hhash = NULL;
    int rc = 0;

    if (out == NULL)
        return 0;
    if (BCryptOpenAlgorithmProvider(&halg, BCRYPT_SHA256_ALGORITHM,
                                    NULL, 0) != 0)
        goto done;
    if (BCryptCreateHash(halg, &hhash, NULL, 0, NULL, 0, 0) != 0)
        goto done;
    if (BCryptHashData(hhash, (PUCHAR)data, (ULONG)len, 0) != 0)
        goto done;
    if (BCryptFinishHash(hhash, out, PROT_SHA256_DIGEST_LEN, 0) != 0)
        goto done;
    rc = 1;
done:
    if (hhash)
        BCryptDestroyHash(hhash);
    if (halg)
        BCryptCloseAlgorithmProvider(halg, 0);
    return rc;
}

int prot_crypto_rsa_verify_sha256(const void* pub, size_t pub_len,
                                  const uint8_t* msg, size_t msg_len,
                                  const uint8_t* sig, size_t sig_len)
{
    BCRYPT_ALG_HANDLE halg = NULL;
    BCRYPT_KEY_HANDLE hkey = NULL;
    BCRYPT_PKCS1_PADDING_INFO pad = { BCRYPT_SHA256_ALGORITHM };
    uint8_t digest[PROT_SHA256_DIGEST_LEN] = {0};
    int rc = 0;
    NTSTATUS st;

    if (pub == NULL || pub_len == 0u)
        return 0;
    if (msg == NULL || msg_len == 0u || sig == NULL || sig_len != PROT_SIG_LEN)
        return 0;
    if (!prot_crypto_sha256(msg, msg_len, digest))
        return 0;

    if (BCryptOpenAlgorithmProvider(&halg, BCRYPT_RSA_ALGORITHM,
                                    NULL, 0) != 0)
        goto done;
    st = BCryptImportKeyPair(halg, NULL, BCRYPT_RSAPUBLIC_BLOB, &hkey,
                             (PUCHAR)(uintptr_t)pub, (ULONG)pub_len, 0);
    if (st != 0)
        goto done;
    st = BCryptVerifySignature(hkey, &pad, digest, PROT_SHA256_DIGEST_LEN,
                               (PUCHAR)(uintptr_t)sig, (ULONG)sig_len,
                               BCRYPT_PAD_PKCS1);
    rc = (st == 0);     /* STATUS_SUCCESS -> 验签通过 */
done:
    if (hkey)
        BCryptDestroyKey(hkey);
    if (halg)
        BCryptCloseAlgorithmProvider(halg, 0);
    return rc;
}

uint32_t prot_crypto_capabilities(void)
{
    return PROT_CRYPTO_HAS_SHA256 | PROT_CRYPTO_HAS_RSA;
}

#endif /* PROT_PLATFORM_WINDOWS */
