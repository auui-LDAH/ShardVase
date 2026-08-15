/*
 * license.c — RSA 授权验签 (A1), 用 Windows CNG (BCrypt) 做标准 RSA 验签
 *
 * 只做验签 (公钥), 不做任何私钥操作。验签路径:
 *   prot_license_build_message -> SHA-256 (BCrypt) -> BCryptVerifySignature(PKCS1 v1.5)
 * 任何一步失败都返回 0 (验签失败), 不泄漏原因给调用方。
 *
 * 编译链接需 bcrypt.lib。公钥来自 tools/vmenc.py keygen 生成的
 * g_prot_license_pubblob (BCRYPT_RSAPUBLIC_BLOB, 嵌入二进制)。
 */

#include "protect/license.h"

#include <string.h>       /* memcpy */
#include <windows.h>
#include <bcrypt.h>

size_t prot_license_build_message(const char* serial, size_t serial_len,
                                  uint64_t machine_id, uint32_t tier,
                                  uint8_t* out_msg, size_t out_cap)
{
    size_t plen = serial_len + 8u + sizeof(PROT_LICENSE_PRODUCT) - 1u + 1u;
    size_t i;
    if (out_msg == NULL || out_cap < plen)
        return 0u;
    memcpy(out_msg, serial, serial_len);
    for (i = 0u; i < 8u; i++)
        out_msg[serial_len + i] = (uint8_t)(machine_id >> (8u * i));
    memcpy(out_msg + serial_len + 8u, PROT_LICENSE_PRODUCT,
           sizeof(PROT_LICENSE_PRODUCT) - 1u);
    out_msg[plen - 1u] = (uint8_t)(tier & 0xFFu); /* Phase 4: tier 参与签名 */
    return plen;
}

static int sha256_digest(const uint8_t* msg, size_t msg_len, uint8_t out[32])
{
    BCRYPT_ALG_HANDLE halg = NULL;
    BCRYPT_HASH_HANDLE hhash = NULL;
    int rc = 0;

    if (BCryptOpenAlgorithmProvider(&halg, BCRYPT_SHA256_ALGORITHM, NULL, 0) != 0)
        goto done;
    if (BCryptCreateHash(halg, &hhash, NULL, 0, NULL, 0, 0) != 0)
        goto done;
    if (BCryptHashData(hhash, (PUCHAR)msg, (ULONG)msg_len, 0) != 0)
        goto done;
    if (BCryptFinishHash(hhash, out, 32, 0) != 0)
        goto done;
    rc = 1;
done:
    if (hhash)
        BCryptDestroyHash(hhash);
    if (halg)
        BCryptCloseAlgorithmProvider(halg, 0);
    return rc;
}

int prot_license_verify(const uint8_t* msg, size_t msg_len,
                        const uint8_t* sig, size_t sig_len)
{
    BCRYPT_ALG_HANDLE halg = NULL;
    BCRYPT_KEY_HANDLE hkey = NULL;
    BCRYPT_PKCS1_PADDING_INFO pad = { BCRYPT_SHA256_ALGORITHM };
    uint8_t digest[32] = {0};
    int rc = 0;
    NTSTATUS st;

    if (g_prot_license_pubblob == NULL || g_prot_license_pubblob_len == 0u)
        return 0;
    if (msg == NULL || msg_len == 0u || sig == NULL || sig_len != 256u)
        return 0;
    if (!sha256_digest(msg, msg_len, digest))
        return 0;

    if (BCryptOpenAlgorithmProvider(&halg, BCRYPT_RSA_ALGORITHM, NULL, 0) != 0)
        goto done;
    st = BCryptImportKeyPair(halg, NULL, BCRYPT_RSAPUBLIC_BLOB, &hkey,
                             (PUCHAR)(uintptr_t)g_prot_license_pubblob,
                             (ULONG)g_prot_license_pubblob_len, 0);
    if (st != 0)
        goto done;
    st = BCryptVerifySignature(hkey, &pad, digest, 32,
                               (PUCHAR)(uintptr_t)sig, (ULONG)sig_len,
                               BCRYPT_PAD_PKCS1);
    rc = (st == 0); /* STATUS_SUCCESS -> 验签通过 */
done:
    if (hkey)
        BCryptDestroyKey(hkey);
    if (halg)
        BCryptCloseAlgorithmProvider(halg, 0);
    return rc;
}