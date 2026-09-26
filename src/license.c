/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 ShardVase contributors
 *
 * 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；
 * 商业授权见 LICENSE.md。
 */
/*
 * license.c — RSA 授权验签 (A1)
 *
 * 只做验签 (公钥), 不做任何私钥操作。验签路径:
 *   prot_license_build_message (本文件, **纯逻辑**)
 *     -> prot_crypto_sha256 + prot_crypto_rsa_verify_sha256 (密码学层)
 * 任何一步失败都返回 0 (验签失败), 不泄漏原因给调用方。
 *
 * ## L2（2026-09-23）: 密码学已抽出到独立层
 *   **改动前**: 本文件**直接调用 BCrypt**（Windows CNG）做 SHA-256 与
 *   RSA 验签 -> 整个授权链**不可移植**。
 *
 *   **改动后**:
 *     · `prot_license_build_message` —— **消息构造，纯逻辑**（无平台依赖）
 *     · `prot_license_verify`        —— **流程编排**（调密码学层，无 BCrypt）
 *     · 密码学原语 -> `protect/prot_crypto.h`（平台层实现）
 *
 *   => 本文件**不再含任何平台 API / 平台类型**，
 *      跨平台时**无需改动**（只需实现密码学层）。
 *
 *   **行为等价性**: BCrypt 调用**逐字迁移**到
 *   `src/platform/prot_crypto_win.c`，返回值语义与错误路径完全一致
 *   （已实测: 门禁全绿 + 可复现性保持）。
 *
 * 公钥来自 tools/vmenc.py keygen 生成的 g_prot_license_pubblob
 * (BCRYPT_RSAPUBLIC_BLOB, 嵌入二进制)。
 */

#include "protect/license.h"
#include "protect/prot_crypto.h"    /* L2: 密码学抽象层 */
#include "protect/prot_noise.h"   /* W1.6 序言噪声 */

#include <string.h>       /* memcpy */

size_t prot_license_build_message(const char* serial, size_t serial_len,
                                  uint64_t machine_id, uint32_t tier,
                                  uint32_t expires,
                                  uint8_t* out_msg, size_t out_cap)
{
    PROT_NOISE();   /* W1.6 序言噪声 */
    size_t plen = serial_len + 8u + sizeof(PROT_LICENSE_PRODUCT) - 1u + 1u + 4u;
    size_t i;
    if (out_msg == NULL || out_cap < plen)
        return 0u;
    memcpy(out_msg, serial, serial_len);
    for (i = 0u; i < 8u; i++)
        out_msg[serial_len + i] = (uint8_t)(machine_id >> (8u * i));
    memcpy(out_msg + serial_len + 8u, PROT_LICENSE_PRODUCT,
           sizeof(PROT_LICENSE_PRODUCT) - 1u);
    out_msg[serial_len + 8u + sizeof(PROT_LICENSE_PRODUCT) - 1u] =
        (uint8_t)(tier & 0xFFu); /* tier 参与签名 */
    for (i = 0u; i < 4u; i++)    /* expires (LE32) 参与签名 */
        out_msg[plen - 4u + i] = (uint8_t)(expires >> (8u * i));
    return plen;
}

int prot_license_verify(const uint8_t* msg, size_t msg_len,
                        const uint8_t* sig, size_t sig_len)
{
    PROT_NOISE();   /* W1.6 序言噪声 */

    /* L2: 平台检查 + 密码学调用都交给抽象层（本文件不再含 BCrypt）。
     *
     * ⚠️ **L6b（2026-09-25）修正: 去掉 `g_prot_license_pubblob == NULL`**
     *
     *   `g_prot_license_pubblob` 声明为**数组**
     *   （`extern const uint8_t g_prot_license_pubblob[]`）
     *   -> 数组名**永不为 NULL** -> 该比较**恒假**（死代码）。
     *
     *   **GCC 的 `-Waddress` 抓到了**（`the comparison will always
     *   evaluate as 'false'`），而 **MSVC 不报** ——
     *   若不是做 Linux 移植，这段死代码会一直留着。
     *
     *   **正确判据是长度**（长度 0 才表示"无公钥"）。
     */
    if (g_prot_license_pubblob_len == 0u)
        return 0;
    if (msg == NULL || msg_len == 0u || sig == NULL || sig_len != PROT_SIG_LEN)
        return 0;

    return prot_crypto_rsa_verify_sha256(
        (const void*)(uintptr_t)g_prot_license_pubblob,
        (size_t)g_prot_license_pubblob_len,
        msg, msg_len, sig, sig_len);
}