/*
 * blob.c — VM 镜像 blob 装载器 (DBI launcher, 技术债 #3)
 *
 * 对应契约 docs/CONTRACT.md §4.4。启动时装载构建期打包的 vm.blob:
 *   - 校验 MAGIC "PROTVMBL" / COUNT / 尾部 BLOB_CRC (prot_crc32, 覆盖
 *     全部头部与密文, 防篡改)。
 *   - 按 name 抽出所需镜像, 填充 prot_vm_image (code 指向装载缓冲内
 *     的密文, 不拷贝)。
 *   - 装载缓冲是密文; VM 解释器仍按活动窗口解密 + 用后即焚, 明文
 *     语义不变。
 * 失败路径: 文件缺失 -> PROT_ERR_BLOB_MISSING; magic/CRC/长度不符 ->
 * PROT_ERR_BLOB_CORRUPT; 缺名字 -> PROT_ERR_BLOB_NAME。不泄漏内部状态。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "protect/blob.h"
#include "protect/license.h"
#include "protect/protdef.h"

#define PROT_BLOB_MAGIC_LEN 8u
#define PROT_BLOB_NAME_LEN  16u
#define PROT_BLOB_HEADER    (PROT_BLOB_MAGIC_LEN + 4u)
#define PROT_BLOB_ENTRY_HDR 40u /* NAME16 + CODE_LEN4 + KEY0_8 + KEY1_8 + CRC4 */

/* BLOB_SIGN_PLAN: v1 签名 blob (MAGIC "PROTVMB1")。
 * 布局: MAGIC8 | COUNT4 | entries | SIG_LEN4 | SIG(256B) | BLOB_CRC4 */
#define PROT_BLOB_MAGIC_V1  "PROTVMB1"
#define PROT_BLOB_SIG_LEN   384u

/* N 加固: "PROTVMBL" 不以连续字符串出现 —— 拆成两个 u32 (LE) 比较。
 * 生成侧 (vmenc.py pack) 仍写原始字节, 加载器按整数逐段校验。
 * v1 判定: 前 8 字节 == "PROTVMB1" (与 v0 首 7 字节相同, 第 8 字节 1 vs L)。 */
static int blob_magic_ok(const uint8_t* p, uint32_t* is_v1)
{
    /* "PROTVMB1" = 'P','R','O','T','V','M','B','1' */
    static const uint8_t m1[8] = { 'P', 'R', 'O', 'T', 'V', 'M', 'B', '1' };
    static const uint8_t m0[8] = { 'P', 'R', 'O', 'T', 'V', 'M', 'B', 'L' };
    uint32_t lo, hi;
    memcpy(&lo, p, 4);
    memcpy(&hi, p + 4, 4);
    if (memcmp(p, m1, 8) == 0) {
        *is_v1 = 1u;
        return 1;
    }
    if (memcmp(p, m0, 8) == 0) {
        *is_v1 = 0u;
        return 1;
    }
    (void)lo;
    (void)hi;
    return 0;
}

static uint32_t blob_u32(const uint8_t* p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t blob_u64(const uint8_t* p)
{
    uint64_t v = 0u;
    uint32_t i;
    for (i = 0u; i < 8u; i++)
        v |= (uint64_t)p[i] << (8u * i);
    return v;
}

prot_status prot_vm_blob_load(const char* path,
                              const char* const* names, uint32_t name_count,
                              prot_vm_image* out,
                              void** out_buf, size_t* out_buf_size)
{
    FILE* f;
    long fsz;
    uint8_t* buf = NULL;
    size_t size;
    uint32_t count, i, j;
    size_t pos;
    uint32_t crc;
    uint32_t got = 0u;

    if (out_buf != NULL)
        *out_buf = NULL;
    if (out_buf_size != NULL)
        *out_buf_size = 0u;
    if (path == NULL || names == NULL || name_count == 0u || out == NULL)
        return PROT_ERR_INVALID_ARG;

    if (fopen_s(&f, path, "rb") != 0 || f == NULL)
        return PROT_ERR_BLOB_MISSING;
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return PROT_ERR_BLOB_CORRUPT;
    }
    fsz = ftell(f);
    if (fsz <= 0 || fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return PROT_ERR_BLOB_CORRUPT;
    }
    size = (size_t)fsz;

    buf = (uint8_t*)malloc(size);
    if (buf == NULL) {
        fclose(f);
        return PROT_ERR_BLOB_CORRUPT;
    }
    if (fread(buf, 1, size, f) != size) {
        fclose(f);
        free(buf);
        return PROT_ERR_BLOB_CORRUPT;
    }
    fclose(f);

    if (size < PROT_BLOB_HEADER + 4u) {
        free(buf);
        return PROT_ERR_BLOB_CORRUPT;
    }
    {
        uint32_t is_v1 = 0u;
        if (!blob_magic_ok(buf, &is_v1)) {
            free(buf);
            return PROT_ERR_BLOB_CORRUPT;
        }
        /* BLOB_SIGN_PLAN (D1a): 强制 v1 —— v0 (未签名) 直接拒绝 */
        if (!is_v1) {
            free(buf);
            return PROT_ERR_BLOB_CORRUPT;
        }
    }
    count = blob_u32(buf + PROT_BLOB_MAGIC_LEN);
    if (count == 0u || count > 64u) {
        free(buf);
        return PROT_ERR_BLOB_CORRUPT;
    }

    /* 尾部 BLOB_CRC 覆盖 [0, size-4) */
    crc = prot_crc32(buf, size - 4u);
    if (crc != blob_u32(buf + size - 4u)) {
        free(buf);
        return PROT_ERR_BLOB_CORRUPT;
    }

    /* BLOB_SIGN_PLAN: v1 RSA 验签 —— 消息 = [0, sig_len_field)。
     * SIG_LEN 字段在 entries 之后 (BLOB_HEADER + sum(entry))。 */
    {
        size_t sig_off;
        uint32_t sig_len;
        size_t pos2 = PROT_BLOB_HEADER;
        for (i = 0u; i < count; i++) {
            uint32_t code_len;
            if (pos2 + PROT_BLOB_ENTRY_HDR > size - 4u) {
                free(buf);
                return PROT_ERR_BLOB_CORRUPT;
            }
            code_len = blob_u32(buf + pos2 + 16u);
            if (pos2 + PROT_BLOB_ENTRY_HDR + code_len > size - 4u) {
                free(buf);
                return PROT_ERR_BLOB_CORRUPT;
            }
            pos2 += PROT_BLOB_ENTRY_HDR + code_len;
        }
        sig_off = pos2;
        if (sig_off + 4u + PROT_BLOB_SIG_LEN > size - 4u) {
            free(buf);
            return PROT_ERR_BLOB_CORRUPT; /* 缺签名区 */
        }
        sig_len = blob_u32(buf + sig_off);
        if (sig_len != PROT_BLOB_SIG_LEN) {
            free(buf);
            return PROT_ERR_BLOB_CORRUPT;
        }
        if (!prot_license_verify(buf, sig_off, buf + sig_off + 4u,
                                 PROT_BLOB_SIG_LEN)) {
            free(buf);
            return PROT_ERR_BLOB_CORRUPT; /* 签名无效 -> 视同损坏 */
        }
    }

    pos = PROT_BLOB_HEADER;
    for (i = 0u; i < count; i++) {
        uint32_t code_len;
        uint8_t name[PROT_BLOB_NAME_LEN];
        uint32_t match = 0u;

        if (pos + PROT_BLOB_ENTRY_HDR > size - 4u) {
            free(buf);
            return PROT_ERR_BLOB_CORRUPT;
        }
        memcpy(name, buf + pos, PROT_BLOB_NAME_LEN);
        code_len = blob_u32(buf + pos + 16u);
        if (pos + PROT_BLOB_ENTRY_HDR + code_len > size - 4u) {
            free(buf);
            return PROT_ERR_BLOB_CORRUPT;
        }

        for (j = 0u; j < name_count; j++) {
            size_t nlen = strlen(names[j]);
            if (nlen == 0u || nlen >= PROT_BLOB_NAME_LEN)
                continue;
            if (memcmp(name, names[j], nlen) == 0u &&
                name[nlen] == 0u) {
                match = 1u;
                break;
            }
        }
        if (match) {
            prot_vm_image* img = &out[j];
            img->code = buf + pos + PROT_BLOB_ENTRY_HDR;
            img->code_len = code_len;
            img->key[0] = blob_u64(buf + pos + 20u);
            img->key[1] = blob_u64(buf + pos + 28u);
            img->crc = blob_u32(buf + pos + 36u);
            got |= (1u << j);
        }
        pos += PROT_BLOB_ENTRY_HDR + code_len;
    }

    if (got != ((1u << name_count) - 1u)) {
        free(buf);
        return PROT_ERR_BLOB_NAME; /* 至少一个所需镜像缺失 */
    }

    if (out_buf != NULL)
        *out_buf = buf;
    else
        free(buf);
    if (out_buf_size != NULL)
        *out_buf_size = size;
    return PROT_OK;
}
