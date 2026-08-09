/*
 * strcrypt.h — 字符串加密: 明文只在二进制中以密文存在
 *
 * 明文由 tools/strgen.py 加密为字节数组, 运行时用滚动密钥流解密。
 * 防止攻击者直接搜索关键字符串 (如提示语、错误信息)。
 */
#ifndef PROT_STRCRYPT_H
#define PROT_STRCRYPT_H

#include "protect/protdef.h"

typedef enum prot_str_id {
    PROT_STR_BANNER = 0,
    PROT_STR_PROMPT_SERIAL,
    PROT_STR_MSG_OK,
    PROT_STR_MSG_FAIL,
    PROT_STR_MSG_DBG,
    PROT_STR_MSG_TAMPER,
    PROT_STR_MSG_HWID,
    PROT_STR_COUNT
} prot_str_id;

/* 取解密后的字符串 (内部静态缓冲; id 非法返回 NULL) */
const char* prot_str_get(prot_str_id id);

/*
 * 底层解密助手: enc[0..len) 用滚动密钥流解密到 out, out[len] = 0。
 * 密钥流: k = k * PROT_KS_MUL + PROT_KS_ADD (uint64 回绕);
 *         每字节输出 (k >> 56) & 0xFF; 加密/解密同式。
 */
void prot_str_decrypt(const uint8_t* enc, uint32_t len, uint64_t key, char* out);

#endif /* PROT_STRCRYPT_H */