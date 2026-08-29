/*
 * vm_rekey.c — S2 (2026-08-29): 运行时密钥多样性
 * 装载后镜像差分流重编码: cc'[i] = cc[i] ^ B(key) ^ B(new)
 * 新密钥解密得同一明文 -> CRC/语义不受影响, blob 文件与签名不变.
 */
#include <stdint.h>

#include "protect/protdef.h"
#include "protect/vm.h"

prot_status prot_vm_rekey(prot_vm_image* img, uint64_t new_key)
{
    uint64_t a, b;
    uint8_t* code;
    uint32_t i;
    if (img == NULL || img->code == NULL || img->code_len == 0u)
        return PROT_ERR_INVALID_ARG;
    if (new_key == 0u)
        new_key = 1u;
    code = (uint8_t*)(uintptr_t)img->code;
    a = img->key[0];
    b = new_key;
    for (i = 0u; i < img->code_len; i++) {
        a = a * PROT_KS_MUL + PROT_KS_ADD;
        b = b * PROT_KS_MUL + PROT_KS_ADD;
        code[i] ^= (uint8_t)(a >> 56) ^ (uint8_t)(b >> 56);
    }
    img->key[0] = new_key;
    return PROT_OK;
}
