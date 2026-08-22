/*
 * selfcrypt.c — 运行时自变形解密例程 (N1, 阶段 0 原型, D2a)
 *
 * 方案 B (原位加密, 阶段 0 结论):
 *   - .text 原位: 目标函数体构建期 XOR 加密 (不搬移, 无跳板) ——
 *     函数内相对 call/jmp (E8/E9 rel32) 不受影响 (方案 C 搬移证伪);
 *   - .protcrypt 专用节 (.protcry): 只存 meta [count][rva,len,key...];
 *   - 运行期 prot_selfcrypt_init 定位 .text 目标段, VirtualProtect RW
 *     -> 原位解密 -> FlushInstructionCache -> 还原 RX (不执行则保持)。
 *
 * 完整性 (D1b): .text CRC 对目标段掩码 (hashpatch.py + integrity.c),
 * 加密态(文件)与解密态(运行)该段不参与 CRC; 解密态 CRC 校验留待阶段 2。
 * 降级开关 PROT_SELFCRYPT_DISABLE: init 空转 (构建期不加密)。
 *
 * 注意: 本函数自身不得被加密 (它是解密桩的目标)。
 */
#include "protect/selfcrypt.h"

#include <windows.h>
#include <string.h>

#ifdef PROT_SELFCRYPT_DISABLE

prot_status prot_selfcrypt_init(void)
{
    return PROT_OK; /* 降级: 函数体在 .text 原位直接运行 */
}

#else

prot_status prot_selfcrypt_init(void)
{
    uint8_t* blob = g_prot_selfcrypt_blob;
    HMODULE hmod = GetModuleHandleW(NULL);
    uint8_t* base = (uint8_t*)hmod;
    uint32_t n;
    DWORD oldp = 0u;
    uint32_t i;

    if (hmod == NULL || g_prot_selfcrypt_blob_size < 4u)
        return PROT_OK;
    memcpy(&n, blob, 4u);
    if (n == 0u || n > 4u)
        return PROT_OK; /* 未加密构建 (构建脚本未运行) -> 跳过 */

    {
        uint8_t* first = base + *(const uint32_t*)(blob + 4u);
        uint32_t last_len = *(const uint32_t*)(blob + 4u + (n - 1u) * 16u + 4u);
        uint8_t* last = base + *(const uint32_t*)(blob + 4u + (n - 1u) * 16u);
        SIZE_T span = (SIZE_T)((last + last_len) - first);

        if (!VirtualProtect((LPVOID)first, span, PAGE_READWRITE, &oldp))
            return PROT_ERR_INTERNAL;

        for (i = 0u; i < n; i++) {
            const uint8_t* e = blob + 4u + i * 16u;
            uint32_t rva, len;
            uint64_t k;
            uint8_t* dst;
            uint32_t j;
            memcpy(&rva, e, 4u);
            memcpy(&len, e + 4u, 4u);
            memcpy(&k, e + 8u, 8u);
            dst = base + rva;
            for (j = 0u; j < len; j++) {
                k = k * PROT_KS_MUL + PROT_KS_ADD;
                dst[j] = (uint8_t)(dst[j] ^ (uint8_t)(k >> 56));
            }
        }

        FlushInstructionCache(GetCurrentProcess(), (LPCVOID)first, span);
        VirtualProtect((LPVOID)first, span, PAGE_EXECUTE_READ, &oldp);
    }
    return PROT_OK;
}

#endif /* PROT_SELFCRYPT_DISABLE */
