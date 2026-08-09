/*
 * hostid.c — 机器标识 (Phase 4: 真实硬件绑定)
 *
 * prot_hostid_get: 多因子 FNV-1a (64 位) 折叠:
 *   1) 系统盘卷序列号 (GetVolumeInformationW C:\)
 *   2) 计算机名 (GetComputerNameW)
 *   3) 最终 32 位高低折叠
 * 算法与 tools/vmenc.py 的 hostid() 完全一致 (docstring 标注), 保证构建期
 * genserial 烧录的 EXPECT 与运行期 demo 读取的 machine_id 对得上。
 * 任何一侧改动必须同步, 否则构建期校验结果与运行期不符。
 */

#include <windows.h>

#include "protect/hostid.h"

/* FNV-1a 64 位常量 */
#define HOSTID_FNV_BASIS 0xCBF29CE484222325u
#define HOSTID_FNV_PRIME 0x100000001B3u

uint64_t prot_hostid_get(void) {
    uint64_t h = HOSTID_FNV_BASIS;
    WCHAR comp[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD n;
    DWORD vol_serial;
    DWORD max_len;
    DWORD fs_flags;

    vol_serial = 0u;
    max_len = 0u;
    fs_flags = 0u;
    if (GetVolumeInformationW(L"C:\\", NULL, 0, &vol_serial, &max_len, &fs_flags,
                              NULL, 0)) {
        h ^= (uint64_t)(uint32_t)vol_serial;
        h *= HOSTID_FNV_PRIME;
        h ^= (uint64_t)(uint32_t)max_len;
        h *= HOSTID_FNV_PRIME;
        h ^= (uint64_t)(uint32_t)fs_flags;
        h *= HOSTID_FNV_PRIME;
    }

    n = MAX_COMPUTERNAME_LENGTH + 1;
    if (GetComputerNameW(comp, &n)) {
        uint32_t i;
        for (i = 0; i < n; i++) {
            h ^= (uint64_t)(uint16_t)comp[i];
            h *= HOSTID_FNV_PRIME;
        }
    }

    h ^= h >> 32; /* 高位与低位折叠, 保持两侧一致 */
    return h;
}