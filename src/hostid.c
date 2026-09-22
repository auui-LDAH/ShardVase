/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 ShardVase contributors
 *
 * 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；
 * 商业授权见 LICENSE.md。
 */
/*
 * hostid.c — 机器标识 (Phase 4: 真实硬件绑定, D5 硬件因子增强)
 *
 * prot_hostid_get: 多因子 FNV-1a (64 位) 折叠:
 *   1) 系统盘卷序列号 (GetVolumeInformationW C:\)
 *   2) 计算机名 (GetComputerNameW)
 *   3) MachineGuid (HKLM\SOFTWARE\Microsoft\Cryptography)       [D5]
 *   4) 系统盘物理序列号 (IOCTL_STORAGE_QUERY_PROPERTY)           [D5]
 *   5) 最终 32 位高低折叠
 * 算法与 tools/vmenc.py 的 hostid() 完全一致 (docstring 标注), 保证构建期
 * genserial 烧录的 EXPECT 与运行期 demo 读取的 machine_id 对得上。
 * 任何一侧改动必须同步, 否则构建期校验结果与运行期不符。
 * 注意: 因子 3/4 属机器标识, 换机/换盘/重装会变化 (COMPAT §5)。
 */

#include <windows.h>
#include <winioctl.h>

#include <stdlib.h>
#include <string.h>

#include "protect/hostid.h"

/* FNV-1a 64 位常量 */
#define HOSTID_FNV_BASIS 0xCBF29CE484222325u
#define HOSTID_FNV_PRIME 0x100000001B3u

/* MachineGuid: HKLM\SOFTWARE\Microsoft\Cryptography (Windows 安装唯一 ID).
 * 克隆 VM 时通常不同 (由虚拟化平台分配), 是防克隆的有效因子之一。 */
static int machine_guid(char out[64])
{
    HKEY key = NULL;
    WCHAR wbuf[64];
    DWORD sz = sizeof(wbuf); /* REG_SZ 是 UTF-16, 需宽字符缓冲 */
    DWORD type = 0;
    LONG st;

    st = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                       L"SOFTWARE\\Microsoft\\Cryptography", 0,
                       KEY_READ | KEY_WOW64_64KEY, &key);
    if (st != ERROR_SUCCESS)
        return 0;
    st = RegQueryValueExW(key, L"MachineGuid", NULL, &type,
                          (LPBYTE)wbuf, &sz);
    RegCloseKey(key);
    if (st != ERROR_SUCCESS || type != REG_SZ)
        return 0;
    /* 宽字符转 ASCII (guid 是 ASCII 字符集) */
    if (WideCharToMultiByte(CP_ACP, 0, wbuf, -1, out, 64, NULL, NULL) == 0)
        return 0;
    return (out[0] != '\0');
}

/* 系统盘物理序列号: \\.\PhysicalDrive0 + IOCTL_STORAGE_QUERY_PROPERTY */
static int disk_serial(char out[64])
{
    HANDLE h;
    STORAGE_PROPERTY_QUERY q;
    char buf[1024];
    DWORD ret = 0u;
    int found = 0;

    memset(&q, 0, sizeof(q));
    q.PropertyId = StorageDeviceProperty;
    q.QueryType = PropertyStandardQuery;
    h = CreateFileW(L"\\\\.\\PhysicalDrive0", 0,
                    FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return 0;
    if (DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY, &q, sizeof(q),
                        buf, sizeof(buf), &ret, NULL)) {
        STORAGE_DEVICE_DESCRIPTOR* d = (STORAGE_DEVICE_DESCRIPTOR*)buf;
        if (d->SerialNumberOffset > 0u &&
            d->SerialNumberOffset + 1u < sizeof(buf)) {
            strncpy_s(out, 64, (const char*)buf + d->SerialNumberOffset, _TRUNCATE);
            found = 1;
        }
    }
    CloseHandle(h);
    return found;
}

uint64_t prot_hostid_get(void) {
    uint64_t h = HOSTID_FNV_BASIS;
    WCHAR comp[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD n;
    DWORD vol_serial;
    DWORD max_len;
    DWORD fs_flags;
    char guid[64];
    char dserial[64];
    uint32_t i;

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
        for (i = 0; i < n; i++) {
            h ^= (uint64_t)(uint16_t)comp[i];
            h *= HOSTID_FNV_PRIME;
        }
    }

    /* D5: MachineGuid (Windows 安装唯一 ID) */
    if (machine_guid(guid)) {
        for (i = 0; guid[i] != '\0'; i++) {
            h ^= (uint64_t)(uint8_t)guid[i];
            h *= HOSTID_FNV_PRIME;
        }
    }

    /* D5: 系统盘物理序列号 (ASCII) */
    if (disk_serial(dserial)) {
        for (i = 0; dserial[i] != '\0'; i++) {
            h ^= (uint64_t)(uint8_t)dserial[i];
            h *= HOSTID_FNV_PRIME;
        }
    }

    h ^= h >> 32; /* 高位与低位折叠, 保持两侧一致 */
    return h;
}
