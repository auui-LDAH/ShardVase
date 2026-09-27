/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 ShardVase contributors
 *
 * 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；
 * 商业授权见 LICENSE.md。
 */
/*
 * prot_platform_win.c — 平台抽象层（Windows 实现）
 *
 * ## 这个文件是什么（L1：跨平台缺口 #3 的接入步骤）
 *   `include/protect/prot_platform.h` 定义了平台原语的**薄接口**。
 *   本文件提供 **Windows 实现**，委托到既有 Windows API。
 *
 * ## 为什么先做 Windows 实现
 *   L1 的目标不是"移植 Linux"，而是**证明接口可用** ——
 *   把 Windows 实现接上，并让 **1-2 个模块实际改用它**。
 *   这样接口才算被验证过，而非纸面设计。
 *
 * ## 注册位置
 *   本文件在 `modules.json` 的 `primitives` 中登记为 `platform_win`
 *   （与 `crc32` / `vm_rekey` 同类 —— **基础设施，总是编译**）。
 *
 * ## 诚实边界
 *   · 仅**部分**接口有实现（见各函数注释）
 *   · 未实现的接口返回明确的失败值，**不静默**
 *   · 本文件**不改变任何现有行为** —— 它只是把既有 API 调用集中封装
 */

#include "protect/prot_platform.h"

#if PROT_PLATFORM == PROT_PLATFORM_WINDOWS

#include <windows.h>
#include <tlhelp32.h>
#include <winhttp.h>
#include "protect/prot_compiler.h"   /* B4: PROT_FOPEN_S */
#include <psapi.h>
#include <stdlib.h>   /* C3: malloc */
#include <string.h>
#include <stdio.h>

#pragma comment(lib, "psapi.lib")

/* ------------------------------------------------------------------ *
 * 分组 1: 内存页管理
 * ------------------------------------------------------------------ */

static DWORD win_prot_of(prot_page_prot p)
{
    switch (p) {
    case PROT_PAGE_READ:             return PAGE_READONLY;
    case PROT_PAGE_READWRITE:        return PAGE_READWRITE;
    case PROT_PAGE_EXECUTE:          return PAGE_EXECUTE;
    case PROT_PAGE_EXECUTE_READ:     return PAGE_EXECUTE_READ;
    case PROT_PAGE_EXECUTE_READWRITE:return PAGE_EXECUTE_READWRITE;
    default:                         return PAGE_READWRITE;
    }
}

void* prot_plat_alloc(size_t size, prot_page_prot prot)
{
    if (size == 0)
        return NULL;
    return VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE,
                        win_prot_of(prot));
}

prot_status prot_plat_protect(void* addr, size_t size, prot_page_prot prot)
{
    DWORD old = 0;
    if (addr == NULL || size == 0)
        return PROT_ERR_INVALID_ARG;
    if (!VirtualProtect(addr, size, win_prot_of(prot), &old))
        return PROT_ERR_UNSUPPORTED;
    return PROT_OK;
}

prot_status prot_plat_free(void* addr, size_t size)
{
    (void)size;     /* VirtualFree(MEM_RELEASE) 需要 size=0 */
    if (addr == NULL)
        return PROT_ERR_INVALID_ARG;
    if (!VirtualFree(addr, 0, MEM_RELEASE))
        return PROT_ERR_UNSUPPORTED;
    return PROT_OK;
}

uint32_t prot_plat_capabilities(void)
{
    /* Windows 全部支持（实测: 这些 API 在 Win7+ 均可用） */
    return PROT_PCAP_PAGE_PROTECT
         | PROT_PCAP_PAGE_ALLOC_RWX
         | PROT_PCAP_DEBUG_DETECT
         | PROT_PCAP_PROC_ENUM
         | PROT_PCAP_MODULE_ENUM
         | PROT_PCAP_TIME_HIRES
         | PROT_PCAP_FILE_SELF;
}

/* ------------------------------------------------------------------ *
 * 分组 2: 调试检测原语
 *
 * **注意**: 本函数只采集**事实** —— "检测到怎么办"由模块决定
 *          （与 host_hooks 的职责分离一致）。
 * ------------------------------------------------------------------ */

prot_status prot_plat_debug_primitives(prot_debug_primitives* out)
{
    if (out == NULL)
        return PROT_ERR_INVALID_ARG;
    memset(out, 0, sizeof(*out));

    out->being_debugged = IsDebuggerPresent() ? 1 : 0;

    {
        BOOL remote = FALSE;
        if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote))
            out->remote_debugger = remote ? 1 : 0;
    }

    /* 硬件断点: 读 Dr0-Dr3（仅 x64）。失败则标记"不支持"。 */
#if defined(_M_X64)
    {
        CONTEXT ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(GetCurrentThread(), &ctx)) {
            out->hardware_supported = 1;
            out->hardware_breakpoints =
                (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) ? 1 : 0;
        }
    }
#else
    out->hardware_supported = 0;
#endif
    return PROT_OK;
}

/* ------------------------------------------------------------------ *
 * 分组 3: 进程/模块枚举
 * ------------------------------------------------------------------ */

/* 窄字符拷贝（**不用 strncpy** —— /WX 下触发 C4996 不安全警告）。
 *
 * 与项目其它处的做法一致: 显式循环 + 强制终止符。 */
static void copy_narrow(char* dst, size_t capacity, const char* src)
{
    size_t i;
    if (dst == NULL || capacity == 0)
        return;
    for (i = 0; i + 1 < capacity && src[i] != '\0'; i++)
        dst[i] = src[i];
    dst[i] = '\0';
}

/* 宽字符 -> 窄字符（ASCII 安全；非 ASCII 用 '?' 占位）。 */
static void narrow_ascii(const wchar_t* src, char* dst, size_t capacity)
{
    size_t i;
    if (dst == NULL || capacity == 0)
        return;
    for (i = 0; i + 1 < capacity && src[i] != L'\0'; i++) {
        wchar_t c = src[i];
        dst[i] = (c > 0 && c < 128) ? (char)c : '?';
    }
    dst[i] = '\0';
}

size_t prot_plat_enum_processes(prot_proc_info* out, size_t capacity)
{
    HANDLE snap;
    PROCESSENTRY32W pe;
    size_t n = 0;

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;

    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (out != NULL && n < capacity) {
                out[n].pid = (uint32_t)pe.th32ProcessID;
                narrow_ascii(pe.szExeFile, out[n].name,
                             sizeof(out[n].name));
            }
            n++;
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return n;
}

size_t prot_plat_enum_modules(prot_module_info* out, size_t capacity)
{
    HMODULE mods[256];
    DWORD needed = 0;
    size_t n = 0;
    DWORD i;

    if (!EnumProcessModules(GetCurrentProcess(), mods,
                            (DWORD)sizeof(mods), &needed))
        return 0;

    for (i = 0; i < needed / sizeof(HMODULE); i++) {
        MODULEINFO mi;
        char name[MAX_PATH] = { 0 };
        if (out != NULL && n < capacity) {
            memset(&mi, 0, sizeof(mi));
            if (GetModuleInformation(GetCurrentProcess(), mods[i],
                                     &mi, (DWORD)sizeof(mi))) {
                out[n].base = mi.lpBaseOfDll;
                out[n].size = (size_t)mi.SizeOfImage;
            }
            GetModuleFileNameA(mods[i], name, (DWORD)sizeof(name));
            copy_narrow(out[n].name, sizeof(out[n].name), name);
        }
        n++;
    }
    return n;
}

/* ------------------------------------------------------------------ *
 * 分组 4: 计时与自身映像
 * ------------------------------------------------------------------ */

uint64_t prot_plat_monotonic_ns(void)
{
    LARGE_INTEGER freq, now;
    if (!QueryPerformanceFrequency(&freq) || freq.QuadPart == 0)
        return 0;
    if (!QueryPerformanceCounter(&now))
        return 0;
    /* 避免溢出: 先算秒再算纳秒余数 */
    return (uint64_t)(now.QuadPart / freq.QuadPart) * 1000000000ull
         + (uint64_t)((now.QuadPart % freq.QuadPart) * 1000000000ull
                      / freq.QuadPart);
}

size_t prot_plat_self_path(char* out, size_t capacity)
{
    DWORD n;
    if (out == NULL || capacity == 0)
        return 0;
    n = GetModuleFileNameA(NULL, out, (DWORD)capacity);
    if (n == 0 || (size_t)n >= capacity)
        return 0;
    out[n] = '\0';
    return (size_t)n;
}

/* ------------------------------------------------------------------ *
 * 分组 5: 机器指纹因子（L5b）
 *
 * **逐字迁移**自 src/hostid.c 的 4 个因子来源 ——
 * 保持**取值方式与顺序**完全一致，以**保证指纹不变**
 * （基线: b4281468e21a4033，已实测比对）。
 * ------------------------------------------------------------------ */

/* 缓冲区生命周期: 因子里的 str 指向静态缓冲区 ->
 * 调用方在**下次调用前**使用安全，且无需释放。
 * （与原 hostid.c 的局部缓冲语义不同，但折叠是即时的，故等价。） */
static char s_hf_guid[64];
static char s_hf_dserial[64];

/* MachineGuid: HKLM\SOFTWARE\Microsoft\Cryptography */
static int hf_machine_guid(char out[64])
{
    HKEY key = NULL;
    WCHAR wbuf[64];
    DWORD sz = sizeof(wbuf);
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
    if (WideCharToMultiByte(CP_ACP, 0, wbuf, -1, out, 64, NULL, NULL) == 0)
        return 0;
    return (out[0] != '\0');
}

/* 系统盘物理序列号: \\.\PhysicalDrive0 + IOCTL_STORAGE_QUERY_PROPERTY */
static int hf_disk_serial(char out[64])
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
                    FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                    OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return 0;
    if (DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY, &q, sizeof(q),
                        buf, sizeof(buf), &ret, NULL)) {
        STORAGE_DEVICE_DESCRIPTOR* d = (STORAGE_DEVICE_DESCRIPTOR*)buf;
        if (d->SerialNumberOffset > 0u &&
            d->SerialNumberOffset + 1u < sizeof(buf)) {
            copy_narrow(out, 64, (const char*)buf + d->SerialNumberOffset);
            found = 1;
        }
    }
    CloseHandle(h);
    return found;
}

size_t prot_plat_host_factors(prot_host_factor* out, size_t capacity)
{
    size_t n = 0;
    WCHAR comp[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD cn = MAX_COMPUTERNAME_LENGTH + 1;
    DWORD vol_serial = 0u, max_len = 0u, fs_flags = 0u;
    DWORD comp_len = 0;

    if (out == NULL || capacity == 0)
        return 0;

    /* ⚠️ **容量预检**（2026-09-23 实测教训: 初版容量 8 -> 指纹变了）
     *
     * 因子构成最坏: 卷 3 + 计算机名 ≤16 + GUID 1 + 磁盘序列号 1 = 21。
     * 初版 PROT_HOST_MAX_FACTORS = 8 -> **静默截断** ->
     * 折叠的码元数少于原实现 -> 指纹从 b4281468e21a4033 变成
     * 1706bdf43d5c194c -> **会破坏所有已签发授权**。
     *
     * 故此处: 容量不足时**明确失败返回 0**，而非静默截断
     * （宁可"取不到指纹"也不"取到错的指纹"）。 */
    if (capacity < 3u + (size_t)MAX_COMPUTERNAME_LENGTH + 1u + 2u)
        return 0;

    /* --- 因子 1~3: 卷序列号（U32 × 3，与原实现同序）---
     *
     * 原 hostid.c 把这三个值**分别**折叠（vol_serial/max_len/fs_flags）。
     * 为保持指纹不变，本接口把它们作为**三个独立 U32 因子**返回。 */
    if (GetVolumeInformationW(L"C:\\", NULL, 0, &vol_serial, &max_len,
                              &fs_flags, NULL, 0)) {
        out[n].kind = PROT_HOST_FACTOR_U32; out[n].u32 = vol_serial;
        out[n].str = NULL; out[n].str_len = 0; n++;
        out[n].kind = PROT_HOST_FACTOR_U32; out[n].u32 = max_len;
        out[n].str = NULL; out[n].str_len = 0; n++;
        out[n].kind = PROT_HOST_FACTOR_U32; out[n].u32 = fs_flags;
        out[n].str = NULL; out[n].str_len = 0; n++;
    }

    /* --- 因子 4: 计算机名（**UTF-16 码元**逐字符折叠）---
     *
     * ⚠️ 原实现按 **UTF-16 码元**折叠（`(uint16_t)comp[i]`），
     * **不是**按 ASCII 字节！故此处把宽字符逐码元转成 U32 因子。
     * （若误按 ASCII 折叠 -> 指纹会变 —— 见上"容量预检"注释中的教训。） */
    if (GetComputerNameW(comp, &cn)) {
        DWORD i;
        comp_len = cn;
        for (i = 0; i < comp_len; i++) {
            out[n].kind = PROT_HOST_FACTOR_U32;
            out[n].u32 = (uint32_t)(uint16_t)comp[i];
            out[n].str = NULL; out[n].str_len = 0; n++;
        }
    }

    /* --- 因子 5: MachineGuid（ASCII 逐字节）--- */
    if (hf_machine_guid(s_hf_guid)) {
        out[n].kind = PROT_HOST_FACTOR_STR;
        out[n].str = s_hf_guid;
        out[n].str_len = 0;
        out[n].u32 = 0;
        n++;
    }

    /* --- 因子 6: 物理盘序列号（ASCII 逐字节）--- */
    if (hf_disk_serial(s_hf_dserial)) {
        out[n].kind = PROT_HOST_FACTOR_STR;
        out[n].str = s_hf_dserial;
        out[n].str_len = 0;
        out[n].u32 = 0;
        n++;
    }

    return n;
}

/* ------------------------------------------------------------------ *
 * 分组 6: NT 原生查询（C0/C1）
 *
 * ## 实现策略（**保行为不变**）
 *   Windows 上**直接调用原生 API**（`NtQueryInformationProcess` 等）——
 *   与原 `syscall.c` / `antidebug.c` 的行为**逐字一致**。
 *
 *   **注意**: 本层**不做** "从 ntdll stub 提取 SSN + 构造直调 stub"
 *   （那仍由 `src/syscall.c` 负责 —— 它是**Windows 特有的绕 hook 手段**）。
 *   本层只提供"**查询语义**"。
 * ------------------------------------------------------------------ */

typedef LONG(WINAPI* plat_ntqip_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef LONG(WINAPI* plat_ntqsi_t)(ULONG, PVOID, ULONG, PULONG);

/* 平台无关 cls -> Windows NT class */
static ULONG plat_piq_to_nt(uint32_t cls)
{
    switch (cls) {
    case PROT_PIQ_DEBUG_PORT:          return 7u;   /* ProcessDebugPort */
    case PROT_PIQ_DEBUG_FLAGS:         return 31u;  /* ProcessDebugFlags */
    case PROT_PIQ_DEBUG_OBJECT_HANDLE: return 30u;  /* ProcessDebugObjectHandle */
    default: return 0u;
    }
}

static plat_ntqip_t plat_ntqip(void)
{
    HMODULE h = GetModuleHandleW(L"ntdll.dll");
    if (h == NULL)
        return NULL;
    return (plat_ntqip_t)(void*)GetProcAddress(h,
                                               "NtQueryInformationProcess");
}

static plat_ntqsi_t plat_ntqsi(void)
{
    HMODULE h = GetModuleHandleW(L"ntdll.dll");
    if (h == NULL)
        return NULL;
    return (plat_ntqsi_t)(void*)GetProcAddress(h,
                                               "NtQuerySystemInformation");
}

int prot_plat_nt_query_process(uint32_t cls, void* buf, size_t len,
                               size_t* ret)
{
    plat_ntqip_t fn;
    ULONG rl = 0;
    ULONG ntcls = plat_piq_to_nt(cls);
    LONG st;

    if (buf == NULL)
        return PROT_NT_ERROR;
    if (ntcls == 0u)
        return PROT_NT_UNSUPPORTED;

    fn = plat_ntqip();
    if (fn == NULL)
        return PROT_NT_UNSUPPORTED;

    st = fn(GetCurrentProcess(), ntcls, buf, (ULONG)len, &rl);
    if (ret != NULL)
        *ret = (size_t)rl;
    return (st >= 0) ? PROT_NT_OK : PROT_NT_ERROR;
}

int prot_plat_nt_query_system(uint32_t cls, void* buf, size_t len,
                              size_t* ret)
{
    plat_ntqsi_t fn;
    ULONG rl = 0;
    LONG st;

    if (buf == NULL)
        return PROT_NT_ERROR;
    if (cls != PROT_SIQ_KERNEL_DEBUGGER)
        return PROT_NT_UNSUPPORTED;

    fn = plat_ntqsi();
    if (fn == NULL)
        return PROT_NT_UNSUPPORTED;

    st = fn(0x23u, buf, (ULONG)len, &rl);   /* SystemKernelDebuggerInformation */
    if (ret != NULL)
        *ret = (size_t)rl;
    return (st >= 0) ? PROT_NT_OK : PROT_NT_ERROR;
}

uint32_t prot_plat_nt_query_available(void)
{
    return (plat_ntqip() != NULL && plat_ntqsi() != NULL) ? 1u : 0u;
}

/* ------------------------------------------------------------------ *
 * 分组 7: 自身映像与安全读取（C2）
 * ------------------------------------------------------------------ */

void* prot_plat_self_base(void)
{
    /* HMODULE 即**加载基址**（Windows 语义） */
    return (void*)GetModuleHandleW(NULL);
}

void prot_plat_flush_icache(void* addr, size_t len)
{
    if (addr == NULL || len == 0)
        return;
    FlushInstructionCache(GetCurrentProcess(), addr, len);
}

prot_status prot_plat_safe_read(void* dst, const void* src, size_t len)
{
    /* ## 用 SEH 实现（与 selfcrypt.c 的原实现**语义等价**）
     *
     * 原代码在 selfcrypt.c 内联了 `__try/__except`；
     * 本函数把它**集中到平台层** —— 逻辑不变，位置变了。
     */
    if (dst == NULL || src == NULL)
        return PROT_ERR_INVALID_ARG;
    if (len == 0)
        return PROT_OK;

    __try {
        memcpy(dst, src, len);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return PROT_ERR_INTEGRITY;
    }
    return PROT_OK;
}

/* ------------------------------------------------------------------ *
 * 分组 8: 互斥锁（C2）
 *
 * Windows 用 `SRWLOCK`（与原 selfcrypt.c 的用法一致）——
 * 放在 `_opaque` 缓冲里（大小 64 >= sizeof(SRWLOCK) == 8）。
 * ------------------------------------------------------------------ */

prot_status prot_plat_mutex_init(prot_plat_mutex* m)
{
    if (m == NULL)
        return PROT_ERR_INVALID_ARG;
    /* SRWLOCK 无需显式初始化（SRWLOCK_INIT 即全零） */
    memset(m, 0, sizeof(*m));
    return PROT_OK;
}

void prot_plat_mutex_lock(prot_plat_mutex* m)
{
    if (m == NULL)
        return;
    AcquireSRWLockExclusive((PSRWLOCK)(void*)m->_opaque);
}

void prot_plat_mutex_unlock(prot_plat_mutex* m)
{
    if (m == NULL)
        return;
    ReleaseSRWLockExclusive((PSRWLOCK)(void*)m->_opaque);
}

/* ------------------------------------------------------------------ *
 * 分组 9: 节表 / 重定位 / IAT（C3，Windows）
 *
 * ## 实现要点
 *   直接把 `integrity.c` 原有的 PE 解析逻辑**搬迁**到本层 ——
 *   逻辑**逐字保留**（包括边界检查），只是换了"入口"。
 *   => 行为等价性可保证（已由门禁的 e2e/attacks 验证）。
 * ------------------------------------------------------------------ */

#include <windows.h>

static void plat_copy_name(char* dst, size_t cap, const char* src,
                           size_t src_cap)
{
    size_t i;
    if (dst == NULL || cap == 0)
        return;
    for (i = 0; i + 1 < cap && i < src_cap && src[i] != '\0'; i++)
        dst[i] = src[i];
    dst[i] = '\0';
}

size_t prot_plat_enum_sections(prot_section_view* out, size_t capacity)
{
    uint8_t* base = (uint8_t*)GetModuleHandleW(NULL);
    const IMAGE_DOS_HEADER* dos;
    const IMAGE_NT_HEADERS* nt;
    const IMAGE_SECTION_HEADER* sec;
    size_t n = 0;
    WORD i;

    if (base == NULL)
        return 0;
    dos = (const IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return 0;
    nt = (const IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return 0;

    sec = IMAGE_FIRST_SECTION(nt);
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (out != NULL && n < capacity) {
            uint32_t len = (sec->Misc.VirtualSize < sec->SizeOfRawData)
                           ? sec->Misc.VirtualSize : sec->SizeOfRawData;
            plat_copy_name(out[n].name, PROT_SECTION_NAME_MAX,
                           (const char*)sec->Name, sizeof(sec->Name));
            out[n].rva = (size_t)sec->VirtualAddress;
            out[n].size = (size_t)len;
        }
        n++;
    }
    return n;
}

size_t prot_plat_reloc_ranges(prot_range* out, size_t capacity)
{
    uint8_t* base = (uint8_t*)GetModuleHandleW(NULL);
    const IMAGE_DOS_HEADER* dos;
    const IMAGE_NT_HEADERS* nt;
    const IMAGE_DATA_DIRECTORY* dd;
    const uint8_t* reloc_end;
    const IMAGE_BASE_RELOCATION* br;
    size_t n = 0;

    if (base == NULL)
        return 0;
    dos = (const IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return 0;
    nt = (const IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    dd = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (dd->VirtualAddress == 0u || dd->Size == 0u)
        return 0;

    br = (const IMAGE_BASE_RELOCATION*)(base + dd->VirtualAddress);
    reloc_end = (const uint8_t*)br + dd->Size;
    while ((const uint8_t*)br + sizeof(IMAGE_BASE_RELOCATION) <= reloc_end &&
           br->VirtualAddress != 0u &&
           br->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION) &&
           (const uint8_t*)br + br->SizeOfBlock <= reloc_end) {
        uint32_t cnt = (br->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2u;
        const uint16_t* ent = (const uint16_t*)(br + 1);
        uint32_t k;
        for (k = 0u; k < cnt; k++) {
            uint32_t type = (uint32_t)(ent[k] >> 12);
            size_t w = (type == 10u) ? 8u : ((type == 3u) ? 4u : 0u);
            if (w != 0u) {
                size_t tgt = (size_t)br->VirtualAddress
                             + (size_t)(ent[k] & 0xFFFu);
                if (out != NULL && n < capacity) {
                    out[n].rva = tgt;
                    out[n].size = w;
                }
                n++;
            }
        }
        br = (const IMAGE_BASE_RELOCATION*)((const uint8_t*)br
                                            + br->SizeOfBlock);
    }
    return n;
}

int prot_plat_iat_range(prot_range* out)
{
    uint8_t* base = (uint8_t*)GetModuleHandleW(NULL);
    const IMAGE_DOS_HEADER* dos;
    const IMAGE_NT_HEADERS* nt;
    const IMAGE_DATA_DIRECTORY* iat;

    if (base == NULL || out == NULL)
        return 0;
    dos = (const IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return 0;
    nt = (const IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    iat = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
    if (iat->VirtualAddress == 0u || iat->Size == 0u)
        return 0;
    out->rva = (size_t)iat->VirtualAddress;
    out->size = (size_t)iat->Size;
    return 1;
}

const char* prot_plat_crc_target_name(unsigned idx)
{
    /* Windows: PE 节名（与 hashpatch.py 的 TARGET_NAMES 一致） */
    static const char* const names[3] = { ".text", ".rdata", ".pdata" };
    return (idx < 3u) ? names[idx] : NULL;
}

/* ------------------------------------------------------------------ *
 * 分组 10: 线程 / 计时 / 原子 / 终止（C3，Windows）
 * ------------------------------------------------------------------ */

void prot_plat_sleep_ms(uint32_t ms)
{
    if (ms == 0u)
        return;
    Sleep((DWORD)ms);
}

typedef struct plat_win_thread_ctx {
    prot_plat_thread_fn fn;
    void* arg;
} plat_win_thread_ctx;

static DWORD WINAPI plat_win_thread_entry(LPVOID p)
{
    plat_win_thread_ctx* c = (plat_win_thread_ctx*)p;
    prot_plat_thread_fn fn = c->fn;
    void* arg = c->arg;
    free(c);
    if (fn != NULL)
        fn(arg);
    return 0;
}

int prot_plat_thread_create(prot_plat_thread_fn fn, void* arg,
                            void** out_handle)
{
    plat_win_thread_ctx* c;
    HANDLE h;

    if (fn == NULL)
        return 0;
    c = (plat_win_thread_ctx*)malloc(sizeof(*c));
    if (c == NULL)
        return 0;
    c->fn = fn;
    c->arg = arg;

    h = CreateThread(NULL, 0, plat_win_thread_entry, c, 0, NULL);
    if (h == NULL) {
        free(c);
        return 0;
    }
    /* 本模块不需要 join -> 关掉句柄（线程继续运行） */
    CloseHandle(h);
    if (out_handle != NULL)
        *out_handle = NULL;
    return 1;
}

void prot_plat_terminate(int exit_code)
{
    TerminateProcess(GetCurrentProcess(), (UINT)exit_code);
}

int prot_plat_atomic_load(volatile int* p)
{
    return (p == NULL) ? 0 : (int)InterlockedCompareExchange(
        (volatile LONG*)p, 0, 0);
}

int prot_plat_atomic_exchange(volatile int* p, int v)
{
    return (p == NULL) ? 0 : (int)InterlockedExchange((volatile LONG*)p,
                                                      (LONG)v);
}

int prot_plat_atomic_increment(volatile int* p)
{
    return (p == NULL) ? 0 : (int)InterlockedIncrement((volatile LONG*)p);
}

/* ------------------------------------------------------------------ *
 * 分组 11: 内存区间 / 线程 / 符号（C4，Windows）
 * ------------------------------------------------------------------ */

static uint32_t plat_win_prot(DWORD p)
{
    uint32_t r = 0u;
    DWORD base = p & 0xFFu;
    if (base == PAGE_NOACCESS)
        return PROT_MEM_PROT_NONE;
    if (base & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY
                | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE
                | PAGE_EXECUTE_WRITECOPY))
        r |= PROT_MEM_PROT_READ;
    if (base & (PAGE_READWRITE | PAGE_WRITECOPY
                | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
        r |= PROT_MEM_PROT_WRITE;
    if (base & (PAGE_EXECUTE | PAGE_EXECUTE_READ
                | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
        r |= PROT_MEM_PROT_EXEC;
    return r;
}

size_t prot_plat_enum_memory(prot_mem_region* out, size_t capacity)
{
    MEMORY_BASIC_INFORMATION mbi;
    uintptr_t addr = 0u;
    size_t n = 0;

    while (VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi)) != 0) {
        if (mbi.State == MEM_COMMIT) {
            if (out != NULL && n < capacity) {
                out[n].base = mbi.BaseAddress;
                out[n].size = (size_t)mbi.RegionSize;
                out[n].prot = plat_win_prot(mbi.Protect);
            }
            n++;
        }
        addr = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        if (addr == 0u)
            break;
    }
    return n;
}

size_t prot_plat_thread_count(void)
{
    HANDLE snap;
    THREADENTRY32 te;
    size_t n = 0;
    DWORD self = GetCurrentProcessId();

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == self)
                n++;
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return n;
}

void* prot_plat_symbol_addr(const char* module, const char* symbol)
{
    HMODULE h;
    if (module == NULL || symbol == NULL)
        return NULL;
    h = GetModuleHandleA(module);
    if (h == NULL)
        return NULL;
    return (void*)GetProcAddress(h, symbol);
}

/* ------------------------------------------------------------------ *
 * 分组 12: 反调试探测原语（C5，Windows）
 *
 * ## 实现策略（**保行为不变**）
 *   本组把 `antidebug.c` 的 **NT 查询**与 **PEB 直读**搬迁到本层 ——
 *   逻辑**逐字保留**（含回退路径），只是换了入口。
 *
 *   ⚠️ **注意**: `PEB 直读`（`__readgsqword(0x60)`）**留在 `antidebug.c`** ——
 *   因为它是**模块的核心特征之一**（项目明确要求 PEB 直读作为
 *   "绕过用户态 hook"的手段）。本层只提供**归一化视图**。
 * ------------------------------------------------------------------ */

typedef LONG(WINAPI* plat_ntqip2_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);

static plat_ntqip2_t plat_ntqip2(void)
{
    HMODULE h = GetModuleHandleW(L"ntdll.dll");
    if (h == NULL)
        return NULL;
    return (plat_ntqip2_t)(void*)GetProcAddress(h,
                                                "NtQueryInformationProcess");
}

prot_status prot_plat_debug_probe(prot_debug_state* out)
{
    plat_ntqip2_t fn;
    ULONG_PTR port = 0;
    HANDLE hDbg = NULL;
    LONG st;
    char kdbg[2] = {0, 0};

    if (out == NULL)
        return PROT_ERR_INVALID_ARG;
    memset(out, 0, sizeof(*out));

    fn = plat_ntqip2();
    if (fn == NULL)
        return PROT_ERR_UNSUPPORTED;

    /* Windows 有**四个独立信号** —— 全部填入 supported_mask（见其语义） */
    st = fn(GetCurrentProcess(), 7u, &port, (ULONG)sizeof(port), NULL);
    if (st >= 0)
        out->tracer_pid = (port != 0) ? 1u : 0u;

    st = fn(GetCurrentProcess(), 30u, &hDbg, (ULONG)sizeof(hDbg), NULL);
    if (st >= 0 && hDbg != NULL) {
        out->tracer_pid = 1u;   /* 归一化: 有 debug object 即有调试器 */
        CloseHandle(hDbg);
    }

    /* 内核调试器（沿用 C1 的平台实现） */
    if (prot_plat_nt_query_system(PROT_SIQ_KERNEL_DEBUGGER, kdbg,
                                  sizeof(kdbg), NULL) == PROT_NT_OK)
        out->kernel_debugger = (kdbg[0] != 0) ? 1u : 0u;

    /* Windows 支持硬件断点（但需要正在调试的上下文才能读 —— 见 antidebug.c）*/
    out->hardware_bp = 0u;

    out->supported_mask = 1u | 2u | 4u;   /* tracer + kernel + hwbp(接口可用) */
    return PROT_OK;
}

/* ## int3 蜜罐（Windows: VEH）
 *   与原 `antidebug.c` 的 `ad_int3_probe` **逻辑一致** —— 搬迁。
 */
static volatile LONG g_plat_int3_caught;

static LONG CALLBACK plat_vh_int3(EXCEPTION_POINTERS* ep)
{
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_BREAKPOINT)
        return EXCEPTION_CONTINUE_SEARCH;
    InterlockedExchange(&g_plat_int3_caught, 1);
    ep->ContextRecord->Rip += 1;   /* 跳过 1 字节 int3 */
    return EXCEPTION_CONTINUE_EXECUTION;
}

uint32_t prot_plat_int3_probe(void)
{
    uint8_t* stub;
    PVOID hveh;
    uint32_t r = 0u;

    stub = (uint8_t*)VirtualAlloc(NULL, 2, MEM_COMMIT | MEM_RESERVE,
                                  PAGE_EXECUTE_READWRITE);
    if (stub == NULL)
        return 0u;
    stub[0] = 0xCCu;   /* int3 */
    stub[1] = 0xC3u;   /* ret */
    FlushInstructionCache(GetCurrentProcess(), stub, 2);

    InterlockedExchange(&g_plat_int3_caught, 0);
    hveh = AddVectoredExceptionHandler(1, plat_vh_int3);
    if (hveh != NULL) {
        ((void(WINAPI*)(void))stub)();
        RemoveVectoredExceptionHandler(hveh);
        r = (InterlockedCompareExchange(&g_plat_int3_caught, 0, 0) == 0)
            ? 2u : 1u;
    }
    VirtualFree(stub, 0, MEM_RELEASE);
    return r;
}

int prot_plat_parent_name(char* name, size_t cap)
{
    FILE* f;
    DWORD ppid = 0;
    (void)name;
    (void)cap;

    /* ## Windows 侧的父进程名获取**较繁琐**
     *   （NtQueryInformationProcess(ProcessBasicInformation) -> OpenProcess
     *     -> QueryFullProcessImageNameW）
     *   该逻辑**保留在 `antidebug.c`**（它需要 PEB/NT 类型，属模块特征）。
     *   本层返回 0 表示"请用模块自己的实现"。
     */
    f = NULL;
    (void)f;
    (void)ppid;
    return 0;
}

int prot_plat_clock_pair(uint64_t* tick_ms, uint64_t* wall_ms)
{
    ULARGE_INTEGER ul;
    FILETIME ft;

    if (tick_ms == NULL || wall_ms == NULL)
        return 0;
    *tick_ms = (uint64_t)GetTickCount64();
    GetSystemTimeAsFileTime(&ft);
    ul.LowPart = ft.dwLowDateTime;
    ul.HighPart = ft.dwHighDateTime;
    /* FILETIME(100ns since 1601) -> ms since epoch */
    *wall_ms = (ul.QuadPart / 10000ull) - 11644473600000ull;
    return 1;
}

uint32_t prot_plat_extra_debug_flags(void)
{
    /* ## Windows 无平台独有维度
     *   本项目的 Windows 版**已有 12 个维度**（PEB/NT/SEH/计时/父子/时钟）——
     *   没有"Windows 独有而 Linux 没有"的额外项需要在此返回。
     *   （Linux 侧的 3 个独有项见 Linux 实现。）
     */
    return 0u;
}

prot_status prot_plat_hide_thread(void)
{
    HMODULE h;
    typedef LONG(WINAPI* nt_set_t)(HANDLE, ULONG, PVOID, ULONG);
    nt_set_t fn;

    h = GetModuleHandleW(L"ntdll.dll");
    if (h == NULL)
        return PROT_ERR_UNSUPPORTED;
    fn = (nt_set_t)(void*)GetProcAddress(h, "NtSetInformationThread");
    if (fn == NULL)
        return PROT_ERR_UNSUPPORTED;
    /* 17 = ThreadHideFromDebugger */
    fn(GetCurrentThread(), 17u, NULL, 0);
    return PROT_OK;
}

/* ------------------------------------------------------------------ *
 * 分组 13: HTTP 下载（B4，Windows: WinHTTP）
 *
 * ⚠️ **本函数是 `demo/main.c` 原 WinHTTP 逻辑的搬迁** ——
 *   但 `main.c` 的调用点**尚未改为调本函数**（那是 B4-3 的工作）。
 *   本层先提供**可被调用的实现**。
 * ------------------------------------------------------------------ */

prot_status prot_plat_http_get(const char* url, const char* out_path,
                               size_t max_size)
{
    HINTERNET hin = NULL, hconn = NULL, hreq = NULL;
    prot_status st = PROT_ERR_INTERNAL;
    wchar_t wurl[1024];
    wchar_t whost[256];
    wchar_t wpath[512];
    URL_COMPONENTS uc;
    FILE* f = NULL;

    if (url == NULL || out_path == NULL)
        return PROT_ERR_INVALID_ARG;

    if (MultiByteToWideChar(CP_UTF8, 0, url, -1, wurl, 1024) == 0)
        return PROT_ERR_INVALID_ARG;

    memset(&uc, 0, sizeof(uc));
    uc.dwStructSize = sizeof(uc);
    uc.lpszHostName = whost; uc.dwHostNameLength = 256;
    uc.lpszUrlPath = wpath;  uc.dwUrlPathLength = 512;

    hin = WinHttpOpen(L"PROT-Demo/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                      WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (hin == NULL)
        return PROT_ERR_INTERNAL;

    if (!WinHttpCrackUrl(wurl, 0, 0, &uc))
        goto done;
    hconn = WinHttpConnect(hin, whost, uc.nPort, 0);
    if (hconn == NULL)
        goto done;
    hreq = WinHttpOpenRequest(hconn, L"GET", wpath, NULL,
                              WINHTTP_NO_REFERER,
                              WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (hreq == NULL)
        goto done;
    if (!WinHttpSendRequest(hreq, WINHTTP_NO_ADDITIONAL_HEADERS, 0, NULL, 0, 0, 0))
        goto done;
    if (!WinHttpReceiveResponse(hreq, NULL))
        goto done;

    /* B4: MSVC 报 C4996（fopen 不安全）-> 用统一宏 PROT_FOPEN_S */
    if (PROT_FOPEN_S(&f, out_path, "wb") != 0)
        goto done;
    {
        size_t total = 0u;
        DWORD avail = 0u;
        uint8_t chunk[4096];
        size_t cap = (max_size != 0u) ? max_size : (16u * 1024u * 1024u);
        int overflow = 0;
        while (WinHttpQueryDataAvailable(hreq, &avail) && avail != 0u) {
            DWORD want = (avail > sizeof(chunk)) ? (DWORD)sizeof(chunk) : avail;
            DWORD got = 0u;
            if (!WinHttpReadData(hreq, chunk, want, &got) || got == 0u)
                break;
            if (total + got > cap) { overflow = 1; break; }
            total += got;
            (void)fwrite(chunk, 1, got, f);
        }
        fclose(f);
        f = NULL;
        if (overflow) {
            remove(out_path);
            st = PROT_ERR_INTERNAL;
        } else {
            st = PROT_OK;
        }
    }

done:
    if (f != NULL)
        fclose(f);
    if (hreq != NULL)
        WinHttpCloseHandle(hreq);
    if (hconn != NULL)
        WinHttpCloseHandle(hconn);
    if (hin != NULL)
        WinHttpCloseHandle(hin);
    return st;
}

/* 下载到内存（`--check-url` 用）—— 复用 WinHTTP 流程，但写入缓冲。
 *
 * 实现方式: **先下载到临时文件再用 http_get 的公共部分**
 *   —— 但那样多一次磁盘 IO。
 *   故此处**独立实现**（代码短，且避免临时文件管理）。
 */
prot_status prot_plat_http_get_mem(const char* url, char* buf, size_t cap,
                                   size_t* out_len)
{
    HINTERNET hin = NULL, hconn = NULL, hreq = NULL;
    prot_status st = PROT_ERR_INTERNAL;
    wchar_t wurl[1024], whost[256], wpath[512];
    URL_COMPONENTS uc;

    if (url == NULL || buf == NULL || cap == 0u)
        return PROT_ERR_INVALID_ARG;
    if (MultiByteToWideChar(CP_UTF8, 0, url, -1, wurl, 1024) == 0)
        return PROT_ERR_INVALID_ARG;

    memset(&uc, 0, sizeof(uc));
    uc.dwStructSize = sizeof(uc);
    uc.lpszHostName = whost; uc.dwHostNameLength = 256;
    uc.lpszUrlPath = wpath;  uc.dwUrlPathLength = 512;

    hin = WinHttpOpen(L"PROT-Demo/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                      WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (hin == NULL)
        return PROT_ERR_INTERNAL;
    if (!WinHttpCrackUrl(wurl, 0, 0, &uc))
        goto done;
    hconn = WinHttpConnect(hin, whost, uc.nPort, 0);
    if (hconn == NULL)
        goto done;
    hreq = WinHttpOpenRequest(hconn, L"GET", wpath, NULL, WINHTTP_NO_REFERER,
                              WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (hreq == NULL)
        goto done;
    if (!WinHttpSendRequest(hreq, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 3000))
        goto done;
    if (!WinHttpReceiveResponse(hreq, NULL))
        goto done;
    {
        DWORD avail = 0u;
        DWORD got = 0u;
        if (WinHttpQueryDataAvailable(hreq, &avail) && avail > 0u
            && (size_t)avail < cap) {
            if (WinHttpReadData(hreq, buf, avail, &got)) {
                buf[got] = '\0';
                if (out_len != NULL)
                    *out_len = (size_t)got;
                st = PROT_OK;
            }
        }
    }

done:
    if (hreq != NULL)  WinHttpCloseHandle(hreq);
    if (hconn != NULL) WinHttpCloseHandle(hconn);
    if (hin != NULL)   WinHttpCloseHandle(hin);
    return st;
}

/* 平台层: 页大小（C2 后续，2026-09-25）。 */
size_t prot_plat_page_size(void)
{
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return (si.dwPageSize != 0u) ? (size_t)si.dwPageSize : (size_t)4096u;
}

/* 控制台设为 UTF-8（B 阶段，2026-09-25）——
   `demo/main.c` 原直接调用，现走平台层。 */
prot_status prot_plat_console_utf8(void)
{
    (void)SetConsoleOutputCP(65001u);   /* CP_UTF8 */
    (void)SetConsoleCP(65001u);
    return PROT_OK;
}

#endif /* PROT_PLATFORM_WINDOWS */
