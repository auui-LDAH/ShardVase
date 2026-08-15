/*
 * syscall.c — direct syscall 直调 (A6)
 *
 * 对应契约 docs/CONTRACT.md §6.3。
 * 在 ntdll 导出 stub 可能被 inline hook 的场景下, 从 stub 字节码中提取
 * syscall 号 (SSN) 并绕开 stub 入口直接 syscall 进入内核。
 *
 * 实现:
 *   1. 定位 ntdll 导出函数 (GetProcAddress, 只读地址, 与 hook 无关)。
 *   2. 在其字节码窗口内扫描 `0F 05` (syscall), 向前找最近的 `B8 <imm32>`
 *      (mov eax, SSN) —— 标准 x64 stub 形态 (Win10/11 均含; 部分版本有
 *      `test byte ptr [7FFE0308],1` 分支, syscall 指令仍唯一)。
 *   3. 在可执行内存生成 12 字节 stub: mov r10,rcx; mov eax,SSN; syscall; ret
 *      (x64 调用约定第 1 参须移入 r10; 第 5+ 参由调用者压栈, stub 不动)。
 *   4. 任何失败 (SSN 提取失败/分配失败) -> 返回 STATUS_UNSUCCESSFUL,
 *      调用方回退 GetProcAddress 路径 —— 与现状等价, 不新增误报面。
 *
 * 线程安全: 一次性初始化 (InterlockedCompareExchange 自旋), stub 只读后
 * 可并发调用。
 */

#include <windows.h>
#include <string.h>

#include "protect/syscall.h"

#define PROT_SYS_SSN_INVALID 0xFFFFFFFFu

typedef NTSTATUS(NTAPI* sys_ntqip_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* sys_ntqsi_t)(ULONG, PVOID, ULONG, PULONG);

static void* s_stub_qip;              /* NtQueryInformationProcess 直调 stub */
static void* s_stub_qsi;              /* NtQuerySystemInformation 直调 stub */
static volatile LONG s_sys_init;      /* 一次性初始化标志 */

/*
 * 在导出函数字节码窗口内提取 SSN:
 * 找 `0F 05` (syscall), 再向前 (最多 24 字节) 找 `B8/B9 <imm32>`。
 * 返回 SSN; 未找到返回 PROT_SYS_SSN_INVALID。
 */
static uint32_t sys_find_ssn(const uint8_t* fn)
{
    int32_t i, j;

    for (i = -32; i <= 48; i++) {
        if (fn[i] == 0x0Fu && fn[i + 1] == 0x05u) {
            for (j = i - 1; j >= i - 24 && j >= 0; j--) {
                if (fn[j] == 0xB8u || fn[j] == 0xB9u) {
                    uint32_t ssn;
                    memcpy(&ssn, fn + j + 1, 4);
                    if (ssn < 0x1000u)
                        return ssn;
                }
            }
        }
    }
    return PROT_SYS_SSN_INVALID;
}

/* 运行时生成 12 字节直调 stub 并设为只读可执行; 失败返回 NULL */
static void* sys_make_stub(uint32_t ssn)
{
    static const uint8_t code[12] = {
        0x4Cu, 0x8Bu, 0xD1u,          /* mov r10, rcx          */
        0xB8u, 0x00u, 0x00u, 0x00u, 0x00u, /* mov eax, imm32 (SSN) */
        0x0Fu, 0x05u,                 /* syscall               */
        0xC3u                         /* ret                   */
    };
    uint8_t* p;
    DWORD old;

    p = (uint8_t*)VirtualAlloc(NULL, sizeof(code), MEM_COMMIT | MEM_RESERVE,
                               PAGE_EXECUTE_READWRITE);
    if (p == NULL)
        return NULL;
    memcpy(p, code, sizeof(code));
    memcpy(p + 4, &ssn, 4);
    FlushInstructionCache(GetCurrentProcess(), p, sizeof(code));
    VirtualProtect(p, sizeof(code), PAGE_EXECUTE_READ, &old);
    return p;
}

static void sys_init(void)
{
    HMODULE h;
    uint32_t ssn;
    const uint8_t* qip;
    const uint8_t* qsi;

    if (InterlockedCompareExchange(&s_sys_init, 1, 0) != 0)
        return; /* 已初始化 */

    h = GetModuleHandleW(L"ntdll.dll");
    if (h == NULL)
        return; /* ntdll 必然已加载; 失败则保持 NULL, 调用方回退 */

    qip = (const uint8_t*)GetProcAddress(h, "NtQueryInformationProcess");
    qsi = (const uint8_t*)GetProcAddress(h, "NtQuerySystemInformation");

    if (qip != NULL) {
        ssn = sys_find_ssn(qip);
        if (ssn != PROT_SYS_SSN_INVALID)
            s_stub_qip = sys_make_stub(ssn);
    }
    if (qsi != NULL) {
        ssn = sys_find_ssn(qsi);
        if (ssn != PROT_SYS_SSN_INVALID)
            s_stub_qsi = sys_make_stub(ssn);
    }
}

NTSTATUS prot_sys_nt_query_information_process(HANDLE h, ULONG cls,
                                               PVOID buf, ULONG len,
                                               PULONG ret)
{
    sys_init();
    if (s_stub_qip != NULL)
        return ((sys_ntqip_t)s_stub_qip)(h, cls, buf, len, ret);
    return (NTSTATUS)0xC0000001; /* STATUS_UNSUCCESSFUL: 调用方回退 */
}

NTSTATUS prot_sys_nt_query_system_information(ULONG cls, PVOID buf,
                                              ULONG len, PULONG ret)
{
    sys_init();
    if (s_stub_qsi != NULL)
        return ((sys_ntqsi_t)s_stub_qsi)(cls, buf, len, ret);
    return (NTSTATUS)0xC0000001; /* STATUS_UNSUCCESSFUL: 调用方回退 */
}

uint32_t prot_sys_available(void)
{
    sys_init();
    return (s_stub_qip != NULL && s_stub_qsi != NULL) ? 1u : 0u;
}
