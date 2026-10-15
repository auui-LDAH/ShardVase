/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 ShardVase contributors
 *
 * 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；
 * 商业授权见 LICENSE.md。
 */
/*
 * test_target.c — 带符号的测试目标 (供 WinPE-SymPatcher 验证 COFF 符号解析)
 *
 * 模拟被保护程序的"盾": 一个反调试判定 + 一个可被补丁的布尔。
 * 编译: cl /Z7 (或 /Zi) 保留 COFF 符号 (非 /DEBUG:NONE).
 */
#include <stdio.h>
#include <string.h>
#include <windows.h>

/* 模拟"盾"的关键布尔: 反调试判定结果 */
static volatile int is_debugger_attached = 1;

/* 模拟 antidebug scan (被符号表定位的目标函数) */
__declspec(noinline) int prot_antidebug_scan(void)
{
    /* 真实工程中是 PEB/NtQuery 多因子; 这里用 PEB.BeingDebugged 模拟 */
    uintptr_t peb = (uintptr_t)__readgsqword(0x60);
    is_debugger_attached = (*(const unsigned char*)(peb + 0x02) != 0) ? 1 : 0;
    return is_debugger_attached;
}

/* 模拟"盾"判定聚合 */
__declspec(noinline) int prot_antidebug_detected(void)
{
    return is_debugger_attached != 0 ? 1 : 0;
}

int main(int argc, char** argv)
{
    int rounds = 0;
    int fake_debug = (argc > 1 && strcmp(argv[1], "--fake-debug") == 0);
    /* 日志路径取运行期 temp 目录（原先硬编码了开发机的用户目录 ——
     * 既泄露个人信息, 又在别的机器上跑不通）。 */
    char log_path[MAX_PATH];
    FILE* log = NULL;
    if (GetTempPathA(MAX_PATH, log_path) != 0) {
        strncat(log_path, "target_log.txt",
                MAX_PATH - strlen(log_path) - 1);
        log = fopen(log_path, "a");
    }
    if (log) {
        fprintf(log, "[target] starting pid=%lu is_debugger_attached=%d fake_debug=%d\n",
                (unsigned long)GetCurrentProcessId(), is_debugger_attached, fake_debug);
        fflush(log);
    }
    if (fake_debug) {
        /* 模拟被调试: 置 PEB.BeingDebugged = 1 (真实调试器会这么做) */
        uintptr_t peb = (uintptr_t)__readgsqword(0x60);
        *(volatile unsigned char*)(peb + 0x02) = 1;
        if (log) {
            fprintf(log, "[target] fake-debug set PEB.BeingDebugged=1\n");
            fflush(log);
        }
    }
    for (;;) {
        prot_antidebug_scan();
        if (prot_antidebug_detected()) {
            if (log) {
                fprintf(log, "[target] DEBUGGER DETECTED (round %d)\n", rounds);
                fflush(log);
            }
        } else {
            if (log) {
                fprintf(log, "[target] clean (round %d)\n", rounds);
                fflush(log);
            }
        }
        rounds++;
        Sleep(1000);
    }
    if (log) fclose(log);
    return 0;
}
