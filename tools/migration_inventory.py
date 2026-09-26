#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""migration_inventory.py — 逐 API 枚举 Linux 迁移清单（L5a）

## 用途
  重新生成 docs/LINUX_MIGRATION_INVENTORY.md 的**数据部分**。
  新增平台 API 后可重跑本工具，得到更新的清单。

## 原说明
  逐 API 枚举**迁移清单**（38% 平台依赖 -> Linux 等价物）。

## 为什么需要
  L1-L4 只做了**局部**接入点。要真正移植，需要**逐条**知道:
    · 每个平台 API 用在**哪个文件/哪个函数**
    · 它的**语义**是什么（不是名字，是行为）
    · Linux 的**等价物**是什么
    · **差异**在哪（差异才是移植的真难点）

## 方法（**实测枚举，不猜**）
  1. 扫描所有平台 API 调用点（文件 + 行 + 上下文）
  2. 归类到平台层接口（哪些已被抽象层覆盖、哪些没有）
  3. 输出**可执行的清单**
"""
import glob
import json
import os
import re
import sys
from collections import OrderedDict

os.chdir(r'D:\specifically for development and work\Reverse Engineering')
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

# ---- 平台 API -> (语义, Linux 等价物, 差异) ----
API_MAP = {
    'VirtualAlloc': (
        '分配内存页（RWX 能力）',
        'mmap(NULL, len, prot, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)',
        'W^X: Linux/Android 10+ 可能禁止 RWX，需 mprotect 分两步'),
    'VirtualProtect': (
        '改页保护属性',
        'mprotect(addr, len, prot)',
        '**页对齐要求相同**；但 Linux 不返回旧属性（需自己记）'),
    'VirtualFree': (
        '释放页',
        'munmap(addr, len)',
        '**必须传原长度**（Windows 传 0 表示整块）—— 语义差异'),
    'GetProcAddress': (
        '按名解析动态符号',
        'dlsym(handle, name)',
        '基本等价；Linux 需先 dlopen'),
    'LoadLibrary': (
        '加载动态库',
        'dlopen(path, RTLD_NOW)',
        '路径解析规则不同（Linux 用 RPATH/LD_LIBRARY_PATH）'),
    'CreateToolhelp32Snapshot': (
        '枚举进程/模块',
        '遍历 /proc（或 /proc/self/maps）',
        '**机制完全不同**；已在平台层封装（L1）'),
    'Process32FirstW': (
        '取首个进程（宽字符）',
        '/proc 遍历 + /proc/<pid>/comm',
        'Linux 进程名限 15 字符（TASK_COMM_LEN）—— **真实差异**'),
    'Process32NextW': (
        '取下一个进程',
        'readdir 继续',
        '同上'),
    'IsDebuggerPresent': (
        '检测调试器附加',
        '/proc/self/status 的 TracerPid != 0',
        'PTRACE 检测 vs PEB —— **机制完全不同**（已封装）'),
    'CheckRemoteDebuggerPresent': (
        '检测远程调试',
        '（Linux 无直接等价；用 TracerPid）',
        '**无 1:1 等价** —— 需降级或省略'),
    'GetThreadContext': (
        '读线程上下文（含硬件断点 Dr0-Dr3）',
        'ptrace(PTRACE_GETREGS) 需被 trace；或读 /proc/<pid>/...',
        '**权限模型不同**: Linux 读别的进程需 ptrace 附加；'
        '读自身可用 PTRACE_TRACEME 或信号'),
    'EnumProcessModules': (
        '枚举已加载模块',
        '解析 /proc/self/maps',
        '**格式完全不同**（需自己解析文本）'),
    'GetModuleInformation': (
        '取模块基址与大小',
        '/proc/self/maps 的起止地址',
        '需解析 maps 文本'),
    'GetModuleFileNameA': (
        '取模块文件路径',
        'dladdr() 或 /proc/self/maps',
        'dladdr 需 -ldl；maps 更可靠'),
    'QueryPerformanceCounter': (
        '高精度单调计时',
        'clock_gettime(CLOCK_MONOTONIC, &ts)',
        '**基本等价**（都是单调）；已在平台层封装'),
    'QueryPerformanceFrequency': (
        '计时频率',
        '（Linux 直接给纳秒，无需频率）',
        '**无对应物** —— 平台层已吸收该差异'),
    'TerminateProcess': (
        '终止进程',
        'exit() / _exit() / kill(getpid(), SIGKILL)',
        '**注意**: Linux 上用 _exit 避免 atexit；语义抉择'),
    'OpenProcess': (
        '打开进程句柄',
        '（Linux 无句柄模型；ptrace 附加即"打开"）',
        '**模型不同** —— 需重构调用方'),
    'NtQuerySystemInformation': (
        '查系统信息（隐藏 API）',
        '/proc /sys 接口',
        '**机制完全不同**'),
    'GetTickCount': (
        '毫秒计时（可能被 hook）',
        'clock_gettime(CLOCK_MONOTONIC)',
        'Windows 上 GetTickCount 是**反调试诱饵**（可被 hook）；'
        'Linux 无此特性'),
    'IsWow64Process': (
        '是否为 WOW64',
        '（Linux 无对应）',
        '**平台特有概念**'),
    'Sleep': (
        '睡眠',
        'nanosleep / usleep',
        '基本等价'),
    'GetCurrentProcess': (
        '取当前进程伪句柄',
        'getpid()',
        '模型不同但用途等价'),
    'GetCurrentThread': (
        '取当前线程伪句柄',
        'gettid()（需 syscall 或 pthread_self）',
        '基本等价'),
    'CloseHandle': (
        '关闭句柄',
        'close() / dlclose()',
        '按对象类型不同'),
    '__readgsqword': (
        '读 GS 段（Windows TEB/PEB）',
        '（Linux 用 FS 段: __builtin_thread_pointer）',
        '**架构特定** —— 段寄存器不同'),
    '__rdtsc': (
        '读时间戳计数器',
        '__builtin_ia32_rdtsc()',
        '基本等价'),
    '__cpuid': (
        'CPUID 指令',
        '__get_cpuid() / __builtin_cpu_*',
        '基本等价（GCC 提供内建）'),
    'GetVolumeInformationA': (
        '取卷序列号（机器绑定）',
        'statvfs() 的 f_fsid 或 /etc/machine-id',
        '**语义不同**: Windows 卷序列号 vs Linux machine-id —— '
        '**不是等价物，是替代方案**'),
    'RegOpenKeyExA': (
        '读注册表（机器绑定）',
        '/etc/machine-id 或 /sys/class/dmi/id/product_uuid',
        '**机制完全不同**（无注册表）'),
    'RegQueryValueExA': (
        '读注册表值',
        '读 /etc/machine-id 文本',
        '同上'),
    'BCryptOpenAlgorithmProvider': (
        '打开密码学算法',
        'OpenSSL EVP_* / mbedTLS',
        '已在平台层封装（L2）'),
    'BCryptVerifySignature': (
        'RSA 验签',
        'EVP_DigestVerify / mbedtls_pk_verify',
        '已在平台层封装（L2）'),
    'BCryptHashData': (
        '哈希数据',
        'EVP_DigestUpdate / SHA256_Update',
        '已在平台层封装（L2）'),
    'WinHttpOpen': (
        'HTTP 客户端（在线校验）',
        'libcurl',
        '**需链接 libcurl** —— 属"可选在线路径"，离线不受影响'),
    'WinHttpConnect': ('HTTP 连接', 'libcurl', '同上'),
    'WinHttpSendRequest': ('HTTP 请求', 'libcurl', '同上'),
}

# ---- 扫描所有调用点 ----
print('=' * 84)
print('逐 API 迁移清单（**实测枚举**）')
print('=' * 84)

FILES = (glob.glob('src/*.c') + glob.glob('src/**/*.c', recursive=True)
         + glob.glob('demo/*.c') + glob.glob('tools/attacker/**/*.c',
                                             recursive=True)
         + glob.glob('prot_sdk/**/*.c', recursive=True))
FILES = sorted(set(f for f in FILES if '.git' not in f))

found = OrderedDict()   # api -> [(file, line, snippet)]
for f in FILES:
    try:
        t = open(f, encoding='utf-8', errors='replace').read()
    except OSError:
        continue
    body = re.sub(r'/\*.*?\*/', '', t, flags=re.S)
    body = re.sub(r'//[^\n]*', '', body)
    for i, line in enumerate(body.split('\n'), 1):
        for api in API_MAP:
            if re.search(r'\b%s\b' % re.escape(api), line):
                found.setdefault(api, []).append(
                    (f.replace('\\', '/'), i, line.strip()[:70]))

print('  扫描 %d 个 C 文件' % len(FILES))
print('  发现 %d 个不同 API' % len(found))
print()

# 平台层已覆盖的
COVERED = {
    'CreateToolhelp32Snapshot', 'Process32FirstW', 'Process32NextW',
    'EnumProcessModules', 'GetModuleInformation', 'GetModuleFileNameA',
    'IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'GetThreadContext',
    'QueryPerformanceCounter', 'QueryPerformanceFrequency',
    'VirtualAlloc', 'VirtualProtect', 'VirtualFree',
    'BCryptOpenAlgorithmProvider', 'BCryptVerifySignature',
    'BCryptHashData', 'BCryptCreateHash', 'BCryptFinishHash',
    'BCryptDestroyHash', 'BCryptDestroyKey',
    'BCryptCloseAlgorithmProvider', 'BCryptImportKeyPair',
}

rows = []
for api, hits in found.items():
    sem, lin, diff = API_MAP.get(api, ('（未登记）', '（待补）', '（待补）'))
    cov = '✅ 已封装' if api in COVERED else '⬜ 待封装'
    rows.append((api, len(hits), cov, sem, lin, diff, hits))

# 按"是否已封装"排序
rows.sort(key=lambda r: (r[2].startswith('✅'), -r[1]))

for api, n, cov, sem, lin, diff, hits in rows:
    print('  --- %s  (%d 处)  %s ---' % (api, n, cov))
    print('      语义: %s' % sem)
    print('      Linux: %s' % lin)
    print('      **差异**: %s' % diff)
    locs = sorted(set(h[0] for h in hits))
    print('      位置: %s' % ', '.join(locs[:4]))

print()
print('=' * 84)
print('汇总')
print('=' * 84)
cov_n = sum(1 for r in rows if r[2].startswith('✅'))
print('  API 总数: %d' % len(rows))
print('  **已被平台层封装**: %d' % cov_n)
print('  **待封装**: %d' % (len(rows) - cov_n))
print()
print('  待封装清单（按调用点数量）:')
for api, n, cov, sem, lin, diff, hits in rows:
    if not cov.startswith('✅'):
        print('    %-32s %2d 处  -> %s' % (api, n, lin[:44]))
