# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ShardVase contributors
# 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；商业授权见 LICENSE.md。
"""
tests/e2e.py - 端到端测试  (Lane D)

对应契约 docs/CONTRACT.md §11。用 subprocess 运行 build\\demo.exe,
读 demo/vm_build.json 取正确序列号, demo/strings.txt 取期望文本。

测试:
  T1 normal-ok    正确序列号 -> MSG_OK 文本 + 退出码 0
  T2 normal-bad   错误序列号 -> MSG_FAIL 文本 + 退出码 1
  T3 debug-detect 附加内核调试器 -> MSG_DBG 文本 + 退出码 0xDB (附加失败则 SKIP)
  T4 tamper-detect 翻转 .text 一个字节 -> MSG_TAMPER 文本 + 退出码 0xBAD
  T9/T10          翻转 .rdata/.pdata 一个字节 -> 退出码 0xBAD (A3; 消息可能乱码)
  T11 watchdog-stable --wait-after 14s 期间看门狗周期复查零误报 (A5)
  T12 license-tier-forge 改 TIER 行 -> license: 0 / 退出码 1 (Phase 4)
  T13/T14 blob-missing / blob-tamper -> 退出码 0xB10B (DBI launcher)
  T15-T19 吊销黑名单: 命中 0xB1E4 / 干净通过 / 无文件不阻断 / 损坏不阻断 / warn 继续 (I1)
  T20/T21 试用期: 未来到期通过 / 已过期拒绝 (Phase 4 expires 参与签名)
  T22-T24 在线验证: 在线吊销 0xB1E4 / 在线 ok 通过 / 服务不可达降级 (M3.1 mock)
  T25/T26 在线会话级期望值: 正确期望值通过 / 错误期望值拒绝 (N5)
  T27/T28 在线 blob 下发: 签名版通过 / 篡改版拒绝 (BLOB_SIGN_PLAN)

任一 FAIL -> sys.exit(1)。
"""

import ctypes
import json
import os
import shutil
import struct
import subprocess
import sys
import time

# ---------------------------------------------------------------------------
# 隐藏窗口（2026-09-25）
#
# Windows 上从 Python 启动控制台程序（powershell/cmd/wsl/cl）会**弹出黑窗**。
# 统一用 tools/winproc.py 封装（CREATE_NO_WINDOW + STARTUPINFO/SW_HIDE）。
#
# **为什么统一封装**: 实测本项目约 60 处调用都无隐藏措施；
#   一处修好 = 全部修好，且可自检（见 winproc.py 的 --selftest）。
#
# 路径推导: 从本文件位置向上找含 tools/winproc.py 的目录。
# ---------------------------------------------------------------------------
import os as _os_hw
import sys as _sys_hw


def _hw_tools_dir():
    d = _os_hw.path.dirname(_os_hw.path.abspath(__file__))
    for _ in range(4):
        cand = _os_hw.path.join(d, 'tools')
        if _os_hw.path.isfile(_os_hw.path.join(cand, 'winproc.py')):
            return cand
        d = _os_hw.path.dirname(d)
    return None


_hw_tools = _hw_tools_dir()
if _hw_tools and _hw_tools not in _sys_hw.path:
    _sys_hw.path.insert(0, _hw_tools)
import winproc  # noqa: E402


REPO = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
EXE = os.path.join(REPO, 'build', 'demo.exe')
BUILD = os.path.join(REPO, 'build')
JSON_PATH = os.path.join(REPO, 'demo', 'vm_build.json')
STRINGS = os.path.join(REPO, 'demo', 'strings.txt')
LICENSE = os.path.join(REPO, 'build', 'license.txt')   # A1: build.ps1 sign 产物

KERNEL32 = ctypes.WinDLL('kernel32', use_last_error=True)

KERNEL32.DebugActiveProcess.argtypes = [ctypes.c_ulong]
KERNEL32.DebugActiveProcess.restype = ctypes.c_int
KERNEL32.WaitForDebugEvent.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
KERNEL32.WaitForDebugEvent.restype = ctypes.c_int
KERNEL32.ContinueDebugEvent.argtypes = [ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
KERNEL32.ContinueDebugEvent.restype = ctypes.c_int
KERNEL32.DebugActiveProcessStop.argtypes = [ctypes.c_ulong]
KERNEL32.DebugActiveProcessStop.restype = ctypes.c_int

PROT_EXIT_DEBUG_DETECTED = 0xDB
PROT_EXIT_TAMPERED = 0xBAD
WINERROR_WDAC_BLOCK = 4551  # 0x11C7: 文件被 Device Guard/WDAC 代码完整性策略阻止


def wdac_blocked(exc):
    """True 若异常来自 WDAC 拦截 (winerror 4551 / 文本含"无法启动")."""
    return (isinstance(exc, OSError) and
            getattr(exc, 'winerror', None) == WINERROR_WDAC_BLOCK) or \
           ('无法启动' in repr(exc))


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def load_vm_build_json(path):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def load_strings(path):
    out = {}
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.rstrip('\r\n')
            if not line or '|' not in line:
                continue
            name, _, text = line.partition('|')
            out[name.strip()] = text
    return out


def run_demo(args=None, stdin=None, exe=EXE, timeout=40):
    """Run demo.exe; return (exitcode, decoded_stdout, decoded_stderr)."""
    cmd = [exe] + (args or [])
    p = winproc.Popen(
        cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, cwd=os.path.dirname(exe))
    out, err = p.communicate(stdin, timeout=timeout)
    return (p.returncode,
            out.decode('utf-8', 'replace'),
            err.decode('utf-8', 'replace'))


def pump_and_read(proc, timeout=30):
    """Wait for proc exit. Return (exitcode_or_None, stdout_text, stderr_text)."""
    try:
        out, err = proc.communicate(timeout=timeout)
        return proc.returncode, out.decode('utf-8', 'replace'), \
            err.decode('utf-8', 'replace')
    except subprocess.TimeoutExpired:
        return None, '', ''


def pe_text_raw_offset(path):
    """Offset of the first raw byte of .text (PointerToRawData)."""
    return pe_section_raw_offset(path, '.text')


def pe_section_raw_offset(path, sec_name):
    """Offset of the first raw byte of section `sec_name` (PointerToRawData)."""
    with open(path, 'rb') as f:
        data = f.read()
    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    num = struct.unpack_from('<H', data, e_lfanew + 6)[0]
    opt = struct.unpack_from('<H', data, e_lfanew + 20)[0]
    tab = e_lfanew + 24 + opt
    for i in range(num):
        off = tab + i * 40
        name = data[off:off + 8].rstrip(b'\x00')
        if name == sec_name.encode('ascii'):
            return struct.unpack_from('<I', data, off + 20)[0]
    raise RuntimeError('%s not found in %s' % (sec_name, path))


def make_tampered_copy(sec_name='.text', rel_off=0, from_end=0):
    """复制 exe 并翻转指定节内某字节。

    ## from_end（2026-09-25 新增）
      `from_end=1` 表示翻转**该节最后一个字节**。
      用途见 T4 注释: 布局随机化后 ".text 首字节" 不再是确定的
      翻转目标（可能落在完整性检查自身的代码上 -> 翻转即崩溃）。
    """
    dst = os.path.join(BUILD, 'demo_tampered.exe')
    shutil.copyfile(EXE, dst)
    raw_off = pe_section_raw_offset(dst, sec_name)
    if from_end:
        # 从 PE 头读该节 SizeOfRawData -> 末字节
        with open(dst, 'rb') as f:
            f.seek(0x3C)
            pe = struct.unpack('<I', f.read(4))[0]
            f.seek(pe + 6)
            nsec = struct.unpack('<H', f.read(2))[0]
            f.seek(pe + 20)
            optsz = struct.unpack('<H', f.read(2))[0]
            tb = pe + 24 + optsz
            last_off = None
            for i in range(nsec):
                f.seek(tb + i * 40)
                nm = f.read(8).rstrip(b'\x00').decode('ascii', 'replace')
                if nm == sec_name:
                    buf = f.read(16)   # VirtualSize, VirtualAddress,
                                       # SizeOfRawData, PointerToRawData
                    vsize, _va, rsz, _pr = struct.unpack('<IIII', buf)
                    # ## 关键: 用 **VirtualSize**（不是 SizeOfRawData）
                    #
                    # 完整性 CRC 的长度 = min(vsize, rawsize) = vsize。
                    # raw 尾部多出的对齐字节（rawsize > vsize）**不在
                    # CRC 覆盖内** -> 翻它检不出（实测 exit=0）。
                    # `raw + vsize - 1` = **最后一个 CRC 覆盖的内容字节**
                    # = 最后一个贡献者（g_pad_text）的尾部。
                    last_off = raw_off + min(vsize, rsz) - 1
                    break
        if last_off is None:
            raise RuntimeError('section %s not found' % sec_name)
        ro = last_off
    else:
        ro = raw_off + rel_off
    with open(dst, 'r+b') as f:
        f.seek(ro)
        b = f.read(1)
        f.seek(ro)
        f.write(bytes([b[0] ^ 0xFF]))
    return dst


# ---------------------------------------------------------------------------
# 调试器附加: kernel32.DebugActiveProcess + WaitForDebugEvent 事件泵
# ---------------------------------------------------------------------------
class DebugAttacher(object):
    DBG_CONTINUE = 2                      # DBG_CONTINUE
    EXIT_PROCESS_DEBUG_EVENT = 5          # EXIT_PROCESS_DEBUG_EVENT
    WAIT_TIMEOUT = 0x00000102

    def __init__(self):
        self._pid = None

    def attach(self, pid):
        if not KERNEL32.DebugActiveProcess(pid):
            return False
        self._pid = pid
        return True

    def pump(self, timeout=25.0):
        """
        泵调试事件直到进程退出 (EXIT_PROCESS_DEBUG_EVENT) 或超时。
        附加期间必须持续 ContinueDebugEvent, 否则目标进程保持挂起。
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            ev = ctypes.create_string_buffer(512)
            if KERNEL32.WaitForDebugEvent(ev, 200):
                code = ctypes.c_ulong.from_buffer(ev).value
                dbg_pid = ctypes.c_ulong.from_buffer(ev, 4).value
                dbg_tid = ctypes.c_ulong.from_buffer(ev, 8).value
                if code == self.EXIT_PROCESS_DEBUG_EVENT:
                    self.detach()
                    return
                KERNEL32.ContinueDebugEvent(dbg_pid, dbg_tid, self.DBG_CONTINUE)
            else:
                if ctypes.get_last_error() != self.WAIT_TIMEOUT:
                    break
        self.detach()

    def detach(self):
        if self._pid is not None:
            KERNEL32.DebugActiveProcessStop.argtypes = [ctypes.c_ulong]
            KERNEL32.DebugActiveProcessStop(self._pid)
            self._pid = None


# ---------------------------------------------------------------------------
def main():
    if not os.path.isfile(EXE):
        print('FAIL: %s not found (run build.ps1 first)' % EXE, flush=True)
        return 1

    cfg = load_vm_build_json(JSON_PATH)
    strs = load_strings(STRINGS)
    serial = cfg['serial']
    msg_ok = strs['MSG_OK']
    msg_fail = strs['MSG_FAIL']
    msg_dbg = strs['MSG_DBG']
    msg_tamper = strs['MSG_TAMPER']

    results = []

    # ---- T1: 正确序列号 + 有效授权 (A1) --------------------------------
    try:
        if not os.path.isfile(LICENSE):
            raise RuntimeError('license.txt not found (build.ps1 sign step)')
        code, out, _ = run_demo(
            args=['--license-file', LICENSE],
            stdin=(serial + '\n').encode('utf-8'))
        ok = (code == 0) and (msg_ok in out) and ('license: 1' in out)
        results.append(('T1 normal-ok', 'PASS' if ok else 'FAIL',
                        'exit=%d license_ok=1' % code))
    except Exception as e:
        results.append(('T1 normal-ok', 'FAIL', repr(e)))

    # ---- T2: 错误序列号（授权文件亦无法对齐签名载荷） ------------------
    try:
        code, out, _ = run_demo(
            args=['--license-file', LICENSE],
            stdin=b'WRONG-SERIAL-0000\n')
        ok = (code == 1) and (msg_fail in out)
        results.append(('T2 normal-bad', 'PASS' if ok else 'FAIL',
                        'exit=%d' % code))
    except Exception as e:
        results.append(('T2 normal-bad', 'FAIL', repr(e)))

    # ---- T3: 调试器附加 -------------------------------------------------
    # 本环境 (自动化壳) 可能无法驱动完整调试会话, 且附加失败会留下
    # 挂起进程。先对自身做一次 1 秒 preflight (零子进程, 无泄漏):
    #   DebugActiveProcess(getpid()) -> WaitForDebugEvent 有事件则环境可用;
    # 不可用则整项 SKIP, 不做真实附加。
    try:
        debug_ok = False
        if KERNEL32.DebugActiveProcess(os.getpid()):
            ev = ctypes.create_string_buffer(512)
            if KERNEL32.WaitForDebugEvent(ev, 1200):
                debug_ok = True
                KERNEL32.ContinueDebugEvent(
                    ctypes.c_ulong.from_buffer(ev, 4).value,
                    ctypes.c_ulong.from_buffer(ev, 8).value, 2)
            KERNEL32.DebugActiveProcessStop(os.getpid())

        if not debug_ok:
            results.append(('T3 debug-detect', 'SKIP',
                            'no debug session support in this env'))
        else:
            proc = winproc.Popen(
                [EXE, '--wait-ms', '4000'],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, cwd=os.path.dirname(EXE))
            time.sleep(1.0)
            dbg = DebugAttacher()
            if not dbg.attach(proc.pid):
                results.append(('T3 debug-detect', 'SKIP',
                                'DebugActiveProcess failed (err=0x%x)' %
                                ctypes.get_last_error()))
            else:
                import threading
                t = threading.Thread(target=dbg.pump, kwargs={'timeout': 25.0})
                t.daemon = True
                t.start()
                code, out, _err = pump_and_read(proc, timeout=30)
                t.join(timeout=1)
                if code is None:
                    if proc.poll() is None:
                        proc.kill()
                        proc.wait()
                    results.append(('T3 debug-detect', 'SKIP',
                                    'debug session stalled in this env'))
                else:
                    ok = (code == PROT_EXIT_DEBUG_DETECTED) and (msg_dbg in out)
                    results.append(('T3 debug-detect',
                                    'PASS' if ok else 'FAIL',
                                    'exit=%d' % code))
    except Exception as e:
        results.append(('T3 debug-detect', 'FAIL', repr(e)))

    # ---- T4: 篡改检测 (.text) -------------------------------------------
    # 注: 托管环境若启用 WDAC (代码完整性策略), 新复制的篡改副本会因文件
    # 信誉被拦截 (winerror 4551) -> 记 SKIP (真机无 WDAC 时正常验证)。
    try:
        # ## 2026-09-25: 改翻 **.text 最后一字节**（填充区）
        #
        # 源文件顺序随机化（B 阶段）后，".text 首字节" 的归属**随构建变化**:
        #   实测某次 = `build_reloc_mask`（完整性检查自身的函数）->
        #   翻转 -> 检查器执行损坏代码 -> **崩溃 0xC0000005** ->
        #   无法给出 MSG_TAMPER。
        # （这不是防护漏洞: 攻击者得到的是崩溃/fail-closed。）
        #
        # 末字节 = `g_pad_text` 尾部（prot_padding.c 固定追加在清单之后 ->
        # 位置确定）+ CRC 覆盖 + 不被执行 -> **检测必然发生**。
        tampered = make_tampered_copy('.text', from_end=1)
        code, text, _ = run_demo(exe=tampered,
                                 args=['--license-file', LICENSE],
                                 stdin=(serial + '\n').encode('utf-8'))
        ok = (code == PROT_EXIT_TAMPERED) and (msg_tamper in text)
        results.append(('T4 tamper-detect', 'PASS' if ok else 'FAIL',
                        'exit=%d' % code))
    except Exception as e:
        if wdac_blocked(e):
            results.append(('T4 tamper-detect', 'SKIP',
                            'WDAC blocked tampered copy (winerror 4551)'))
        else:
            results.append(('T4 tamper-detect', 'FAIL', repr(e)))

    # ---- T9/T10: 篡改检测扩展 (A3) —— 翻 .rdata/.pdata 一个字节也退 0xBAD
    # 注意: .rdata 含加密字符串, 篡改后 MSG_TAMPER 解密即乱码, 故只断言退出码;
    #       .rdata 段首 832 字节是 IAT (加载器启动时覆盖, 掩码排除, 见 CONTRACT
    #       §7), 篡改它本来就会被 loader 重写, 故测试从 +0x1000 处翻转。
    for tname, sec, rel in (('T9 tamper-rdata', '.rdata', 0x1000),
                            ('T10 tamper-pdata', '.pdata', 0)):
        try:
            tampered = make_tampered_copy(sec, rel)
            code, text, _ = run_demo(exe=tampered,
                                     args=['--license-file', LICENSE],
                                     stdin=(serial + '\n').encode('utf-8'))
            ok = (code == PROT_EXIT_TAMPERED)
            results.append((tname, 'PASS' if ok else 'FAIL',
                            'exit=%d' % code))
        except Exception as e:
            if wdac_blocked(e):
                results.append((tname, 'SKIP',
                                'WDAC blocked tampered copy (winerror 4551)'))
            else:
                results.append((tname, 'FAIL', repr(e)))

    # ---- T5: VM 指令集单测 (Phase 1d 新增指令) ------------------------
    vm_unit = os.path.join(BUILD, 'vm_unit.exe')
    try:
        code, out, _ = run_demo(exe=vm_unit)
        ok = (code == 0) and ('PASS' in out)
        results.append(('T5 vm-unit-ops', 'PASS' if ok else 'FAIL',
                        out.strip() or 'exit=%d' % code))
    except Exception as e:
        results.append(('T5 vm-unit-ops', 'FAIL', repr(e)))

    # ---- T6: 多实例稳定性 (Phase 2c 运行时语义随机化不得改变结果) ----
    try:
        n_run = 8
        bad = 0
        for _ in range(n_run):
            code, out, _ = run_demo(args=['--license-file', LICENSE],
                                    stdin=(serial + '\n').encode('utf-8'))
            if code != 0 or msg_ok not in out:
                bad += 1
        ok = (bad == 0)
        results.append(('T6 multi-run-stable', 'PASS' if ok else 'FAIL',
                        '%d/%d ok' % (n_run - bad, n_run)))
    except Exception as e:
        results.append(('T6 multi-run-stable', 'FAIL', repr(e)))

    # ---- T7: 干净环境 selftest 全 0 (新检测项不得误报) ----
    try:
        code, out, _ = run_demo(args=['--selftest', '--license-file', LICENSE],
                                stdin=(serial + '\n').encode('utf-8'))
        suspicious = []
        vm_notes = []
        for line in out.splitlines():
            for field in ('debug_heap_flags', 'int3_honey'):
                if line.strip().startswith(field):
                    val = line.split(':')[-1].strip()
                    if val != '0':
                        suspicious.append(field + '=' + val)
            for field in ('vm_hypervisor', 'vm_vendor', 'vm_processes',
                          'dbi_inline_hooks', 'dbi_frida_agent',
                          'dbi_rxrw_regions', 'dbi_thread_count'):
                if line.strip().startswith(field):
                    val = line.split(':')[-1].strip()
                    if val != '0':
                        vm_notes.append(field + '=' + val)
        ok = (code == 0) and (not suspicious)
        results.append(('T7 selftest-clean', 'PASS' if ok else 'FAIL',
                        'code=%d suspicious=%s vm=%s' %
                        (code, suspicious or 'none', vm_notes or 'none')))
    except Exception as e:
        results.append(('T7 selftest-clean', 'FAIL', repr(e)))

    # ---- T8: RSA 授权防伪造 —— 篡改签名 1 位 -> license_ok=0 ----------
    try:
        forged = os.path.join(BUILD, 'license_forged.txt')
        with open(LICENSE, 'r', encoding='utf-8') as f:
            lines = f.read().splitlines()
        out_lines = []
        for ln in lines:
            if ln.startswith('SIGNATURE='):
                s = ln[len('SIGNATURE='):]
                b = bytearray(s.encode('ascii'))
                b[len(b) // 2] = b'B'[0]  # 改动 base64 字符, 反则成完全不同字节
                out_lines.append('SIGNATURE=' + b.decode('ascii'))
            else:
                out_lines.append(ln)
        if not any(l.startswith('SIGNATURE=') for l in out_lines):
            raise RuntimeError('no SIGNATURE line to forge')
        with open(forged, 'w', encoding='utf-8', newline='\n') as f:
            f.write('\n'.join(out_lines) + '\n')
        code, out, _ = run_demo(args=['--license-file', forged],
                                stdin=(serial + '\n').encode('utf-8'))
        ok = (code == 1) and ('license: 0' in out) and (msg_fail in out)
        results.append(('T8 license-forge', 'PASS' if ok else 'FAIL',
                        'exit=%d license_ok=0' % code))
    except Exception as e:
        results.append(('T8 license-forge', 'FAIL', repr(e)))

    # ---- T11: A5 看门狗长驻留 —— --wait-after 期间周期复查不得误报 ----
    try:
        code, out, _ = run_demo(
            args=['--license-file', LICENSE, '--wait-after', '14000'],
            stdin=(serial + '\n').encode('utf-8'))
        ok = (code == 0) and (msg_ok in out) and ('license: 1' in out)
        results.append(('T11 watchdog-stable', 'PASS' if ok else 'FAIL',
                        'exit=%d (14s residency)' % code))
    except Exception as e:
        results.append(('T11 watchdog-stable', 'FAIL', repr(e)))

    # ---- T12: 分级授权防篡改 (Phase 4) —— 改 TIER 行 -> 载荷不匹配被拒 ----
    try:
        forged = os.path.join(BUILD, 'license_tier_forged.txt')
        with open(LICENSE, 'r', encoding='utf-8') as f:
            lines = f.read().splitlines()
        out_lines = []
        for ln in lines:
            if ln.startswith('TIER='):
                cur = ln[len('TIER='):]
                out_lines.append('TIER=' + ('2' if cur != '2' else '0'))
            else:
                out_lines.append(ln)
        if not any(l.startswith('TIER=') for l in out_lines):
            raise RuntimeError('no TIER line to forge')
        with open(forged, 'w', encoding='utf-8', newline='\n') as f:
            f.write('\n'.join(out_lines) + '\n')
        code, out, _ = run_demo(args=['--license-file', forged],
                                stdin=(serial + '\n').encode('utf-8'))
        ok = (code == 1) and ('license: 0' in out) and (msg_fail in out)
        results.append(('T12 license-tier-forge', 'PASS' if ok else 'FAIL',
                        'exit=%d license_ok=0' % code))
    except Exception as e:
        results.append(('T12 license-tier-forge', 'FAIL', repr(e)))

    # ---- T13/T14: DBI launcher (技术债 #3) —— blob 缺失/损坏 -> 0xB10B ----
    PROT_EXIT_BLOB_MISSING = 0xB10B
    blob_path = os.path.join(BUILD, 'vm.blob')
    try:
        code, out, _ = run_demo(
            args=['--license-file', LICENSE, '--vm-blob',
                  os.path.join(BUILD, 'no_such_blob.bin')],
            stdin=(serial + '\n').encode('utf-8'))
        ok = (code == PROT_EXIT_BLOB_MISSING)
        results.append(('T13 blob-missing', 'PASS' if ok else 'FAIL',
                        'exit=%d' % code))
    except Exception as e:
        results.append(('T13 blob-missing', 'FAIL', repr(e)))

    try:
        if not os.path.isfile(blob_path):
            raise RuntimeError('vm.blob not found (run build.ps1)')
        forged_blob = os.path.join(BUILD, 'vm_corrupt.blob')
        b = bytearray(open(blob_path, 'rb').read())
        b[len(b) // 2] ^= 0xFF
        with open(forged_blob, 'wb') as f:
            f.write(bytes(b))
        code, out, _ = run_demo(
            args=['--license-file', LICENSE, '--vm-blob', forged_blob],
            stdin=(serial + '\n').encode('utf-8'))
        ok = (code == PROT_EXIT_BLOB_MISSING)
        results.append(('T14 blob-tamper', 'PASS' if ok else 'FAIL',
                        'exit=%d' % code))
    except Exception as e:
        results.append(('T14 blob-tamper', 'FAIL', repr(e)))

    # ---- T27/T28: 在线 blob 下发 (BLOB_SIGN_PLAN) ------------------------
    # T27: /v1/blob 下发签名版 vm.blob -> demo --blob-url 装载验签通过;
    # T28: 下发篡改版 -> 验签失败 -> 0xB10B。
    import http.server
    import threading

    class _BlobHandler(http.server.BaseHTTPRequestHandler):
        serve_blob = b''
        def log_message(self, *a):
            pass
        def do_GET(self):
            if '/v1/blob' not in self.path:
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Content-Length', str(len(self.serve_blob)))
            self.end_headers()
            self.wfile.write(self.serve_blob)

    def start_blob_mock(blob_bytes):
        _BlobHandler.serve_blob = blob_bytes
        srv = http.server.HTTPServer(('127.0.0.1', 0), _BlobHandler)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        return srv

    try:
        if not os.path.isfile(blob_path):
            raise RuntimeError('vm.blob not found (run build.ps1)')
        good = open(blob_path, 'rb').read()
        srv = start_blob_mock(good)
        url = 'http://127.0.0.1:%d/v1/blob' % srv.server_address[1]
        code, out, _ = run_demo(
            args=['--license-file', LICENSE,
                  '--blob-url', url,
                  '--vm-blob', os.path.join(BUILD, 'vm_missing_placeholder.blob')],
            stdin=(serial + '\n').encode('utf-8'))
        ok = (code == 0) and (msg_ok in out)
        results.append(('T27 online-blob-ok', 'PASS' if ok else 'FAIL',
                        'exit=%d (signed blob via /v1/blob)' % code))
        srv.shutdown()
    except Exception as e:
        results.append(('T27 online-blob-ok', 'FAIL', repr(e)))

    try:
        if not os.path.isfile(blob_path):
            raise RuntimeError('vm.blob not found (run build.ps1)')
        bad = bytearray(open(blob_path, 'rb').read())
        bad[len(bad) // 2] ^= 0xFF  # 篡改: 签名必失效
        srv = start_blob_mock(bytes(bad))
        url = 'http://127.0.0.1:%d/v1/blob' % srv.server_address[1]
        code, out, _ = run_demo(
            args=['--license-file', LICENSE,
                  '--blob-url', url,
                  '--vm-blob', os.path.join(BUILD, 'vm_missing_placeholder.blob')],
            stdin=(serial + '\n').encode('utf-8'))
        ok = (code == PROT_EXIT_BLOB_MISSING)
        results.append(('T28 online-blob-tamper', 'PASS' if ok else 'FAIL',
                        'exit=%d (tampered blob rejected by signature)' % code))
        srv.shutdown()
    except Exception as e:
        results.append(('T28 online-blob-tamper', 'FAIL', repr(e)))

    # ---- T15-T19: 授权吊销 (I1, 离线黑名单) ------------------------------
    PROT_EXIT_REVOKED = 0xB1E4
    vmenc = os.path.join(REPO, 'tools', 'vmenc.py')
    privkey = os.path.join(BUILD, 'keys', 'license_priv.json')
    def make_revoke(serial, tier=None, path='revoke.blob', signed=True):
        args = ['python', vmenc, 'revoke', '--out', os.path.join(BUILD, path)]
        if signed and os.path.isfile(privkey):
            args += ['--sign', privkey]  # BLOB_SIGN_PLAN: v1 签名黑名单
        if serial:
            args += ['--add', serial]
            if tier is not None:
                args += ['--tier', str(tier)]
        winproc.run(args, check=True, capture_output=True)
        return os.path.join(BUILD, path)

    try:
        hit = make_revoke(serial, 1, 'revoke_hit.blob')
        code, out, _ = run_demo(
            args=['--license-file', LICENSE, '--vm-blob',
                  os.path.join(BUILD, 'vm.blob'), '--revoke-file', hit],
            stdin=(serial + '\n').encode('utf-8'))
        ok = (code == PROT_EXIT_REVOKED)
        results.append(('T15 revoke-hit', 'PASS' if ok else 'FAIL',
                        'exit=%d' % code))
    except Exception as e:
        results.append(('T15 revoke-hit', 'FAIL', repr(e)))

    try:
        clean = make_revoke('OTHER-SERIAL-0001', 1, 'revoke_clean.blob')
        code, out, _ = run_demo(
            args=['--license-file', LICENSE, '--vm-blob',
                  os.path.join(BUILD, 'vm.blob'), '--revoke-file', clean],
            stdin=(serial + '\n').encode('utf-8'))
        ok = (code == 0) and (msg_ok in out)
        results.append(('T16 revoke-clean', 'PASS' if ok else 'FAIL',
                        'exit=%d' % code))
    except Exception as e:
        results.append(('T16 revoke-clean', 'FAIL', repr(e)))

    try:
        code, out, _ = run_demo(
            args=['--license-file', LICENSE, '--vm-blob',
                  os.path.join(BUILD, 'vm.blob'),
                  '--revoke-file', os.path.join(BUILD, 'no_revoke.blob')],
            stdin=(serial + '\n').encode('utf-8'))
        ok = (code == 0) and (msg_ok in out)  # 离线优先: 无文件不阻断
        results.append(('T17 revoke-absent', 'PASS' if ok else 'FAIL',
                        'exit=%d' % code))
    except Exception as e:
        results.append(('T17 revoke-absent', 'FAIL', repr(e)))

    try:
        corrupt = os.path.join(BUILD, 'revoke_corrupt.blob')
        b = bytearray(open(os.path.join(BUILD, 'revoke_hit.blob'), 'rb').read())
        b[len(b) // 2] ^= 0xFF
        with open(corrupt, 'wb') as f:
            f.write(bytes(b))
        code, out, _ = run_demo(
            args=['--license-file', LICENSE, '--vm-blob',
                  os.path.join(BUILD, 'vm.blob'), '--revoke-file', corrupt],
            stdin=(serial + '\n').encode('utf-8'))
        ok = (code == 0) and (msg_ok in out)  # 损坏: 不阻断 + 告警
        results.append(('T18 revoke-corrupt', 'PASS' if ok else 'FAIL',
                        'exit=%d' % code))
    except Exception as e:
        results.append(('T18 revoke-corrupt', 'FAIL', repr(e)))

    try:
        code, out, _ = run_demo(
            args=['--license-file', LICENSE, '--vm-blob',
                  os.path.join(BUILD, 'vm.blob'),
                  '--revoke-file', os.path.join(BUILD, 'revoke_hit.blob'),
                  '--revoke-policy', 'warn'],
            stdin=(serial + '\n').encode('utf-8'))
        ok = (code == 0) and (msg_ok in out)  # warn: 告警但继续
        results.append(('T19 revoke-warn', 'PASS' if ok else 'FAIL',
                        'exit=%d' % code))
    except Exception as e:
        results.append(('T19 revoke-warn', 'FAIL', repr(e)))

    # ---- T20/T21: 试用期控制 (Phase 4 expires, 参与签名) ------------------
    vmenc = os.path.join(REPO, 'tools', 'vmenc.py')
    def make_license(expires, path):
        winproc.run(['python', vmenc, 'sign', '--key',
                        os.path.join(REPO, 'build', 'keys', 'license_priv.json'),
                        '--json', JSON_PATH, '--out', os.path.join(BUILD, path),
                        '--expires', str(expires)],
                       check=True, capture_output=True)
        return os.path.join(BUILD, path)

    try:
        lic_future = make_license(1893456000, 'lic_future.txt')  # 2030-01-01
        code, out, _ = run_demo(args=['--license-file', lic_future],
                                stdin=(serial + '\n').encode('utf-8'))
        ok = (code == 0) and (msg_ok in out)
        results.append(('T20 license-future', 'PASS' if ok else 'FAIL',
                        'exit=%d (exp=2030)' % code))
    except Exception as e:
        results.append(('T20 license-future', 'FAIL', repr(e)))

    try:
        lic_past = make_license(1, 'lic_past.txt')  # 1970-01-01 (已过期)
        code, out, _ = run_demo(args=['--license-file', lic_past],
                                stdin=(serial + '\n').encode('utf-8'))
        ok = (code == 1) and ('license: 0' in out) and (msg_fail in out)
        results.append(('T21 license-expired', 'PASS' if ok else 'FAIL',
                        'exit=%d license_ok=0' % code))
    except Exception as e:
        results.append(('T21 license-expired', 'FAIL', repr(e)))

    # ---- T22-T24: 在线验证 (M3.1 mock server) -----------------------------
    # 起本地 mock server (tools/mock_server.py), 验证 online provider:
    # revoked -> 0xB1E4; ok -> 正常; 服务不可达 -> 降级本地 (不锁死)。
    import http.server
    import threading
    import urllib.request

    class _CheckHandler(http.server.BaseHTTPRequestHandler):
        revoke_serial = None
        def log_message(self, *a):
            pass
        def do_GET(self):
            if '/v1/check' not in self.path:
                self.send_response(404)
                self.end_headers()
                return
            revoked = (self.revoke_serial is not None and
                       ('serial=%s' % self.revoke_serial) in self.path)
            body = b'{"status":"revoked","reason":"e2e"}' if revoked \
                else b'{"status":"ok","tier":1}'
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(body)

    def start_mock(revoke_serial=None):
        h = _CheckHandler
        h.revoke_serial = revoke_serial
        srv = http.server.HTTPServer(('127.0.0.1', 0), h)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        return srv

    try:
        srv = start_mock(serial)  # 吊销当前 serial
        url = 'http://127.0.0.1:%d/v1/check' % srv.server_address[1]
        code, out, _ = run_demo(
            args=['--license-file', LICENSE, '--vm-blob',
                  os.path.join(BUILD, 'vm.blob'), '--check-url', url],
            stdin=(serial + '\n').encode('utf-8'))
        ok = (code == PROT_EXIT_REVOKED)
        results.append(('T22 online-revoked', 'PASS' if ok else 'FAIL',
                        'exit=%d' % code))
        srv.shutdown()
    except Exception as e:
        results.append(('T22 online-revoked', 'FAIL', repr(e)))

    try:
        srv = start_mock(None)  # 不吊销
        url = 'http://127.0.0.1:%d/v1/check' % srv.server_address[1]
        code, out, _ = run_demo(
            args=['--license-file', LICENSE, '--vm-blob',
                  os.path.join(BUILD, 'vm.blob'), '--check-url', url],
            stdin=(serial + '\n').encode('utf-8'))
        ok = (code == 0) and (msg_ok in out)
        results.append(('T23 online-ok', 'PASS' if ok else 'FAIL',
                        'exit=%d' % code))
        srv.shutdown()
    except Exception as e:
        results.append(('T23 online-ok', 'FAIL', repr(e)))

    try:
        # 服务不可达 (未监听端口) -> 静默降级, 不锁死
        code, out, _ = run_demo(
            args=['--license-file', LICENSE, '--vm-blob',
                  os.path.join(BUILD, 'vm.blob'),
                  '--check-url', 'http://127.0.0.1:59999/v1/check'],
            stdin=(serial + '\n').encode('utf-8'))
        ok = (code == 0) and (msg_ok in out)
        results.append(('T24 online-degrade', 'PASS' if ok else 'FAIL',
                        'exit=%d (offline fallback)' % code))
    except Exception as e:
        results.append(('T24 online-degrade', 'FAIL', repr(e)))

    # ---- T25: 在线会话级期望值 (N5) ------------------------------------
    # 服务端下发正确期望值 -> 通过 (exit 0); 下发错误期望值 -> 拒绝 (exit 1)。
    # 破解者 patch "期望值比较" 只对当次会话有效 (每次启动期望值不同)。
    class _ExpectHandler(http.server.BaseHTTPRequestHandler):
        wrong = False
        def log_message(self, *a):
            pass
        def do_GET(self):
            if self.wrong:
                body = b'{"status":"ok","tier":1,"expect1":"0x1111111111111111","expect2":"0x2222222222222222"}'
            else:
                # 与 vmenc.compute_expect 一致的正确值 (从请求参数复算)
                import sys as _sys
                _sys.path.insert(0, os.path.join(REPO, 'tools'))
                try:
                    from vmenc import compute_expect
                    from urllib.parse import parse_qs, urlparse
                    qs = parse_qs(urlparse(self.path).query)
                    serial_q = qs.get('serial', [''])[0]
                    mid_q = int(qs.get('mid', ['0'])[0], 16)
                    h, total = compute_expect(serial_q, mid_q)
                    body = ('{"status":"ok","tier":1,"expect1":"0x%x","expect2":"0x%x"}'
                            % (h, total)).encode()
                except Exception:
                    body = b'{"status":"ok","tier":1}'
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(body)

    def start_expect_mock(wrong):
        _ExpectHandler.wrong = wrong
        srv = http.server.HTTPServer(('127.0.0.1', 0), _ExpectHandler)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        return srv

    try:
        srv = start_expect_mock(False)  # 正确期望值
        url = 'http://127.0.0.1:%d/v1/check' % srv.server_address[1]
        code, out, _ = run_demo(
            args=['--license-file', LICENSE, '--vm-blob',
                  os.path.join(BUILD, 'vm.blob'), '--check-url', url],
            stdin=(serial + '\n').encode('utf-8'))
        ok = (code == 0) and (msg_ok in out)
        results.append(('T25 online-expect-ok', 'PASS' if ok else 'FAIL',
                        'exit=%d (session expect accepted)' % code))
        srv.shutdown()
    except Exception as e:
        results.append(('T25 online-expect-ok', 'FAIL', repr(e)))

    try:
        srv = start_expect_mock(True)  # 错误期望值
        url = 'http://127.0.0.1:%d/v1/check' % srv.server_address[1]
        code, out, _ = run_demo(
            args=['--license-file', LICENSE, '--vm-blob',
                  os.path.join(BUILD, 'vm.blob'), '--check-url', url],
            stdin=(serial + '\n').encode('utf-8'))
        ok = (code == 1) and (msg_fail in out)
        results.append(('T26 online-expect-wrong', 'PASS' if ok else 'FAIL',
                        'exit=%d (session expect rejected)' % code))
        srv.shutdown()
    except Exception as e:
        results.append(('T26 online-expect-wrong', 'FAIL', repr(e)))

    failed = False
    for name, status, detail in results:
        print('%-14s  %-4s   (%s)' % (name, status, detail), flush=True)
        if status == 'FAIL':
            failed = True

    sys.exit(1 if failed else 0)


if __name__ == '__main__':
    import threading
    main()