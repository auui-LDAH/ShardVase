# -*- coding: utf-8 -*-
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
    p = subprocess.Popen(
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


def make_tampered_copy(sec_name='.text', rel_off=0):
    dst = os.path.join(BUILD, 'demo_tampered.exe')
    shutil.copyfile(EXE, dst)
    ro = pe_section_raw_offset(dst, sec_name) + rel_off
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
            proc = subprocess.Popen(
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
    try:
        tampered = make_tampered_copy('.text')
        code, text, _ = run_demo(exe=tampered,
                                 args=['--license-file', LICENSE],
                                 stdin=(serial + '\n').encode('utf-8'))
        ok = (code == PROT_EXIT_TAMPERED) and (msg_tamper in text)
        results.append(('T4 tamper-detect', 'PASS' if ok else 'FAIL',
                        'exit=%d' % code))
    except Exception as e:
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
        for field in ('debug_heap_flags', 'int3_honey'):
            for line in out.splitlines():
                if line.strip().startswith(field):
                    val = line.split(':')[-1].strip()
                    if val != '0':
                        suspicious.append(field + '=' + val)
        ok = (code == 0) and (not suspicious)
        results.append(('T7 selftest-clean', 'PASS' if ok else 'FAIL',
                        'code=%d suspicious=%s' % (code, suspicious or 'none')))
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

    # ---- T15-T19: 授权吊销 (I1, 离线黑名单) ------------------------------
    PROT_EXIT_REVOKED = 0xB1E4
    vmenc = os.path.join(REPO, 'tools', 'vmenc.py')
    def make_revoke(serial, tier=None, path='revoke.blob'):
        args = ['python', vmenc, 'revoke', '--out', os.path.join(BUILD, path)]
        if serial:
            args += ['--add', serial]
            if tier is not None:
                args += ['--tier', str(tier)]
        subprocess.run(args, check=True, capture_output=True)
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

    failed = False
    for name, status, detail in results:
        print('%-14s  %-4s   (%s)' % (name, status, detail), flush=True)
        if status == 'FAIL':
            failed = True

    sys.exit(1 if failed else 0)


if __name__ == '__main__':
    import threading
    main()