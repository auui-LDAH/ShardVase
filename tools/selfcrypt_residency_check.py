#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""selfcrypt_residency_check.py — D2c **驻留期密文态**门禁（2026-10-06）

## 被检查的不变量

    「`prot_selfcrypt_init()` 返回之后、任何 `enter/leave(组 0)` 开窗之前，
      selfcrypt **组 0**（VM 引擎调用链）各条目在**进程内存里必须是磁盘密文**
      —— 逐字节等于 `build/demo.exe` 中同区间的字节。」

    组 1（EXT 扩展组）**不在**本判据内：看门狗每轮自己开/关一次 EXT 窗口
    （`src/integrity.c:188` enter / `:256` leave），窗口内它**就该**是明文。

## 为什么需要（**这不是假想的风险, 是刚踩过的坑**）

    D2b 的旧实现把**全部** n 条解密并**留在明文态** —— 从 `prot_selfcrypt_init()`
    返回到首次 `leave(组)` 之间存在一个**全量明文驻留窗口**: 实测自然路径
    ~0.66 s、`--wait-ms 6000` 时 ~6.67 s（`docs/HANDOVER.md` §2.35）。
    这段时间里本项目的承诺「非调用时刻内存是密文」（`docs/N1_PHASE2_PLAN.md`
    §威胁边界: dump 抓不到明文引擎）**不成立**。

    修法是 D2c（`c2666b9`）：init 逐条解密 + 逐条 CRC 校验，**校验完立即回密**。
    但当时那轮验证是**一次性手工探针**（`build/_d2c_truth.py`，在 gitignored 的
    `build/` 下）—— 门禁里**没有**自动判据 ⇒ 这条不变量**回归了不会有测试变红**，
    而它恰恰是 D2b 那片注释块反复承诺的东西。与 §2.32「陈旧复选框」、
    T11 的「P5 只判不得直接 E8 调用」同型: **机制在、门禁不在**。
    本文件就是把这个空白补上。

## 判据（① 是前提，②③④ 缺一不可）

    ① 组 0 条目数 > 0 —— 否则判据**空转**，直接 FAIL，不静默通过；
    ② `g_sc_d2b_enabled == 1` —— 编译期开关真在产物里生效。为 0 说明 D2c 的
       回密循环**根本没编进去**（`src/selfcrypt.c:348-354` 在
       `#ifdef PROT_SELFCRYPT_D2B` 内）；单列这一条是为了让报告能区分
       「D2c 回归」与「D2b 没编译进来」，而不是笼统一句 FAIL；
    ③ 采样轮数 >= MIN_SAMPLES —— **「读不到」 != 「不存在」**。一条采样都没
       拿到、或读内存失败，必须 FAIL，不许被读成「没发现问题」；
    ④ 每一轮采样里，组 0 **每一条**目的内存字节都**逐字节**等于磁盘密文。
       任何一条不等（含只等一部分）即 FAIL，并给出首个不符的**轮次与字节位**。

    ⚠️ 判据是**失效安全**的: 地址算错 / 节名解析错 / 读内存失败 / 读错区间，
       结果一律是"内存 != 磁盘" ⇒ **红**。**绿**只有一种达成方式 ——
       地址对、字节真的一致。故本判据**不可能**因为管道缺陷而假绿。

## 含负向自检（`--selftest`）

    `judge()` 是**纯函数**（只吃 `entries` / `samples` / `refs`），故自检在内存里
    造数据即可: **不启进程、不写盘、不编译**。4 条变异必须全部被抓:

        M1 组 0 某条某一轮的内存改成"与磁盘不同"（= 回密没生效的签名）
        M2 采样列表清空（无证据）
        M3 组 0 某条某一轮取不到（只等到一部分）
        M4 磁盘参考改 1 个字节（证明比较是**逐字节**的，不是只看长度/前缀）

    基线（真实形态的合成数据）必须**全绿** —— 只红不绿的判据同样是坏的。

## 用法
    python tools/selfcrypt_residency_check.py [--exe PATH] [--map PATH]
                                              [--selftest] [--quiet]
退出码: 0 = 一致; 1 = 漂移; 2 = SKIP（非 Windows / 缺产物 / 无 selfcrypt 目标）

## 为什么能安全地跑
    **只读** 目标进程（只 `ReadProcessMemory`）与 `build/demo.exe` / `.map`；
    起的是**独立进程**（demo.exe `--wait-after` 驻留），不写 `build/`、不编译、
    不改产物。进程经 `tools/winproc.py` 启动（CREATE_NO_WINDOW）—— 本项目硬约束:
    **不弹窗**。

## 诚实边界
    · 仅 Windows（OpenProcess / ReadProcessMemory / Toolhelp32）；非 Windows **SKIP**。
    · 负向自检证明的是**比较器与判据**有判别力（纯数据变异），**不是**端到端地
      另编一个 D2a / 无 D2c 的产物来证明"回归必然变红" —— 那需要第二次构建，
      与本项目"门禁只读、不编译"的纪律冲突。端到端那一半由本项的**正向运行**
      背书: 它真的起进程、真的读内存、真的与磁盘逐字节比。
    · 采样窗口内没有 `enter/leave(组 0)` 调用点（`--wait-after` 在序列号提示
      **之前**，`demo/main.c:740-744`），故本项判的正是「**关窗时必须回密**」；
      窗口内该不该是明文不由本项判断。
    · 本项**不覆盖** `examples/`（该示例管线不接 selfcrypt，`.protcry` 条目数 n=0
      ⇒ 走 SKIP）—— 这条与 `src/selfcrypt.c` D2c 注释里的诚实边界一致。
"""
import argparse
import ctypes
import ctypes.wintypes as wt
import json
import os
import random
import re
import subprocess
import sys
import time

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')


REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXE = os.path.join(REPO, 'build', 'demo.exe')
MAP = os.path.join(REPO, 'build', 'demo.map')
BLOB = os.path.join(REPO, 'build', 'vm.blob')
LICENSE = os.path.join(REPO, 'build', 'license.txt')

PREF = 0x140000000                  # 链接时首选基址（与 build.ps1 一致）
PROCESS_ALL = 0x1F0FFF
READY_TIMEOUT_S = 25.0              # 等模块基址 + 看门狗就绪的上限
SETTLE_S = 0.2                      # 打开进程后的最短稳定等待
KEEP_MS = 30000                     # 让 demo 的驻留窗口远长于采样窗口
OBSERVE_S = 4.0                     # 采样窗口（回归是**持续**的，不是瞬时的）
POLL_S = 0.1                        # 采样间隔
MIN_SAMPLES = 10                    # 少于这么多轮 = 证据不足（见判据③）

D2B_SYM = 'g_sc_d2b_enabled'
READY_SYM = 'g_wd_interval'         # 就绪哨兵，理由见 _wait_ready 的注释

# 路径推导: 从本文件位置向上找含 tools/winproc.py 的目录。
#   统一用 tools/winproc.py 封装（CREATE_NO_WINDOW + STARTUPINFO/SW_HIDE）。
#   一处修好 = 全部修好，且可自检（见 winproc.py 的 --selftest）。
_os_hw = os.path.dirname(os.path.abspath(__file__))
while _os_hw and not os.path.isfile(os.path.join(_os_hw, 'tools', 'winproc.py')):
    _nxt = os.path.dirname(_os_hw)
    if _nxt == _os_hw:
        break
    _os_hw = _nxt
for _d in (os.path.join(_os_hw, 'tools'), os.path.join(_os_hw, 'tests')):
    if _d not in sys.path:
        sys.path.insert(0, _d)
import mapfile                                   # noqa: E402  单一 map 解析实现
import protchain_check as pc                     # noqa: E402  节表 / selfcrypt meta 权威解析
import winproc                                   # noqa: E402  隐藏窗口统一封装
import guard_selftest                            # noqa: E402  Toolhelp32 基址的既有实现


def _group_vm(default=0):
    """组号取自 `include/protect/selfcrypt.h`（`PROT_SELFCRYPT_GROUP_VM`）。

    **不硬编码**: 组号一旦漂移，本判据会**静默地去查另一个组** ——
    那正是本文件存在的理由（"机制在、门禁不在"）的镜像形态。
    """
    p = os.path.join(REPO, 'include', 'protect', 'selfcrypt.h')
    try:
        with open(p, encoding='utf-8') as f:
            t = f.read()
    except OSError:
        return default
    m = re.search(r'#define\s+PROT_SELFCRYPT_GROUP_VM\s+(\d+)\s*u?\b', t)
    return int(m.group(1)) if m else default


GROUP_VM = _group_vm()


# ---------------------------------------------------------------------------
# 判据（纯函数 —— 自检能在内存里变异它，不启进程）
# ---------------------------------------------------------------------------
def disk_refs(data, secs, entries):
    """取每条 selfcrypt 条目在**磁盘产物**里的密文字节 -> (refs, why)。

    换算与 `tests/protchain_check.py:337 p1_selfcrypt_ciphertext` **同一形式**:
    条目 RVA 相对映像基址, 而 `.text` 的文件偏移基准是它的节 RVA。
    越界一律返回 `(None, 原因)` —— 宁 SKIP 不静默。
    """
    text = next((s for s in secs if s['name'] == '.text'), None)
    if text is None:
        return None, '.text 节缺失'
    refs = {}
    for (rva, ln, _g) in entries:
        rel = rva - text['virtual_addr']
        if rel < 0 or rel + ln > text['size_raw']:
            return None, ('rva=0x%x len=%d 超出 .text 原始数据跨度 '
                          '(rel=0x%x size_raw=%d)' % (rva, ln, rel, text['size_raw']))
        off = text['ptr_raw'] + rel
        refs[rva] = data[off:off + ln]
    return refs, ''


def judge(entries, samples, refs):
    """判据本体（**纯函数**）: 组 0 在全部采样轮次都必须是磁盘密文。

        entries  `protchain_check.selfcrypt_meta()` 的输出 [(rva, len, group), ...]
        samples  [{rva: bytes}, ...] 每轮采到的内存字节（取不到则无该 key）
        refs     {rva: bytes}        磁盘密文参考（`disk_refs()` 的产物）

    返回 `[(name, ok, detail), ...]`（`chk` 形态，便于逐条打印与自检对比）。
    """
    checks = []

    def chk(name, cond, detail):
        checks.append((name, bool(cond), detail))

    g0 = [e for e in entries if e[2] == GROUP_VM]
    chk('组 0 条目数 > 0', len(g0) > 0,
        '组 0 %d 条 / 组 1 %d 条' % (len(g0), len(entries) - len(g0)))
    chk('采样轮数 >= %d' % MIN_SAMPLES, len(samples) >= MIN_SAMPLES,
        '%d 轮' % len(samples))

    missing, drifted = [], []
    for (rva, ln, _g) in g0:
        ref = refs.get(rva)
        if ref is None or len(ref) != ln:
            missing.append('rva=0x%x 无磁盘参考（期望 %d B）' % (rva, ln))
            continue
        for i, s in enumerate(samples):
            got = s.get(rva)
            if got is None or len(got) != ln:
                missing.append('rva=0x%x 第 %d 轮取不到（期望 %d B）' % (rva, i, ln))
                break
            if got != ref:
                # 首个不符字节位 —— 定位"只回密了一部分"那种场景
                k = next((j for j in range(ln) if got[j] != ref[j]), 0)
                drifted.append('rva=0x%x 第 %d 轮内存 != 磁盘密文'
                               '（首差 @+0x%x: 内存 %02x / 磁盘 %02x）'
                               % (rva, i, k, got[k], ref[k]))
                break

    chk('组 0 每条目都有磁盘参考', not missing, '; '.join(missing[:3]) or 'ok')
    # ⚠️ 这一条的 detail 必须**说出失败的真正原因**。原实现写成
    #    `'; '.join(drifted[:3]) or ('全部 %d 轮逐字节一致' % len(samples))` ——
    #    当 `g0` 为空（如 `tests/protchain_check.py` 的 group 偏移被读错，
    #    9 条全被判成组 1）时 `drifted` 也是空，于是**判 FAIL 的那一行却打印
    #    「全部 40 轮逐字节一致」**，读日志的人只会看到自相矛盾。
    #    实测出处：build/logs/release_check_20261009_041442.log（§2.52）。
    if not g0:
        d4 = ('组 0 为空（%d 条全被判为组 1）-> 判据**空转**，没有任何条目被比对。'
              '先看①：这通常意味着 meta 的 group 字段被读错了' % len(entries))
    elif not samples:
        d4 = '一轮都没采到（0 轮）-> 无证据'
    elif missing:
        d4 = '; '.join(missing[:3])
    elif drifted:
        d4 = '; '.join(drifted[:3])
    else:
        d4 = '全部 %d 轮逐字节一致' % len(samples)

    chk('组 0 在全部采样轮次均为磁盘密文',
        bool(g0) and len(samples) > 0 and not drifted and not missing, d4)
    return checks


# ---------------------------------------------------------------------------
# 负向自检
# ---------------------------------------------------------------------------
def _synth(ln, seed):
    rnd = random.Random(seed)
    return bytes(rnd.randrange(256) for _ in range(ln))


def selftest():
    """负向自检: 变异必须被判据抓到；基线必须全绿。"""
    entries = [(0x1000, 64, GROUP_VM), (0x1100, 32, GROUP_VM),
               (0x2000, 48, GROUP_VM + 1)]
    refs = {0x1000: _synth(64, 1), 0x1100: _synth(32, 2)}
    good = [dict(refs) for _ in range(MIN_SAMPLES)]

    base = judge(entries, good, refs)
    bad = [c for c in base if not c[1]]
    print('[selfcrypt-residency-selftest] 基线: %d 条判据, %d 条失败'
          % (len(base), len(bad)))
    for name, ok, detail in bad:
        print('  [XX] %s  (%s)' % (name, detail))

    def m1():
        s = [dict(refs) for _ in range(MIN_SAMPLES)]
        b = s[1][0x1000]
        s[1][0x1000] = bytes([b[0] ^ 0xFF]) + b[1:]
        return s, refs

    def m2():
        return [], refs

    def m3():
        s = [dict(refs) for _ in range(MIN_SAMPLES)]
        del s[2][0x1100]
        return s, refs

    def m4():
        r = dict(refs)
        b = r[0x1100]
        r[0x1100] = b[:8] + bytes([b[8] ^ 0x01]) + b[9:]
        return [dict(refs) for _ in range(MIN_SAMPLES)], r

    mutations = [
        ('M1 组 0 某条一轮内存 != 磁盘密文（回密没生效的签名）', m1),
        ('M2 采样列表清空（无证据不得通过）', m2),
        ('M3 组 0 某条某一轮取不到（只等到一部分）', m3),
        ('M4 磁盘参考改 1 个字节（证明是逐字节比较）', m4),
    ]
    caught = 0
    for label, fn in mutations:
        try:
            s, r = fn()
            res = judge(entries, s, r)
        except Exception as e:                      # noqa: BLE001
            res = [('crash', False, repr(e))]
        hit = [c for c in res if not c[1]]
        if hit:
            caught += 1
            print('  [ok] %s -> 被抓: %s' % (label, hit[0][0]))
        else:
            print('  [XX] %s -> **未被抓**（判据无判别力）' % label)

    total = len(mutations)
    print('[selfcrypt-residency-selftest] %d/%d 变异被抓' % (caught, total))
    # ⚠️ 下面这 4 条是**合成基线**（组 0 恰好 2 条 / 10 轮），不是本体跑出来的
    #    数据。原实现没有任何前缀，于是门禁日志里它们紧挨在本体的
    #    `FAIL: 2/4 条判据未通过` 之上，读起来像"4 条全 ok 却报 2/4 FAIL"
    #    —— 实测出处 §2.52。加上这行表头，两段就不再可能被读混。
    print('  --- 以下是合成基线（自检用例数据, 非本体采样）---')
    for name, ok, detail in base:
        print('  [%s] %s  (%s)' % ('ok' if ok else 'XX', name, detail))
    return 0 if (caught == total and not bad) else 1


# ---------------------------------------------------------------------------
# 运行期采样
# ---------------------------------------------------------------------------
def _spawn(exe, keep_ms, serial):
    """起一个 `--wait-after` 驻留的 demo（隐藏窗口，硬约束 m14637/m14638）。"""
    d = os.path.dirname(exe)
    blob = os.path.join(d, 'vm.blob')
    lic = os.path.join(d, 'license.txt')
    args = [exe, '--selftest', '--vm-blob', blob, '--wait-after', str(keep_ms)]
    if os.path.isfile(lic):
        args += ['--license-file', lic]
    p = winproc.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                      stderr=subprocess.DEVNULL, cwd=d)
    # 喂序列号: 不喂会停在 `demo/main.c:764 fgets`（`--wait-after` 在它**之前**,
    # 故驻留窗口与喂不喂无关；喂了只是让进程在窗口后能正常收尾）。
    if serial:
        try:
            p.stdin.write((serial + '\n').encode('utf-8'))
            p.stdin.flush()
        except OSError:
            pass
    return p


def _kernel32():
    k32 = ctypes.WinDLL('kernel32', use_last_error=True)
    k32.OpenProcess.restype = wt.HANDLE
    k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
    k32.ReadProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p,
                                      ctypes.c_void_p, ctypes.c_size_t,
                                      ctypes.POINTER(ctypes.c_size_t)]
    k32.CloseHandle.argtypes = [wt.HANDLE]
    # ⚠️ 复用 `guard_selftest._module_base()` **必须自己补齐这几个原型**:
    #   它内部只调 `CreateToolhelp32Snapshot` / `Module32First` / `Module32Next`，
    #   而它自己的调用点**没设过 argtypes/restype** —— 于是快照句柄按默认 32 位
    #   `c_int` 返回（本机句柄恰好小, 侥幸没出事）。本文件把 `restype` 设成
    #   `HANDLE` 之后，同一个函数立刻炸:
    #       ctypes.ArgumentError: argument 1: OverflowError: int too long to convert
    #   （实测, 2026-10-06 第一次跑）=> 三个原型**必须成对**设置，缺一个就崩。
    k32.CreateToolhelp32Snapshot.restype = wt.HANDLE
    k32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
    k32.Module32First.restype = wt.BOOL
    k32.Module32First.argtypes = [wt.HANDLE,
                                  ctypes.POINTER(guard_selftest._MODULEENTRY32)]
    k32.Module32Next.restype = wt.BOOL
    k32.Module32Next.argtypes = [wt.HANDLE,
                                 ctypes.POINTER(guard_selftest._MODULEENTRY32)]
    return k32


def _rd(k32, h, va, n):
    buf = (ctypes.c_ubyte * n)()
    got = ctypes.c_size_t(0)
    if k32.ReadProcessMemory(h, ctypes.c_void_p(va), buf, n,
                             ctypes.byref(got)) and got.value == n:
        return bytes(buf)
    return None


def run(exe, map_path, keep_ms, observe_s, quiet):
    with open(exe, 'rb') as f:
        data = f.read()
    secs = pc.sections_of(data)
    # ## 纪律（照 `tools/prot_dbg.py:601-604`）: 复用 `protchain_check` 之前必须
    #   把 `_CURRENT_EXE` 指向**本次被测产物** —— 否则 `load_section_names()`
    #   会去解析**另一个平台**的 `prot_sections.json`，拿到静默错误的随机节名
    #   ⇒ `.protcry` 找不到 ⇒ **掩码/条目恒空**（看起来像"这个构建没有加密目标"）。
    pc._CURRENT_EXE = exe
    entries = pc.selfcrypt_meta(data, secs)
    if not entries:
        print('[selfcrypt-residency] SKIP: 无 selfcrypt meta 条目'
              '（n=0 或找不到 %s）—— 该产物未接 selfcrypt' % (pc.cry_section_names(),))
        return 2

    refs, why = disk_refs(data, secs, entries)
    if refs is None:
        print('[selfcrypt-residency] SKIP: 磁盘密文参考不可用 —— %s' % why)
        return 2

    syms = mapfile.parse(map_path)
    rva_d2b = syms.get(D2B_SYM)
    rva_rdy = syms.get(READY_SYM)
    if rva_d2b is None or rva_rdy is None:
        print('[selfcrypt-residency] FAIL: %s 缺符号 %s / %s'
              % (map_path, D2B_SYM, READY_SYM))
        print('  **读不到 != 不存在**: 不要把它读成"没问题"'
              '（该产物若定义了 PROT_SELFCRYPT_DISABLE 就不会有这些符号）')
        return 1

    serial = None
    try:
        _gen, vmj = pc.resolve_gen_paths(exe)
        with open(vmj, encoding='utf-8') as f:
            serial = json.load(f).get('serial')
    except (OSError, ValueError):
        serial = None

    if not quiet:
        print('=== selfcrypt_residency_check（D2c 驻留期密文态）===')
        print('  exe=%s  条目 %d 条（组 %d: %d 条）  '
              '采样 %d 轮 × %.0f ms（窗口 %.1fs）'
              % (os.path.basename(exe), len(entries), GROUP_VM,
                 len([e for e in entries if e[2] == GROUP_VM]),
                 int(observe_s / POLL_S), POLL_S * 1000, observe_s))
        for (rva, ln, g) in entries:
            print('    条目 rva=0x%-6x len=%-4d 组=%d%s'
                  % (rva, ln, g, '' if g == GROUP_VM else '  (不判)'))

    k32 = _kernel32()
    p = _spawn(exe, keep_ms, serial)
    h = None
    try:
        # --- 取运行时基址 + 等看门狗就绪 ---
        base = None
        t0 = time.time()
        while time.time() - t0 < READY_TIMEOUT_S:
            if p.poll() is not None:
                print('[selfcrypt-residency] FAIL: 进程提前退出 rc=%s（未取到基址）'
                      % p.returncode)
                return 1
            if h is None:
                h = k32.OpenProcess(PROCESS_ALL, False, p.pid)
            if h:
                base = guard_selftest._module_base(k32, p.pid,
                                                   os.path.basename(exe))
                if base:
                    break
            time.sleep(0.05)
        if not h or not base:
            print('[selfcrypt-residency] FAIL: 取不到进程句柄 / 模块运行时基址'
                  '（打开=%s 基址=%s）' % (bool(h), hex(base) if base else None))
            return 1

        # 就绪哨兵 = `g_wd_interval != 0`（`src/integrity.c:828`，本工具从不写它）
        # —— 与 `tools/guard_selftest.py:356 _wait_ready` 同一纪律:
        #   非 0 即证明「init + blob 装载 + start_watchdog 都已走完」，
        #   采样因此落在 `--wait-after` 驻留窗口内，而**不是** init 内部那段
        #   "解密以校验"的瞬时明文（那段是本设计固有的，不该被判据抓）。
        ready, seen = False, []
        while time.time() - t0 < READY_TIMEOUT_S:
            if p.poll() is not None:
                break
            v = _rd(k32, h, base + rva_rdy, 4)
            iv = int.from_bytes(v, 'little') if v else None
            if iv is not None and iv not in seen:
                seen.append(iv)
            if iv:
                ready = True
                break
            time.sleep(0.1)
        if not ready:
            print('[selfcrypt-residency] FAIL: 未等到看门狗就绪（哨兵 %s 观测值=%s, '
                  '进程 rc=%s）—— 判据无判别力，不要读成"密文态正常"'
                  % (READY_SYM, seen, p.poll()))
            return 1

        d2b = _rd(k32, h, base + rva_d2b, 1)
        d2b_v = d2b[0] if d2b else None
        if not quiet:
            print('  就绪: %s=%s（等了 %.2fs）基址=%s  %s=%s'
                  % (READY_SYM, seen, time.time() - t0, hex(base),
                     D2B_SYM, d2b_v))

        # --- 采样 ---
        time.sleep(SETTLE_S)
        samples = []
        t1 = time.time()
        while time.time() - t1 < observe_s:
            if p.poll() is not None:
                break
            s = {}
            for (rva, ln, _g) in entries:
                b = _rd(k32, h, base + rva, ln)
                if b is not None:
                    s[rva] = b
            if s:
                samples.append(s)
            time.sleep(POLL_S)

        checks = judge(entries, samples, refs)
        # 组 1 诊断（**不判**）: 看门狗窗口内它就该是明文 —— 若真观察到，
        # 说明采样器**能**分辨明文/密文两态（对判据的活体旁证, 不做门禁要求）。
        g1 = [e for e in entries if e[2] != GROUP_VM]
        g1_plain = sum(1 for s in samples
                       if any(s.get(r) is not None and s[r] != refs[r] for r, _l, _g in g1))
        if not quiet:
            print('  [组 1 诊断] 明文出现 %d/%d 轮（组 1 不在判据内）'
                  % (g1_plain, len(samples)))
            for name, ok, detail in checks:
                print('  [%s] %s  (%s)' % ('ok' if ok else 'XX', name, detail))

        if d2b_v != 1:
            print('[selfcrypt-residency] FAIL: %s=%s（期望 1）—— D2c 的回密循环在 '
                  '`#ifdef PROT_SELFCRYPT_D2B` 内（`src/selfcrypt.c:348-354`），'
                  '开关没生效 => 组 0 会**常驻明文**。这不是"回归"'
                  '，是这份产物根本没编译该机制' % (D2B_SYM, d2b_v))
            return 1

        failed = [c for c in checks if not c[1]]
        if failed:
            # ⚠️ 失败诊断**不受 --quiet 抑制**。`--quiet` 的契约是「成功时不啰嗦」，
            #    不是「失败时沉默」。原实现把逐条打印一起关掉 ⇒ 门禁（它自己传
            #    `--quiet`）写进日志的只有这一行计数，读日志的人根本看不到
            #    哪条判据红了、为什么 —— 实测见 §2.52（`FAIL: 2/4` 上方紧跟着
            #    的是 **--selftest 合成基线**的 4 条 `[ok]`，看起来像自相矛盾）。
            print('[selfcrypt-residency] FAIL: %d/%d 条判据未通过'
                  % (len(failed), len(checks)))
            for name, _ok, detail in failed:
                print('  [XX] %s  (%s)' % (name, detail))
            return 1
        print('[selfcrypt-residency] PASS: 组 0 %d 条 × %d 轮 全部逐字节等于磁盘密文'
              % (len([e for e in entries if e[2] == GROUP_VM]), len(samples)))
        return 0
    finally:
        if h:
            k32.CloseHandle(h)
        if p.poll() is None:
            p.kill()
            p.wait()


def main(argv=None):
    ap = argparse.ArgumentParser(prog='selfcrypt_residency_check.py',
                                 description='D2c 驻留期密文态检查')
    ap.add_argument('--exe', default=EXE)
    ap.add_argument('--map', dest='map_path', default=None)
    ap.add_argument('--keep-ms', type=int, default=KEEP_MS)
    ap.add_argument('--observe-s', type=float, default=OBSERVE_S)
    ap.add_argument('--selftest', action='store_true')
    ap.add_argument('--quiet', action='store_true')
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()

    if sys.platform != 'win32':
        print('[selfcrypt-residency] SKIP: 仅 Windows'
              '（OpenProcess / ReadProcessMemory / Toolhelp32）')
        return 2

    exe = os.path.abspath(args.exe)
    map_path = os.path.abspath(args.map_path
                              or os.path.splitext(exe)[0] + '.map')
    missing = [p for p in (exe, map_path) if not os.path.isfile(p)]
    if missing:
        print('[selfcrypt-residency] SKIP: 缺产物 %s' % missing)
        return 2

    return run(exe, map_path, args.keep_ms, args.observe_s, args.quiet)


if __name__ == '__main__':
    sys.exit(main())
