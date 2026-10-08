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
  T29 selfcrypt-meta II-1: 翻 .protcry 元数据 CRC -> 退出码 0xBAD (版面外对照同基线)
  T30 selfcrypt-body: 翻密文函数体(段 CRC 已掩码剔除) -> 仍退 0xBAD (II-1 解密态 CRC)
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

try:
    import ctypes                 # Windows-only
except ImportError:  # pragma: no cover
    ctypes = None
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

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')



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
# ## 平台感知（C-3, 2026-09-25）
#   与 `attacks.py`（C-2）同法: `--platform linux` 切换。
#   **默认 win**（门禁里 e2e 项跑 Windows），Linux 侧由 `--platform linux`
#   显式选择（与 genpaths 的"显式平台"原则一致）。
# ## 平台适配公共层（S5, 2026-09-25）
#   平台解析 / 归一化 / WSL 直执 来自 `tests/_platform.py`（**单一来源**）。
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _platform as _plat          # noqa: E402

# `to_wsl` 来自公共层（S5）；S5 的正则事故曾把它吞掉（`_run_demo_wsl`
# 改走 `_plat.run_demo_via_wsl` 后一直没暴露，W4 起 blob mock 需要它）。
to_wsl = _plat.to_wsl

_PLATFORM = _plat.parse_platform(sys.argv)

sys.path.insert(0, os.path.join(REPO, 'tools'))
import genpaths as _gp             # noqa: E402
_P = _gp.paths(_PLATFORM)

EXE = (os.path.join(REPO, 'build', 'demo.exe') if _PLATFORM == 'win'
       else os.path.join(REPO, 'build', 'demo_linux'))
BUILD = _P.build_dir           # 按平台（A 阶段: win=build/, linux=build/linux）
JSON_PATH = _P.vm_build_json
STRINGS = os.path.join(REPO, 'demo', 'strings.txt')
LICENSE = _P.b('license.txt')   # A1: sign 产物（按平台）

# ## ⚠️ `ctypes.WinDLL` **必须条件化**（C-3, 2026-09-25）
#   它是**模块级**执行 —— Linux 上 `ctypes.WinDLL` **不存在** ->
#   **import e2e.py 即崩**（连一个用例都跑不了）。
#   Linux 侧用 **ptrace**（见 DebugAttacher / C-1 的 tracer 实现）。
if ctypes is not None:
    KERNEL32 = ctypes.WinDLL('kernel32', use_last_error=True)

    KERNEL32.DebugActiveProcess.argtypes = [ctypes.c_ulong]
    KERNEL32.DebugActiveProcess.restype = ctypes.c_int
    KERNEL32.WaitForDebugEvent.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
    KERNEL32.WaitForDebugEvent.restype = ctypes.c_int
    KERNEL32.ContinueDebugEvent.argtypes = [ctypes.c_ulong, ctypes.c_ulong,
                                            ctypes.c_ulong]
    KERNEL32.ContinueDebugEvent.restype = ctypes.c_int
    KERNEL32.DebugActiveProcessStop.argtypes = [ctypes.c_ulong]
    KERNEL32.DebugActiveProcessStop.restype = ctypes.c_int
else:
    KERNEL32 = None

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


# W4: WSL mock 助手来自**公共层** `tests/_platform.py`
#     （e2e 与 attacks 共用 —— 单一来源，避免"两处实现漂移"）。

def _norm_exit(code, platform=None):
    """平台语义归一化（S5: 委托公共层）。"""
    return _plat.norm_exit(code, platform or _PLATFORM)

def _norm_expect(expected, platform=None):
    """期望值归一化（S5: 委托公共层）。"""
    return _plat.norm_expect(expected, platform or _PLATFORM)



# W4: **已删** `ONLINE_LABELS` 与 `_Results`（2026-09-25）
#
#   它们曾在 **W3 之前**把 6 项在线用例标 `PLATFORM_NA`
#   （Linux 无 HTTP 能力 -> 判据巧合成立时按"假通过"处理）。
#
#   **W3 之后**: Linux 有了 POSIX socket HTTP，这些用例**已真跑全过**
#   -> NA 机制为空 -> **死代码** -> 删除（**不留失效的判定逻辑**）。
#
#   仍标 `PLATFORM_NA` 的只剩 **T3**（Windows 调试会话专用）——
#   那是**直接 append** 的，不经此机制。

def run_demo(args=None, stdin=None, exe=EXE, timeout=40):
    """运行 demo；返回 (exitcode, stdout, stderr)。

    ## 平台分派（C-3, 2026-09-25）
      · **win**: 现状（`winproc.Popen`）
      · **linux**: 经 WSL **直执**（`wsl.exe --cd <cwd> -- <exe> <args>`）

      ## 为什么复用 C-2 的做法
        C-2 (`attacks.py`) 已用三路对照**验证**该形态:
          · **不经 bash**（`bash -c` 会吞掉 **stdin** 与**退出码**）
          · `--cd` 指定 cwd（demo 需相对路径找产物）
          · **路径型参数转 WSL 形态**（Windows 路径传给 WSL 里的 demo
            会 `fopen` 失败 -> `license: 0`）
        => 本处**同一形态**（避免重踩）。
    """
    if _PLATFORM != 'win':
        return _run_demo_wsl(args, stdin, exe, timeout)
    cmd = [exe] + (args or [])
    p = winproc.Popen(
        cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, cwd=os.path.dirname(exe))
    out, err = p.communicate(stdin, timeout=timeout)
    return (p.returncode,
            out.decode('utf-8', 'replace'),
            err.decode('utf-8', 'replace'))


def _run_demo_wsl(args, stdin, exe, timeout):
    """经 WSL **直执**（S5: 委托公共层 `_platform.run_demo_via_wsl`）。

    ## 契约核对（替换前逐项对照，**等价**）
      · 不经 bash（`bash -c` 会吞 stdin/退出码）
      · 路径型参数转 WSL 形态
      · 自动补 `--vm-blob`（Linux 侧 blob 在 `build/linux/`）
      · stdin/stdout/stderr 全 PIPE
    => 委托公共层，**消除**"两处各写一遍"的漂移源。
    """
    return _plat.run_demo_via_wsl(
        exe, args=args, stdin=stdin, timeout=timeout,
        vm_blob_path=_P.b('vm.blob'))



def pump_and_read(proc, timeout=30):
    """Wait for proc exit. Return (exitcode_or_None, stdout_text, stderr_text).

    ## 超时路径必须**自己回收**进程（2026-10-05 修）
      原实现在 `TimeoutExpired` 时只 `return (None, '', '')` —— 既不 kill
      也不 wait，把**活进程 + PIPE 句柄**留给调用方。T3 的调用方随后做了
      `proc.kill(); proc.wait()`（**无 timeout**）：被附加调试的目标处于
      暂停态时 kill 不能立刻终结它，`wait()` 于是**永久阻塞** —— 实测全门禁
      因此挂死 1h45m，`build/_t3hang.py` 的 faulthandler 栈落在
      `subprocess.py:1280 wait` / `_wait`。
      现在：超时就 kill + **有界** wait，并返回 None 表示"没拿到退出码"。
    """
    try:
        out, err = proc.communicate(timeout=timeout)
        return proc.returncode, out.decode('utf-8', 'replace'), \
            err.decode('utf-8', 'replace')
    except subprocess.TimeoutExpired:
        _reap(proc)
        return None, '', ''


def _reap(proc, timeout=5):
    """**有界**回收一个可能处于调试暂停态的进程（2026-10-05 新增）。

    ## 为什么要单独一个（而不是内联 `proc.kill(); proc.wait()`）
      `proc.wait()` **无 timeout** 时，一旦 kill 未能真正终结进程就**永久
      阻塞** —— 全门禁因此挂死 1h45m。这里每一步都有界：
        · `kill()` 本身可能抛（进程已退）
        · `wait(timeout=...)` 超时后再补一次 kill 并**不再等**
      调用方仍应先 `DebugActiveProcessStop` **解除调试暂停**，
      否则 kill 也无法立刻终结被调试进程。
    """
    try:
        if proc.poll() is None:
            proc.kill()
    except Exception:                    # noqa: BLE001
        pass
    try:
        proc.wait(timeout=timeout)
    except Exception:                    # noqa: BLE001
        pass


def pe_text_raw_offset(path):
    """Offset of the first raw byte of .text (PointerToRawData)."""
    return pe_section_raw_offset(path, '.text')


def pe_section_raw_offset(path, sec_name):
    """节的文件偏移（**自动识别 PE / ELF**）。

    ## C-3（2026-09-25）
      原实现**只认 PE**（硬编码 `e_lfanew` 偏移）——
      对 ELF 会读到垃圾值（与 `measure_sections` 同类缺陷）。
      => 复用 **F 阶段**的 `protchain_check.sections_of`
         （**自动分派**，字段名一致: `ptr_raw` / `name`）——
         避免"同一判据各写一遍"（复制即漂移）。
    """
    import sys as _sys
    _sys.path.insert(0, os.path.join(REPO, 'tests'))
    from protchain_check import sections_of
    with open(path, 'rb') as f:
        data = f.read()
    # C-3: 应用节名的**格式映射**（.rdata -> .rodata 等）
    real = mapped_sec_name(path, sec_name)
    secs = sections_of(data)
    for s in secs:
        if s['name'] == real:
            return s['ptr_raw']
    raise RuntimeError('%s (real=%s) not found in %s'
                       % (sec_name, real, path))


#: ## 节名的**格式映射**（C-3, 2026-09-25）
#: PE 用 `.rdata/.pdata`，ELF 用 `.rodata/.eh_frame`。
#: **按文件格式映射**（不猜平台）—— 与 `sections_of` 同一判据。
SECTION_NAME_ALIAS = {
    'PE': {'.rdata': '.rdata', '.pdata': '.pdata'},
    'ELF': {'.rdata': '.rodata', '.pdata': '.eh_frame',
            '.text': '.text'},
}


def _is_elf_file(path):
    with open(path, 'rb') as f:
        return f.read(4) == b'\x7fELF'


def mapped_sec_name(path, sec_name):
    """把**逻辑节名**映射为**该产物格式的实际节名**（C-3）。"""
    fmt = 'ELF' if _is_elf_file(path) else 'PE'
    return SECTION_NAME_ALIAS.get(fmt, {}).get(sec_name, sec_name)


def tamper_candidates(sec_name):
    """**数据驱动**的篡改候选偏移（T9/T10 用，W3 2026-09-25）。

    ## 为什么需要（**实测教训**）
      T4 用 `from_end=1`（CRC 末字节）**可行** —— 因为 **`.text` 尾是 padding**
      （`g_pad_text`，不被执行）。
      但 **`.rdata` 尾是 IAT 名称表**（`"Heap"`/`"HeapSize"`/…，**真实数据**）:
        翻转 -> `0xC0000139`（**DLL 装载失败**）—— **不是** 0xBAD。
      => **"末字节"不是通解**；固定偏移（如 `+0x1000`）在不同布局下也会落空。

      **本函数按实证顺序给出候选**（从"更可能安全"到"更可能不安全"）:
        1. CRC 覆盖范围的**中段**（避开头尾的 IAT/名称表）
        2. 逐步向两端扩散
      调用方**逐个试探**，直到 demo 给出 `0xBAD`（= 被 CRC 覆盖且不影响运行）。

      **若全部失败 -> 调用方如实 FAIL**（暴露"该节无法被覆盖"的真问题），
      **不放宽判据**。
    """
    import sys as _sys
    _sys.path.insert(0, os.path.join(REPO, 'tests'))
    from protchain_check import sections_of
    with open(EXE, 'rb') as f:
        data = f.read()
    real = mapped_sec_name(EXE, sec_name)
    for s in sections_of(data):
        if s['name'] == real:
            crc = min(s['virtual_size'], s['size_raw'])
            if crc <= 0:
                return []
            # 中段起，向外扩散（步长取 CRC 的 1/8，最多 8 个候选）
            mid = crc // 2
            step = max(1, crc // 16)
            out = []
            for k in range(0, 8):
                for cand in (mid + k * step, mid - k * step):
                    if 0 <= cand < crc and cand not in out:
                        out.append(cand)
            return out
    return []


def section_bounds(path, sec_name):
    """节的 (文件偏移, 大小) —— **两格式统一**（复用 sections_of）。

    ## 为什么不用内嵌 PE 解析
      `make_tampered_copy` 原来 `f.seek(0x3C)` 直接读 PE 节表 ->
      对 ELF 读到垃圾值 -> `unpack requires a buffer of 2 bytes`（实测 T4）。
      => 复用 **F 阶段**的 `sections_of`（自动分派）——
         **避免同一判据各写一遍**（与 `pe_section_raw_offset` 同法）。
    """
    real = mapped_sec_name(path, sec_name)
    import sys as _sys
    _sys.path.insert(0, os.path.join(REPO, 'tests'))
    from protchain_check import sections_of
    with open(path, 'rb') as f:
        data = f.read()
    for s in sections_of(data):
        if s['name'] == real:
            # ## 返回 **CRC 长度** = min(virtual_size, size_raw)
            #
            # 保留原 PE 实现的关键语义（**实测教训**）:
            #   完整性 CRC 长度 = min(vsize, rawsize)；
            #   raw 尾部对齐字节**不在 CRC 覆盖内** -> 翻它**检不出**。
            #   => 篡改目标必须是 `min(vsize, rawsize) - 1`。
            # ELF 侧两者都 = sh_size（**语义一致**）。
            return s['ptr_raw'], min(s['virtual_size'], s['size_raw'])
    raise RuntimeError('%s (real=%s) not found in %s'
                       % (sec_name, real, path))


def make_tampered_copy(sec_name='.text', rel_off=0, from_end=0):
    """复制产物并翻转指定节内某字节（**PE / ELF 通吃**，C-3 重写）。

    ## from_end（2026-09-25 新增）
      `from_end=1` 表示翻转**该节 CRC 覆盖的最后一个字节**。
      用途见 T4 注释: 布局随机化后 ".text 首字节" 的归属**随构建变化**
      （某次 = 完整性检查自身的函数 -> 翻转即崩溃 -> 无法给 MSG_TAMPER）。
      末字节 = `g_pad_text` 尾部（确定位置）+ CRC 覆盖 + 不被执行
      -> **检测必然发生**。

    ## C-3 重写（2026-09-25）
      原实现的 `from_end` 分支**内嵌 PE 头解析**（`f.seek(0x3C)` ...）
      -> 对 ELF 读到垃圾值 -> `unpack requires a buffer of 2 bytes`（实测 T4）。
      => 改用 `section_bounds`（**复用 sections_of**，自动分派）：
      · 节名映射在这里天然生效（`.rdata`->`.rodata` 等，T9/T10）
      · CRC 长度语义保留（min(vsize, rawsize)）
    """
    dst = os.path.join(BUILD, 'demo_tampered.exe')
    shutil.copyfile(EXE, dst)
    raw_off, crc_len = section_bounds(dst, sec_name)
    if from_end:
        if crc_len <= 0:
            raise RuntimeError('section %s has zero CRC length' % sec_name)
        ro = raw_off + crc_len - 1      # 最后一个 CRC 覆盖字节
    else:
        ro = raw_off + rel_off
    with open(dst, 'r+b') as f:
        f.seek(ro)
        b = f.read(1)
        if not b:
            raise RuntimeError('tamper offset %d out of file' % ro)
        f.seek(ro)
        f.write(bytes([b[0] ^ 0xFF]))
    return dst


def cry_section_name():
    """T29: 读构建期产物 `demo/gen/<plat>/prot_sections.json` 的 protcry 随机节名。

    ## 为什么不硬编码 `.protcry`
      节名**按构建随机化**（`tools/gen_sections.py`）。实测本次构建
      `.protcry` -> `.b3locz1` ⇒ 硬编码必然找不到。

    ## 为什么不用 `protchain_check.cry_section_names()`
      它走 `load_section_names()` 的**模块级默认产物**（不带平台参数）
      -> Linux 侧会读到 Windows 的 JSON。这里按 `_P.gen`（平台感知）读。
    """
    p = os.path.join(_P.gen, 'prot_sections.json')
    with open(p, 'r', encoding='utf-8') as f:
        d = json.load(f)
    nm = (d.get('sections') or {}).get('protcry')
    if not nm:
        raise RuntimeError('%s 缺少 sections.protcry（先跑 build.ps1）' % p)
    return nm


def make_meta_tampered_copy(sec_off, rel_off):
    """T29: 复制产物并翻转 `.protcry` 节内相对偏移 `rel_off` 的一个字节。

    `sec_off` = 该节 `ptr_raw`（调用方用 `section_bounds` 取，节名随机）。
    偏移语义对齐 `tools/selfcrypt_proto.py:441-444` 的写入侧:
    `meta = [count u32][entry*24]`，`entry = rva4|len4|key8|crc4|group4`
    ⇒ 第 i 条 entry 的 **crc32 字段** 在节内偏移 `4 + i*24 + 16`。
    """
    dst = os.path.join(BUILD, 'demo_meta_tampered.exe')
    shutil.copyfile(EXE, dst)
    ro = sec_off + rel_off
    with open(dst, 'r+b') as f:
        f.seek(ro)
        b = f.read(1)
        if not b:
            raise RuntimeError('tamper offset %d out of file' % ro)
        f.seek(ro)
        f.write(bytes([b[0] ^ 0xFF]))
    return dst


def selfcrypt_covered_ranges():
    """T30: 读构建期产物 `build/selfcrypt_mask.txt`，返回 selfcrypt 覆盖区间。

    `build.ps1` 步骤 6 调 `tools/selfcrypt_proto.py --mask-out`，把**原位加密的
    函数区间**写成每行 `0x<rva>,<len>`；`tools/hashpatch.py:383-386` 用**同一份
    掩码**（`EXCLUDE_MASKS`）把这些区间从**段 CRC** 里排除（运行侧
    `src/integrity.c build_selfcrypt_mask` 同规则）。
    ⇒ 落在这些区间内的篡改，**段 CRC 原理上检不出**，只有 II-1 解密态 CRC 能抓。

    返回 `[(rva, len), ...]`；文件缺失返回 `None`（调用方记 SKIP）。
    """
    p = os.path.join(BUILD, 'selfcrypt_mask.txt')
    if not os.path.isfile(p):
        return None
    out = []
    with open(p, 'r', encoding='utf-8') as f:
        for ln in f:
            ln = ln.strip()
            if not ln or ln.startswith('#'):
                continue
            head, _, tail = ln.partition(',')
            out.append((int(head, 0), int(tail.strip())))
    return out


def make_selfcrypt_body_tampered_copy(sec_off, rel_off):
    """T30: 复制产物并翻转 `.text` 内相对偏移 `rel_off` 的一个字节。

    与 `make_meta_tampered_copy` 的区别只在**目标语义**：本函数的偏移指向
    **密文函数体内部**（由 `selfcrypt_covered_ranges()` 的区间算出），落到
    `demo_selfcrypt_body_tampered.exe`，便于与 T29 的副本并存。
    """
    dst = os.path.join(BUILD, 'demo_selfcrypt_body_tampered.exe')
    shutil.copyfile(EXE, dst)
    ro = sec_off + rel_off
    with open(dst, 'r+b') as f:
        f.seek(ro)
        b = f.read(1)
        if not b:
            raise RuntimeError('tamper offset %d out of file' % ro)
        f.seek(ro)
        f.write(bytes([b[0] ^ 0xFF]))
    return dst

# ---------------------------------------------------------------------------
# 调试器附加: kernel32.DebugActiveProcess + WaitForDebugEvent 事件泵
# ## 2026-10-04 恢复（真缺陷修复）: 本类被 `22826c5`「feat(C-3): e2e 全量
#  移植」整块误删，**但 T3 的调用点 `main()` 未同步删除** ->
#  `DebugAttacher` 成为孤儿调用。`py_compile` 只查语法，抓不到。
#  **为何潜伏到 2026-10-04**: 该类删除后 T3 一直靠 preflight 必然失败
#  （旧探针 `DebugActiveProcess(os.getpid())`，Windows 禁止进程调试自身）
#  走 SKIP，`else` 分支**从未被执行**; S6 把 preflight 改成对**派生子进程**
#  附加后，只要环境允许调试就必然走到调用点 -> `NameError`。
#  **恢复来源**: `git show 22826c5^:tests/e2e.py:216-255`（逐字恢复）。
#  **守护**: `build/_undef.py` 全库静态审计（引用但未绑定的全局名）。
# ---------------------------------------------------------------------------
class DebugAttacher(object):
    # ## ⚠️ `DBG_CONTINUE` **必须是 0x00010002**（2026-10-05 修，真根因）
    #   原实现写 `2`（裸整数）。`ContinueDebugEvent` 的 `dwContinueStatus`
    #   只接受 **DBG_CONTINUE = 0x00010002** 或
    #   **DBG_EXCEPTION_NOT_HANDLED = 0x80010001**；传 2 实测
    #   **返回 0 / err=0x57 = ERROR_INVALID_PARAMETER** ⇒ 调试对象
    #   **从未被恢复运行**（停在初始断点: cpu=0、
    #   `ExitCodeProcess=0x103` = `STILL_ACTIVE`、附加期间 stdout 一个字
    #   都没有）。**后果链**: `--wait-ms` 永不生效 ⇒ `proc.kill()` 也终结
    #   不了处于调试暂停态的进程 ⇒ 无界 `proc.wait()` **永久阻塞** ⇒
    #   全门禁挂死 1h45m（`build/_t3hang.py` 的 faulthandler 栈落在
    #   `subprocess.py:1280 wait`）。
    #   **修后实测**（`build/_t3cont.py`）: `Continue -> 1 err=0x0`，
    #   事件序列 `CREATE_PROCESS / LOAD_DLL / CREATE_THREAD×3 / LOAD_DLL…`，
    #   **附加期间**就打印 `反调试扫描: 发现可疑` + `MSG_DBG`，并收到
    #   `EXIT_PROCESS` 且退出码 **0xdb** ⇒ 是真的"被调试运行时检出"，
    #   不是 detach 之后的残留。
    DBG_CONTINUE = 0x00010002             # DBG_CONTINUE（**不是 2**）
    DBG_EXCEPTION_NOT_HANDLED = 0x80010001
    EXIT_PROCESS_DEBUG_EVENT = 5          # EXIT_PROCESS_DEBUG_EVENT
    WAIT_TIMEOUT = 0x00000102             # 保留（历史值；实际超时见下）
    # ## 超时 errno 白名单（2026-10-05 修）
    #   `WaitForDebugEvent` 在**没有事件**时返回的 errno 实测是
    #   **0x79 = ERROR_SEM_TIMEOUT**，**不是** `WAIT_TIMEOUT (0x102)`。
    #   原实现只认 `0x102` ⇒ 一旦在**正确线程**上泵就会把它当成致命错误
    #   而 `break` ⇒ 泵形同虚设。这里把三类超时值都当作"继续等"。
    TIMEOUT_ERRNOS = (0x79, 0x102, 0x5B4)

    def __init__(self):
        self._pid = None

    def attach(self, pid):
        if not KERNEL32.DebugActiveProcess(pid):
            return False
        self._pid = pid
        return True

    def pump(self, timeout=25.0):
        """
        泵调试事件, 最多 `timeout` 秒。

        ## ⚠️ 必须在 `attach()` 的**同一个线程**上调用（2026-10-05）
          `DebugActiveProcess` 在主线程、`WaitForDebugEvent` 挪到子线程后,
          子线程**第一次**调用就拿 `err=0x6 = ERROR_INVALID_HANDLE` 且
          **零事件**（实测 `build/_t3fix.py`）。注意 `0x6` 只是"attach 与
          pump 分离"的形态, **不是**让进程不动的根因 —— 根因是
          `DBG_CONTINUE` 写错（见类常量注释）。无论如何, 本函数在
          `attach()` 的同一线程上调用于此更稳妥。

        返回 `(事件数, 是否见到 EXIT_PROCESS, 退出码或 None, Continue 失败次数)`。
        **本函数不 detach** —— 由调用方决定何时 detach（`detach()` 幂等）。
        """
        deadline = time.monotonic() + timeout
        n_events = 0
        saw_exit = False
        exit_code = None
        cont_fails = 0
        while time.monotonic() < deadline:
            ev = ctypes.create_string_buffer(512)
            if KERNEL32.WaitForDebugEvent(ev, 200):
                code = ctypes.c_ulong.from_buffer(ev).value
                dbg_pid = ctypes.c_ulong.from_buffer(ev, 4).value
                dbg_tid = ctypes.c_ulong.from_buffer(ev, 8).value
                n_events += 1
                # ## 先 Continue 再判 EXIT（2026-10-05 修）
                #   原实现在 `EXIT_PROCESS` 时**直接 return, 不 Continue**
                #   —— 调试事件不继续会留下悬挂的调试对象。顺序改成
                #   "先继续, 再记录退出码"。
                ctypes.set_last_error(0)
                if not KERNEL32.ContinueDebugEvent(dbg_pid, dbg_tid,
                                                   self.DBG_CONTINUE):
                    cont_fails += 1
                if code == self.EXIT_PROCESS_DEBUG_EVENT:
                    saw_exit = True
                    # EXIT_PROCESS 的退出码在 DEBUG_EVENT 结构 offset 16
                    exit_code = ctypes.c_ulong.from_buffer(ev, 16).value
                    break
            else:
                err = ctypes.get_last_error()
                if err not in self.TIMEOUT_ERRNOS:
                    break
        return n_events, saw_exit, exit_code, cont_fails

    def detach(self):
        if self._pid is not None:
            KERNEL32.DebugActiveProcessStop.argtypes = [ctypes.c_ulong]
            KERNEL32.DebugActiveProcessStop(self._pid)
            self._pid = None


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

    results = []    # W4: _Results(NA 机制) 已删（在线用例真跑）

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
    # ## ⚠️ Linux 侧 = **平台不适用**（S6, 2026-09-25）
    #   T3 整块是 **Windows 调试会话**逻辑（`DebugActiveProcess` + `cmd /c`
    #   探针），Linux **无等价物** —— 若不设守卫，Linux 侧会跑 Windows
    #   路径并报出 `winerror 5`（**语义错位**: 把 Windows 错误码当作
    #   Linux 侧的原因）。
    #
    #   **Linux 侧的实际覆盖已存在**: `tests/attacks_linux.py` 的**负向③**
    #   （`ptrace` 附加 -> `debug_object=1` + demo 主动退出）——
    #   那才是 Linux 的正确验证入口。**指向它，不伪装成"跳过"**。
    if _PLATFORM != 'win':
        results.append(('T3 debug-detect', 'PLATFORM_NA',
                        'T3 是 Windows 调试会话用例（DebugActiveProcess '
                        '无 Linux 等价物）；Linux 覆盖见 attacks_linux '
                        '负向③（ptrace 附加 -> debug_object=1）'))
    else:
        # ## 2026-10-05 重写（三处真缺陷）
        #
        #   ① **`DBG_CONTINUE` 写错**（裸 `2` 而非 `0x00010002`）—— 见
        #      `DebugAttacher` 类常量注释。这是**全门禁挂死 1h45m 的根因**:
        #      `ContinueDebugEvent` 返回 0/`0x57`, 调试对象停在初始断点,
        #      连 `kill()` 都终结不了它 -> 无界 `proc.wait()` 永久阻塞。
        #   ② **preflight 探针对象错**（S6 的 `cmd /c timeout`）—— 本节
        #      原意是"先确认能驱动调试会话再测, 避免留下挂起进程"。但实测
        #      该探针在本环境 **8/8 被拒**（`err=0x5` = 拒绝访问）, 而**同一
        #      环境对真实目标 `demo.exe` 的附加是成功的**（`build/_t3preflight.py`
        #      与 `build/_t3ctrl.py`）⇒ 探针**恒 SKIP**、真缺口永不执行;
        #      更糟的是它**偶发成功**（07:20:59 那次门禁就跑进了 `else` 分支,
        #      于是暴露了挂死）。**拿错误的对象做能力探测**与 `SETTLE_S`
        #      同型 —— 故**整块删除**, 直接用真实目标探测: 附加失败即
        #      带 errno 记 SKIP（诚实: 环境限制, 不是"未做"）。
        #   ③ **无界回收** —— 现在一律"**先 detach 再 kill, 且带 timeout**":
        #      被调试进程解除暂停后 kill/wait 才能成功（实测 detach 后
        #      `rc=219` 立刻返回）。
        #
        #   **判据未变**（仍是 `exit == 0xDB` 且 stdout 含 `MSG_DBG`）——
        #   修 ① 之后它在**被调试运行期间**就成立（`build/_t3cont.py`:
        #   附加期间 stdout 已含 `MSG_DBG`, 并收到 `EXIT_PROCESS` 且
        #   offset16 的退出码 = `0xdb`）⇒ 是**真检出**, 不是 detach 残留。
        proc = None
        dbg = DebugAttacher()
        try:
            proc = winproc.Popen(
                [EXE, '--wait-ms', '4000'],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, cwd=os.path.dirname(EXE))
            time.sleep(1.0)              # 等 PE 加载完成（足以被附加）
            ctypes.set_last_error(0)
            if not dbg.attach(proc.pid):
                err = ctypes.get_last_error()
                # 环境能力限制, 非"未做"（保留原 SKIP 语义与错误码）
                results.append(('T3 debug-detect', 'SKIP',
                                'env denies process debugging '
                                '(err=%d/0x%x); 保留 SKIP（环境限制，非未做）'
                                % (err, err)))
            else:
                # **同线程泵**（本函数在主线程, 与 attach 同线程）
                n_events, saw_exit, ev_exit, cont_fails = dbg.pump(timeout=15.0)
                dbg.detach()             # 先 detach: 让被调试进程解除暂停
                code, out = None, b''
                try:
                    out, _err = proc.communicate(None, timeout=10)
                    code = proc.returncode
                except subprocess.TimeoutExpired:
                    code = None
                if code is None:
                    _reap(proc)
                txt = out.decode('utf-8', 'replace') if out else ''
                ok = (code is not None and
                      _norm_exit(code) == _norm_expect(PROT_EXIT_DEBUG_DETECTED)
                      and msg_dbg in txt)
                results.append(
                    ('T3 debug-detect', 'PASS' if ok else 'FAIL',
                     'exit=%s ev_exit=%s events=%d cont_fail=%d' % (
                         code,
                         ('0x%x' % ev_exit) if ev_exit is not None else None,
                         n_events, cont_fails)))
        except Exception as e:
            results.append(('T3 debug-detect', 'FAIL', repr(e)))
        finally:
            # **零泄漏 + 有界**: detach(幂等) -> kill -> 带 timeout 的 wait
            dbg.detach()
            if proc is not None and proc.poll() is None:
                _reap(proc)

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
        ok = (_norm_exit(code) == _norm_expect(PROT_EXIT_TAMPERED)) and (msg_tamper in text)
        results.append(('T4 tamper-detect', 'PASS' if ok else 'FAIL',
                        'exit=%d' % code))
    except Exception as e:
        if wdac_blocked(e):
            results.append(('T4 tamper-detect', 'SKIP',
                            'WDAC blocked tampered copy (winerror 4551)'))
        else:
            results.append(('T4 tamper-detect', 'FAIL', repr(e)))

    # ---- T9/T10: 篡改检测扩展 (A3) —— 翻 .rdata/.pdata 一个字节也退 0xBAD
    # 注意: .rdata 含加密字符串, 篡改后 MSG_TAMPER 解密即乱码, 故只断言退出码。
    #
    # ## ⚠️ 定位方式已加固（W3, 2026-09-25）—— **不再用固定偏移**
    #
    #   **原实现**: `.rdata` 的固定偏移 `+0x1000`（注释说是"跳过段首 IAT"）。
    #   **实测问题**: 该偏移与"CRC 覆盖范围"**无必然关系** ——
    #     不同构建（如 `-RecordSeeds` 与 `-SeedsFile`）的**布局不同**
    #     （实测 `demo.exe` 329080 vs 327680 字节）-> 翻转位置落到
    #     **非 CRC 覆盖区** -> **检不出** -> `exit=0` -> T9 假失败。
    #     （`+0x1000` 与"段首 832 字节"本就无逻辑关系，是**经验值**。）
    #
    #   ## ⚠️ 修法已修正（W3, 2026-09-25 二次修正）
    #     **第一次修法（`from_end=1`）方向错误** —— 实测 `.rdata` 的
    #     CRC 末尾是 **IAT 名称表**（`"Heap"` / `"HeapSize"` /
    #     `"HeapReAlloc"` ... **真实数据**）：
    #       `rel=crc-1` -> `0xC0000139`（**DLL 装载失败**）
    #     而 T4 之所以能用 `from_end`，是因为 **`.text` 尾是 padding**。
    #     => **`.rdata` 不能照搬**（"末字节"不是通解）。
    #
    #     **正确修法（数据驱动）**: 用 `find_tamper_offset()`
    #     —— 从 CRC 覆盖范围的**中段**开始逐个候选试探，
    #     直到 demo **确实给 `0xBAD`**（= 既被 CRC 覆盖、又不影响运行）。
    #     · 位置**由实测确定**（不依赖固定经验值）
    #     · 全部候选都失败 -> **如实 FAIL**（暴露"该节无法被覆盖"的真问题）
    for tname, sec, rel in (('T9 tamper-rdata', '.rdata', 'auto'),
                            ('T10 tamper-pdata', '.pdata', 'auto')):
        try:
            # rel='auto' -> **数据驱动定位**（见上方加固说明）
            tried = []
            if rel == 'auto':
                tampered, code, text = None, None, ''
                for cand in tamper_candidates(sec):
                    tried.append(cand)
                    tampered = make_tampered_copy(sec, cand)
                    code, text, _ = run_demo(exe=tampered,
                                             args=['--license-file',
                                                   LICENSE],
                                             stdin=(serial + '\n').encode(
                                                 'utf-8'))
                    if (_norm_exit(code) == _norm_expect(PROT_EXIT_TAMPERED)):
                        break                 # 命中: 该偏移安全且被覆盖
            else:
                tampered = make_tampered_copy(sec, rel)
                code, text, _ = run_demo(exe=tampered,
                                     args=['--license-file', LICENSE],
                                     stdin=(serial + '\n').encode('utf-8'))
            ok = (_norm_exit(code) == _norm_expect(PROT_EXIT_TAMPERED))
            results.append((tname, 'PASS' if ok else 'FAIL',
                            'exit=%d' % code))
        except Exception as e:
            if wdac_blocked(e):
                results.append((tname, 'SKIP',
                                'WDAC blocked tampered copy (winerror 4551)'))
            else:
                results.append((tname, 'FAIL', repr(e)))

    # ---- T29: selfcrypt 元数据 CRC 篡改 (N1 二期 II-1 回归) -------------
    # ## 为什么需要本用例（2026-10-06）
    #   II-1 的机制**早已实现**: `prot_selfcrypt_init()`
    #   （`src/selfcrypt.c:290-314`）逐条解密引擎函数后，把**解出来的
    #   明文 CRC32** 与 `.protcry` meta 里存的**明文 CRC** 比对 ——
    #   `src/selfcrypt.c:240 if (got != crc) { (void)prot_plat_protect(
    #   dst,len,PROT_PAGE_EXECUTE_READ); return PROT_ERR_INTEGRITY; }`；
    #   失败经 `demo/main.c:525-530` -> `MSG_TAMPER` + `exit(0xBAD)`。
    #   **但 `tests/` 内从未有任何用例翻过 `.protcry`**（`make_tampered_copy`
    #   三个调用点只翻 `.text`/`.rdata`/`.pdata`）—— 与 §2.24（DebugAttacher
    #   孤儿）、§2.27（`exit_pol` 未定义名）**同型: 失败路径的代码最难被测到**。
    #   本用例就是那条一直缺失的回归。
    #
    # ## 判据（2026-10-06 实测确立）
    #   · 翻第 i 条 entry 的 **crc32 字段** -> init 校验失败 -> `0xBAD`
    #   · 翻节内 **meta 之外**的填充字节（对照）-> meta 未被读 -> **同基线**
    #   对照的意义: 证明"变红"来自 **meta 内容本身**，而不是"文件被动过"
    #   （该节不在 integrity 的 CRC 目标表内，`tools/hashpatch.py:112`
    #   `TARGET_NAMES = ('.text', '.rdata', '.pdata', '.protxec')`）。
    #
    # ## 诚实边界
    #   · `PROT_SELFCRYPT_DISABLE` 构建（`src/selfcrypt.c:64-76` 三个入口
    #     直接 `return PROT_OK`）或未接 selfcrypt 的构建下，blob 头 count
    #     为 0 -> **本用例检不出**，如实记 SKIP 并写明原因（**未验证 != 通过**）。
    #   · 本用例只覆盖"**解密态**校验"这一半；密文态 CRC（计划里的第 4 个
    #     烧录标记 `PROTCRYP`）**从未实现**，不在射程内。
    #   · `prot_selfcrypt_leave` 走 `sc_do_range(i, 0)` **不校验**
    #     （`src/selfcrypt.c:389`）⇒ 篡改只会在 init / D2b enter 的**解密**
    #     路径上被抓住，这正是本用例走正常启动的原因。
    try:
        sec = cry_section_name()
        raw_off, crc_len = section_bounds(EXE, sec)
        if crc_len < 4:
            raise RuntimeError('section %s CRC 长度 %d < 4' % (sec, crc_len))
        with open(EXE, 'rb') as f:
            f.seek(raw_off)
            n = struct.unpack('<I', f.read(4))[0]
        meta_end = 4 + n * 24
        if n == 0 or n > 16:
            results.append(('T29 meta-crc', 'SKIP',
                            'selfcrypt meta count=%d（PROT_SELFCRYPT_DISABLE '
                            '或该构建未接 selfcrypt；未验证 != 通过）' % n))
        elif meta_end > crc_len:
            results.append(('T29 meta-crc', 'FAIL',
                            'meta_end=%d 超出节 CRC 长度 %d' % (meta_end,
                                                                crc_len)))
        else:
            # 基线
            code_b, out_b, _ = run_demo(
                args=['--license-file', LICENSE],
                stdin=(serial + '\n').encode('utf-8'))
            # 对照: 节尾部填充（meta 之外）
            ctrl = make_meta_tampered_copy(raw_off, crc_len - 1)
            code_c, out_c, _ = run_demo(
                exe=ctrl, args=['--license-file', LICENSE],
                stdin=(serial + '\n').encode('utf-8'))
            # 本体: 第 0 条 entry 的 crc32 字段首字节
            meta = make_meta_tampered_copy(raw_off, 4 + 0 * 24 + 16)
            code_m, out_m, _ = run_demo(
                exe=meta, args=['--license-file', LICENSE],
                stdin=(serial + '\n').encode('utf-8'))
            base_ok = (code_b == 0) and (msg_ok in out_b)
            ctrl_ok = (code_c == code_b)
            hit = (_norm_exit(code_m) == _norm_expect(PROT_EXIT_TAMPERED)
                   and msg_tamper in out_m)
            ok = base_ok and ctrl_ok and hit
            results.append(
                ('T29 meta-crc', 'PASS' if ok else 'FAIL',
                 'exit=%d ctrl=%d base=%d meta_n=%d%s' % (
                     code_m, code_c, code_b, n,
                     '' if (base_ok and ctrl_ok) else ' (对照不成立)')))
    except Exception as e:
        if wdac_blocked(e):
            results.append(('T29 meta-crc', 'SKIP',
                            'WDAC blocked tampered copy (winerror 4551)'))
        else:
            results.append(('T29 meta-crc', 'FAIL', repr(e)))

    # ---- T30: selfcrypt 密文态篡改 (N1 二期计划里的 T30) -----------------
    # ## 为什么 T30 必须与 T29 分开存在
    #   `build.ps1` 步骤 6 把引擎函数**原位加密**（`.text` 里落的是密文），
    #   步骤 7 才烧录段 CRC；而 `tools/hashpatch.py:383-386` 会把**这些密文
    #   区间从段 CRC 里排除**（掩码来自 `--mask-out`，运行侧
    #   `src/integrity.c build_selfcrypt_mask` 同规则）。
    #   ⇒ **落在这几段密文函数体内的篡改，段 CRC 原理上检不出**；唯一能抓住
    #     它的是 II-1 的**解密态 CRC**（`src/selfcrypt.c:125-240`
    #     `sc_do_range(idx, 1)` 解密后重算 CRC，与 meta 明文 CRC 比对）。
    #   T29 翻 **meta 里存的 CRC 字段**（验"存的值被信任"）；
    #   T30 翻**密文函数体本身**（验"密文确实被解密并按 CRC 重算了"）。
    #
    # ## 判据（2026-10-06 实测确立）
    #   · **结构性断言（本用例的承重点）**: 目标偏移必须落在掩码区间内
    #     （读 `build/selfcrypt_mask.txt` 核对）。少了这条，本用例只是 T4 的
    #     另一个副本，证明不了"段 CRC 覆盖不到"。
    #   · 翻该字节 -> `0xBAD` + `MSG_TAMPER`（被 II-1 抓住）。
    #   · 对照: 翻 `.text` 内**不在掩码区间**的末尾字节 -> 也 `0xBAD`
    #     （被段 CRC 抓住，即 T4 那条路径）—— 证明两条机制都活着，
    #     分开它们的**只有掩码结构**。
    #   · 顺序佐证（条件式）: 基线若打印过 `反调试扫描` 行（= 该模块已编入），
    #     则密文态篡改必须在**它之前**被抓住 —— `demo/main.c:525` 的
    #     `prot_selfcrypt_init()` 早于 `:544` 的 `prot_antidebug_scan()`。
    #
    # ## 诚实边界
    #   · 掩码是**构建产物**；未跑 selfcrypt 的构建（meta count=0）或掩码缺失
    #     时记 SKIP 并写明（**未验证 != 通过**）。
    #   · 本用例证明"密文区间**也**被 II-1 覆盖"，**不**证明加密不可逆 ——
    #     密钥 `key0` 仍以明文存于 meta（`tools/selfcrypt_proto.py:442-444`）。
    try:
        ranges = selfcrypt_covered_ranges()
        if not ranges:
            results.append(('T30 cipher-crc', 'SKIP',
                            'build/selfcrypt_mask.txt 缺失或为空（该构建未跑 '
                            'selfcrypt；未验证 != 通过）'))
        else:
            sec = cry_section_name()
            prot_off, _prot_len = section_bounds(EXE, sec)
            with open(EXE, 'rb') as f:
                f.seek(prot_off)
                n = struct.unpack('<I', f.read(4))[0]
            if n == 0 or n > 16:
                results.append(('T30 cipher-crc', 'SKIP',
                                'selfcrypt meta count=%d（PROT_SELFCRYPT_DISABLE '
                                '或该构建未接 selfcrypt；未验证 != 通过）' % n))
            else:
                import sys as _sys
                _sys.path.insert(0, os.path.join(REPO, 'tests'))
                from protchain_check import sections_of
                with open(EXE, 'rb') as f:
                    _secs = sections_of(f.read())
                _text = next((s for s in _secs if s['name'] == '.text'), None)
                if _text is None:
                    raise RuntimeError('.text not found（RVA 无法换算成文件偏移）')
                t_va = _text['virtual_addr']
                t_ptr = _text['ptr_raw']
                t_crc = min(_text['virtual_size'], _text['size_raw'])
                # 取最长的一段密文函数体，中点作为篡改目标
                rva0, len0 = max(ranges, key=lambda r: r[1])
                off0 = rva0 - t_va
                # 承重断言 ①: 目标落在掩码区间内（= 段 CRC 不覆盖它）
                if not any(mrva <= rva0 and rva0 + len0 <= mrva + mlen
                           for mrva, mlen in ranges):
                    raise RuntimeError('掩码区间不自洽: rva=0x%x len=%d not in %r'
                                       % (rva0, len0, ranges))
                # 承重断言 ②: 该区间确实在 .text 段 CRC 的跨度内
                if off0 < 0 or off0 + len0 > t_crc:
                    raise RuntimeError('selfcrypt 区间 off=0x%x len=%d 超出 '
                                       '.text CRC 跨度 %d' % (off0, len0, t_crc))
                tgt_off = off0 + len0 // 2
                ctl_off = t_crc - 1     # 同 T4: .text 末字节，在 CRC 内、未掩码
                if any(mrva <= t_va + ctl_off < mrva + mlen
                       for mrva, mlen in ranges):
                    raise RuntimeError('对照偏移 0x%x 落在掩码区间内' % ctl_off)

                code_b, out_b, _ = run_demo(
                    args=['--license-file', LICENSE],
                    stdin=(serial + '\n').encode('utf-8'))
                body = make_selfcrypt_body_tampered_copy(t_ptr, tgt_off)
                code_t, out_t, _ = run_demo(
                    exe=body, args=['--license-file', LICENSE],
                    stdin=(serial + '\n').encode('utf-8'))
                ctrl = make_selfcrypt_body_tampered_copy(t_ptr, ctl_off)
                code_c, out_c, _ = run_demo(
                    exe=ctrl, args=['--license-file', LICENSE],
                    stdin=(serial + '\n').encode('utf-8'))

                base_ok = (code_b == 0) and (msg_ok in out_b)
                ctl_ok = (_norm_exit(code_c) == _norm_expect(PROT_EXIT_TAMPERED)
                          and msg_tamper in out_c)
                hit = (_norm_exit(code_t) == _norm_expect(PROT_EXIT_TAMPERED)
                       and msg_tamper in out_t)
                early_ok = True
                early = 'n/a'
                if '反调试扫描' in out_b:
                    early_ok = ('反调试扫描' not in out_t)
                    early = 'yes' if early_ok else 'no'
                ok = base_ok and ctl_ok and hit and early_ok
                results.append(
                    ('T30 cipher-crc', 'PASS' if ok else 'FAIL',
                     'exit=%d ctrl=%d base=%d n=%d off=0x%x early=%s%s' % (
                         code_t, code_c, code_b, n, tgt_off, early,
                         '' if (base_ok and ctl_ok) else ' (对照不成立)')))
    except Exception as e:
        if wdac_blocked(e):
            results.append(('T30 cipher-crc', 'SKIP',
                            'WDAC blocked tampered copy (winerror 4551)'))
        else:
            results.append(('T30 cipher-crc', 'FAIL', repr(e)))

    # ---- T5: VM 指令集单测 (Phase 1d 新增指令) ------------------------
    vm_unit = (os.path.join(BUILD, 'vm_unit.exe')
           if _PLATFORM == 'win'
           else os.path.join(REPO, 'build', 'vm_unit_linux'))
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
                b[len(b) // 2] = (ord('B') if b[len(b) // 2] != ord('B')
                              else ord('C'))  # C-3: **保证改变**
                                          # (与 C-2 A5 同因: 硬编码
                                          #  写 'B' 可能**本来就相等**
                                          #  -> 篡改无效 -> 假失败)
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
        ok = (_norm_exit(code) == _norm_expect(PROT_EXIT_BLOB_MISSING))
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
        ok = (_norm_exit(code) == _norm_expect(PROT_EXIT_BLOB_MISSING))
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
        # W4: **按平台分派**
        # Linux 侧: 字节**无法经命令行传** -> 写临时文件再让 mock 下发
        # （**文件是最通用的跨边界通道**；参数仍用命令行而非环境变量，
        #  见 §32.2）。
        if _PLATFORM != 'win':
            tmp = os.path.join(BUILD, '_w4_blob.bin')
            with open(tmp, 'wb') as _f:
                _f.write(blob_bytes)
            try:
                return _plat.start_wsl_mock(['--mode', 'blob',
                                        '--blob-file', to_wsl(tmp)])
            finally:
                try:
                    os.remove(tmp)
                except OSError:
                    pass
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
        ok = (_norm_exit(code) == _norm_expect(PROT_EXIT_BLOB_MISSING))
        results.append(('T28 online-blob-tamper', 'PASS' if ok else 'FAIL',
                        'exit=%d (tampered blob rejected by signature)' % code))
        srv.shutdown()
    except Exception as e:
        results.append(('T28 online-blob-tamper', 'FAIL', repr(e)))

    # ---- T15-T19: 授权吊销 (I1, 离线黑名单) ------------------------------
    PROT_EXIT_REVOKED = 0xB1E4
    vmenc = os.path.join(REPO, 'tools', 'vmenc.py')
    # ## 密钥是**共享的**（C-3 实测修正, 2026-09-25）
    #   `build/keys/*.json` 是**密钥材料** —— 两平台用**同一把私钥**
    #   （B 阶段证实: BCRYPT blob 与 DER 由同一私钥导出）->
    #   **不参与平台隔离**（隔离的边界 = **平台产物**，不是 build/ 下所有东西）。
    #   原来用 `BUILD`（已平台化）导致 `build/linux/keys/` 不存在 ->
    #   revoke **未签名**（v0 而非 v1）-> demo 按无效不阻断 -> T15 误判 FAIL。
    privkey = os.path.join(REPO, 'build', 'keys', 'license_priv.json')
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
        ok = (_norm_exit(code) == _norm_expect(PROT_EXIT_REVOKED))
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
        # W4: **按平台分派**（Linux 侧服务必须进 WSL —— 同 loopback 才通）
        if _PLATFORM != 'win':
            args = ['--mode', 'check']
            if revoke_serial:
                args += ['--revoke-serial', revoke_serial]
            return _plat.start_wsl_mock(args)
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
        ok = (_norm_exit(code) == _norm_expect(PROT_EXIT_REVOKED))
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
        #
        # ## S1 修正: **Linux 侧可真验证**（2026-09-25）
        #   判据"不可达 -> 降级"在 Linux **同样成立**，因为:
        #     · Windows: 端口 59999 未监听 -> `prot_plat_http_get_mem`
        #       返回网络失败 -> **走 else（降级）分支**
        #     · Linux: `prot_plat_http_get_mem` 返回 `PROT_ERR_UNSUPPORTED`
        #       -> **走同一个 else（降级）分支**
        #   => **代码路径相同**（"HTTP 不成功就降级"），故 Linux 的结果
        #      是对**同一分支**的真实验证（只是触发原因不同）。
        #   **诚实标注**: 触发原因不同（未实现 vs 不可达）——
        #      若将来 Linux 实现 HTTP，本用例需复查。
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
        if _PLATFORM != 'win':
            args = ['--mode', 'expect']
            if wrong:
                args += ['--wrong']
            return _plat.start_wsl_mock(args)
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

    # ## 汇总（C-3, 2026-09-25）: 透明列出 PASS/FAIL/SKIP/**PLATFORM_NA**
    #   —— 与 attacks.py（C-2）同一格式。
    #   `PLATFORM_NA` **不计失败**但**必须可见**（"未验证 != 通过"）；
    #   `SKIP` 是原设计的环境自检（如 T3 debug-preflight）。
    n_pass = sum(1 for _n, st, _d in results if st == 'PASS')
    n_fail = sum(1 for _n, st, _d in results if st == 'FAIL')
    n_skip = sum(1 for _n, st, _d in results if st == 'SKIP')
    n_na = sum(1 for _n, st, _d in results if st == 'PLATFORM_NA')
    print()
    print('[e2e] 平台=%s  总计 %d: PASS %d / FAIL %d / SKIP %d / NA %d'
          % (_PLATFORM, len(results), n_pass, n_fail, n_skip, n_na),
          flush=True)

    sys.exit(1 if failed else 0)


if __name__ == '__main__':
    import threading
    main()