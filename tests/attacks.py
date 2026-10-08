# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ShardVase contributors
# 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；商业授权见 LICENSE.md。
"""
tests/attacks.py - 攻击模拟测试 (基础设施, 不需真机, Lane D)

在随构建生成的产物上做无调试器的"攻击者视角"回归, 验证保护在多种旁路下仍就地:

  A1 machine-bind         本机正确序列号+有效授权必须通过 (machine_id 绑定成立)
  A2 vm-ciphertext        VM 镜像 blob 的字节呈高熵均匀分布 (非明文: 静态不可还原)
  A3 build-fingerprint    记录本轮 VM 镜像内容指纹 (供跨轮对比随机性)
  A4 selftest-clean       --selftest 干净环境各项为 0 (新检测项无误报, 与 T7 互补)
  A5 license-forge        改 1 位签名 -> 必须被判无效 (RSA 防伪造)
  A6 license-other-machine 用同一私钥给异机 machine_id 签 license -> 本机必须拒绝
  A7 license-tier-forge   改 TIER 行 -> 必须被判无效 (Phase 4 分级授权防篡改)
  A8 blob-forge           构造 v0 blob (无签名) -> 拒绝 (D1a 强制 v1, BLOB_SIGN)
  A9 revoke-forge         构造 v0 黑名单 -> 不阻断 (签名强制, revoke 签名)
  A10 static-trace        静态扫描 N4 受保护函数无直接 call (间接化成本)
  A11 selfcrypt-dump      静态 dump 引擎函数无序言特征 (N1 密文)
  A12 offline-fix-expect  在线会话值覆盖本地固定期望值 (N5 边界)

依赖: 已构建产物 (build\\demo.exe / demo\\gen\\*.c / build\\license.txt)。
纯黑盒: 不解析 VM 结构, 不修改受保护文件。
任一 FAIL -> sys.exit(1)。
"""

import hashlib
import json
import os
import struct
import subprocess
import sys
import zlib

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
# ## 平台感知路径（C-2, 2026-09-25）
#   `--platform linux` -> 用 `build/demo_linux` + `build/linux/...`
#   （A 阶段已把状态文件按平台隔离）。
#
#   **为什么默认仍是 Windows**: 保持既有行为（门禁里 attacks 项跑 Windows），
#   Linux 侧由 `--platform linux` 显式选择（与 genpaths 的"显式平台"原则一致）。
# ## 平台适配公共层（S5, 2026-09-25）
#   平台解析 / 归一化 / WSL 直执 全部来自 `tests/_platform.py`
#   （**单一来源** —— 原先 e2e 与 attacks 各写一遍，实测已漂移）。
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _platform as _plat          # noqa: E402

_PLATFORM = _plat.parse_platform(sys.argv)

sys.path.insert(0, os.path.join(REPO, 'tools'))
import genpaths as _gp             # noqa: E402

_P = _gp.paths(_PLATFORM)
EXE = (os.path.join(REPO, 'build', 'demo.exe') if _PLATFORM == 'win'
       else os.path.join(REPO, 'build', 'demo_linux'))
JSON_PATH = _P.vm_build_json
STRINGS = os.path.join(REPO, 'demo', 'strings.txt')
LICENSE = _P.b('license.txt')          # A1: sign 产物（按平台）
VMENC = os.path.join(REPO, 'tools', 'vmenc.py')

# ## 干净环境应全 0 的字段（C-2: 按平台）
#   ⚠️ Linux/WSL **本身就是虚拟机** -> `vm_hypervisor` / `vm_vendor`
#   会被**正确报出**（源码标注为"**咨询项, 不影响运行**"）——
#   那是"检测有效"而非"环境脏"。
#   => Linux 侧排除这两个字段（**平台语义**，非放宽）。
CLEAN_FIELDS = ('peb_being_debugged', 'peb_nt_global_flag', 'debug_port',
                'debug_flags', 'debug_object', 'hardware_breakpoints',
                'timing_suspicious', 'kernel_debugger', 'debug_heap_flags',
                'int3_honey')
#: Linux 侧额外排除的"咨询项"字段
CLEAN_FIELDS_LINUX = CLEAN_FIELDS + ('vm_hypervisor', 'vm_vendor',
                                     'vm_processes')


def _msg(name):
    with open(STRINGS, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.rstrip('\r\n')
            if '|' in line:
                key, _, text = line.partition('|')
                if key.strip() == name:
                    return text
    return name


# `to_wsl` 来自公共层（S5）；保留同名别名以免改多处调用点。
to_wsl = _plat.to_wsl


def _norm_exit(code, platform=None):
    """平台语义归一化（S5: 委托公共层 `_platform.norm_exit`）。"""
    return _plat.norm_exit(code, platform or _PLATFORM)
def _norm_expect(expected, platform=None):
    """期望值归一化（S5: 委托公共层 `_platform.norm_expect`）。"""
    return _plat.norm_expect(expected, platform or _PLATFORM)
def run_demo(args=None, stdin=None):
    """运行 demo，返回 (returncode, stdout)。

    ## 平台分派（C-2, 2026-09-25）
      · **win**: 本地 `Popen`（现状，行为不变）
      · **linux**: 经 `wsl.exe` 执行 —— ELF **不能在 Windows 上直接跑**
        （实测: `OSError 8 / 193 不是有效的 Win32 应用程序`）

      ## 为什么只改这一处
        12 个用例里 **10 个**只依赖本函数的**返回值契约** ->
        改这里即可全部生效（**单点适配**，避免逐用例改）。
    """
    if _PLATFORM != 'win':
        return _run_demo_wsl(args, stdin)
    cmd = [EXE] + (args or [])
    p = winproc.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, cwd=os.path.dirname(EXE))
    try:
        out, err = p.communicate(stdin, timeout=40)
    except subprocess.TimeoutExpired:
        # ## 超时也必须回收（2026-10-08 修，**与 e2e.run_demo 同一处缺陷**）
        #   原实现让 `TimeoutExpired` 上抛 -> demo 作为**活进程**留下
        #   -> Windows 上独占自身映像 -> 门禁 `mutate_check` 的
        #   `shutil.copy2` 报 `[WinError 32]`（CI 偶发 FAIL，
        #   证据见 docs/HANDOVER.md §2.50 与 build/_leak_probe.py）。
        _plat.reap(p)
        return None, ''
    return p.returncode, out.decode('utf-8', 'replace')


def _run_demo_wsl(args, stdin):
    """经 WSL 运行 Linux 产物（返回码/输出契约与 `run_demo` 一致）。

    ## ⚠️ 自动补 `--vm-blob`（C-2 实测）
      Windows 侧 `run_demo` 的 cwd 是 `build/`，`vm.blob` 就在旁边 ->
      demo 默认能找到；**Linux 侧 blob 在 `build/linux/`** ->
      不传 `--vm-blob` 就报 **"VM 镜像装载失败 (code=10)"** ->
      A1/A4/A9/A12 全部失败（**实测输出直指此项**）。

      => 由本适配层**自动追加**（调用方未显式传时）——
         **平台差异在适配层吸收**，10 个用例无需改动。
    """
    args = list(args or [])
    # ## ⚠️ **所有路径型参数都要转 WSL 形态**（C-2 决定性实测）
    #   实测: `--license-file` 传的是 Windows 绝对路径
    #   （`D:\...\build\linux\license.txt`）-> demo 在 WSL 里**打不开**
    #   -> `license: 0`（验签失败）-> A1/A4 误报失败。
    #
    #   => 逐个把"看起来是 Windows 绝对路径"的参数转成 WSL 形式。
    #      （与 A 阶段"路径的来源与形态要同时考虑"同一教训。）
    def _fix_arg(a):
        if isinstance(a, str) and len(a) > 2 and a[1] == ':' \
                and a[2] in ('\\', '/'):
            return to_wsl(a)
        return a

    args = [_fix_arg(a) for a in args]
    if '--vm-blob' not in args:
        args += ['--vm-blob', to_wsl(_P.b('vm.blob'))]
    env = dict(os.environ)
    env['WSL_UTF8'] = '1'
    # ## ⚠️ **不经 bash**（C-2 决定性实测）
    #   `bash -c "cd ... && exec demo ..."` 会**消费/重定向 stdin**
    #   -> demo 读到空 -> `license: 0`（验签失败）-> A1/A4 误报失败。
    #
    #   实测对比（**唯一差异 = stdin 方式**）:
    #     手工 `run(..., input=serial+chr(10))`      -> rc=0, license: 1 ✅
    #     测试 `Popen(..., stdin=PIPE)+communicate`  -> rc=1, license: 0 ❌
    #   两条命令逐字符一致。
    #
    #   => **用 `wsl.exe -- <exe> <args>` 直执**（不经 shell）：
    #      · stdin 直达 demo
    #      · 退出码直达（与 G 阶段 vmc 的教训同源 —— **凡需精确控制
    #        子进程 IO/状态，就不经 shell 包装**）
    #
    #   `cwd` 由 `wsl --cd` 指定（demo 需要 cwd 找 vm.blob 等相对路径）。
    cmd = ['wsl.exe', '-d', 'Ubuntu-24.04', '--cd',
           to_wsl(os.path.dirname(EXE)), '--', to_wsl(EXE)] + args
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, env=env)
    try:
        out, _ = p.communicate(stdin, timeout=60)
    except subprocess.TimeoutExpired:
        # ## 超时也必须回收（2026-10-08 修，同 `run_demo` 的 win 分支）
        _plat.reap(p)
        return None, ''
    return p.returncode, (out or b'').decode('utf-8', 'replace')


def blob_bytes():
    """从 demo/gen/vm_*_blob.c 提取 s_code 字节数组. 返回 {name: bytes}.
    只处理 vm_*_blob.c (排除 expect_default.c 等其他生成物)。"""
    out = {}
    # C-2: 生成物目录**按平台**（A 阶段已隔离）
    _gen = _P.gen
    for fn in sorted(os.listdir(_gen)):
        if not fn.startswith('vm_') or not fn.endswith('_blob.c'):
            continue
        with open(os.path.join(_gen, fn), 'r', encoding='utf-8') as f:
            text = f.read()
        # s_code[] = { 0x12, ... }; 找第一个 '{' 与对应 '}'
        start = text.find('{')
        end = text.find('}', start)
        if start < 0 or end < 0:
            continue
        body = text[start + 1:end]
        vals = []
        for tok in body.replace('\n', ' ').split(','):
            tok = tok.strip()
            if tok.lower().startswith('0x'):
                vals.append(int(tok, 16) & 0xFF)
        if vals:
            out[os.path.basename(fn)] = bytes(vals)
    return out


def shannon_entropy(data):
    if not data:
        return 0.0
    hist = [0] * 256
    for b in data:
        hist[b] += 1
    import math
    ent = 0.0
    n = float(len(data))
    for c in hist:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


def main():
    with open(JSON_PATH, 'r', encoding='utf-8') as f:
        cfg = json.load(f)
    serial = cfg['serial']
    msg_ok = _msg('MSG_OK')
    msg_fail = _msg('MSG_FAIL')

    results = []

    # ---- A1: 本机 machine_id 绑定成立 (带有效授权文件) ------------------
    try:
        if not os.path.isfile(LICENSE):
            raise RuntimeError('license.txt not found (run build.ps1)')
        code, out = run_demo(args=['--license-file', LICENSE],
                             stdin=(serial + '\n').encode('utf-8'))
        ok = (code == 0) and (msg_ok in out) and ('license: 1' in out)
        results.append(('A1 machine-bind', 'PASS' if ok else 'FAIL',
                        'code=%d' % code))
    except Exception as e:
        results.append(('A1 machine-bind', 'FAIL', repr(e)))

    # ---- A2: VM 镜像密文高熵 (非明文可静态还原) -----------------------
    # 只统计 VM blob (vm_*_blob.c); 用相对熵 (ent/log2(len), 上限 1.0),
    # 小 blob (如 21 字节的 gate) 绝对熵低但比例应接近 1 —— 这才证明是密文。
    try:
        blobs = blob_bytes()
        bad = []
        for name, data in sorted(blobs.items()):
            if not name.startswith('vm_') or not name.endswith('_blob.c'):
                continue
            if len(data) < 4:
                continue
            ent = shannon_entropy(data)
            import math
            rel = ent / math.log2(len(data))
            if rel < 0.85:
                bad.append('%s rel=%.2f' % (name, rel))
        vm_count = sum(1 for n in blobs if n.startswith('vm_') and n.endswith('_blob.c'))
        ok = (vm_count >= 4) and (not bad)
        results.append(('A2 vm-ciphertext', 'PASS' if ok else 'FAIL',
                        'blobs=%d %s' % (vm_count, '; '.join(bad) or 'high-entropy')))
    except Exception as e:
        results.append(('A2 vm-ciphertext', 'FAIL', repr(e)))

    # ---- A3: 本轮镜像内容指纹 (供跨轮对比) ----------------------------
    try:
        h = hashlib.sha256()
        for name, data in sorted(blob_bytes().items()):
            h.update(name.encode('ascii'))
            h.update(data)
        results.append(('A3 build-fingerprint', 'PASS',
                        'sha256=%s' % h.hexdigest()[:16]))
    except Exception as e:
        results.append(('A3 build-fingerprint', 'FAIL', repr(e)))

    # ---- A4: --selftest 干净环境全 0 (vm_* 为咨询项, VM 环境预期非 0, 仅记录) ----
    try:
        code, out = run_demo(args=['--selftest', '--license-file', LICENSE],
                             stdin=(serial + '\n').encode('utf-8'))
        nonzero = []
        vm_notes = []
        for line in out.splitlines():
            line = line.strip()
            if ':' not in line:
                continue
            fname, _, fval = line.partition(':')
            fname = fname.strip()
            fval = fval.strip()
            if fname.startswith('vm_') or fname.startswith('dbi_'):
                if fval != '0':
                    vm_notes.append('%s=%s' % (fname, fval))
            elif fname in CLEAN_FIELDS and fval != '0':
                nonzero.append('%s=%s' % (fname, fval))
        # C-2: **平台语义归一化**（Linux 的 exit 只保留低 8 位）
        #   ⚠️ 注意 `vm_*` / `dbi_*` 已在上面归入 `vm_notes`（**咨询项**，
        #   不算 nonzero）—— WSL 本身是虚拟机，`vm_hypervisor=1` 是
        #   "检测有效"而非"环境脏"（源码标注: 咨询项, 不影响运行）。
        ok = (_norm_exit(code) == 0) and (not nonzero)
        results.append(('A4 selftest-clean', 'PASS' if ok else 'FAIL',
                        'code=%d nonzero=%s vm=%s' %
                        (code, nonzero or 'none', vm_notes or 'none')))
    except Exception as e:
        results.append(('A4 selftest-clean', 'FAIL', repr(e)))

    # ---- A5: 伪造授权 (改签名 1 位) 必须被拒 --------------------------
    # 演示 RSA 防伪造: 攻击者就算完全复刻 VM/expect 算法, 也造不出合法签名。
    try:
        forged = os.path.join(REPO, 'build', 'license_forged.txt')
        with open(LICENSE, 'r', encoding='utf-8') as f:
            lines = f.read().splitlines()
        out_lines = []
        for ln in lines:
            if ln.startswith('SIGNATURE='):
                s = ln[len('SIGNATURE='):]
                b = bytearray(s.encode('ascii'))
                b[len(b) // 2] = ord('B') if b[len(b) // 2] != ord('B') else ord('C') if b[len(b) // 2] != ord('B') else ord('C')
                out_lines.append('SIGNATURE=' + b.decode('ascii'))
            else:
                out_lines.append(ln)
        with open(forged, 'w', encoding='utf-8', newline='\n') as f:
            f.write('\n'.join(out_lines) + '\n')
        code, out = run_demo(args=['--license-file', forged],
                             stdin=(serial + '\n').encode('utf-8'))
        ok = (code == 1) and ('license: 0' in out)
        results.append(('A5 license-forge', 'PASS' if ok else 'FAIL',
                        'code=%d license_ok=0' % code))
    except Exception as e:
        results.append(('A5 license-forge', 'FAIL', repr(e)))

    # ---- A6: 异机授权 (机器标识不匹配) 必须被拒 ------------------------
    # 用同一私钥给「另一台机器 id」签一份 license, 当前机器运行应拒绝
    # (载荷含 machine_id, 与本地 hostid 不同 -> 验签失败)。
    try:
        other = os.path.join(REPO, 'build', 'license_othermachine.txt')
        winproc.run(
            ['python', VMENC, 'sign', '--key',
             os.path.join(REPO, 'build', 'keys', 'license_priv.json'),
             '--json', JSON_PATH, '--out', other,
             '--machine-id', '0x123456789ABCDEF0'],
            check=True, capture_output=True)
        code, out = run_demo(args=['--license-file', other],
                             stdin=(serial + '\n').encode('utf-8'))
        ok = (code == 1) and ('license: 0' in out)
        results.append(('A6 license-other-machine', 'PASS' if ok else 'FAIL',
                        'code=%d license_ok=0' % code))
    except Exception as e:
        results.append(('A6 license-other-machine', 'FAIL', repr(e)))

    # ---- A7: 分级授权 tier 篡改 (Phase 4, 与 e2e T12 互补) --------------
    try:
        forged = os.path.join(REPO, 'build', 'license_tier_forged.txt')
        with open(LICENSE, 'r', encoding='utf-8') as f:
            lines = f.read().splitlines()
        out_lines = []
        for ln in lines:
            if ln.startswith('TIER='):
                cur = ln[len('TIER='):]
                out_lines.append('TIER=' + ('2' if cur != '2' else '0'))
            else:
                out_lines.append(ln)
        with open(forged, 'w', encoding='utf-8', newline='\n') as f:
            f.write('\n'.join(out_lines) + '\n')
        code, out = run_demo(args=['--license-file', forged],
                             stdin=(serial + '\n').encode('utf-8'))
        ok = (code == 1) and ('license: 0' in out)
        results.append(('A7 license-tier-forge', 'PASS' if ok else 'FAIL',
                        'code=%d license_ok=0' % code))
    except Exception as e:
        results.append(('A7 license-tier-forge', 'FAIL', repr(e)))

    # ---- A8: 伪造签名 blob (ATTACK_PLAN) ---------------------------------
    # 攻击者手段: 理解格式后构造 v0 blob (无签名, 自算 CRC) —— D1a 强制 v1
    # 应拒绝。从现有 v1 blob 剥离签名区构造 v0 (不改动保护文件)。
    try:
        blob_path = os.path.join(REPO, 'build', 'vm.blob')
        if not os.path.isfile(blob_path):
            raise RuntimeError('vm.blob not found (run build.ps1)')
        v1 = open(blob_path, 'rb').read()
        # v1: MAGIC8|COUNT4|entries|SIG_LEN4|SIG384|CRC4 -> v0: MAGIC8|COUNT4|entries|CRC4
        sig_off = len(v1) - 4 - 384 - 4
        body = b'PROTVMBL' + v1[8:sig_off]
        v0 = body + struct.pack('<I', zlib.crc32(body) & 0xFFFFFFFF)
        forged_path = os.path.join(REPO, 'build', 'vm_forged_v0.blob')
        with open(forged_path, 'wb') as f:
            f.write(v0)
        code, out = run_demo(args=['--license-file', LICENSE,
                                   '--vm-blob', forged_path],
                             stdin=(serial + '\n').encode('utf-8'))
        # C-2: **平台语义归一化**（Linux 的 exit 只保留低 8 位 -> 11）
        ok = (_norm_exit(code) == _norm_expect(0xB10B))  # BLOB_MISSING
        results.append(('A8 blob-forge', 'PASS' if ok else 'FAIL',
                        'code=%d (v0 forged blob rejected)' % code))
    except Exception as e:
        results.append(('A8 blob-forge', 'FAIL', repr(e)))

    # ---- A9: 伪造黑名单 (ATTACK_PLAN) ------------------------------------
    # 攻击者手段: 构造 v0 黑名单 (PROTREVK, 自算 CRC) 想吊销他人/绕过 ——
    # 签名强制下应 CORRUPT 不阻断; 且真实 v1 黑名单命中语义不变。
    try:
        revoke_path = os.path.join(REPO, 'build', 'revoke_forged_v0.blob')
        body = (b'PROTREVK' + struct.pack('<I', 1) + struct.pack('<I', 1) +
                b'VICTIM-SERIAL-0001'.ljust(48, b'\x00') +
                struct.pack('<I', 0xFF) + struct.pack('<Q', 0))
        v0 = body + struct.pack('<I', zlib.crc32(body) & 0xFFFFFFFF)
        with open(revoke_path, 'wb') as f:
            f.write(v0)
        code, out = run_demo(args=['--license-file', LICENSE,
                                   '--vm-blob', os.path.join(REPO, 'build', 'vm.blob'),
                                   '--revoke-file', revoke_path],
                             stdin=(serial + '\n').encode('utf-8'))
        # 伪造 v0 黑名单: 损坏 -> 不阻断 (CORRUPT 语义), 正常通过
        ok = (code == 0) and (msg_ok in out)
        results.append(('A9 revoke-forge', 'PASS' if ok else 'FAIL',
                        'code=%d (forged v0 blacklist non-blocking)' % code))
    except Exception as e:
        results.append(('A9 revoke-forge', 'FAIL', repr(e)))

    # ---- A10: 静态追踪 N4 间接链 (ATTACK_PLAN) ---------------------------
    # 攻击者手段: dumpbin/反汇编静态追踪, 找 prot_vm_run 等目标函数的直接
    # call 或从间接表定位 —— N4 间接化应使"直接 call"不存在。
    #
    # ## ⚠️ M4 实测修正（2026-09-25）
    #   本项原先**自己重算**一份与 P5 相同的判据，因而**继承了 P5 的四个缺陷**
    #   （坐标系错配 / 密文噪声 / 函数集合错误 / 未区分设计允许的调用）。
    #   证据: 修正前 A10 报 `direct-call=['0x6430']` —— 那是**数值巧合**，
    #   与间接化无关（详见 `protchain_check.p5_indirect_no_direct_call`
    #   的注释）。
    #
    #   => **改为直接复用 P5 的修正实现** ——
    #      避免"同一判据在两处各写一遍"（复制即漂移；本项已因此错过修正）。
    try:
        import sys as _sys
        _sys.path.insert(0, os.path.join(REPO, 'tests'))
        # C-2: 用 `sections_of`（**自动分派 PE/ELF**）而非 `pe_sections`
        from protchain_check import (sections_of,
                                     p5_indirect_no_direct_call)
        exe_data = open(EXE, 'rb').read()
        secs = sections_of(exe_data)
        ok, why = p5_indirect_no_direct_call(exe_data, secs)
        results.append(('A10 static-trace', 'PASS' if ok else 'FAIL',
                        'N4 indirect: %s' % why))
    except Exception as e:
        results.append(('A10 static-trace', 'FAIL', repr(e)))

    # ---- A11: dump 视角验证 N1 自变形 (ATTACK_PLAN) ----------------------
    # 攻击者手段: 静态 dump 引擎函数做特征扫描 (找 x64 序言) —— 加密态
    # 应无序言特征; 运行期 dump 为 D2a 明文, 属设计语义 (诚实记录)。
    try:
        import sys as _sys2
        _sys2.path.insert(0, os.path.join(REPO, 'tests'))
        # C-2: 同上 —— 用自动分派版本
        from protchain_check import sections_of as _ps
        from protchain_check import selfcrypt_meta as _sc_meta2
        exe_data = open(EXE, 'rb').read()
        secs = _ps(exe_data)
        text = next(s for s in secs if s['name'] == '.text')
        plain = []
        for rva, ln, _grp in _sc_meta2(exe_data, secs):
            toff = text['ptr_raw'] + (rva - text['virtual_addr'])
            head = exe_data[toff:toff + 8]
            if head.startswith((b'\x40\x55', b'\x40\x56', b'\x40\x57',
                                b'\x48\x89', b'\x48\x83')):
                plain.append(hex(rva))
        ok = (not plain)
        results.append(('A11 selfcrypt-dump', 'PASS' if ok else 'FAIL',
                        'plaintext-fns=%s (static ciphertext)' %
                        (plain or 'none')))
    except Exception as e:
        results.append(('A11 selfcrypt-dump', 'FAIL', repr(e)))

    # ---- A12: 离线固定期望值对抗 N5 会话值 (ATTACK_PLAN) ------------------
    # 攻击者手段: 认为"固定本地期望值可一劳永逸"——在线会话下服务端下发
    # 不同值, 固定值失效。此处用错误期望值模拟"攻击者固定值"。
    try:
        import http.server as _hs
        import threading as _th

        class _H(_hs.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                # 错误期望值: 攻击者固定的值 (与服务端真实值不同)
                body = (b'{"status":"ok","tier":1,'
                        b'"expect1":"0x1111111111111111",'
                        b'"expect2":"0x2222222222222222"}')
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(body)

        # ## W4: **按平台分派** —— Linux 侧服务必须进 WSL
        #   （demo 在 WSL 内，Windows 侧的 127.0.0.1 它连不到 ——
        #    实测 curl rc=7，§32.2 记录）。
        #   `mock_http --mode expect --wrong` 的语义与本类 `_H` **相同**。
        if _PLATFORM != 'win':
            srv = _plat.start_wsl_mock(['--mode', 'expect', '--wrong'])
        else:
            srv = _hs.HTTPServer(('127.0.0.1', 0), _H)
            th = _th.Thread(target=srv.serve_forever, daemon=True)
            th.start()
        url = 'http://127.0.0.1:%d/v1/check' % srv.server_address[1]
        code, out = run_demo(args=['--license-file', LICENSE,
                                   '--vm-blob', os.path.join(REPO, 'build', 'vm.blob'),
                                   '--check-url', url],
                             stdin=(serial + '\n').encode('utf-8'))
        srv.shutdown()
        ok = (code == 1) and (msg_fail in out)
        # ## C-2: Linux 侧**平台不适用**（在线会话能力缺失）
        #   A12 依赖在线会话（HTTP 服务器 + `--check-url`），而服务器跑在
        #   **Windows 侧** -> **WSL 的 127.0.0.1 != Windows 的 127.0.0.1**
        #   -> demo 连不上 -> 走**离线降级**（`code=0`）。
        #
        #   **这是预期的平台行为**（C 阶段已记录: Linux 侧网络能力如实降级，
        #   `prot_plat_http_get*` 返回 `PROT_ERR_UNSUPPORTED`）。
        #   => 该项在 Linux 上**无法按原判据验证** -> 标记 `PLATFORM_NA`，
        #      **不伪装成 PASS**（"未验证 != 通过"）。
        #
        #   ## ⚠️ S1/S2 修正（2026-09-25）: 放进 WSL **也不可行**
        #     原以为"若服务器进 WSL 本项可验证" —— **实测推翻**:
        #     `prot_plat_http_get*` 在 Linux **如实返回
        #     `PROT_ERR_UNSUPPORTED`**（设计决策: 不用 libcurl）——
        #     demo **不会发起请求**，服务器放哪里都无用。
        #     => 本项在 Linux 属"**设计上不可验证**"（非"待做"）。
        #        要在 Linux 通过需**先实现 Linux HTTP**（产品特性决策）。
        # ## W4: **去 NA**（2026-09-25）—— Linux 已有 HTTP 能力
        #   此前 Linux 侧标 `PLATFORM_NA`，理由是
        #   `prot_plat_http_get*` 返回 `PROT_ERR_UNSUPPORTED`（**W3 之前**）。
        #   **W3 之后**实现 POSIX socket HTTP -> 本用例**真跑**。
        #   => 与 Windows **同一判据**（不再有平台特例）。
        results.append(('A12 offline-fix-expect',
                        'PASS' if ok else 'FAIL',
                        'code=%d (online session value overrides '
                        'local fix)' % code))
    except Exception as e:
        results.append(('A12 offline-fix-expect', 'FAIL', repr(e)))

    # ## 统计: `PLATFORM_NA` **不计入失败**（C-2）
    #   但**单独列出**（透明），不混入 PASS。
    n_na = sum(1 for _n, st, _d in results if st == 'PLATFORM_NA')
    failed = False
    for name, status, detail in results:
        print('%-20s  %-4s   (%s)' % (name, status, detail), flush=True)
        if status == 'FAIL':
            failed = True
    # ## 汇总（C-2）: 透明列出 PASS / FAIL / **平台不适用**
    #   —— `PLATFORM_NA` 单独计数（**不混入 PASS**），符合
    #      "未验证 != 通过"的纪律。
    n_pass = sum(1 for _n, st, _d in results if st == 'PASS')
    n_fail = sum(1 for _n, st, _d in results if st == 'FAIL')
    print()
    print('[attacks] 平台=%s  总计 %d: PASS %d / FAIL %d / NA %d'
          % (_PLATFORM, len(results), n_pass, n_fail, n_na), flush=True)
    sys.exit(1 if failed else 0)


if __name__ == '__main__':
    main()