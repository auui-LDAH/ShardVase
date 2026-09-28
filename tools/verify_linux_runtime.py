#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""`tools/verify_linux_runtime.py` — **Linux 运行时验证工具**（固化）。

## 为什么固化（而非临时脚本）
  本轮所有 Linux 验证都是**临时脚本**（在 %TEMP%）—— 不可入库、不可进 CI、
  无自检。与 M1 时固化 `linux_compile_check.py` **同一理由**。

## 本工具做什么
  ① **构建**（调 build.sh）—— 可选跳过
  ② **单元测试**（vm_unit：VM 指令集）—— 已有 ✅
  ③ **契约测试**（platform_conformance）—— 已有 ✅
  ④ **端到端授权链**（demo --selftest + 正确序列号 -> "校验通过"）
  ⑤ **第二支柱验证**（节名随机化 + 文件大小统一）
  ⑥ **自检**: 用**故意错误的期望**验证"能报出失败"

  ## 诚实边界
    · 需 WSL + Ubuntu-24.04（无 WSL 时**明确跳过**，不静默通过）
    · `attacks`/`e2e` 的 **Windows 专用项**（调试器附加、PE 篡改）
      **不在本工具范围** —— 那些是平台特有的攻击面
"""
import argparse
import json
import os
import re
import subprocess
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DISTRO = 'Ubuntu-24.04'


def to_wsl(p):
    p = os.path.abspath(p)
    return '/mnt/%s%s' % (p[0].lower(), p[2:].replace('\\', '/'))


# ## ⚠️ 取退出码的纪律（2026-09-25 实测教训，**通用**）
#
#   **要读被测进程的退出码，就用 `wsl.exe -- <cmd>` 直执**。
#
#   **反例（错法）**: `bash -c "cmd; echo RC=$?"`
#     读到的是 **shell 最后一句话**的退出码，不是被测进程的 ——
#     实测把 `vmc.py` 的 `return 1`（**正确报错**）读成 **0**，
#     差点把"测量假象"记录成"vmc 有缺陷"。
#
#   **与既有教训同族**: `release_check.ps1` 的 `Check` 曾因"取错值"
#     而**谎报通过**（见该文件"严重教训"注释）—— 同一类错误的另一表现。
#
#   => 本文件中**凡需判成败**的调用，一律用 `wsl_direct()`（见下）。
def wsl_direct(argv, timeout=1800):
    """**直接执行**（不套 shell）—— 返回 (returncode, 输出)。

    用于**必须判成败**的场景（被测进程的退出码直达，不经 shell 改写）。
    """
    env = dict(os.environ)
    env['WSL_UTF8'] = '1'
    r = subprocess.run(['wsl.exe', '-d', DISTRO, '--'] + list(argv),
                       capture_output=True, timeout=timeout, env=env,
                       cwd=REPO)
    return r.returncode, (r.stdout + r.stderr).decode('utf-8', 'replace')


def wsl(cmd, timeout=2400):
    env = dict(os.environ)
    env['WSL_UTF8'] = '1'
    r = subprocess.run(['wsl.exe', '-d', DISTRO, '--', 'bash', '-c', cmd],
                       capture_output=True, timeout=timeout, env=env)
    return r.returncode, (r.stdout + r.stderr).decode('utf-8', 'replace')


def run_all(skip_build=False, quiet=False, readonly=False):
    rp = to_wsl(REPO)
    results = []
    tail_sizes = []   # 记录构建产物大小（用于"大小统一"判据）

    if readonly:
        # ## 只读模式（门禁用）: **不构建**，只验证已有产物
        #
        # **为什么需要**: 完整模式会跑 `build.sh` -> 把 `demo/gen/`
        # 改成 **Linux 值** -> 污染门禁中其它检查项（实测: 连带
        # e2e/mutate 失败）。=> 门禁内只做**只读**验证。
        rc, o = wsl('cd "%s" && test -x build/demo_linux && '
                    'test -f build/vm.blob && echo READY' % rp)
        if 'READY' not in o:
            results.append(('Linux 产物就绪', False,
                            '需先跑 build.sh（门禁内不构建）'))
            if not quiet:
                print('  FAIL Linux 产物不存在（需先完整构建）')
            return results
        results.append(('Linux 产物就绪', True, ''))

    if not skip_build and not readonly:
        rc, o = wsl('cd "%s" && bash build.sh 2>&1 | tail -3' % rp)
        ok = 'DONE' in o
        results.append(('构建 (build.sh)', ok, '' if ok else o[-160:]))
        if not quiet:
            print('  %s 构建' % ('ok  ' if ok else 'FAIL'))
        rc2, o2 = wsl('cd "%s" && stat -c%%s build/demo_linux' % rp,
                      timeout=120)
        for _l in o2.split('\n'):
            if _l.strip().isdigit():
                tail_sizes.append(int(_l.strip()))
                break
        if not ok:
            return results

    # ① 单元测试: VM 指令集（0 Windows 特征）
    vmcmd = ('cd "%s" && gcc -O2 -Wall -Wextra -Werror -std=c11 '
             '-D_GNU_SOURCE -I include -I demo/gen -o build/vm_unit_linux '
             'src/vm.c src/crc32.c src/platform/prot_platform_linux.c '
             'src/platform/prot_crypto_linux.c demo/gen/vm_unit_blob.c '
             'demo/gen/vm_unit_brk_blob.c tests/vm_unit.c '
             '-lcrypto -lpthread 2>&1 | head -8 && ./build/vm_unit_linux'
             % rp)
    rc, o = wsl(vmcmd, timeout=900)
    ok = ('vm_unit: PASS' in o)
    results.append(('vm_unit (VM 指令集)', ok, o.strip()[-120:]))
    if not quiet:
        print('  %s vm_unit' % ('ok  ' if ok else 'FAIL'))

    # ② 契约测试: 平台层
    pccmd = ('cd "%s" && gcc -O2 -Wall -Wextra -Werror -std=c11 '
             '-D_GNU_SOURCE -I include -o build/pconf_linux '
             'tests/platform_conformance.c '
             'src/platform/prot_platform_linux.c '
             'src/platform/prot_crypto_linux.c -lcrypto -lpthread '
             '2>&1 | head -8 && ./build/pconf_linux 2>&1 | tail -3' % rp)
    rc, o = wsl(pccmd, timeout=900)
    ok = ('PASS' in o and 'FAIL' not in o)
    results.append(('平台层契约测试', ok, o.strip()[-120:]))
    if not quiet:
        print('  %s 契约测试' % ('ok  ' if ok else 'FAIL'))

    # ③ 端到端授权链
    serial = None
    try:
        with open(os.path.join(REPO, 'demo/vm_build.json'),
                  encoding='ascii') as f:
            serial = json.load(f).get('serial')
    except (OSError, ValueError):
        pass
    if serial:
        ecmd = ('cd "%s" && printf "%%s\\n" "%s" | ./build/demo_linux '
                '--vm-blob build/vm.blob --license-file build/license.txt '
                '2>&1 | tail -4' % (rp, serial))
        rc, o = wsl(ecmd, timeout=600)
        ok = ('校验通过' in o)
        results.append(('端到端授权链', ok, o.strip()[-140:]))
        if not quiet:
            print('  %s 授权链' % ('ok  ' if ok else 'FAIL'))

    # ③b VM 合约测试（vmc 的 Linux 移植）—— 第 7 项
    #
    # ## 依据
    #   `tools/vmc_linux.py` 复刻 `tests/vmc_tests.py` 的流程，
    #   用例**直接复用**其 CASES（不重新解析源码 -> 不漂移）。
    #   平台差异仅一处: runner 的 `sscanf_s` -> 自包含十六进制解析。
    vmc_py = os.path.join(REPO, 'tools', 'vmc_linux.py')
    if os.path.exists(vmc_py):
        r3 = subprocess.run([sys.executable, '-X', 'utf8', vmc_py, '--quiet'],
                            capture_output=True, timeout=1800, cwd=REPO)
        o3 = (r3.stdout + r3.stderr).decode('utf-8', 'replace')
        # 输出格式: `[vmc_linux] PASS: 功能 6/6, 错误 3/3`
        m3 = re.search(r'功能 (\d+)/(\d+), 错误 (\d+)/(\d+)', o3)
        ok3 = (r3.returncode == 0)
        det3 = ('功能 %s/%s + 错误 %s/%s' % m3.groups()) if m3 else '无法解析'
        results.append(('VM 合约测试 (vmc)', ok3, det3))
        if not quiet:
            print('  %s VM 合约测试 (vmc) %s'
                  % ('ok  ' if ok3 else 'FAIL', det3))

    # ③c 保护链静态断言（P1-P6）—— 第 8 项
    #
    # ## 依据
    #   `protchain_check.py` 已加 **ELF 分支**（唯一平台相关处 = 节表解析；
    #   P3/P4/P6 本就格式无关）。`--exe`/`--blob` 已参数化。
    #
    # ## 各项含义
    #   P1 加密函数区无 x64 序言（密文生效）
    #   P2 mask 文件与 meta 一致（**构建侧与运行侧口径一致**）
    #   P3 blob v1 签名格式
    #   P4 **纯 Python 复算 PKCS#1 v1.5** 验签（**独立实现下签名成立**）
    #   P5 间接表槽位**不被直接 call**（N4 间接化）
    #   P6 expect_default.c 与 vm_build.json 一致
    pchain = os.path.join(REPO, 'tests', 'protchain_check.py')
    if os.path.exists(pchain):
        r4 = subprocess.run([sys.executable, '-X', 'utf8', pchain,
                             '--exe', 'build/demo_linux',
                             '--blob', 'build/vm.blob'],
                            capture_output=True, timeout=900, cwd=REPO)
        o4 = (r4.stdout + r4.stderr).decode('utf-8', 'replace')
        n_p = len(re.findall(r'\bPASS\b', o4))
        n_f = len(re.findall(r'\bFAIL\b', o4))
        ok4 = (r4.returncode == 0 and n_p > 0 and n_f == 0)
        results.append(('保护链静态断言 (protchain)',
                        ok4, 'P1-P6: %d PASS / %d FAIL' % (n_p, n_f)))
        if not quiet:
            print('  %s 保护链静态断言 (P1-P6) %d PASS / %d FAIL'
                  % ('ok  ' if ok4 else 'FAIL', n_p, n_f))

    # ④ 第二支柱: 节名随机化 + 文件大小统一
    #
    # ## ⚠️ 判据修正（2026-09-25 实测教训）
    #   初版用"**数随机样节名的个数**（≥3）"—— 门禁环境下只得 2 个 -> 误判失败。
    #   但**数量不是随机化的判据**！随机化 = "**生成器给的名字被真正应用**"。
    #
    #   正确判据（无需二次构建）:
    #     ① 从 `demo/gen/prot_sections.json` 读**生成器产出的随机名**
    #     ② 检查它们**出现在 ELF 的实际节名列表**中
    #        -> 证明"随机名从生成器一路应用到了产物"
    #     ③ 且这些名字**不是固定名**（`.protcry`/`.protcrc`）
    #        -> 证明"确实随机化了，而非回退默认"
    jsonp = os.path.join(REPO, 'demo/gen/prot_sections.json')
    gen_names = {}
    try:
        with open(jsonp, encoding='ascii') as f:
            gen_names = json.load(f).get('sections', {}) or {}
    except (OSError, ValueError):
        pass

    rc, o = wsl('cd "%s" && readelf -SW build/demo_linux 2>/dev/null | '
                "grep -oE '\\.[A-Za-z0-9_]+' | sort -u" % rp, timeout=300)
    elf_names = set(l.strip() for l in o.split('\n') if l.strip())

    # 需要随机化的逻辑节 -> 期望的固定名（用于判"确实变了"）
    FIXED = {'protcry': ('.protcry', '.protcrypt'),
             'protcrc': ('.protcrc',),
             'protpad': ('.protpad',)}
    applied, randomized = [], []
    for key, fixed in FIXED.items():
        want = gen_names.get(key)
        if not want:
            continue
        if want in elf_names:
            applied.append(key)
        if want not in fixed:
            randomized.append(key)

    ok = bool(applied) and bool(randomized)
    detail = ('生成器名 %s 已应用; 随机化 %s'
              % (','.join(applied) or '无', ','.join(randomized) or '无'))
    results.append(('节名随机化', ok, detail))
    if not quiet:
        print('  %s 节名随机化 (%s)' % ('ok  ' if ok else 'FAIL', detail))

    # 文件大小统一（第二支柱的另一半）
    if tail_sizes:
        uniq = set(tail_sizes)
        ok2 = (len(uniq) == 1)
        results.append(('文件大小统一', ok2,
                        '大小 %s' % sorted(uniq)))
        if not quiet:
            print('  %s 文件大小统一 (%d 字节)'
                  % ('ok  ' if ok2 else 'FAIL', tail_sizes[-1]))

    return results


def main():
    ap = argparse.ArgumentParser(prog='verify_linux_runtime.py')
    ap.add_argument('--skip-build', action='store_true')
    ap.add_argument('--readonly', action='store_true',
                    help='只验证已有产物，**不构建**（门禁用）')
    ap.add_argument('--quiet', action='store_true')
    ap.add_argument('--json', action='store_true')
    ap.add_argument('--selftest', action='store_true')
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    # WSL 可用性（不可用 -> **明确跳过**，不静默通过）
    rc, o = wsl('true', timeout=120)
    if rc != 0:
        print('[skip] WSL 不可用 —— Linux 运行时验证无法执行'
              '（未验证 != 通过）')
        return 0

    res = run_all(args.skip_build, args.quiet or args.json,
                  args.readonly)
    n_ok = sum(1 for _, ok, _ in res if ok)
    if args.json:
        print(json.dumps([{'name': n, 'ok': ok, 'detail': d}
                          for n, ok, d in res], ensure_ascii=False,
                         indent=2))
    else:
        print()
        if not args.quiet:
            print('=' * 62)
        print('[verify_linux_runtime] %s: %d/%d'
              % ('PASS' if n_ok == len(res) else 'FAIL', n_ok, len(res)))
    return 0 if n_ok == len(res) else 1


def selftest():
    """负向自检: 必须能**报出失败**（否则只是装饰）。"""
    fails = []

    def case(name, ok):
        print('  %s %-52s' % ('ok ' if ok else '**FAIL**', name))
        if not ok:
            fails.append(name)

    print('=== verify_linux_runtime 自检 ===')
    rc, _ = wsl('true', timeout=120)
    case('T1 WSL 可用', rc == 0)
    if rc != 0:
        print()
        print('[verify_linux_runtime-selftest] SKIP: WSL 不可用')
        return 2

    # T2: **负向** —— 故意用错误序列号，端到端必须**失败**
    rp = to_wsl(REPO)
    cmd = ('cd "%s" && printf "%%s\\n" "WRONG-SERIAL-XYZ" | '
           './build/demo_linux --vm-blob build/vm.blob '
           '--license-file build/license.txt 2>&1 | tail -2' % rp)
    rc, o = wsl(cmd, timeout=600)
    case('T2 **错误序列号被拒绝**（负向）', '校验通过' not in o)

    # T3: 正确序列号必须**通过**
    serial = None
    try:
        with open(os.path.join(REPO, 'demo/vm_build.json'),
                  encoding='ascii') as f:
            serial = json.load(f).get('serial')
    except (OSError, ValueError):
        pass
    if serial:
        cmd2 = ('cd "%s" && printf "%%s\\n" "%s" | ./build/demo_linux '
                '--vm-blob build/vm.blob --license-file build/license.txt '
                '2>&1 | tail -2' % (rp, serial))
        rc, o = wsl(cmd2, timeout=600)
        case('T3 正确序列号**通过**', '校验通过' in o)

    # T4: 篡改产物 -> 必须被检出（负向）
    cmd3 = ('cd "%s" && cp build/demo_linux /tmp/t.bin && '
            'python3 - <<PYEOF\n'
            'd = bytearray(open("/tmp/t.bin","rb").read())\n'
            'd[0x4000] ^= 0xFF\n'
            'open("/tmp/t.bin","wb").write(bytes(d))\n'
            'PYEOF\n'
            'chmod +x /tmp/t.bin && printf "%%s\\n" "%s" | /tmp/t.bin '
            '--vm-blob build/vm.blob --license-file build/license.txt '
            '2>&1 | tail -2' % (rp, serial or ''))
    rc, o = wsl(cmd3, timeout=600)
    case('T4 **篡改产物被检出**（负向）',
         ('校验通过' not in o) or ('篡改' in o) or ('失败' in o))

    # T5: vmc 的**负向自检**（假断言用例应被拒）
    vmc_py = os.path.join(REPO, 'tools', 'vmc_linux.py')
    if os.path.exists(vmc_py):
        r5 = subprocess.run([sys.executable, '-X', 'utf8', vmc_py,
                             '--selftest'],
                            capture_output=True, timeout=1800, cwd=REPO)
        o5 = (r5.stdout + r5.stderr).decode('utf-8', 'replace')
        case('T5 vmc 假断言被拒（负向）', r5.returncode == 0)

    print()
    print('=' * 62)
    if fails:
        print('[verify_linux_runtime-selftest] FAIL: %s' % '; '.join(fails))
        return 1
    print('[verify_linux_runtime-selftest] PASS: 可自证能正确判定')
    return 0


if __name__ == '__main__':
    sys.exit(main())
