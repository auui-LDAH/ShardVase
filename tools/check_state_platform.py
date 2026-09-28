#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""`tools/check_state_platform.py` — **构建状态自检**（A-d, 2026-09-25）。

## 为什么需要（**实测反复踩到**）
  虽然 A 阶段已按平台分目录，但仍有**跨平台误用**的可能：
  · 工具用错平台的 `prot_sections.json`（实测: e2e 打开 win 的 json
    -> "生成器名 无 已应用" -> 节名随机化判据 FAIL）
  · `vm_build.json` 的 machine_id 属另一平台（历史上造成 e2e 连环失败）

  ## 本工具的判据（**单一事实源**）
    **生成物目录的节名 ⊆ 产物的实际节名**：
    · `demo/gen/<plat>/prot_sections.json` 的所有 `<名称>` 必须出现在
      `build/<plat 产物>` 的节表里
    · 错配（win json + linux 产物 / 反之）-> **FAIL**（而非静默降级）
    + `expect_default.c` 与 `vm_build.json` 的 expect 一致性（同 P6）

  ## 与既有检查的关系
    · `protchain_check` 的 P6 检查 expect 一致性（**单产物**视角）
    · 本工具查**跨平台错配**（状态视角）—— 两者互补

## 自检（`--selftest`，含**负向**）
```
T1  linux 产物 + linux json  -> PASS
T2  linux 产物 + **win json**  -> **必须 FAIL**（制造的错配状态）
T3  win 产物 + **linux json**  -> **必须 FAIL**
T4  文件缺失                  -> **必须 FAIL**（不崩溃）
```
"""
import argparse
import json
import os
import re
import struct
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, 'tests'))

#: 平台 -> (生成物目录, 产物)
PLATFORMS = {
    'win': (os.path.join(REPO, 'demo', 'gen', 'win'),
            os.path.join(REPO, 'build', 'demo.exe')),
    'linux': (os.path.join(REPO, 'demo', 'gen', 'linux'),
              os.path.join(REPO, 'build', 'demo_linux')),
}
EXPECT_DEFAULT = {
    'win': 'expect_default.c',
    'linux': 'expect_default.c',
}
VM_BUILD_JSON = {
    'win': os.path.join(REPO, 'demo', 'vm_build.json'),
    'linux': os.path.join(REPO, 'build', 'linux', 'vm_build.json'),
}


def artifact_section_names(path):
    """产物的节名集合（**复用 protchain_check.sections_of**，自动分派）。"""
    from protchain_check import sections_of
    with open(path, 'rb') as f:
        return {s['name'] for s in sections_of(f.read())}


def check(gen_dir, artifact):
    """核心判据: **生成物节名 ⊆ 产物节名** + expect 一致性。

    返回 (ok, detail)。**错误不抛异常**（除文件缺失，显式返回 False）。
    """
    problems = []

    # ① 节名映射（prot_sections.json）
    sj = os.path.join(gen_dir, 'prot_sections.json')
    if not os.path.isfile(sj):
        return False, 'missing %s' % sj
    if not os.path.isfile(artifact):
        return False, 'missing %s' % artifact
    try:
        with open(sj, encoding='utf-8') as f:
            secs = json.load(f).get('sections', {})
    except (OSError, ValueError) as e:
        return False, 'cannot parse %s: %s' % (sj, e)
    if not isinstance(secs, dict) or not secs:
        return False, 'no sections in %s' % sj

    try:
        real = artifact_section_names(artifact)
    except Exception as e:                     # noqa: BLE001
        return False, 'cannot read sections of %s: %s' % (artifact, e)

    # ## 判据按**事实**分层（A-d 实测核查, 2026-09-25）
    #
    # 读源码 + map + readelf 三处确证:
    #   ① `PROT_CODE_SEG` 在 gcc = **文档化 no-op**
    #      （prot_compiler.h: "无对应：PE 段布局是平台概念"）
    #      => **protxec 在 Linux 设计上不存在**（Windows 必有）
    #   ② `PROT_SEC_FPT` **全库无使用者**（只有定义与随机化）
    #      => **fptable 随机名两平台都不存在**（Windows 只有字面 .fptable）
    #   ③ **protcrc / protcry / protpad 两平台都有** -> **功能必需**
    #      （selfcrypt meta / CRC 烧录 / 填充），可作**可靠判据**
    #
    # => 必需三节缺一个 = **跨平台错配**（FAIL）；
    #    protxec/fptable 缺失 = **已知设计差异**（info，不 FAIL）。
    REQUIRED = ('protcrc', 'protcry', 'protpad')
    optional_missing = []

    for k in REQUIRED:
        v = secs.get(k)
        if not isinstance(v, str):
            problems.append('required section %r missing from %s'
                            % (k, sj))
        elif v not in real:
            problems.append(
                'REQUIRED section %s=%s not in artifact '
                '**(cross-platform mismatch? gen=%s artifact=%s)**'
                % (k, v, os.path.basename(gen_dir),
                   os.path.basename(artifact)))

    # ## optional 只剩 protxec（S3 修正）
    #   · `protxec`: **Windows 有 / Linux 设计上无**
    #     （PROT_CODE_SEG 在 gcc = 文档化 no-op）-> 属**平台设计差异**
    #   · `fptable`: **已从 gen_sections 移除**（S3）—— 我们
    #     **根本不生成**这个映射（产物里的 .fptable 是 CRT 的），
    #     故它不再属于"设计差异"，而是"不存在"
    for k in ('protxec',):
        v = secs.get(k)
        if isinstance(v, str) and v not in real:
            optional_missing.append('%s=%s' % (k, v))

    # ② expect_default.c 与 vm_build.json 一致性（同 P6）
    exp = os.path.join(gen_dir, EXPECT_DEFAULT['linux'])
    vj = VM_BUILD_JSON['linux'] if 'linux' in gen_dir.replace('\\', '/') \
        else VM_BUILD_JSON['win']
    if os.path.isfile(exp):
        if not os.path.isfile(vj):
            problems.append('expect_default.c exists but vm_build.json '
                            'missing: %s' % vj)
        else:
            try:
                with open(exp, encoding='utf-8', errors='replace') as f:
                    src = f.read()
                m = re.search(
                    r'g_prot_expect_default\[2\] = \{ (0x[0-9a-fA-F]+)ULL, '
                    r'(0x[0-9a-fA-F]+)ULL \}', src)
                jb = json.load(open(vj, encoding='ascii'))
                if m and (jb.get('expect1') != m.group(1)
                          or jb.get('expect2') != m.group(2)):
                    problems.append('expect mismatch: default=%s/%s vs '
                                    'vm_build.json=%s/%s'
                                    % (m.group(1), m.group(2),
                                       jb.get('expect1'), jb.get('expect2')))
            except (OSError, ValueError) as e:
                problems.append('cannot parse expect artifacts: %s' % e)

    if problems:
        return False, '; '.join(problems)
    note = ''
    if optional_missing:
        # 已知设计差异（见 REQUIRED 注释）—— **提示，不判失败**
        note = ('; info: optional sections absent by design: %s'
                % ','.join(optional_missing))
    return True, ('%d/%d section names applied; expect consistent%s'
                  % (len(secs) - len(optional_missing), len(secs), note))


def main():
    ap = argparse.ArgumentParser(prog='check_state_platform.py')
    ap.add_argument('--platform', choices=['win', 'linux', 'both'],
                    default='both')
    ap.add_argument('--json', action='store_true')
    ap.add_argument('--quiet', action='store_true',
                    help='只输出汇总行（门禁用）')
    ap.add_argument('--selftest', action='store_true',
                    help='自检（**含负向**: 制造错配必须报错）')
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    plats = ['win', 'linux'] if args.platform == 'both' else [args.platform]
    results = []
    for p in plats:
        gen_dir, art = PLATFORMS[p]
        ok, det = check(gen_dir, art)
        results.append((p, ok, det))
        if not args.json:
            print('[%s] %-4s %s' % (p, 'ok' if ok else 'FAIL', det))

    if args.json:
        print(json.dumps([{'platform': p, 'ok': ok, 'detail': d}
                          for p, ok, d in results],
                         ensure_ascii=False, indent=2))
    all_ok = all(ok for _, ok, _ in results)
    if not args.json:
        print('[check_state_platform] %s (%d/%d)'
              % ('PASS' if all_ok else 'FAIL',
                 sum(1 for _, ok, _ in results if ok), len(results)))
    return 0 if all_ok else 1


def selftest():
    """自检: **正向 + 3 个负向**（制造错配必须被报出）。"""
    import shutil
    import tempfile

    fails = []

    _quiet = '--quiet' in (sys.argv or [])
    def case(name, ok):
        if not _quiet:
            print('  %s %-58s'
                  % ('ok ' if ok else '**FAIL**', name))
        if not ok:
            fails.append(name)

    print('=== check_state_platform 自检 ===')

    # T0 前置: 真实产物就绪
    lw, aw = PLATFORMS['win']
    ll, al = PLATFORMS['linux']
    win_ok = os.path.isfile(aw) and os.path.isfile(
        os.path.join(lw, 'prot_sections.json'))
    lin_ok = os.path.isfile(al) and os.path.isfile(
        os.path.join(ll, 'prot_sections.json'))
    case('T0 前置: 两平台产物与生成物存在（缺则需先构建）',
         win_ok and lin_ok)
    if not (win_ok and lin_ok):
        print()
        print('[check_state_platform-selftest] SKIP: 产物未就绪'
              '（未验证 != 通过）')
        return 2

    # T1 正向: linux 产物 + linux 生成物
    ok, det = check(ll, al)
    case('T1 **正向**: linux 产物 + linux 生成物 -> PASS', ok)
    if not ok:
        print('      detail: %s' % det)

    # T2 负向: linux 产物 + **win 生成物** -> 必须 FAIL
    ok2, det2 = check(lw, al)
    case('T2 **负向**: linux 产物 + win 生成物 -> **必须 FAIL**',
         not ok2)
    if not ok2:
        print('      detail: %s' % det2[:80])

    # T3 负向: win 产物 + **linux 生成物** -> 必须 FAIL
    ok3, det3 = check(ll, aw)
    case('T3 **负向**: win 产物 + linux 生成物 -> **必须 FAIL**',
         not ok3)
    if not ok3:
        print('      detail: %s' % det3[:80])

    # T4 负向: 文件缺失 -> 必须 FAIL 且**不崩溃**
    tmp = tempfile.mkdtemp(prefix='chkstate_')
    try:
        ok4, det4 = check(tmp, os.path.join(tmp, 'no_artifact.exe'))
        case('T4 **负向**: 文件缺失 -> **必须 FAIL**（不崩溃）',
             not ok4)
        print('      detail: %s' % det4[:80])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # T5 负向: expect 不一致 -> 必须 FAIL（在临时目录制造）
    tmp2 = tempfile.mkdtemp(prefix='chkstate2_')
    try:
        import shutil as _sh
        _sh.copytree(ll, os.path.join(tmp2, 'gen'), dirs_exist_ok=True)
        # 改 expect_default.c 的一个 expect 值
        exp = os.path.join(tmp2, 'gen', 'expect_default.c')
        src = open(exp, encoding='utf-8').read()
        altered = re.sub(r'expect2 值', '', src)
        # 直接替换第二个 ULL 值为全 a
        altered = re.sub(r'(g_prot_expect_default\[2\] = \{ 0x[0-9a-f]+ULL, )'
                         r'0x[0-9a-f]+(ULL)', r'\g<1>0xaaaa\g<2>', src)
        open(exp, 'w', encoding='utf-8', newline='\n').write(altered)
        ok5, det5 = check(os.path.join(tmp2, 'gen'), al)
        # ## 断言**失败原因**（防"因错误原因通过"——
        #   若因节名错配失败就看不到 expect 检查是否工作）
        case('T5 **负向**: expect 不一致 -> **FAIL 且因 expect**',
             (not ok5) and ('expect mismatch' in det5))
        print('      detail: %s' % det5[:90])
    finally:
        shutil.rmtree(tmp2, ignore_errors=True)

    print()
    print('=' * 66)
    if fails:
        print('[check_state_platform-selftest] FAIL: %s' % '; '.join(fails))
        return 1
    print('[check_state_platform-selftest] PASS: 正向 + 4 负向均可自证')
    return 0


if __name__ == '__main__':
    sys.exit(main())
