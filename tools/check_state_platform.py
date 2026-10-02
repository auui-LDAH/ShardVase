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


#: ## gen_padding 会填充的**标准节**（与 tools/gen_padding.py 的 PADDABLE 一致）
#:   填充引用允许 = 本平台 json 的生成名 **∪** 这几个标准节。
STD_PAD_SECTIONS = {'.text', '.rdata'}


def check_padding_names(gen_dir):
    """**检查 ①**: `prot_padding.c` 引用的节名 ⊆ 本平台 json。

    ## 为什么需要（§34.2 的判据盲区）
      实测: Linux 的 padding 引用 **Windows 的节名**（`.gk9o791` 等）——
      既有两道检查**同时放行**:
        · `节名随机化` 查**产物**（由 C 源 `PROT_SEC_*` 宏产生，与填充无关）
        · `文件大小统一` 只比 3 次构建**彼此**一致（**同样错 -> 同样一致**）
      => "**自洽 ≠ 正确**" —— 需要**独立参照**（本检查即那个参照）。

    返回 (ok, detail)。padding 未生成 -> **info 不判失败**（可能是组合差异）。
    """
    pad = os.path.join(gen_dir, 'prot_padding.c')
    sj = os.path.join(gen_dir, 'prot_sections.json')
    if not os.path.isfile(pad):
        return True, 'padding not generated (info)'
    if not os.path.isfile(sj):
        return False, 'missing %s' % sj
    try:
        secs = json.load(open(sj, encoding='utf-8')).get('sections', {})
    except (OSError, ValueError) as e:
        return False, 'cannot parse %s: %s' % (sj, e)

    src = open(pad, encoding='utf-8', errors='replace').read()
    refs = set(re.findall(r'"(\.[A-Za-z0-9_]+)"', src))
    if not refs:
        return True, 'padding has no section literals (info)'
    allowed = set(secs.values()) | STD_PAD_SECTIONS
    foreign = sorted(refs - allowed)
    if foreign:
        # ## 这正是 §34.2 的缺陷形态（**实测发生过**）
        return False, ('padding 引用**非本平台**节名: %s '
                       '(gen_dir=%s; allowed=本平台 json + 标准节)'
                       % (foreign, os.path.basename(gen_dir)))
    return True, ('padding %d 节名 ⊆ json(%d 生成名) + 标准节'
                  % (len(refs), len(secs)))


def check_flat_clean(gen_root):
    """**检查 ②**: `demo/gen/` 根下**无文件**（flat 已清理，防复活）。

    ## 为什么需要（§34.6 的回归风险）
      flat 清理后**曾被 `vmc_tests` 复活**（根因已修 -> blob 改写 BUILD）
      —— 但**无守护** -> 将来谁再写 flat 都会静默出现，
      而且其中若有**旧平台的 json**（如 `prot_sections.json`），
      会成为**下一次 §34.2 缺陷的诱饵**。

    返回 (ok, detail)。
    """
    if not os.path.isdir(gen_root):
        return False, 'missing dir %s' % gen_root
    flat = sorted(f for f in os.listdir(gen_root)
                  if os.path.isfile(os.path.join(gen_root, f)))
    if flat:
        return False, ('flat 文件复活（本应只有 win/ 与 linux/ 子目录）: '
                       '%s' % flat)
    return True, 'flat clean (0 files, only win/ linux/)'


def missing_prereq(gen_dir, artifact):
    """**前置产物**是否齐备。齐备 -> `None`；否则返回缺失说明。

    ## 为什么必须与"错配"区分开（2026-10-02 实测缺陷）
      在**只构建 Windows** 的环境（CI 的 Windows-only runner、干净克隆）上，
      linux 产物与生成物**本就不存在** -> `check()` 返回 `missing ...` ->
      `main()` 汇总为 FAIL -> **门禁在干净环境上永远红**。
      实测: CI 上本项报 `[X]`，日志只有
        `[linux] FAIL missing ...demo/gen/linux/prot_sections.json`
      —— 报的是"文件没有"，**不是"状态错配"**。
      而"永远红的门禁" == 没有门禁（会被无视）。

    ## 但**也不能算通过**
      前置不存在时本判据**从未执行**。按本项目反复记名的
      「未验证 != 通过」，`main()` 走 **SKIP（退出 2）**，
      与 `tools/guard_selftest.py`(`SKIP: 缺 build/demo.exe ...（需先构建）`)、
      `tools/prot_dbg.py`(`T0 前置: 产物+map 就绪（缺则 SKIP，不假装通过）`)、
      `tools/linux_compile_check.py`(`return 2`) 的既有 SKIP 语义一致。

    ## 为什么本函数**不能**改 `check()`
      `check()` 的 `missing -> False` 是 `selftest` T4 负向用例的**判据本身**
      （"文件缺失 -> **必须 FAIL**（不崩溃）"，`:332-338`）。
      把 `check()` 改成返回 SKIP 会让 T4 失去意义（一个从未被负向测试
      证明过的判据等于没有判据）。=> 只把**前置判定**提到 `main()` 层，
      `check()` 的语义一字不改。
    """
    sj = os.path.join(gen_dir, 'prot_sections.json')
    if not os.path.isfile(sj):
        return '缺生成物 %s' % sj
    if not os.path.isfile(artifact):
        return '缺产物 %s' % artifact
    return None


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

    # ## D3（2026-09-29）: 两个判据盲区检查
    #   ① padding 节名 ⊆ 本平台 json（§34.2 "自洽 != 正确"的守护）
    #   ② flat 目录无残留（§34.6 防"复活"回归）
    ok_pad, det_pad = check_padding_names(gen_dir)
    if not ok_pad:
        problems.append('PAD: %s' % det_pad)
    ok_flat, det_flat = check_flat_clean(os.path.dirname(gen_dir))
    if not ok_flat:
        problems.append('FLAT: %s' % det_flat)

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
    return True, ('%d/%d section names applied; expect consistent; '
                  'pad=%s; flat=%s%s'
                  % (len(secs) - len(optional_missing), len(secs),
                     'ok' if ok_pad else det_pad,
                     'ok' if ok_flat else det_flat, note))


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
    skipped = []
    for p in plats:
        gen_dir, art = PLATFORMS[p]
        # 前置缺失 -> **SKIP**（不是 FAIL；见 missing_prereq 的注释）
        miss = missing_prereq(gen_dir, art)
        if miss is not None:
            results.append((p, None, miss))
            skipped.append(p)
            if not args.json:
                print('[%s] SKIP %s（本项未验证 != 通过）' % (p, miss))
            continue
        ok, det = check(gen_dir, art)
        results.append((p, ok, det))
        if not args.json:
            print('[%s] %-4s %s' % (p, 'ok' if ok else 'FAIL', det))

    if args.json:
        print(json.dumps([{'platform': p,
                           'ok': ok,
                           'skipped': ok is None,
                           'detail': d}
                          for p, ok, d in results],
                         ensure_ascii=False, indent=2))
    # ## 三态: 有 FAIL -> 1；**有任何平台被跳过 -> 2**（未验证 != 通过）；否则 0
    #
    #   为什么"部分跳过"也返回 SKIP（而不是"跳过 1 / 通过 1 就算 PASS"）:
    #   本项的名字与判据都是**跨平台**的（"生成物节名 ⊆ 产物"要两平台都成立
    #   才叫状态正常）。若 linux 产物根本没构建，本项**只验证了一半** ——
    #   报 `[ok]` 就是**过度声称**（"未验证 != 通过"）。诚实的做法是
    #   SKIP: 告诉读者"这项没跑全，别把它当通过"。
    #   CI 上（Windows-only runner）正是这种情况 -> 门禁显示 `[skip]`。
    checked = [(p, ok, d) for p, ok, d in results if ok is not None]
    n_fail = sum(1 for _, ok, _ in checked if not ok)
    all_ok = (n_fail == 0)
    if not args.json:
        print('[check_state_platform] %s (检查 %d/%d，跳过 %d)'
              % ('PASS' if all_ok else 'FAIL', len(checked), len(results),
                 len(skipped)))
        if skipped and all_ok:
            print('[check_state_platform] SKIP: %s 平台产物未构建 —— '
                  '本项未验证（未验证 != 通过）' % ','.join(skipped))
    if not all_ok:
        return 1
    if skipped:
        return 2
    return 0


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
    # ## 前置不满足 -> **SKIP，不报 FAIL**（2026-10-02 修正）
    #   原写法把 T0 也走 `case()` -> 缺产物时先打一行 `**FAIL** T0 前置`
    #   再打 SKIP，**看起来像失败**。而"前置不满足"与"判据不成立"是两回事:
    #   报告称 FAIL 会让读者以为状态错配 —— 实测 CI 上正是如此。
    #   现在: 前置不满足 -> 只打 SKIP 说明 + `return 2`（未验证 != 通过）。
    if not (win_ok and lin_ok):
        miss = []
        if not win_ok:
            miss.append('win（build/demo.exe + demo/gen/win/）')
        if not lin_ok:
            miss.append('linux（build/demo_linux + demo/gen/linux/）')
        print('')
        print('[check_state_platform-selftest] SKIP: %s 产物未就绪 —— '
              '需先构建（未验证 != 通过）' % ' 与 '.join(miss))
        return 2
    case('T0 前置: 两平台产物与生成物存在', True)

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

        # ## T6 **负向**: padding 节名错配（**正是 §34.2 的缺陷形态**）
        #
        # 构造: 临时目录放 **win 的 json + linux 的 padding** ->
        # padding 引用的名字都不在该 json 里 -> **必须 FAIL**。
        tmp6 = tempfile.mkdtemp(prefix='csp_pad_')
        try:
            shutil.copyfile(os.path.join(PLATFORMS['win'][0],
                                         'prot_sections.json'),
                            os.path.join(tmp6, 'prot_sections.json'))
            shutil.copyfile(os.path.join(PLATFORMS['linux'][0],
                                         'prot_padding.c'),
                            os.path.join(tmp6, 'prot_padding.c'))
            ok6, det6 = check_padding_names(tmp6)
            case('T6 **负向**: padding(win) + json(win 配 linux) -> 必须 FAIL',
                 not ok6)
            print('      detail: %s' % det6[:90])
        finally:
            shutil.rmtree(tmp6, ignore_errors=True)

        # ## T7 **负向**: flat 文件复活 -> 必须 FAIL
        #
        # 在**临时目录**造（**不碰真 demo/gen** —— 否则失败/中断会留污染）。
        tmp7 = tempfile.mkdtemp(prefix='csp_flat_')
        try:
            open(os.path.join(tmp7, 'stray.c'), 'w').close()
            ok7, det7 = check_flat_clean(tmp7)
            case('T7 **负向**: flat 出现文件 -> 必须 FAIL', not ok7)
            print('      detail: %s' % det7[:90])
        finally:
            shutil.rmtree(tmp7, ignore_errors=True)
    finally:
        shutil.rmtree(tmp2, ignore_errors=True)

    print()
    print('=' * 66)
    if fails:
        print('[check_state_platform-selftest] FAIL: %s' % '; '.join(fails))
        return 1
    print('[check_state_platform-selftest] PASS: 1 前置 + 1 正向 + **6 负向**均可自证')
    return 0


if __name__ == '__main__':
    sys.exit(main())
