#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tools/oss_release.py — 完全开源执行清单（一键，含安全检查）

把 docs/HISTORY_REWRITE_PLAN.md 的步骤固化成一个**可审查**的脚本，
避免手工执行时漏步或顺序错误。

用法：
    python tools/oss_release.py --check          # 只做只读核查（默认）
    python tools/oss_release.py --rewrite        # 执行历史重写（不可逆）
    python tools/oss_release.py --update-sha     # 重写后更新 SHA 引用

设计原则：**每一步都可单独执行、单独验证**。默认 dry-run。
"""

import argparse
import glob
import os
import re
import shutil
import subprocess
import sys

REPO = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
os.chdir(REPO)

# 需清除的标识（内容层面）
LEAKS = ['issuer-host', 'test-host', 'DEV-MACHINE', 'devuser', 'devuser',
         'devuser', '100.x.x.x', '100.x.x.x']

# 身份目标（与既有公开仓库一致）
NEWNAME = 'jurecoasertkrockt777'
NEWMAIL = 'jurecoasertkrockt777@users.noreply.github.com'
OLDMAILS = ['jurecoasertkrockt777@users.noreply.github.com', 'devusereim2025@outlook.com']


def sh(*args, cwd=None, check=False):
    p = subprocess.run(list(args), cwd=cwd or REPO,
                       capture_output=True)
    return p.returncode, p.stdout.decode('utf-8', errors='replace'), \
        p.stderr.decode('utf-8', errors='replace')


def cmd_check():
    """只读核查：工作区 + 历史 + 身份 + 必备文件。"""
    print('=' * 64)
    print('开源就绪核查')
    print('=' * 64)

    ok = True

    print()
    print('--- 1. 工作区泄露 ---')
    rc, out, _ = sh('git', 'ls-files')
    files = [f for f in out.split('\n') if f.strip()]
    hits = 0
    for f in files:
        if not os.path.exists(f) or os.path.getsize(f) > 3_000_000:
            continue
        try:
            body = open(f, encoding='utf-8', errors='replace').read()
        except OSError:
            continue
        for n in LEAKS:
            if n in body:
                hits += 1
                print('  [X] %s 含 %s' % (f, n))
    print('  工作区命中: %d %s' % (hits, '✓' if hits == 0 else ''))
    ok = ok and hits == 0

    print()
    print('--- 2. git 历史泄露 ---')
    hist = 0
    for n in LEAKS:
        rc, out, _ = sh('git', 'log', '--all', '--oneline', '-S', n)
        c = len([l for l in out.split('\n') if l.strip()])
        if c:
            hist += 1
            print('  [X] %-18s 历史残留 %d 个提交' % (n, c))
    print('  历史命中: %d %s' % (hist, '✓' if hist == 0 else '(需 --rewrite)'))
    ok = ok and hist == 0

    print()
    print('--- 3. 提交身份 ---')
    rc, out, _ = sh('git', 'log', '--format=%an <%ae>|%cn <%ce>')
    ids = sorted(set(l for l in out.split('\n') if l.strip()))
    idbad = False
    for i in ids:
        flag = ''
        for m in OLDMAILS:
            if m in i:
                flag = '  <== 需 --rewrite'
                idbad = True
        print('  %s%s' % (i, flag))
    ok = ok and not idbad

    print()
    print('--- 4. 开源必备文件 ---')
    NEED = ['LICENSE', 'LICENSE.md', 'README.md', 'SECURITY.md',
            'CONTRIBUTING.md', 'CODE_OF_CONDUCT.md', '.gitignore',
            '.github/PULL_REQUEST_TEMPLATE.md',
            '.github/ISSUE_TEMPLATE/security.yml']
    for f in NEED:
        e = os.path.exists(f)
        if not e:
            ok = False
        print('  %s %s' % ('✓' if e else '[X]', f))

    print()
    print('--- 5. drills 输入可用性（开源阻塞检查）---')
    need_files = glob.glob(os.path.join(REPO, 'archive', 'attack-drill*.json'))
    ignored = 0
    for f in need_files:
        rc, _, _ = sh('git', 'check-ignore', '-q', os.path.relpath(f, REPO))
        if rc == 0:
            ignored += 1
    print('  archive/attack-drill*.json: %d 个, 被忽略 %d'
          % (len(need_files), ignored))
    if ignored:
        ok = False
        print('  [X] 克隆者无法运行 drills.py extract')
    else:
        print('  ✓ extract 输入全部入库')

    print()
    print('=' * 64)
    print('核查结论: %s' % ('✓ 已就绪' if ok else '! 有未完成项'))
    return 0 if ok else 1


def cmd_rewrite():
    """执行历史重写（不可逆）。"""
    print('=' * 64)
    print('历史重写 —— 不可逆操作')
    print('=' * 64)

    # 前置: 备份
    print()
    print('--- 0. 备份 ---')
    bundle = os.path.join(os.environ.get('TEMP', '/tmp'), 'oss-prerewrite.bundle')
    rc, _, err = sh('git', 'bundle', 'create', bundle, '--all')
    if rc != 0:
        print('  [X] bundle 备份失败: %s' % err[:100])
        return 1
    print('  ✓ %s (%.2f MB)' % (bundle, os.path.getsize(bundle) / 1024 / 1024))

    # 规则文件
    repl = os.path.join(os.environ.get('TEMP', '/tmp'), 'oss-replacements.txt')
    with open(repl, 'w', encoding='utf-8', newline='\n') as f:
        for n in LEAKS:
            val = '100.x.x.x' if n.startswith('100.') else (
                'issuer-host' if n == 'issuer-host' else
                'test-host' if n == 'test-host' else
                'DEV-MACHINE' if n.startswith('DESKTOP') else 'devuser')
            f.write('%s==>%s\n' % (n, val))
    print('  ✓ 替换规则: %s' % repl)

    mailmap = os.path.join(REPO, '.mailmap')
    with open(mailmap, 'w', encoding='utf-8', newline='\n') as f:
        f.write('%s <%s> <%s>\n' % (NEWNAME, NEWMAIL, OLDMAILS[0]))
        f.write('%s <%s> <%s>\n' % (NEWNAME, NEWMAIL, OLDMAILS[1]))
        f.write('%s <%s> jurecoasertkrockt777\n' % (NEWNAME, NEWMAIL))
    print('  ✓ .mailmap 已写（身份统一为 noreply）')

    # 执行
    print()
    print('--- 1. filter-repo ---')
    fr = shutil.which('git-filter-repo') or \
        os.path.join(os.path.dirname(sys.executable), 'Scripts', 'git-filter-repo.exe')
    if not os.path.exists(fr):
        print('  [X] 找不到 git-filter-repo（pip install git-filter-repo）')
        return 1
    p = subprocess.run([fr, '--replace-text', repl, '--mailmap', '.mailmap',
                        '--force'], cwd=REPO, capture_output=True)
    out = (p.stdout + p.stderr).decode('utf-8', 'replace')
    for l in out.split('\n'):
        if any(k in l for k in ('New history', 'Completely', 'Parsed 1', 'error')):
            print('  %s' % l.strip()[:100])
    if p.returncode != 0:
        print('  [X] 失败')
        return 1

    print()
    print('--- 2. 重写后核查 ---')
    return cmd_check()


def cmd_update_sha():
    """重写后更新文档 SHA 引用。"""
    cm = os.path.join(REPO, '.git', 'filter-repo', 'commit-map')
    if not os.path.isfile(cm):
        print('[X] 找不到 %s —— 先执行 --rewrite' % cm)
        return 1
    tool = os.path.join(REPO, 'tools', 'update_sha_refs.py')
    p = subprocess.run([sys.executable, '-X', 'utf8', tool, '--map', cm,
                        '--apply'], capture_output=True)
    out = (p.stdout + p.stderr).decode('utf-8', 'replace')
    for l in out.split('\n')[-12:]:
        if l.strip():
            print('  %s' % l.strip()[:100])
    return p.returncode


def main():
    ap = argparse.ArgumentParser(prog='oss_release.py',
                                 description='完全开源执行清单')
    g = ap.add_mutually_exclusive_group()
    g.add_argument('--check', action='store_true', help='只读核查（默认）')
    g.add_argument('--rewrite', action='store_true', help='执行历史重写（不可逆）')
    g.add_argument('--update-sha', action='store_true', help='更新文档 SHA 引用')
    args = ap.parse_args()

    if args.rewrite:
        return cmd_rewrite()
    if args.update_sha:
        return cmd_update_sha()
    return cmd_check()


if __name__ == '__main__':
    sys.exit(main())
