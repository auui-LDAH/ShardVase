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

# 身份目标（与既有公开仓库一致）—— 这是**公开**信息，可硬编码
NEWNAME = 'jurecoasertkrockt777'
NEWMAIL = 'jurecoasertkrockt777@users.noreply.github.com'

# 旧身份**不硬编码**，改为运行期从 git 历史探测。
#
# 为什么（2026-09-21 教训）: 初版把个人邮箱写成常量 OLDMAILS = ['<邮箱>', ...]，
# 结果**重写工具自己成了泄露源** —— 该文件入库后，历史里就永久留有那个邮箱，
# 而 filter-repo 的 mailmap 只重写提交元数据，不会清理文件内容。
# 改为探测后，工具本身不含任何个人数据，可安全公开。


def discover_old_identities():
    """从 git 历史探测需替换的旧身份（邮箱 + 用户名）。

    返回 (emails, names)。排除已是 noreply 的目标身份。
    """
    emails, names = set(), set()
    rc, out, _ = sh('git', 'log', '--all', '--format=%ae|%ce|%an|%cn')
    for line in out.split('\n'):
        if not line.strip():
            continue
        parts = line.split('|')
        for e in parts[:2]:
            e = e.strip()
            if e and e != NEWMAIL and 'noreply' not in e:
                emails.add(e)
        for n in parts[2:]:
            n = n.strip()
            if n and n != NEWNAME:
                names.add(n)
    return sorted(emails), sorted(names)


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
        # 判定: 只要不是目标 noreply 身份就算需处理（不依赖硬编码名单）
        if NEWMAIL not in i or NEWNAME not in i:
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

    # --- 6. 需人工决策的事项（脚本无法代决）---
    print()
    print('--- 6. 待人工决策 ---')
    pending = []

    # 历史重写：不可逆操作
    if hist:
        pending.append(('历史重写（不可逆）',
                        'python tools/oss_release.py --rewrite '
                        '-> 再 --update-sha'))

    # 定价文档：商业决策
    pricing = os.path.join(REPO, 'docs', 'commercial', 'PRICING.md')
    if os.path.exists(pricing):
        body = open(pricing, encoding='utf-8').read()
        if re.search(r'[¥￥]\s?[\d,]{3,}', body):
            pending.append((
                'docs/commercial/PRICING.md 含真实报价 —— 完全开源会一并公开',
                '三选一: 公开 / 移出仓库 / 保留并标注草案'))

    # 公开仓库同步：对外动作
    rc, out, _ = sh('git', 'remote', '-v')
    if not out.strip():
        # 统计待同步文件数（用同步工具的 dry-run 判定）
        sync_tool = os.path.join(REPO, 'tools', 'sync_public.py')
        n_pending = '?'
        if os.path.isfile(sync_tool):
            p = subprocess.run([sys.executable, '-X', 'utf8', sync_tool],
                               capture_output=True)
            txt = (p.stdout + p.stderr).decode('utf-8', 'replace')
            m = re.search(r'需同步 \((\d+)\)', txt)
            n_pending = m.group(1) if m else '?'
        pending.append((
            '公开仓库同步推送（对外动作）—— 待同步 %s 个文件' % n_pending,
            'python tools/sync_public.py --apply'))

    if pending:
        for i, (what, how) in enumerate(pending, 1):
            print('  %d. %s' % (i, what))
            print('     -> %s' % how)
    else:
        print('  (无)')

    print()
    print('=' * 64)
    if ok and not pending:
        print('核查结论: ✓ 已就绪，可执行开源')
    elif ok:
        print('核查结论: 自动项已就绪；另有 %d 项待人工决策' % len(pending))
    else:
        print('核查结论: ! 有未完成项（见上）')
    return 0 if ok else 1


def cmd_rewrite():
    """执行历史重写（不可逆）。"""
    print('=' * 64)
    print('历史重写 —— 不可逆操作')
    print('=' * 64)

    # 前置: 备份（两种形式, 且都**验证可恢复**）
    print()
    print('--- 0. 备份（bundle + 目录副本, 均验证）---')
    tmp = os.environ.get('TEMP', '/tmp')
    bundle = os.path.join(tmp, 'oss-prerewrite.bundle')
    rc, _, err = sh('git', 'bundle', 'create', bundle, '--all')
    if rc != 0:
        print('  [X] bundle 备份失败: %s' % err[:100])
        return 1
    print('  ✓ bundle: %s (%.2f MB)'
          % (bundle, os.path.getsize(bundle) / 1024 / 1024))

    # 验证 bundle 可克隆（不验证的备份等于没有）
    verify = os.path.join(tmp, '_oss_backup_verify')
    shutil.rmtree(verify, ignore_errors=True)
    rc, out, _ = sh('git', 'clone', '-q', bundle, verify)
    n_cur = sh('git', 'rev-list', '--count', 'HEAD')[1].strip()
    if rc != 0 or not os.path.isdir(os.path.join(verify, '.git')):
        print('  [X] bundle 验证失败 —— 中止（备份不可用不能继续）')
        return 1
    n_bak = sh('git', '-C', verify, 'rev-list', '--count', 'HEAD')[1].strip()
    print('  ✓ bundle 可克隆: %s 提交 (当前 %s)' % (n_bak, n_cur))
    if n_bak != n_cur:
        print('  [X] 备份提交数与当前不符 —— 中止')
        return 1
    shutil.rmtree(verify, ignore_errors=True)

    # 目录副本（用 git clone, 而非 shutil.copytree）
    #  教训: copytree 对 .git 可能复制到半写状态, 且 rmtree 在 Windows 上
    #  常因文件锁失败 -> 曾导致备份目录"部分删除"、.git 损坏。
    #  git clone 会校验对象完整性, 是更可靠的备份方式。
    dirbak = os.path.join(os.path.dirname(REPO),
                          os.path.basename(REPO) + '-backup-prehistory')
    if os.path.isdir(dirbak):
        print('  目录副本已存在, 跳过（如需刷新请手工删除后重跑）')
    else:
        rc, _, err = sh('git', 'clone', '-q', bundle, dirbak)
        if rc == 0:
            cnt = sh('git', '-C', dirbak, 'rev-list', '--count', 'HEAD')[1].strip()
            print('  ✓ 目录副本: %s (%s 提交)' % (dirbak, cnt))
        else:
            print('  [!] 目录副本创建失败（bundle 仍可用）: %s' % err[:80])

    # 规则文件
    #
    # 关键: 除 LEAKS 外, **还必须替换旧身份字符串** ——
    # mailmap 只重写提交元数据(author/committer), **不清理文件内容**。
    # 实测教训(A3): oss_release.py 自身与 HISTORY_REWRITE_PLAN.md 的旧版本
    # 在文件内容里留有个⼈邮箱, mailmap 处理后仍在历史中(2 处残留)。
    old_emails, old_names = discover_old_identities()
    print('  探测到旧身份: %d 个邮箱, %d 个用户名'
          % (len(old_emails), len(old_names)))

    repl = os.path.join(os.environ.get('TEMP', '/tmp'), 'oss-replacements.txt')
    n_rules = 0
    with open(repl, 'w', encoding='utf-8', newline='\n') as f:
        for n in LEAKS:
            val = '100.x.x.x' if n.startswith('100.') else (
                'issuer-host' if n == 'issuer-host' else
                'test-host' if n == 'test-host' else
                'DEV-MACHINE' if n.startswith('DESKTOP') else 'devuser')
            f.write('%s==>%s\n' % (n, val))
            n_rules += 1
        # 身份字符串（内容层面）—— 同样必须清除
        for e in old_emails:
            f.write('%s==>%s\n' % (e, NEWMAIL))
            n_rules += 1
        for nm in old_names:
            f.write('%s==>%s\n' % (nm, NEWNAME))
            n_rules += 1
    print('  ✓ 替换规则 %d 条: %s' % (n_rules, repl))

    # mailmap 写在工作副本内（REPO 根），重写后应删除 —— 它本身含旧身份明文。
    # 故写到临时目录 + 用 --mailmap 指定绝对路径，避免污染仓库。
    mailmap = os.path.join(os.environ.get('TEMP', '/tmp'), 'oss-mailmap.txt')
    with open(mailmap, 'w', encoding='utf-8', newline='\n') as f:
        for e in old_emails:
            f.write('%s <%s> <%s>\n' % (NEWNAME, NEWMAIL, e))
        for nm in old_names:
            f.write('%s <%s> %s\n' % (NEWNAME, NEWMAIL, nm))
    print('  ✓ mailmap %d 条（写在临时目录，不污染仓库）'
          % (len(old_emails) + len(old_names)))

    # 执行
    print()
    print('--- 1. filter-repo ---')
    fr = shutil.which('git-filter-repo') or \
        os.path.join(os.path.dirname(sys.executable), 'Scripts', 'git-filter-repo.exe')
    if not os.path.exists(fr):
        print('  [X] 找不到 git-filter-repo（pip install git-filter-repo）')
        return 1
    p = subprocess.run([fr, '--replace-text', repl, '--mailmap', mailmap,
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
