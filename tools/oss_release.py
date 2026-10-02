#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ShardVase contributors
# 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；商业授权见 LICENSE.md。
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
import tempfile
import subprocess
import sys

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
os.chdir(REPO)

# 需清除的标识（内容层面）—— **不存放在本仓库内**。
#
# 设计教训（2026-09-21，自指陷阱的两次出现）:
#   1. 初版把个人邮箱硬编码为常量 -> 工具本身成为泄露源，
#      而 filter-repo 的 mailmap 只改元数据，清不掉文件内容。
#   2. 改为"常量 LEAKS 列表"后，**替换规则把工具自己的常量也替换了** ——
#      `--replace-text` 作用于所有 blob，包括定义规则的那个文件，
#      结果 LEAKS 变成了替换后的新值（['issuer-host', ...]），工具失效。
#
# 根本矛盾: 要清除的字符串**不能出现在被清除的仓库里**。
# 故改为从**仓库外**的配置文件读取（默认 %TEMP%/oss-leaks.txt）。
#
# 这样同时满足: 仓库不含敏感串 + 工具可正常工作 + 对未来新增泄露可复用。
LEAKS_FILE = os.environ.get(
    'OSS_LEAKS_FILE',
    os.path.join(os.environ.get('TEMP', tempfile.gettempdir()),
                 'oss-leaks.txt'))

# 替换值的**推断规则**（不含任何原始标识 —— 那是自指陷阱）
#
# 关键: 本文件不得出现任何"待清除的原始标识"。
# 已踩坑两次:
#   1. 硬编码个人邮箱 -> 工具成为泄露源
#   2. 硬编码 LEAKS 常量 -> 规则把工具自己的常量替换成新值, 工具失效
#   3. (本次) REPLACE_MAP_DEFAULT 的 **dict 键**就是原始标识 -> 又成了泄露
# 故: 原标识只从仓库外的 oss-leaks.txt 读；本文件只保留**推断新值**的规则。
REPLACE_RULES = [
    # (匹配方式, 新值)
    ('ip', '100.x.x.x'),            # 形如 100.x.x.x 的 CGNAT 内网地址
    ('winmachine', 'DEV-MACHINE'),  # DESKTOP-* / LAPTOP-* / 全大写短名
    ('host', 'host'),               # 其它主机名 -> 通用占位（下方细化）
    ('user', 'devuser'),            # 其它短标识（用户名等）
]


# 身份目标（与既有公开仓库一致）—— **公开**信息，可硬编码
NEWNAME = 'jurecoasertkrockt777'
NEWMAIL = 'jurecoasertkrockt777@users.noreply.github.com'


def load_leaks():
    """从仓库外的文件读取待清除标识。

    文件格式: 每行一个标识（# 开头为注释）。
    返回列表；文件不存在则返回空列表（工具仍可用，只是无规则可生成）。
    """
    if not os.path.isfile(LEAKS_FILE):
        return []
    out = []
    for line in open(LEAKS_FILE, encoding='utf-8'):
        s = line.strip()
        if s and not s.startswith('#'):
            out.append(s)
    return out


def leak_replacement(leak):
    """按**特征**推断替换值（不依赖任何硬编码的原始标识）。

    这样本文件可以安全地随仓库公开 —— 它只知道"什么形态该替换成什么"，
    不知道"具体要清除哪些串"（那些在仓库外的 oss-leaks.txt 里）。
    """
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', leak):
        return '100.x.x.x'                       # IP 地址
    if re.match(r'^(DESKTOP|LAPTOP|WIN)-', leak, re.I):
        return 'DEV-MACHINE'                     # Windows 默认机器名格式
    if re.match(r'^[A-Z][A-Z0-9]{5,}$', leak) and not leak.islower():
        return 'DEV-MACHINE'                     # 全大写短名（如 8.3 形式）
    if re.match(r'^[a-z][a-z0-9_-]{2,}$', leak) and '-' not in leak:
        # 全小写单词：可能是主机名或用户名 —— 统一用中性占位
        return 'devuser'
    return 'redacted'

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


def rm_dir(path):
    """可靠地删除目录（Windows 文件锁环境下）。

    教训（两次踩坑）:
      1. shutil.rmtree 在 Windows 上常因文件锁**静默失败**（ignore_errors=True
         会吞掉异常），留下半删目录
      2. 残留目录会让后续 `git clone` 报 "already exists and is not an empty dir"

    故: 先试 rmtree, 再用 `cmd /c rd /s /q` 兜底, 最后确认目录真的没了。
    返回 True 表示目录已不存在。
    """
    if not os.path.isdir(path):
        return True
    shutil.rmtree(path, ignore_errors=True)
    if os.path.isdir(path):
        winproc.run(['cmd', '/c', 'rd', '/s', '/q', path],
                       capture_output=True)
    if os.path.isdir(path):
        # 再等一会（杀毒/索引可能短暂持有句柄）
        import time
        for _ in range(5):
            time.sleep(0.4)
            shutil.rmtree(path, ignore_errors=True)
            if not os.path.isdir(path):
                break
    return not os.path.isdir(path)


def sh(*args, cwd=None, check=False):
    p = winproc.run(list(args), cwd=cwd or REPO,
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
    print('--- 1. 工作区泄露（含身份字符串的内容层扫描）---')
    rc, out, _ = sh('git', 'ls-files')
    files = [f for f in out.split('\n') if f.strip()]
    # 扫描目标 = 泄露清单 + 旧身份的**完整串与本地部分**
    #
    # 教训(A4 后实测): 原先只扫 load_leaks()，而文档里出现的是邮箱的
    # **本地部分**（邮箱 @ 前的数字串），完整邮箱规则匹配不到 -> 残留逃逸。
    targets = list(load_leaks())
    old_emails, old_names = discover_old_identities()
    for e in old_emails:
        targets.append(e)
        loc = e.split('@')[0]
        if len(loc) >= 5:
            targets.append(loc)
    targets += old_names
    targets = sorted(set(t for t in targets if t))

    hits = 0
    for f in files:
        if not os.path.exists(f) or os.path.getsize(f) > 3_000_000:
            continue
        try:
            body = open(f, encoding='utf-8', errors='replace').read()
        except OSError:
            continue
        for n in targets:
            if n in body:
                hits += 1
                print('  [X] %s 含 %s' % (f, n))
    print('  扫描目标 %d 个, 工作区命中: %d %s'
          % (len(targets), hits, '✓' if hits == 0 else ''))
    ok = ok and hits == 0

    print()
    print('--- 2. git 历史泄露 ---')
    hist = 0
    for n in load_leaks():
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

    # 定价文档：**已按 D2 决策移出仓库**（2026-09-21）
    # 保留此检查以防回归: 若定价文档重新出现在版本库中, 应再次提请决策。
    pricing = os.path.join(REPO, 'docs', 'commercial', 'PRICING.md')
    plan = os.path.join(REPO, 'docs', 'COMMERCIAL_PLAN.md')
    for pf, nm in ((pricing, 'docs/commercial/PRICING.md'),
                   (plan, 'docs/COMMERCIAL_PLAN.md')):
        if os.path.exists(pf):
            body = open(pf, encoding='utf-8').read()
            if re.search(r'[¥￥]\s?[\d,]{3,}', body):
                pending.append((
                    '%s 含真实报价但仍在仓库中（应已移出）' % nm,
                    '执行 D2: git rm + gitignore; 备份到仓库外'))

    # 公开仓库同步：对外动作
    rc, out, _ = sh('git', 'remote', '-v')
    if not out.strip():
        # 统计待同步文件数（用同步工具的 dry-run 判定）
        sync_tool = os.path.join(REPO, 'tools', 'sync_public.py')
        n_pending = '?'
        if os.path.isfile(sync_tool):
            p = winproc.run([sys.executable, '-X', 'utf8', sync_tool],
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
    if not rm_dir(verify):
        # 无法清空验证目录 —— 换一个带时间戳的路径，而不是误判为"备份不可用"
        print('  [!] 验证目录无法清空, 改用新路径')
        verify = os.path.join(tmp, '_oss_backup_verify_%d' % os.getpid())
    rc, out, _ = sh('git', 'clone', '-q', bundle, verify)
    n_cur = sh('git', 'rev-list', '--count', 'HEAD')[1].strip()
    if rc != 0 or not os.path.isdir(os.path.join(verify, '.git')):
        err = sh('git', 'clone', bundle, verify)[2]
        print('  [X] bundle 验证失败 —— 中止（备份不可用不能继续）')
        print('      原因: %s' % err.strip().split('\n')[-1][:100])
        return 1
    n_bak = sh('git', '-C', verify, 'rev-list', '--count', 'HEAD')[1].strip()
    print('  ✓ bundle 可克隆: %s 提交 (当前 %s)' % (n_bak, n_cur))
    if n_bak != n_cur:
        print('  [X] 备份提交数与当前不符 —— 中止')
        return 1
    rm_dir(verify)

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
    leaks = load_leaks()
    if not leaks:
        print('  [!] 未读到泄露清单（%s）—— 仅替换身份字符串' % LEAKS_FILE)
    with open(repl, 'w', encoding='utf-8', newline='\n') as f:
        for n in leaks:
            f.write('%s==>%s\n' % (n, leak_replacement(n)))
            n_rules += 1
        # 身份字符串（内容层面）—— 同样必须清除
        for e in old_emails:
            f.write('%s==>%s\n' % (e, NEWMAIL))
            n_rules += 1
            # 同时替换邮箱的**本地部分**（@ 前的数字串），
            # 否则文档里只写数字时仍会残留（A4 后实测发现 1 处）。
            local = e.split('@')[0]
            if len(local) >= 5 and local not in leaks:
                f.write('%s==>devuser\n' % local)
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
    p = winproc.run([fr, '--replace-text', repl, '--mailmap', mailmap,
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
    p = winproc.run([sys.executable, '-X', 'utf8', tool, '--map', cm,
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
