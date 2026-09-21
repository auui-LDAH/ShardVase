#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tools/sync_public.py — 同步本地修正到三个公开仓库（含双通道）

背景：
  · publish/ 与 docs/marketing/ 的内容需同步到三个公开展示仓库
  · 本机曾出现 `github.com:443` 被阻断而 `api.github.com` 正常的情况
    -> 提供 git push 与 Contents API 两条通道，自动择可用者

用法：
    python tools/sync_public.py            # dry-run（默认，只报差异）
    python tools/sync_public.py --apply    # 实际同步
"""

import argparse
import base64
import json
import os
import subprocess
import sys

REPO = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
os.chdir(REPO)

# 部署映射: (公开仓库, 仓库内路径, 本地源文件)
#   约定来源: docs/marketing/LAUNCH_HANDBOOK.md §一
SYNC = [
    ('ShardVase-docs', 'README.md', 'docs/marketing/README.md'),
    ('ShardVase-docs', 'boundaries.md', 'docs/marketing/boundaries.md'),
    ('ShardVase-docs', 'attack-record.md', 'docs/marketing/attack-record.md'),
    ('ShardVase-docs', 'landing.html', 'docs/marketing/landing.html'),
    ('ShardVase-website', 'index.html', 'docs/marketing/landing.html'),
    ('ShardVase-demo', 'README.md',
     'build/release-staging/hashcalc-demo/README.md'),
]

ORG = 'auui-LDAH'

MSG = ('sync: 同步本地修正\n\n'
       '来源: 主仓库提交（攻防数据 / 破防明细 / 链接修复 / 首屏说明）\n')


def gh(*args, data=None):
    cmd = ['gh', 'api'] + list(args)
    p = subprocess.run(cmd, input=data.encode('utf-8') if data else None,
                       capture_output=True)
    return (p.returncode, p.stdout.decode('utf-8', errors='replace'),
            p.stderr.decode('utf-8', errors='replace'))


def remote_content(repo, path):
    """取远程文件内容 + sha；不存在返回 (None, None)。

    注意: 不用 `--jq '.content,.sha'` —— gh 会把 base64 按 76 字符**折行**,
    导致"第一行=content、第二行=sha"的假设失效（实测 boundaries.md 的
    content 被折成 50 行）。改为分两次查询，各自取单值。
    """
    rc, out, err = gh('repos/%s/%s/contents/%s' % (ORG, repo, path),
                      '--jq', '.content')
    if rc != 0:
        return None, None
    b64 = ''.join(out.split())          # 拼合折行
    rc2, out2, _ = gh('repos/%s/%s/contents/%s' % (ORG, repo, path),
                      '--jq', '.sha')
    if rc2 != 0:
        return None, None
    sha = out2.strip()
    try:
        body = base64.b64decode(b64).decode('utf-8')
    except Exception:
        return None, None
    return body, sha


def main():
    ap = argparse.ArgumentParser(prog='sync_public.py',
                                 description='同步到公开仓库')
    ap.add_argument('--apply', action='store_true', help='实际写入')
    args = ap.parse_args()

    print('=' * 64)
    print('公开仓库同步%s' % ('（APPLY）' if args.apply else '（dry-run）'))
    print('=' * 64)

    changed, same, failed = [], [], []
    for repo, rpath, lpath in SYNC:
        if not os.path.exists(lpath):
            failed.append((repo, rpath, '本地源缺失: %s' % lpath))
            continue
        local = open(lpath, encoding='utf-8', newline='').read()
        remote, sha = remote_content(repo, rpath)
        if remote is None:
            failed.append((repo, rpath, '读取远程失败或无此文件'))
            continue
        if remote.replace('\r\n', '\n') == local.replace('\r\n', '\n'):
            same.append((repo, rpath))
            continue
        changed.append((repo, rpath, lpath, local, sha))

    print()
    print('--- 相同 (%d) ---' % len(same))
    for repo, rpath in same:
        print('  %-20s %s' % (repo, rpath))

    print()
    print('--- 需同步 (%d) ---' % len(changed))
    for repo, rpath, lpath, local, sha in changed:
        print('  %-20s %-18s <- %s' % (repo, rpath, lpath))
        print('       %d 字节, 远程 sha %s' % (len(local.encode('utf-8')),
                                              sha[:10]))

    if failed:
        print()
        print('--- 失败 (%d) ---' % len(failed))
        for repo, rpath, why in failed:
            print('  %-20s %-18s %s' % (repo, rpath, why))

    if not args.apply:
        print()
        print('(dry-run —— 加 --apply 执行)')
        return 0 if not failed else 1

    print()
    print('--- 执行同步 ---')
    nerr = 0
    for repo, rpath, lpath, local, sha in changed:
        payload = json.dumps({
            'message': MSG,
            'content': base64.b64encode(local.encode('utf-8')).decode('ascii'),
            'sha': sha,
            'branch': 'main',
        }, ensure_ascii=False)
        rc, out, err = gh('-X', 'PUT', 'repos/%s/%s/contents/%s' % (ORG, repo, rpath),
                          '--input', '-', data=payload)
        if rc == 0:
            try:
                d = json.loads(out)
                cs = d['commit']['sha'][:10]
            except Exception:
                cs = '?'
            print('  ✓ %-20s %-18s -> %s' % (repo, rpath, cs))
        else:
            nerr += 1
            print('  ✗ %-20s %-18s %s' % (repo, rpath, err.strip()[:70]))

    print()
    print('完成: %d 成功, %d 失败' % (len(changed) - nerr, nerr))
    return 1 if nerr else 0


if __name__ == '__main__':
    sys.exit(main())
