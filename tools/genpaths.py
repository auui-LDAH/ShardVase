#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""`tools/genpaths.py` — **生成物路径的单一来源**（A-a，2026-09-25）。

## 为什么需要（A 阶段的动机，**实测**）
  A 阶段要把 `demo/gen/` **按平台分目录**（`demo/gen/win` + `demo/gen/linux`）。
  但实测**改动面很大**:
```
引用 demo/gen 的文件: 98 个（含 build.ps1 × 49 + build.sh × 38）
路径形态: 头文件 10 处 / C 源 42 处 / JSON 4 处 / BIN 12 处 / 资源 2 处
```
  若让**每个调用点各自拼路径**，必然漏改、且难以核查。
  => 引入本模块作为**唯一**回答"生成物目录在哪"的地方。

  ## 为什么不是"所有路径都归它管"
    实测 `build/` 下的东西**本来就已按平台区分文件名**
    （`build/demo.exe` vs `build/demo_linux`）—— **不冲突**。
    本模块**只负责真正冲突的那一类**: `demo/gen/`（共享目录）
    以及状态文件 `vm_build.json`（两侧内容不同）。
    **不做大包大揽**（那会引入无谓的间接层）。

## 设计原则
  ① **显式平台参数**（不依赖运行环境猜测）—— 构建脚本**必须**明确
     自己在为哪个平台构建（否则"猜错平台"这类 bug 无法定位）
  ② **默认值安全**: 未指定平台时，从 `genpaths` 所在仓库推断
     （Windows 上默认 win / 其他默认 linux），但**构建脚本应显式传**
  ③ **`paths()` 返回一个不可变的结构**（而非散落的函数）——
     便于打印、比对、自检

## 诚实边界
  · 本模块**只给路径**，不保证目录存在（调用方按需 `makedirs`）
  · 平台名只有 `win` / `linux` 两种（其他平台需先扩展）
  · **不改变** `build.ps1`/`build.sh` 的默认行为：
  `--layout flat` 可回到旧的 `demo/gen/`（迁移期用）
"""
import os
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PLATFORMS = ('win', 'linux')

#: 布局模式
#:   'split' = demo/gen/win + demo/gen/linux（**目标形态**）
#:   'flat'  = demo/gen（**迁移期兼容**，旧行为）
LAYOUT_SPLIT = 'split'
LAYOUT_FLAT = 'flat'


class GenPaths:
    """生成物路径集合（**不可变**，仅承载路径）。"""

    __slots__ = ('repo', 'platform', 'layout', 'gen', 'vm_build_json')

    def __init__(self, repo, platform, layout):
        self.repo = repo
        self.platform = platform
        self.layout = layout
        if layout == LAYOUT_FLAT:
            self.gen = os.path.join(repo, 'demo', 'gen')
            self.vm_build_json = os.path.join(repo, 'demo', 'vm_build.json')
        else:
            self.gen = os.path.join(repo, 'demo', 'gen', platform)
            # 状态文件按平台分（**两侧内容不同 -> 真冲突**）
            if platform == 'linux':
                self.vm_build_json = os.path.join(repo, 'build', 'linux',
                                                  'vm_build.json')
            else:
                self.vm_build_json = os.path.join(repo, 'demo',
                                                  'vm_build.json')

    # ---- 常用派生子路径（**避免调用方各自拼**）----
    def g(self, *parts):
        """生成物目录下的文件路径（**推荐用法**）。"""
        return os.path.join(self.gen, *parts)

    def include_dirs(self):
        """`-I` 包含路径（与 gen 同目录的**还包括 demo/**，见调用方）。"""
        return [self.gen]

    def as_dict(self):
        return {
            'repo': self.repo,
            'platform': self.platform,
            'layout': self.layout,
            'gen': self.gen,
            'vm_build_json': self.vm_build_json,
        }

    def __repr__(self):
        return ('GenPaths(platform=%r, layout=%r, gen=%r)'
                % (self.platform, self.layout, self.gen))


def default_platform():
    """推断当前平台（**仅供未显式指定时兜底**）。

    ⚠️ 构建脚本**应显式传平台** —— 推断会掩盖"在错误平台构建"的问题。
    """
    return 'win' if os.name == 'nt' else 'linux'


def paths(platform=None, layout=None, repo=None):
    """取得生成物路径集合。

    ## 参数
      `platform` 'win' / 'linux'；None -> `default_platform()`
      `layout`   'split'（默认）/ 'flat'（迁移期回退旧行为）
      `repo`     仓库根；None -> 由本文件位置推断

    ## 返回
      `GenPaths` 实例。
    """
    repo = repo or REPO
    platform = platform or default_platform()
    if platform not in PLATFORMS:
        raise ValueError('unsupported platform: %r (expect one of %s)'
                         % (platform, PLATFORMS))
    layout = layout or os.environ.get('PROT_GEN_LAYOUT', LAYOUT_SPLIT)
    if layout not in (LAYOUT_SPLIT, LAYOUT_FLAT):
        raise ValueError('unsupported layout: %r' % layout)
    return GenPaths(repo, platform, layout)


def selftest():
    """自检: 两平台 + 两布局的路径正确性 + 负向。"""
    fails = []

    def case(name, ok):
        print('  %s %-58s' % ('ok ' if ok else '**FAIL**', name))
        if not ok:
            fails.append(name)

    print('=== genpaths 自检 ===')

    # T1/T2: split 布局的两平台
    w = paths('win', LAYOUT_SPLIT, repo='/R')
    l = paths('linux', LAYOUT_SPLIT, repo='/R')
    case('T1 win/split -> demo/gen/win',
         w.gen.replace('\\', '/') == '/R/demo/gen/win')
    case('T2 linux/split -> demo/gen/linux',
         l.gen.replace('\\', '/') == '/R/demo/gen/linux')

    # T3: 两平台 gen **不同**（核心目的）
    case('T3 两平台 gen 目录**不同**', w.gen != l.gen)

    # T4/T5: 状态文件按平台分（**真冲突点**）
    case('T4 win 状态文件在 demo/vm_build.json',
         w.vm_build_json.replace('\\', '/') == '/R/demo/vm_build.json')
    case('T5 linux 状态文件在 build/linux/vm_build.json',
         l.vm_build_json.replace('\\', '/') == '/R/build/linux/vm_build.json')
    case('T6 两平台状态文件**不同**', w.vm_build_json != l.vm_build_json)

    # T7: flat 布局回退（迁移期兼容）
    f = paths('linux', LAYOUT_FLAT, repo='/R')
    case('T7 flat 布局回退到 demo/gen',
         f.gen.replace('\\', '/') == '/R/demo/gen')
    case('T8 flat 布局状态文件也回退',
         f.vm_build_json.replace('\\', '/') == '/R/demo/vm_build.json')

    # T9: g() 便捷拼路径
    case('T9 g() 拼出 gen 下文件',
         l.g('strings.c').replace('\\', '/')
         == '/R/demo/gen/linux/strings.c')

    # T10 **负向**: 非法平台 -> 抛异常（不静默用错误路径）
    try:
        paths('macos', repo='/R')
        case('T10 **负向**: 非法平台抛异常', False)
    except ValueError:
        case('T10 **负向**: 非法平台抛异常', True)

    # T11 **负向**: 非法布局 -> 抛异常
    try:
        paths('win', 'bogus', repo='/R')
        case('T11 **负向**: 非法布局抛异常', False)
    except ValueError:
        case('T11 **负向**: 非法布局抛异常', True)

    # T12: 环境变量可覆盖布局（便于迁移期）
    os.environ['PROT_GEN_LAYOUT'] = LAYOUT_FLAT
    try:
        case('T12 环境变量 PROT_GEN_LAYOUT 生效',
             paths('win', None, repo='/R').layout == LAYOUT_FLAT)
    finally:
        del os.environ['PROT_GEN_LAYOUT']

    # T13: as_dict 可打印（供构建脚本诊断输出）
    d = l.as_dict()
    case('T13 as_dict() 含关键字段',
         all(k in d for k in ('platform', 'layout', 'gen',
                              'vm_build_json')))

    print()
    print('=' * 66)
    if fails:
        print('[genpaths-selftest] FAIL: %s' % '; '.join(fails))
        return 1
    print('[genpaths-selftest] PASS: 两平台/两布局/负向均可自证')
    return 0


def main():
    import argparse
    ap = argparse.ArgumentParser(prog='genpaths.py')
    ap.add_argument('--platform', default=None)
    ap.add_argument('--layout', default=None)
    ap.add_argument('--selftest', action='store_true')
    ap.add_argument('--json', action='store_true')
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    p = paths(args.platform, args.layout)
    if args.json:
        import json
        print(json.dumps(p.as_dict(), ensure_ascii=False, indent=2))
    else:
        print('platform        = %s' % p.platform)
        print('layout          = %s' % p.layout)
        print('gen             = %s' % p.gen)
        print('vm_build_json   = %s' % p.vm_build_json)
    return 0


if __name__ == '__main__':
    sys.exit(main())
