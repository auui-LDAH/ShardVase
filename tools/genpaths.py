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
  ④ **构建变体（ST3.2）**: `Debug` 构建（`/Zi` + `/DEBUG:FULL`）的产物
     与状态文件必须与发布构建**完全隔离**，故 `build_dir` 末端可加一层
     变体名（`build/debug`）。变体为空时路径与引入本参数前**逐字符相同**。

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

#: 构建变体（ST3.2）
#:   ''      = 默认（发布/开发构建），路径与改动前一致
#:   'debug' = 调试构建（Studio ST3.2: `/Zi` + `/DEBUG:FULL`）
#:
#: **为什么必须隔离**（实测理由）:
#:   ① 直接覆盖 `build/demo.exe` -> 发布产物丢失，且下一次 e2e/门禁
#:      读到的就是带 PDB 的调试产物（节布局已不同）。
#:   ② `section_baseline.json` 是**只增不减**的归一化基线 -> 调试构建
#:      节更大，会把基线抬高 -> 改变 **Release** 的填充尺寸 ->
#:      破坏 I3 可复现（字节比对必然 MISMATCH）。
BUILD_VARIANTS = ('', 'debug')
VARIANT_DEBUG = 'debug'


class GenPaths:
    """生成物路径集合（**不可变**，仅承载路径）。"""

    __slots__ = ('repo', 'platform', 'layout', 'variant', 'gen',
                 'vm_build_json', 'build_dir')

    def __init__(self, repo, platform, layout, variant=''):
        self.repo = repo
        self.platform = platform
        self.layout = layout
        self.variant = variant or ''
        # ## 平台专属 build 目录（A-d 补完，2026-09-25）
        #   实测: `build/vm.blob` / `build/license.txt` /
        #   `build/selfcrypt_mask.txt` 被**两平台都写** ->
        #   跑完 Linux 后 Windows 的 e2e 读到 Linux 的产物 -> 失败。
        #   => 这些**状态文件**也必须按平台分。
        #
        #   Windows 保持 `build/`（主平台，避免改动过大）；
        #   Linux 用 `build/linux/`。
        base = (os.path.join(repo, 'build') if platform == 'win'
                else os.path.join(repo, 'build', 'linux'))
        # ## 变体子目录（ST3.2，2026-10-10）
        #   `Debug` 变体多 `/Zi` + `/DEBUG:FULL` -> PE 里多调试目录、多 PDB、
        #   节尺寸也不同。若与发布构建写同一目录:
        #     ① 覆盖 `build/demo.exe`（发布产物丢失）
        #     ② `section_baseline.json` 被抬高 -> 改变 Release 的填充尺寸
        #        -> 破坏 I3 可复现（基线纪律是"只增不减"）
        #   => 变体目录让调试构建的产物与状态**全部**另起一份。
        #   variant='' 时路径与引入本参数前**逐字符相同**。
        self.build_dir = (os.path.join(base, self.variant) if self.variant
                          else base)

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
    def b(self, *parts):
        """**平台专属 build 目录**下的文件路径（A-d）。

        用于 `vm.blob` / `license.txt` / `selfcrypt_mask.txt` 等
        **两平台都会写、内容不同**的状态文件；变体（如 `debug`）
        亦已并入 `build_dir`，故调用方**不必**再拼变体名。
        """
        return os.path.join(self.build_dir, *parts)

    def g(self, *parts):
        """生成物目录下的文件路径（**推荐用法**）。"""
        return os.path.join(self.gen, *parts)

    def out_rel(self):
        """`build_dir` **相对仓库根**的路径（构建脚本的 `/Fe:` 用相对路径）。

        为什么要这个方法: `build.ps1` 的 cl 命令行里输出路径原本是硬编码
        字面量 `build/demo.exe`。改为由本方法取值后:
          · 无变体时展开结果仍是 `build` -> 命令行**逐字符不变**
            （这是"发布字节逐字节不变"的一部分）
          · `debug` 时得 `build/debug` -> 自动落到隔离目录
        """
        return os.path.relpath(self.build_dir, self.repo)

    def include_dirs(self):
        """`-I` 包含路径（与 gen 同目录的**还包括 demo/**，见调用方）。"""
        return [self.gen]

    def as_dict(self):
        return {
            'repo': self.repo,
            'platform': self.platform,
            'layout': self.layout,
            'variant': self.variant,
            'gen': self.gen,
            'build_dir': self.build_dir,
            'out_rel': self.out_rel(),
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


def paths(platform=None, layout=None, repo=None, variant=None):
    """取得生成物路径集合。

    ## 参数
      `platform` 'win' / 'linux'；None -> `default_platform()`
      `layout`   'split'（默认）/ 'flat'（迁移期回退旧行为）
      `repo`     仓库根；None -> 由本文件位置推断
      `variant`  ''（默认）/ 'debug'；None -> 环境变量 `PROT_BUILD_VARIANT`
                 （与 `PROT_GEN_LAYOUT` 同一层级与同一惯例）

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
    # 变体: 显式参数优先；None 才回退环境变量（**不静默当默认**）
    if variant is None:
        variant = os.environ.get('PROT_BUILD_VARIANT', '')
    variant = (variant or '').strip().lower()
    if variant not in BUILD_VARIANTS:
        raise ValueError('unsupported build variant: %r (expect one of %s)'
                         % (variant, BUILD_VARIANTS))
    return GenPaths(repo, platform, layout, variant)


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

    # T14-T16 **build 目录也按平台分**（A-d 补完）
    case('T14 win 的 build_dir = build',
         w.build_dir.replace('\\', '/') == '/R/build')
    case('T15 linux 的 build_dir = build/linux',
         l.build_dir.replace('\\', '/') == '/R/build/linux')
    case('T16 两平台 build_dir **不同**（状态文件隔离）',
         w.build_dir != l.build_dir)
    case('T17 b() 拼出 build 下文件',
         l.b('vm.blob').replace('\\', '/') == '/R/build/linux/vm.blob')

    # T18-T24 **构建变体**（ST3.2）: Debug 产物与状态隔离
    dw = paths('win', LAYOUT_SPLIT, repo='/R', variant='debug')
    dl = paths('linux', LAYOUT_SPLIT, repo='/R', variant='debug')
    case('T18 win/debug -> build/debug',
         dw.build_dir.replace('\\', '/') == '/R/build/debug')
    case('T19 linux/debug -> build/linux/debug',
         dl.build_dir.replace('\\', '/') == '/R/build/linux/debug')
    case('T20 无变体 -> 与改动前**逐字符相同**',
         w.build_dir.replace('\\', '/') == '/R/build')
    # 变体**只**隔离产物与状态目录；生成物目录/状态 json 不动
    # （否则同一份源码会在两个 gen 目录下生成两套头文件 -> 互相矛盾）
    case('T21 变体不改变 gen / vm_build_json',
         dw.gen == w.gen and dw.vm_build_json == w.vm_build_json)
    case('T22 out_rel() 给相对路径（/Fe: 用）',
         dw.out_rel().replace('\\', '/') == 'build/debug'
         and w.out_rel().replace('\\', '/') == 'build')
    # T23 **负向**: 非法变体 -> 抛异常（不静默当默认变体）
    try:
        paths('win', LAYOUT_SPLIT, repo='/R', variant='release-dbg')
        case('T23 **负向**: 非法变体抛异常', False)
    except ValueError:
        case('T23 **负向**: 非法变体抛异常', True)
    # T24: 环境变量可覆盖变体（构建脚本之外的调用方）
    os.environ['PROT_BUILD_VARIANT'] = 'debug'
    try:
        case('T24 环境变量 PROT_BUILD_VARIANT 生效',
             paths('win', LAYOUT_SPLIT, repo='/R').variant == 'debug')
    finally:
        del os.environ['PROT_BUILD_VARIANT']

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
    # ## shell 友好的专用输出（A-b，2026-09-25）
    #   构建脚本（build.sh）需要**直接取路径**，解析 JSON 麻烦 ->
    #   提供两个"只打印一个路径"的模式（**单一来源不变**）。
    ap.add_argument('--print-gen', action='store_true',
                    help='只打印生成物目录（供 shell 变量赋值）')
    # ## 相对形态（A-c，2026-09-25）
    #   构建脚本在**仓库根**执行 -> 相对路径**无空格**
    #   （本仓库路径含空格 -> 绝对路径会在 cmd/shell 里被拆）。
    #   => 编译期路径一律用相对形态（**从根上消除引号问题**）。
    ap.add_argument('--variant', default=None,
                    help='构建变体 (缺省=空; debug=调试构建, 产物入 build/<变体>)')
    ap.add_argument('--print-out-rel', action='store_true',
                    help='只打印 build 目录**相对仓库根**的路径 (构建脚本用)')
    ap.add_argument('--print-build-dir', action='store_true',
                    help='只打印平台专属 build 目录（A-d）')
    ap.add_argument('--print-gen-rel', action='store_true',
                    help='只打印**相对仓库根**的生成物目录（无空格）')
    ap.add_argument('--print-vm-json', action='store_true',
                    help='只打印 vm_build.json 路径')
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    p = paths(args.platform, args.layout, variant=args.variant)
    if args.print_gen:
        print(p.gen)
        return 0
    if args.print_build_dir:
        print(p.build_dir)
        return 0
    if args.print_out_rel:
        print(p.out_rel())
        return 0
    if args.print_gen_rel:
        print(os.path.relpath(p.gen, p.repo).replace('\\', '/'))
        return 0
    if args.print_vm_json:
        print(p.vm_build_json)
        return 0
    if args.json:
        import json
        print(json.dumps(p.as_dict(), ensure_ascii=False, indent=2))
    else:
        print('platform        = %s' % p.platform)
        print('layout          = %s' % p.layout)
        print('variant         = %s' % p.variant)
        print('gen             = %s' % p.gen)
        print('build_dir       = %s' % p.build_dir)
        print('vm_build_json   = %s' % p.vm_build_json)
    return 0


if __name__ == '__main__':
    sys.exit(main())
