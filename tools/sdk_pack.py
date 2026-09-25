#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""sdk_pack.py — 生成可分发的 SDK 包（"套件制作器"的关键一步）

## 用户构想
  "开源的反逆向套件制作器" —— 用户应拿到**一个包 + 一条命令**，
  而不是"克隆整个仓库"。

## 现状（实测）
  QUICKSTART 写着"**本仓库**（tools/ src/ include/ 会被复用）"
  => 用户必须持有整个仓库（含 docs/ publish/ tests/ drills/ 等无关内容）

## 本工具做什么
  按**实测依赖闭包**（11 个 tools + src/ + include/ + 骨架 + 契约）
  生成最小可分发包:
    dist/shardvase-sdk-<version>/
      ├─ README.md            <- 快速上手（本包专用）
      ├─ include/             <- C 头文件
      ├─ src/                 <- C 源码
      ├─ tools/               <- 构建流水线（**仅必需**）
      ├─ prot_sdk/            <- 骨架 + 向导 + 用户文档
      ├─ modules.json         <- 契约
      ├─ compositions/        <- 参考组合
      ├─ profiles/            <- 参考策略
      ├─ LICENSE.md
      └─ VERSION / MANIFEST.txt

## 用法
  python tools/sdk_pack.py                 # 生成到 dist/
  python tools/sdk_pack.py --out <dir>
  python tools/sdk_pack.py --zip           # 同时打 zip
  python tools/sdk_pack.py --selftest      # 负向测试
"""
import argparse
import glob
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ---- 必需内容（按实测依赖闭包）----
REQUIRED_DIRS = ['include', 'src', 'tools', 'compositions', 'profiles']
REQUIRED_FILES = ['modules.json', 'LICENSE.md']

# tools/ 里**必需**的脚本（实测闭包 11 个 + 用户会用到的几个）
TOOLS_KEEP = {
    # 骨架构建直接调用
    'compose.py', 'hashpatch.py', 'indirect.py', 'selfcrypt_proto.py',
    'strgen.py', 'vmcalc_build.py', 'vmenc.py',
    # 传递依赖
    'compat.py', 'c2vasm.py', 'solve_profile.py', 'modcheck.py',
    # 用户会用到的辅助
    'gen_sections.py', 'gen_padding.py', 'normalize_tail.py',
    'conformance.py', 'identity.py', 'merge_baseline.py',
    'measure_sections.py', 'vmc.py',
}

# prot_sdk/ 需要的内容
SDK_FILES = [
    'QUICKSTART.md', 'TUTORIAL.md', 'GUI_GUIDE.md', 'README.md',
]
SDK_DIRS = ['skeleton', 'wizard', 'dotnet', 'showcase']

# 明确排除
EXCLUDE_PATTERNS = [
    r'__pycache__', r'\.pyc$', r'\.pyo$',
    r'tools[\\/]attacker[\\/]',
    r'\.git[\\/]',
]


def _skip(path):
    p = path.replace('\\', '/')
    return any(re.search(pat, p) for pat in EXCLUDE_PATTERNS)


def _version():
    h = os.path.join(REPO, 'include', 'protect', 'version.h')
    try:
        t = open(h, encoding='utf-8-sig').read()
        m = re.search(r'PROT_VERSION_STR\s+"([^"]+)"', t)
        return m.group(1) if m else '0.0.0'
    except OSError:
        return '0.0.0'


def build_pack(dest, quiet=False):
    """把 SDK 内容复制到 dest。返回 (文件数, 字节数) 或抛异常。"""
    nfile = 0
    nbyte = 0

    def copy(src, dst):
        nonlocal nfile, nbyte
        if _skip(src):
            return
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(src, dst)
        nfile += 1
        nbyte += os.path.getsize(dst)

    # 目录整体复制
    for d in REQUIRED_DIRS:
        sd = os.path.join(REPO, d)
        if not os.path.isdir(sd):
            raise FileNotFoundError('必需目录缺失: %s' % d)
        for root, dirs, files in os.walk(sd):
            dirs[:] = [x for x in dirs if x != '__pycache__']
            rel = os.path.relpath(root, REPO)
            # tools/ 只保留必需脚本
            if d == 'tools':
                for fn in files:
                    if fn in TOOLS_KEEP:
                        copy(os.path.join(root, fn),
                             os.path.join(dest, rel, fn))
                continue
            for fn in files:
                copy(os.path.join(root, fn), os.path.join(dest, rel, fn))

    # 单文件
    for f in REQUIRED_FILES:
        sf = os.path.join(REPO, f)
        if not os.path.exists(sf):
            raise FileNotFoundError('必需文件缺失: %s' % f)
        copy(sf, os.path.join(dest, f))

    # prot_sdk
    for f in SDK_FILES:
        sf = os.path.join(REPO, 'prot_sdk', f)
        if os.path.exists(sf):
            copy(sf, os.path.join(dest, 'prot_sdk', f))
    for d in SDK_DIRS:
        sd = os.path.join(REPO, 'prot_sdk', d)
        if not os.path.isdir(sd):
            continue
        for root, dirs, files in os.walk(sd):
            dirs[:] = [x for x in dirs if x != '__pycache__']
            rel = os.path.relpath(root, REPO)
            for fn in files:
                copy(os.path.join(root, fn), os.path.join(dest, rel, fn))

    # 协议规范（第三方实现依据）
    spec = os.path.join(REPO, 'docs', 'MODULE_PROTOCOL_SPEC.md')
    if os.path.exists(spec):
        copy(spec, os.path.join(dest, 'docs', 'MODULE_PROTOCOL_SPEC.md'))
    gov = os.path.join(REPO, 'docs', 'PROTOCOL_GOVERNANCE.md')
    if os.path.exists(gov):
        copy(gov, os.path.join(dest, 'docs', 'PROTOCOL_GOVERNANCE.md'))

    # VERSION
    v = _version()
    with open(os.path.join(dest, 'VERSION'), 'w', encoding='utf-8',
              newline='\n') as f:
        f.write(v + '\n')
    nfile += 1

    # MANIFEST（可审计）
    lines = ['# ShardVase SDK %s — 包清单' % v,
             '# 由 tools/sdk_pack.py 生成',
             '# 内容为**实测依赖闭包**（骨架构建所需的最小集合）',
             '']
    for root, dirs, files in os.walk(dest):
        dirs[:] = [x for x in dirs if x != '__pycache__']
        for fn in sorted(files):
            if fn == 'MANIFEST.txt':
                continue
            p = os.path.join(root, fn)
            rel = os.path.relpath(p, dest).replace('\\', '/')
            lines.append('%-58s %8d' % (rel, os.path.getsize(p)))
    with open(os.path.join(dest, 'MANIFEST.txt'), 'w', encoding='utf-8',
              newline='\n') as f:
        f.write('\n'.join(lines) + '\n')
    nfile += 1

    # 包专用 README
    readme = '''# ShardVase SDK %s

> **这是一个可分发的 SDK 包** —— 你不需要克隆整个 ShardVase 仓库。
> 包内为**实测依赖闭包**（骨架构建所需的最小集合）。

## 快速上手

```
1. 安装: Windows x64 + VS2022（C++ 工作负载）+ Python 3.8+
2. 生成工程:
     python prot_sdk\\wizard\\prot_wizard.py
3. 选拼装图（推荐 standard）-> 生成
4. 构建:
     powershell -File <你的工程>\\build_skeleton.ps1 -Project <你的工程>
5. 产物: <你的工程>\\build\\<app_name>.exe
```

详见 `prot_sdk/QUICKSTART.md`。

## 内容

| 目录 | 说明 |
|------|------|
| `include/` | C 头文件（模块接口 + 基础设施）|
| `src/` | C 源码（13 个防护模块 + 2 个原语）|
| `tools/` | 构建流水线（**仅必需脚本**，见 MANIFEST.txt）|
| `prot_sdk/` | 骨架工程模板 + 向导 + 用户文档 |
| `modules.json` | 模块契约（18 字段 × 13 模块）|
| `compositions/` | 参考组合（4 档）|
| `profiles/` | 参考策略（4 档，用**威胁**而非模块列表）|
| `docs/` | 协议规范 + 治理文档（第三方实现依据）|

## 校验包完整性

```
python tools/modcheck.py                 # 契约与源码一致
python tools/conformance.py modules.json # 协议合规
python tools/skeleton_check.py           # 骨架可构建（DIY 路径）
```

## 许可

AGPL-3.0-or-later；商业授权见 `LICENSE.md`。
''' % v
    with open(os.path.join(dest, 'README.md'), 'w', encoding='utf-8',
              newline='\n') as f:
        f.write(readme)
    nfile += 1

    return nfile, nbyte


def selftest():
    """负向测试: 打包器必须能抓错。"""
    fails = []

    def case(name, ok):
        print('  %s %-52s' % ('ok ' if ok else '**FAIL**', name))
        if not ok:
            fails.append(name)

    print('=== 版本号可读 ===')
    v = _version()
    case('版本号格式合法 (%s)' % v, bool(re.match(r'^\d+\.\d+\.\d+', v)))

    print()
    print('=== 打包并校验 ===')
    tmp = tempfile.mkdtemp(prefix='sdkpack_')
    try:
        n, nb = build_pack(tmp, quiet=True)
        case('文件数 > 30 (%d)' % n, n > 30)
        case('总字节 > 100KB (%d)' % nb, nb > 100000)
        # 必需内容
        for rel in ['include/protect/protdef.h', 'src/vm.c',
                    'tools/vmenc.py', 'tools/compat.py',
                    'prot_sdk/skeleton/build_skeleton.ps1',
                    'prot_sdk/skeleton/strings.txt',
                    'modules.json', 'compositions/standard.json',
                    'profiles/balanced.json', 'LICENSE.md',
                    'README.md', 'VERSION', 'MANIFEST.txt']:
            case('含 %s' % rel, os.path.exists(os.path.join(tmp, rel)))
        # **不应**含的内容
        for rel in ['docs/WORKBENCH_ROADMAP.md', 'publish/README.md',
                    'tests/e2e.py', 'drills/_schema.json',
                    'tools/attacker']:
            case('不含 %s' % rel, not os.path.exists(os.path.join(tmp, rel)))
        # **关键**: 骨架 strings.txt 必须与枚举一致（上次缺陷）
        st = os.path.join(tmp, 'prot_sdk', 'skeleton', 'strings.txt')
        hd = os.path.join(tmp, 'include', 'protect', 'strcrypt.h')
        if os.path.exists(st) and os.path.exists(hd):
            enum = re.findall(
                r'PROT_STR_([A-Z0-9_]+)',
                re.search(r'enum\s+prot_str_id\s*\{(.*?)\}',
                          open(hd, encoding='utf-8-sig').read(), re.S
                          ).group(1))
            enum = [x for x in enum if x != 'COUNT']
            names = [l.strip().partition('|')[0].strip()
                     for l in open(st, encoding='utf-8') if l.strip()]
            case('包内 skeleton/strings.txt 与枚举一致 (%d 项)'
                 % len(names), names == enum)
        else:
            case('包内含 strings.txt 与 strcrypt.h', False)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print()
    print('=' * 64)
    if fails:
        print('[sdk_pack-selftest] FAIL: %s' % '; '.join(fails))
        return 1
    print('[sdk_pack-selftest] PASS: 打包器可自证交付正确内容')
    return 0


def main():
    ap = argparse.ArgumentParser(prog='sdk_pack.py')
    ap.add_argument('--out', default=None, help='输出目录（默认 dist/）')
    ap.add_argument('--zip', action='store_true', help='同时打 zip')
    ap.add_argument('--force', action='store_true', help='覆盖已存在目录')
    ap.add_argument('--selftest', action='store_true')
    ap.add_argument('--quiet', action='store_true')
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    v = _version()
    out = args.out or os.path.join(REPO, 'dist')
    dest = os.path.join(out, 'shardvase-sdk-%s' % v)
    if os.path.exists(dest):
        if not args.force:
            print('[sdk_pack] FAIL: %s 已存在（用 --force 覆盖）' % dest,
                  file=sys.stderr)
            return 1
        shutil.rmtree(dest)
    os.makedirs(dest, exist_ok=True)

    try:
        n, nb = build_pack(dest, quiet=args.quiet)
    except (FileNotFoundError, OSError) as e:
        print('[sdk_pack] FAIL: %s' % e, file=sys.stderr)
        return 1

    if not args.quiet:
        print('=== ShardVase SDK %s ===' % v)
        print('  输出: %s' % dest)
        print('  文件: %d 个, %.1f KB' % (n, nb / 1024.0))
        print()
        print('  顶层内容:')
        for x in sorted(os.listdir(dest)):
            p = os.path.join(dest, x)
            kind = '目录' if os.path.isdir(p) else '文件'
            print('    %-28s %s' % (x, kind))

    if args.zip:
        zp = shutil.make_archive(dest, 'zip', root_dir=out,
                                 base_dir=os.path.basename(dest))
        if not args.quiet:
            print()
            print('  zip: %s (%.1f KB)'
                  % (zp, os.path.getsize(zp) / 1024.0))
    return 0


if __name__ == '__main__':
    sys.exit(main())
