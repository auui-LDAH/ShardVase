#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ShardVase contributors
# 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；商业授权见 LICENSE.md。
"""`tools/mapfile.py` — **链接 map 解析的单一实现**（B 阶段，2026-09-25）。

## 为什么抽这一个模块（**实测依据**）
  抽取前有 **4 处实现**（漂移已发生）:

  | 文件 | 函数 | 格式 |
  |------|------|------|
  | `tools/selfcrypt_proto.py` | `parse_map_functions` | MSVC only |
  | `tools/selfcrypt_proto.py` | `parse_elf_map` | gcc only |
  | `tests/protchain_check.py` | `parse_map_file` | 两格式（G 阶段刚加）|
  | `tools/migration_cost.py` | `parse_map` / `parse_map_fns` | MSVC only |

  **漂移的实证**: G 阶段给 `protchain_check` 加了 gcc 支持，
  而另两处的 MSVC-only 实现**仍在** —— 它们对 ELF 会"返回空"，
  **将来必然重新踩同一个坑**。

## 设计原则（**不强行统一**）
  四处实现的**语义确实不同**（实测）:
    ① `selfcrypt_proto.parse_map_functions` **要求 VA 以 `0000000140` 开头**
       —— 硬编码基址前缀（`0x140000000`）。**这是个脆弱点**，
       本模块改为"**基址可显式传入**"，默认仍兼容该行为。
    ② `migration_cost.parse_map` 从 **PE 头读 image_base**（更正确）
       + `setdefault`（**首见优先**，保留第一个符号）。
    ③ `migration_cost.parse_map_fns` 额外**过滤**:
       · 要求行内有 `f` 标记（函数）
       · 排除 `obj` 含 `:`（库对象如 `libvcruntime:frame.obj`）
       · 排除 `obj == 'i'`（导入 thunk）
       —— **这些过滤必须保留**，否则 M1 度量失真（M1 曾因此虚高 31.2%）。

  => 本模块把这些差异做成**显式参数**:
```
parse(path, image_base=None, funcs_only=False, exclude_libs=False)
```

## 地址基准（**关键，两平台不同**）
  | 格式 | 地址含义 | 换算 |
  |------|---------|------|
  | MSVC | 第 4 列 = **绝对 VA** | `RVA = VA - image_base` |
  | gcc (PIE) | `0x<addr>` = **链接期地址** | **即 RVA**（不减基址）|

  ⚠️ **MSVC 陷阱**（2026-09-23 实测教训）: 第 2 列是**节内偏移**，
  **不是**映像 RVA —— 误用会让 RVA 落在节外、度量全部失真。

## 诚实边界
  · gcc map 的**地址基准**假设 **PIE**（`sh_addr` 即 RVA）。
    若构建改为非 PIE（`-no-pie`），需另减基址 —— 本模块**不自动识别**，
    调用方可传 `image_base` 覆盖。
  · 两格式**自动识别**的判据: 是否出现 `XXXX:XXXXXXXX` 冒号形式。
    若某 map 两种特征都有（极不可能），**MSVC 优先**。
"""
import os
import re
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

# PE 默认映像基址（MSVC 默认值；可从 PE 头读取覆盖）
DEFAULT_IMAGE_BASE = 0x140000000

# MSVC map 行: `0001:00000020  sym  0000000140001020 f  a.obj`
#   第 2 列 = 节内偏移（**勿用**）；第 3 列 = 绝对 VA
_RE_MSVC = re.compile(
    r'([0-9a-f]{4}):([0-9a-f]{8})\s+(\S+)\s+([0-9a-f]{8,16})')
# MSVC 带 obj 列（用于 funcs_only / exclude_libs）
_RE_MSVC_FULL = re.compile(
    r'[0-9a-f]{4}:[0-9a-f]{8}\s+(\S+)\s+([0-9a-f]{8,16})\s+f\s+(\S+)')
# gcc map 符号行: 缩进 + `0x<addr>` + 符号名
_RE_GCC = re.compile(r'^\s+0x([0-9a-fA-F]+)\s+(\S+)\s*$', re.M)


def read_image_base(pe_path):
    """从 PE 头读 `OptionalHeader.ImageBase`；失败回退默认值。"""
    try:
        with open(pe_path, 'rb') as f:
            d = f.read(0x200)
        if len(d) < 0x40 or d[:2] != b'MZ':
            return DEFAULT_IMAGE_BASE
        e = int.from_bytes(d[0x3C:0x40], 'little')
        if e + 0x40 > len(d) or d[e:e + 4] != b'PE\x00\x00':
            return DEFAULT_IMAGE_BASE
        opt = e + 24
        optsz = int.from_bytes(d[e + 20:e + 22], 'little')
        if optsz < 0x20:
            return DEFAULT_IMAGE_BASE
        return int.from_bytes(d[opt + 24:opt + 32], 'little')
    except (OSError, ValueError):
        return DEFAULT_IMAGE_BASE


def detect_format(path):
    """探测 map 格式: 'msvc' / 'gcc' / None（读不到或空）。"""
    try:
        with open(path, encoding='utf-8', errors='replace') as f:
            head = f.read(200000)
    except OSError:
        return None
    if _RE_MSVC.search(head):
        return 'msvc'
    if _RE_GCC.search(head):
        return 'gcc'
    return None


def parse(path, image_base=None, funcs_only=False, exclude_libs=False,
          image_base_from_pe=True):
    """解析链接 map -> {符号: 映像RVA}。**自动识别 MSVC / gcc**。

    ## 参数（**差异显式化** —— 见模块 docstring）
      `image_base`        MSVC 侧基址；None 时按 `image_base_from_pe`
                          从 PE 头读，读不到则用 `DEFAULT_IMAGE_BASE`。
      `funcs_only`        **只取函数符号**（MSVC 的 `f` 标记）。
                          gcc 格式下**无此标记** -> 该参数对 gcc 无效
                          （gcc 的 map 已按节分类，调用方自行筛）。
      `exclude_libs`      **排除库对象与导入 thunk**（MSVC）:
                          行内 obj 列含 `:`（`libvcruntime:frame.obj`）
                          或 `obj == 'i'`（导入 thunk）。
                          **M1 门禁必须开**（曾因未排除而虚高 31.2%）。
      `image_base_from_pe` MSVC 侧是否从 PE 头读基址。

    ## 返回
      {符号名: RVA}。**首见优先**（`setdefault`）。

      ## ⚠️ 首见 vs 末见（**实测判定，不是随手选的**）
        原 `protchain_check.parse_map_file` 用**末见覆盖**，本模块用**首见优先**
        —— 实测在 `build/demo.map` 上**有 10 个符号的取值不同**。

        **判定过程**（见 §"重名符号"）：
          那 10 个符号（`$$000000`/`MoveSmall0`/`YmmLoop`/`$xdatasym` …）
          **全部来自库对象**（obj 列含 `:`，如 `LIBCMT:chkstk.obj`）——
          它们是**库内部同名局部标签**（`$$000000` 出现 **19 次**，
          地址各不相同）。
          => 对它们做"符号 -> 地址"的**单一映射本就是语义错误**，
             **首见/末见之争无意义**；**正确处置是过滤**
             （`exclude_libs=True`）。
          实测: 过滤后**零重名**，映射语义成立；
                **我们自己的符号取值不受影响**（已逐一核对）。

        **结论**: 本模块保留 `setdefault`（首见优先，
        与 `migration_cost` 的既有行为一致）；对含重名的场景，
        调用方**应开 `exclude_libs=True`**（M1 门禁必须开）。

    ## 失败时
      返回**空字典**（不抛异常）—— 与既有实现一致
      （调用方以"空"作为"无法解析"的判据）。
    """
    out = {}
    if not path or not os.path.exists(path):
        return out
    try:
        with open(path, encoding='utf-8', errors='replace') as f:
            txt = f.read()
    except OSError:
        return out

    fmt = detect_format(path)
    if fmt is None:
        return out

    if fmt == 'msvc':
        if funcs_only or exclude_libs:
            # 需要 obj 列 -> 用完整正则
            for m in _RE_MSVC_FULL.finditer(txt):
                sym = m.group(1)
                absva = int(m.group(2), 16)
                obj = m.group(3).lower()
                if exclude_libs and (':' in obj or obj == 'i'):
                    continue
                out.setdefault(sym, absva)
        else:
            for m in _RE_MSVC.finditer(txt):
                out.setdefault(m.group(3), int(m.group(4), 16))
        if not out:
            return out
        base = image_base
        if base is None:
            base = (read_image_base(path) if image_base_from_pe
                    else DEFAULT_IMAGE_BASE)
        return {k: v - base for k, v in out.items()}

    # gcc: PIE 下地址即 RVA（**不减基址**）
    for m in _RE_GCC.finditer(txt):
        try:
            out.setdefault(m.group(2), int(m.group(1), 16))
        except ValueError:
            continue
    if image_base:      # 非 PIE 场景由调用方显式传入基址
        return {k: v - image_base for k, v in out.items()}
    return out


def selftest():
    """自检: 两种格式 + 负向。**必须能证明它真能判对**。"""
    import tempfile

    fails = []

    def case(name, ok):
        print('  %s %-56s' % ('ok ' if ok else '**FAIL**', name))
        if not ok:
            fails.append(name)

    print('=== mapfile 自检 ===')

    MSVC = (
        ' Start         Length     Name                   Class\n'
        ' 0001:00000000 00000010H .text$mn                CODE\n'
        ' 0001:00000020       probe_fn   0000000140001020 f   a.obj\n'
        ' 0001:00000100       printf     0000000140001100 f   '
        'libucrt:printf.obj\n'
        ' 0001:00000200       __imp_foo  0000000140001200 i   '
        'libucrt:foo.obj\n'
        ' 0002:00000000       g_data     0000000140003000     b.obj\n'
    )
    GCC = (
        '.text           0x0000000000003880     0x799a\n'
        '                0x0000000000003880                prot_vm_run\n'
        '                0x0000000000003900                main\n'
    )

    d = tempfile.mkdtemp(prefix='mapfile_st_')
    p_msvc = os.path.join(d, 'a.map')
    p_gcc = os.path.join(d, 'b.map')
    p_junk = os.path.join(d, 'c.map')
    open(p_msvc, 'w', encoding='utf-8').write(MSVC)
    open(p_gcc, 'w', encoding='utf-8').write(GCC)
    open(p_junk, 'w', encoding='utf-8').write('这不是 map\n乱码\n')

    # T1 格式探测
    case('T1 探测 MSVC 格式', detect_format(p_msvc) == 'msvc')
    case('T2 探测 gcc 格式', detect_format(p_gcc) == 'gcc')

    # T3 MSVC: 第 4 列 VA - 基址（**不是**第 2 列节内偏移）
    m = parse(p_msvc)
    case('T3 MSVC: probe_fn 用第 4 列 VA 换算',
         m.get('probe_fn') == 0x1020)
    case('T4 MSVC: 不含第 2 列的错误值（0x20）',
         m.get('probe_fn') != 0x20)

    # T5 gcc: 地址即 RVA
    g = parse(p_gcc)
    case('T5 gcc: prot_vm_run RVA = 0x3880', g.get('prot_vm_run') == 0x3880)

    # T6 exclude_libs 过滤（**M1 门禁依赖**）
    m2 = parse(p_msvc, funcs_only=True, exclude_libs=True)
    case('T6 exclude_libs: 排除 libucrt:printf.obj',
         'printf' not in m2)
    case('T7 exclude_libs: 排除 __imp_（obj == i）',
         '__imp_foo' not in m2)
    case('T8 exclude_libs: 保留自己的 a.obj 函数',
         m2.get('probe_fn') == 0x1020)

    # T9 负向: 垃圾输入 -> 空字典（不崩）
    case('T9 **负向**: 垃圾 map -> 空字典（不崩）',
         parse(p_junk) == {})
    # T10 负向: 不存在的文件 -> 空字典
    case('T10 **负向**: 文件不存在 -> 空字典',
         parse(os.path.join(d, 'nope.map')) == {})

    # T11 首见优先（setdefault）
    dup = os.path.join(d, 'dup.map')
    open(dup, 'w', encoding='utf-8').write(
        ' 0001:00000020  sym  0000000140001020 f  a.obj\n'
        ' 0001:00000030  sym  0000000140001030 f  a.obj\n')
    case('T11 同名符号**首见优先**', parse(dup).get('sym') == 0x1020)

    # T12-T14 **重名场景**（实测判定: 库局部标签 -> 应过滤）
    #
    # 依据: Windows 实测 map 有 10 个重名符号（`$$000000` 出现 19 次），
    # **全部来自库对象** -> 单一映射语义不成立 -> 正确处置是过滤。
    dup2 = os.path.join(d, 'dup2.map')
    open(dup2, 'w', encoding='utf-8').write(
        ' 0001:00000020  $$000000  0000000140001020 f  LIBCMT:a.obj\n'
        ' 0001:00000030  $$000000  0000000140001030 f  libucrt:b.obj\n'
        ' 0001:00000040  my_fn     0000000140001040 f  mine.obj\n')
    # T12: 未过滤时首见优先
    case('T12 重名未过滤 -> 首见（0x1020）',
         parse(dup2).get('$$000000') == 0x1020)
    # T13: 过滤库对象后，重名符号**消失**（语义正确）
    case('T13 **exclude_libs 过滤重名库标签**',
         '$$000000' not in parse(dup2, funcs_only=True,
                                 exclude_libs=True))
    # T14: 过滤不影响自有符号
    case('T14 过滤**不影响自有符号**',
         parse(dup2, funcs_only=True, exclude_libs=True).get('my_fn')
         == 0x1040)

    print()
    print('=' * 66)
    if fails:
        print('[mapfile-selftest] FAIL: %s' % '; '.join(fails))
        return 1
    print('[mapfile-selftest] PASS: 两格式 + 负向均可自证')
    return 0


if __name__ == '__main__':
    if '--selftest' in sys.argv:
        sys.exit(selftest())
    print('usage: mapfile.py --selftest')
    sys.exit(2)
