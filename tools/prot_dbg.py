#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ShardVase contributors
# 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；商业授权见 LICENSE.md。
r"""`tools/prot_dbg.py` — 调试控制台（**第 1 步：只读子命令**，2026-09-30）。

## 为什么需要（不是"想要"，是**实测反复踩到**）
  本项目 100+ 次调试里，同一批动作被反复手写、每次写临时脚本、每次可能踩同一批坑。
  见 `docs/DEBUG_CONSOLE_PLAN.md` §1 的清单（map 符号解析 5+ 次 / 运行时地址换算 4+ 次 /
  退出码解释 8+ 次 / 掩码归属判定 3 次 …）。

## 本文件当前只实现**第 1 步**（`sym` / `mask` / `exit` / `doctor`）—— **纯只读，零风险**
  `patch` / `read` / `watch`（第 2 步）与 `run`（第 3 步）、反调试提示（第 4 步）**尚未实现**。
  未实现就是未实现 —— 本工具**不会**假装支持（P4 诚实边界）。

## 用法
```
python tools/prot_dbg.py doctor                  # 环境体检 + **解析链路正向对照**
python tools/prot_dbg.py sym <名字> [<名字>…]     # 符号 -> 链接时 VA / RVA / .text 偏移 / 掩码归属
python tools/prot_dbg.py mask [<名字>…]           # 掩码区清单（产物 meta 为权威）+ 各区内的符号
python tools/prot_dbg.py exit <码> [<码>…]        # 退出码解释（**从 C 头解析，不硬编码**）
python tools/prot_dbg.py --selftest [--quiet]
```
  通用选项: `--exe P`（默认 `build/demo.exe`）· `--map P`（默认与 exe 同名 `.map`）·
  `--json F`（结构化证据落盘）· `--quiet`

## 设计纪律（**每一条都来自实际踩坑**）
  ① **退出码从 `include/protect/*.h` 解析**，不硬编码 —— R1 `docclaim` 的教训: 硬编码会漂移。
  ② **"读不到" ≠ "不存在"**（2026-09-30 我**一小时内连犯三次**）:
     map 正则形态假设错 -> 只解析出 948/2989 个符号 -> 差点判定"符号被优化掉了"。
     => 本工具**任何"空结果"都必须先证明读取链路是通的**:
        `doctor` 做**正向对照** —— map 的符号必须能落进产物节区间内，否则报 ERROR。
  ③ **掩码归属以产物自身的 `.protcry` meta 为权威**，再与 `selfcrypt_mask.txt` **交叉核对**:
     外部 txt 可能与产物不是同一次构建（R3.3 已记名: 归档产物**必须自带** `prot_sections.json`）。
  ④ **复用单一事实源**，不新写解析器:
     `tools/mapfile.py`（map 解析）· `tests/protchain_check.py`（节表 / selfcrypt meta）。
     > ⚠️ **复用函数要连隐式上下文一起设**: `protchain_check` 的
     > `load_section_names` 走模块级 `_CURRENT_EXE` —— 不设就会去解析**另一个平台**的
     > 生成物 JSON，得到**静默错误**的节名（本项目已记名的坑）。
  ⑤ **不向用户暴露未换算的运行时地址**: 打印的是**链接时 VA**，并显式提示 ASLR。
  ⑥ **不改仓库状态**（只读 + 临时目录），自检可在门禁里跑。

## 自检（`--selftest`，1 前置 + 4 正向 + 4 负向）
```
T0 前置: 产物+map 就绪（缺则 SKIP，不假装通过）
T1 **正向** doctor 通过
T2 **正向** sym 一个**从 map 动态取**的真实符号（不硬编码名字）
T3 **正向** exit 0xBAD -> PROT_EXIT_TAMPERED（从头文件解析）
T4 **正向** exit 11 -> 必须指出 = 0xB10B 的**低 8 位**（Linux exit() 截断）
T5 **负向** sym 不存在的符号 -> **必须失败**（且不崩溃）
T6 **负向** exit 未定义的码 -> **必须明确"未知"**，不得猜测
T7 **负向** map 为**空文件** -> doctor **必须报错**（不是静默通过）
T8 **负向** map **非空但格式不可识别** -> doctor 必须报"读不到 != 不存在"
T9 **负向** 掩码判定不得恒真/恒假（区内点必须在、区外点必须不在）
```
"""
import argparse
import json
import os
import re
import shutil
import sys
import tempfile

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _d in ('tools', 'tests'):
    _p = os.path.join(REPO, _d)
    if _p not in sys.path:
        sys.path.insert(0, _p)

import mapfile                  # noqa: E402  单一 map 解析实现
import protchain_check as pc    # noqa: E402  节表 / selfcrypt meta 的权威解析

DEFAULT_EXE = os.path.join(REPO, 'build', 'demo.exe')
PROT_HDR_DIR = os.path.join(REPO, 'include', 'protect')


def rel(p):
    """仓库相对路径（显示用；失败则原样返回）。"""
    try:
        r = os.path.relpath(p, REPO)
        return p if r.startswith('..') else r
    except ValueError:
        return p


def default_map_for(exe):
    """产物 -> 同名 `.map`（`build/demo.exe` -> `build/demo.map`）。"""
    return os.path.splitext(exe)[0] + '.map'


def plat_of(path):
    """按**魔数**判平台（不猜扩展名）。读不到返回 None。"""
    try:
        with open(path, 'rb') as f:
            magic = f.read(4)
    except OSError:
        return None
    return 'linux' if magic == b'\x7fELF' else 'win'


def build_dir_of(plat):
    """平台专属 build 目录（**唯一事实源** `tools/genpaths.py`）。"""
    import genpaths
    return genpaths.paths(plat or 'win').build_dir


# ===========================================================================
# 上下文：一次加载，多命令复用
# ===========================================================================
class Ctx(object):
    """产物 + map + 掩码的**只读**上下文。

    `errors` 里的每一条都是**判据失败**（含"读取链路可疑"），
    调用方**不得**把 `errors` 非空当成"目标不存在"（纪律 ②）。
    """

    def __init__(self, exe=None, map_path=None):
        self.exe = os.path.abspath(exe or DEFAULT_EXE)
        self.map_path = os.path.abspath(map_path or default_map_for(self.exe))
        self.plat = plat_of(self.exe)
        self.errors = []
        self.warns = []
        self.data = None
        self.image_base = mapfile.DEFAULT_IMAGE_BASE
        self.secs = []
        self.text = None
        self.cry_sec = None
        self.meta = []          # [(rva, len, group)]
        self.mask_txt = None    # [(rva, len)] 或 None（文件不存在）
        self.syms = {}          # {名字: RVA}
        self.map_lines = 0
        self.map_fmt = None
        self._load()

    # ---- 加载 -------------------------------------------------------------
    def _load(self):
        self._load_exe()
        self._load_map()
        self._load_mask()

    def _load_exe(self):
        if not os.path.isfile(self.exe):
            self.errors.append('产物不存在: %s'
                               '（先构建: powershell -File build.ps1）' % rel(self.exe))
            return
        try:
            with open(self.exe, 'rb') as f:
                self.data = f.read()
        except OSError as e:
            self.errors.append('产物读取失败: %s' % e)
            return
        try:
            self.secs = pc.sections_of(self.data)
        except Exception as e:                       # noqa: BLE001
            self.errors.append('节表解析失败: %s: %s' % (type(e).__name__, e))
            return
        self.text = next((s for s in self.secs if s['name'] == '.text'), None)
        if self.text is None:
            self.errors.append('产物中找不到 .text 节（节名: %s）'
                               % ', '.join(s['name'] for s in self.secs))
        self.image_base = mapfile.read_image_base(self.exe)

        # ## 纪律 ④: 复用 protchain_check 前**必须**先设隐式上下文
        #   否则 `load_section_names` 会去解析**另一个平台**的 prot_sections.json，
        #   得到静默错误的节名 -> protcry 找不到 -> 掩码恒空（正是纪律 ② 的形态）。
        pc._CURRENT_EXE = self.exe

        try:
            cry_names = pc.cry_section_names()
        except Exception as e:                       # noqa: BLE001
            cry_names = set()
            self.errors.append('protcry 节名解析失败: %s' % e)
        found = [s for s in self.secs if s['name'] in cry_names]
        if not found:
            self.errors.append(
                '产物中找不到 protcry 节（候选名 %s）—— 生成物 JSON 缺失/平台错配？'
                '（**不等于**"没有 selfcrypt"）' % sorted(cry_names))
        else:
            self.cry_sec = found[0]
            try:
                self.meta = pc.selfcrypt_meta(self.data, self.secs)
            except Exception as e:                   # noqa: BLE001
                self.errors.append('selfcrypt meta 解析失败: %s' % e)

    def _load_map(self):
        if not os.path.isfile(self.map_path):
            self.errors.append('map 不存在: %s（先构建；或 --map 指定）'
                               % rel(self.map_path))
            return
        try:
            with open(self.map_path, encoding='utf-8', errors='replace') as f:
                self.map_lines = sum(1 for _ in f)
        except OSError as e:
            self.errors.append('map 读取失败: %s' % e)
            return
        self.map_fmt = mapfile.detect_format(self.map_path)
        self.syms = mapfile.parse(self.map_path)

        # ## 纪律 ②: "读不到" ≠ "不存在" —— 三种"空"必须**分别**判定
        #   ⚠️ 本分支是自检 T7 逼出来的: 最初的写法只覆盖 `map_lines > 0`，
        #      于是**空 map 会静默 PASS**（0 个符号却报 doctor PASS）——
        #      正是"读不到当成不存在"的形态，只是发生在工具自己身上。
        #      => 判据: **符号表为空就不许 PASS**，且原因要区分得开。
        if self.map_lines == 0:
            self.errors.append(
                'map 文件为**空**（0 行）-> 一个符号都取不到，'
                '任何据此得出的"某某符号不存在"结论都无效（**读不到 != 不存在**）')
        elif self.map_fmt is None:
            self.errors.append(
                'map 非空（%d 行）但**格式未识别**（既非 MSVC 亦非 gcc 形态）'
                '-> 这是**读取链路异常**，不是"符号不存在"' % self.map_lines)
        elif not self.syms:
            self.errors.append(
                'map 非空（%d 行）但**解析出 0 个符号** -> 解析链路异常'
                '（**读不到 != 不存在**）' % self.map_lines)
        self._positive_control()

    def _positive_control(self):
        """**正向对照**: 已知非空的靶子必须能被读到。

        今日实测教训: 用链接偏好基址去读 ASLR 后的进程 -> 全部 `err=299`
        -> 差点判定"变量不存在"。**任何"为 0/读不到"的结论都必须先证明链路是通的。**
        这里用**结构性**对照（不硬编码符号名）:
          map 的符号 RVA 必须能落进产物自身节表的区间内。
        落不进去 => 基址算错 / map 与产物不是同一次构建 / 平台错配。
        """
        if not self.syms or not self.secs:
            return
        end = max(s['virtual_addr'] + max(s['virtual_size'], s['size_raw'])
                  for s in self.secs)
        inside = [n for n, r in self.syms.items() if 0 <= r < end]
        if not inside:
            self.errors.append(
                'map 的 %d 个符号**无一**落在产物节区间 [0, 0x%X) 内'
                '-> 基址/平台不匹配（**读不到 != 不存在**；也说明 map 与产物不同源）'
                % (len(self.syms), end))
        else:
            self._n_inside = len(inside)

    def _load_mask(self):
        p = os.path.join(build_dir_of(self.plat), 'selfcrypt_mask.txt')
        if not os.path.isfile(p):
            self.warns.append('掩码提示文件不存在: %s（不影响 meta 权威判定）' % rel(p))
            return
        out = []
        try:
            with open(p, encoding='utf-8', errors='replace') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    parts = line.split(',')
                    if len(parts) < 2:
                        continue
                    out.append((int(parts[0], 0), int(parts[1], 0)))
        except (OSError, ValueError) as e:
            self.warns.append('掩码提示文件解析失败: %s' % e)
            return
        self.mask_txt = out
        got = sorted((r, l) for r, l, _g in self.meta)
        if got != sorted(out):
            self.warns.append(
                '掩码**交叉核对不一致**: 产物 meta %d 区 %s vs `selfcrypt_mask.txt` '
                '%d 区 %s -> 该 txt 与产物**不是同一次构建**（已有检查 P2 会抓；'
                '以产物 meta 为准）' % (len(got), got, len(out), sorted(out)))

    # ---- 查询 -------------------------------------------------------------
    def mask_hit(self, rva):
        """RVA -> 掩码区 `(rva, len, group)` 或 None。"""
        for r, l, g in self.meta:
            if r <= rva < r + l:
                return (r, l, g)
        return None

    def text_off(self, rva):
        """RVA -> `.text` 内偏移（不在 .text 内返回 None）。"""
        if not self.text:
            return None
        t0 = self.text['virtual_addr']
        t1 = t0 + max(self.text['virtual_size'], self.text['size_raw'])
        return (rva - t0) if t0 <= rva < t1 else None

    def sym(self, name):
        """名字 -> 信息 dict；不在 map 中返回 None。"""
        rva = self.syms.get(name)
        if rva is None:
            return None
        return {
            'name': name,
            'rva': rva,
            'va': rva + self.image_base,
            'image_base': self.image_base,
            'text_off': self.text_off(rva),
            'mask': self.mask_hit(rva),
        }

    def why_missing(self, name):
        """符号找不到时，给出**可能原因清单**（而不是只说"没找到"）。"""
        out = []
        if not self.syms:
            out.append('map 未成功解析（见 doctor 的解析链路自检）')
        if name.startswith('_') or name.startswith('?'):
            out.append('MSVC 会修饰名字（`_` 前缀 / `?` 开头的 C++ 修饰名）—— '
                       '请用 map 里的**原始拼写**')
        out.append('名字拼写（区分大小写；`static` 函数会带 `_`/修饰前缀）')
        out.append('该符号被编译器内联/合并（`/O2` 下 static 函数可能消失）')
        out.append('map 与产物不同源（跑一次 build 再试）')
        return out


# ===========================================================================
# exit 子命令：退出码解释（**从 C 头解析**）
# ===========================================================================
def parse_code_table():
    """-> [(值, 名字, 来源, 备注), ...]。**解析**而非硬编码（纪律 ①）。"""
    out = []
    if os.path.isdir(PROT_HDR_DIR):
        for fn in sorted(os.listdir(PROT_HDR_DIR)):
            if not fn.endswith('.h'):
                continue
            p = os.path.join(PROT_HDR_DIR, fn)
            try:
                t = open(p, encoding='utf-8', errors='replace').read()
            except OSError:
                continue
            for m in re.finditer(
                    r'#define\s+(PROT_EXIT_\w+)\s+(0x[0-9A-Fa-f]+|\d+)([^\n]*)', t):
                note = re.sub(r'/\*|\*/', '', m.group(3)).strip()
                out.append((int(m.group(2), 0), m.group(1), fn, note))
    # prot_status 枚举: 顺序隐含取值（PROT_OK = 0），显式 `= N` 覆盖
    p = os.path.join(PROT_HDR_DIR, 'protdef.h')
    if os.path.isfile(p):
        t = open(p, encoding='utf-8', errors='replace').read()
        m = re.search(r'typedef\s+enum\s+prot_status\s*\{(.*?)\}\s*prot_status\s*;',
                      t, re.S)
        if m:
            body = re.sub(r'/\*.*?\*/', '', m.group(1), flags=re.S)
            idx = 0
            for line in body.splitlines():
                line = line.strip().rstrip(',').strip()
                if not line:
                    continue
                mm = re.match(r'(PROT_\w+)\s*(?:=\s*(\d+))?$', line)
                if not mm:
                    continue
                if mm.group(2) is not None:
                    idx = int(mm.group(2))
                out.append((idx, mm.group(1), 'protdef.h (prot_status)',
                            '(状态码，非进程退出码)'))
                idx += 1
    return out


def explain_code(code, table):
    """-> (是否已知, 文本行 list)。"""
    lines = []
    direct = [e for e in table if e[0] == code]
    low = [e for e in table if e[0] > 0xFF and (e[0] & 0xFF) == code]
    if direct:
        for v, n, src, note in direct:
            lines.append('  = 0x%X (%d)  %s   [%s] %s' % (v, v, n, src, note))
    if low:
        if not direct:
            lines.append('  直接匹配: 无')
        lines.append('  ⚠ 但它是以下**大码的低 8 位**（Linux `exit()` 只保留低 8 位，'
                     'Windows `ExitProcess` 保留全 32 位）:')
        for v, n, src, note in low:
            lines.append('      0x%X (%d) & 0xFF = %d  ->  %s   [%s]'
                         % (v, v, code, n, src))
    if not direct and not low:
        lines.append('  未知: 该码**不在** `include/protect/` 的任何 `PROT_EXIT_*` '
                     '定义或 `prot_status` 枚举中。')
        lines.append('  （本工具**不猜测** —— 若确属业务层自定返回码，'
                     '请在源码中加 `#define`/注释后再查。）')
    # ## 同值歧义只在**真的同值**时报（"判据必须唯一"）
    #   最初写法对任何命中 prot_status 的码都报，导致 `11` 也附带一句
    #   与它无关的 0/1/2 说明 —— 噪声会稀释告警，等于没有告警。
    if code in (0, 1, 2) and any(
            e[2] == 'protdef.h (prot_status)' for e in direct):
        lines.append('  ⚠ 同值歧义: %d 在 `demo/main.c` 里**也被用作业务层返回码**'
                     '（`return 1` = 授权无效、`return 2` = 用法错误），'
                     '与 `prot_status` 的数值**不是同一语义** —— 判定时必须结合上下文。'
                     % code)
    # 状态码与退出码数值空间**重叠**（两套枚举各自从 0 起）:
    #   仅当「本码命中 prot_status」且「本码同时是某个 PROT_EXIT_* 的低 8 位」时
    #   才是真正的不可区分（实测例: 11 = PROT_ERR_BLOB_CORRUPT = 0xB10B & 0xFF）。
    if low and any(e[2] == 'protdef.h (prot_status)' for e in direct):
        lines.append('  ⚠ 另一处重叠: `prot_status` 状态码 %d 与 `PROT_EXIT_*` 的'
                     '低 8 位折算值**数值相同**，单看码无法区分 —— '
                     '须结合「谁在什么时机退出」判断（见 `docs/HANDOVER.md`）。' % code)
    return (bool(direct or low), lines)


# ===========================================================================
# 子命令
# ===========================================================================
def cmd_doctor(ctx, quiet, js):
    print('[prot_dbg doctor] 仓库: %s' % REPO)
    print('平台: %s   产物: %s   基址 0x%X (%s)'
          % (ctx.plat or '?', rel(ctx.exe), ctx.image_base,
             '从 PE 头读' if ctx.plat == 'win' else 'ELF 侧'))
    print()
    print('输入文件:')
    for label, p in (('产物', ctx.exe), ('map', ctx.map_path),
                     ('vm.blob', os.path.join(build_dir_of(ctx.plat), 'vm.blob')),
                     ('license.txt',
                      os.path.join(build_dir_of(ctx.plat), 'license.txt')),
                     ('selfcrypt_mask.txt',
                      os.path.join(build_dir_of(ctx.plat), 'selfcrypt_mask.txt'))):
        if os.path.isfile(p):
            print('  ok   %-20s %10d B  %s' % (label, os.path.getsize(p), rel(p)))
        else:
            print('  --   %-20s %10s    %s' % (label, '(缺失)', rel(p)))
    print()
    print('解析链路自检（**"读不到" != "不存在"**）:')
    print('  map 格式识别   %s' % (ctx.map_fmt or '**未识别**'))
    print('  map 原始行数   %d' % ctx.map_lines)
    print('  解析出符号数   %d' % len(ctx.syms))
    n_in = getattr(ctx, '_n_inside', None)
    print('  正向对照       落进产物节区间的符号数: %s'
          % ('%d（链路通）' % n_in if n_in else '**0 -> 链路异常/不同源**'))
    print('  节表           %d 节%s' % (len(ctx.secs),
          '' if not ctx.text else '（.text rva=0x%X vsize=0x%X raw=0x%X）'
          % (ctx.text['virtual_addr'], ctx.text['virtual_size'],
             ctx.text['size_raw'])))
    print()
    print('掩码区（权威来源: 产物 `%s` meta）:'
          % (ctx.cry_sec['name'] if ctx.cry_sec else '?'))
    print('  产物 meta      %d 区' % len(ctx.meta))
    print('  提示文件       %s'
          % ('%d 区（交叉核对一致 ✓）' % len(ctx.mask_txt)
             if ctx.mask_txt is not None
             and sorted((r, l) for r, l, _g in ctx.meta) == sorted(ctx.mask_txt)
             else ('%d 区（**不一致**）' % len(ctx.mask_txt)
                   if ctx.mask_txt is not None else '缺失')))
    print()
    print('提示:')
    print('  · 本工具打印的是**链接时 VA**；运行时地址 = 模块基址 + RVA —— '
          '本机**实测 ASLR 生效**（同一次实验两次基址不同），不要直接拿 VA 去读进程。')
    print('  · 启动 demo 时 `--vm-blob` **必须显式传**，否则 rc=45323 '
          '（PROT_EXIT_BLOB_MISSING）—— 本项目已踩 6+ 次。')
    print('  · 第 2 步（`patch`/`read`/`watch`）与第 3 步（`run`）**尚未实现**。')
    for w in ctx.warns:
        print('  [warn] %s' % w)
    print()
    if ctx.errors:
        print('判据失败 %d 条:' % len(ctx.errors))
        for e in ctx.errors:
            print('  [X] %s' % e)
        print()
        print('[prot_dbg doctor] FAIL')
        js['doctor'] = {'ok': False, 'errors': ctx.errors, 'warns': ctx.warns}
        return 1
    print('[prot_dbg doctor] PASS')
    js['doctor'] = {'ok': True, 'errors': [], 'warns': ctx.warns,
                    'syms': len(ctx.syms), 'mask_regions': len(ctx.meta)}
    return 0


def cmd_sym(ctx, names, quiet, js):
    rc = 0
    out = {}
    for name in names:
        info = ctx.sym(name)
        if info is None:
            rc = 1
            print('%s: **不在 map 中**' % name)
            for r in ctx.why_missing(name):
                print('    · %s' % r)
            out[name] = None
            continue
        m = info['mask']
        in_text = info['text_off'] is not None
        print('%s' % name)
        print('  链接时 VA     0x%016X   （映像基址 0x%X）'
              % (info['va'], info['image_base']))
        print('  RVA           0x%X (%d)' % (info['rva'], info['rva']))
        print('  .text 内偏移  %s'
              % ('+0x%X' % info['text_off'] if info['text_off'] is not None
                 else '（不在 .text 内）'))
        if m:
            print('  掩码区        **在区内** [0x%X, 0x%X)  len=%d  group=%d'
                  % (m[0], m[0] + m[1], m[1], m[2]))
            print('                => 改这段字节 = 改**密文**；'
                  '段 CRC 因掩码清零而**看不到**（但同时 selfcrypt 自己的 '
                  'per-region CRC 会先失败 -> 看门狗 `continue`）')
        elif in_text:
            print('  掩码区        不在任何区内（.text 段 CRC **会**看到改动）')
        else:
            # ## 诚实边界: 段 CRC 只覆盖特定节；对**非 .text** 符号
            #   （数据/只读数据/导入表…）不能顺手套用同一结论。
            print('  掩码区        不在任何区内；且该符号**不在 `.text` 内** '
                  '—— 段 CRC 的结论对它**不直接适用**（需另判该节是否被校验）')
        out[name] = {'rva': info['rva'], 'va': info['va'],
                     'text_off': info['text_off'],
                     'mask': list(m) if m else None}
        print()
    js['sym'] = out
    return rc


def cmd_mask(ctx, names, quiet, js):
    if names:
        return cmd_sym(ctx, names, quiet, js)
    rc = 0 if not ctx.errors else 1
    print('掩码区（权威来源: 产物 `%s` meta，%d 区）'
          % (ctx.cry_sec['name'] if ctx.cry_sec else '?', len(ctx.meta)))
    if not ctx.meta:
        print('  **无掩码区** —— 但先看 doctor 的解析链路自检:'
              '这可能是"读不到"而不是"没有"')
    inside = []
    for i, (r, l, g) in enumerate(ctx.meta):
        hits = sorted(n for n, rv in ctx.syms.items() if r <= rv < r + l)
        prot = [n for n in hits if 'prot_' in n]
        inside.extend(prot)
        print('  #%-2d [0x%06X, 0x%06X)  len=%-5d grp=%d   区内符号 %d（prot_* %d）'
              % (i, r, r + l, l, g, len(hits), len(prot)))
        for n in prot[:6]:
            print('        · %s' % n)
        if len(prot) > 6:
            print('        · …（另 %d 个）' % (len(prot) - 6))
    print()
    n_in = getattr(ctx, '_n_inside', 0) or 0
    print('小计: 掩码区内 prot_* 符号 %d 个 / map 符号 %d 个' % (len(inside), len(ctx.syms)))
    print('提示: 区外目标改动**会**被 .text 段 CRC 抓到；区内目标不会（掩码清零），'
          '但会被 selfcrypt 自己的 per-region CRC 抓到。')
    for w in ctx.warns:
        print('  [warn] %s' % w)
    js['mask'] = {'regions': [[r, l, g] for r, l, g in ctx.meta],
                  'inside_syms': inside,
                  'warns': ctx.warns}
    return rc


def cmd_exit(ctx, codes, quiet, js):
    table = parse_code_table()
    rc = 0
    out = {}
    print('退出码解释（表来源: `include/protect/*.h`，%d 条）' % len(table))
    print()
    for raw in codes:
        try:
            code = int(raw, 0)
        except ValueError:
            print('%s: **不是合法整数**（支持 10 进制与 0x 前缀）' % raw)
            rc = 1
            out[raw] = None
            continue
        known, lines = explain_code(code, table)
        print('%d (0x%X): %s' % (code, code, '已知' if known else '**未知**'))
        for l in lines:
            print(l)
        out[raw] = {'known': known}
        if not known:
            rc = 1
        print()
    js['exit'] = out
    return rc


# ===========================================================================
# 自检
# ===========================================================================
def selftest(quiet):
    def case(name, ok, detail=None):
        fails.append(name) if not ok else None
        if not quiet:
            print('  %s  %s' % ('ok  ' if ok else 'FAIL', name))
            if detail and not ok:
                print('        detail: %s' % detail)
        return ok

    fails = []
    print('=== prot_dbg 自检 ===')
    ctx = Ctx()
    ready = (os.path.isfile(ctx.exe) and os.path.isfile(ctx.map_path)
             and not ctx.errors)
    case('T0 前置: 产物+map 就绪且解析链路自检通过', ready,
         '; '.join(ctx.errors)[:160])
    if not ready:
        print()
        print('[prot_dbg-selftest] SKIP: 产物未就绪或链路异常'
              '（**未验证 != 通过**）')
        return 2

    # T1 正向: doctor
    js = {}
    jsn = {}
    case('T1 **正向**: doctor -> PASS', cmd_doctor(ctx, quiet, jsn) == 0)

    # T2 正向: sym 动态取一个真实符号（不硬编码名字）
    name = next((n for n in ctx.syms if ctx.text_off(ctx.syms[n]) is not None),
                None)
    if case('T2a **正向**: map 中存在落在 .text 内的符号', name is not None):
        case('T2b **正向**: sym 能查到它 -> rc=0',
             cmd_sym(ctx, [name], True, jsn) == 0)
        info = ctx.sym(name)
        case('T2c **正向**: 它的 .text 偏移算得出来',
             info is not None and info['text_off'] is not None)

    # T3 正向: exit 0xBAD
    tbl = parse_code_table()
    ok3, l3 = explain_code(0xBAD, tbl)
    case('T3 **正向**: exit 0xBAD -> PROT_EXIT_TAMPERED',
         ok3 and any('PROT_EXIT_TAMPERED' in x for x in l3))

    # T4 正向: Linux 低 8 位折算
    ok4, l4 = explain_code(0xB10B & 0xFF, tbl)
    case('T4 **正向**: exit 11 -> 指出 = 0xB10B 的低 8 位（Linux exit() 截断）',
         ok4 and any('PROT_EXIT_BLOB_MISSING' in x for x in l4))

    # T5 负向: 不存在的符号 -> 必须失败
    case('T5 **负向**: sym 不存在的符号 -> **必须 rc=1**',
         cmd_sym(ctx, ['__no_such_symbol_prot_dbg__'], True, jsn) == 1)

    # T6 负向: 未定义的码 -> 必须明确未知（不得猜测）
    ok6, l6 = explain_code(0x1234, tbl)
    case('T6 **负向**: exit 0x1234 -> **必须判未知**',
         (not ok6) and any('未知' in x for x in l6))

    # T7/T8 负向: 空 map / 非空但格式不识别 -> doctor 必须报错
    tmp = tempfile.mkdtemp(prefix='protdbg_')
    try:
        for tag, content, want in (
                ('T7 **负向**: map 为**空文件** -> doctor 必须 FAIL',
                 '', 'map 文件为**空**'),
                ('T8 **负向**: map **非空但格式不识别** -> 必须报"读不到 != 不存在"',
                 '这不是 map 文件\n' * 20, '格式未识别')):
            mp = os.path.join(tmp, tag[:2].strip() + '.map')
            with open(mp, 'w', encoding='utf-8', newline='\n') as f:
                f.write(content)
            c2 = Ctx(exe=ctx.exe, map_path=mp)
            joined = ' '.join(c2.errors)
            # doctor 必须返回 1（不是 0），且**原因必须正确**
            rcd = cmd_doctor(c2, True, {})
            case(tag, rcd == 1 and (want in joined),
                 'rc=%d errors=%s' % (rcd, joined[:120]))

        # T9 负向: 掩码判定不得恒真/恒假
        if ctx.meta:
            r, l, _g = ctx.meta[0]
            case('T9a **负向**: 掩码区内一个点必须判"在区内"',
                 ctx.mask_hit(r) is not None)
            # 找第一个**不在**任何区内的符号 RVA
            outside = next((rv for rv in ctx.syms.values()
                            if ctx.mask_hit(rv) is None), None)
            case('T9b **负向**: 掩码区外一个点必须判"不在区内"',
                 outside is not None and ctx.mask_hit(outside) is None)
        else:
            case('T9 掩码判定: 无区可测 -> **不假装通过**', False,
                 'ctx.meta 为空（先看 doctor 的链路自检）')
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print()
    print('=' * 66)
    if fails:
        # ## 静默模式也必须保留**失败信号**（否则门禁里只看到一个 rc，
        #    "诊断信息不可丢失" 是同一条纪律）。
        msg = '[prot_dbg-selftest] FAIL: %s' % '; '.join(fails)
        if quiet:
            sys.stderr.write(msg + '\n')
        else:
            print(msg)
        return 1
    print('[prot_dbg-selftest] PASS: 1 前置 + 4 正向 + 4 负向均可自证')
    return 0


# ===========================================================================
def main(argv=None):
    p = argparse.ArgumentParser(
        prog='prot_dbg.py',
        description='ShardVase 调试控制台（第 1 步: 只读子命令）',
        epilog='子命令: doctor | sym <名字…> | mask [名字…] | exit <码…>')
    p.add_argument('args', nargs='*', help='子命令与操作数')
    p.add_argument('--exe', default=None, help='产物路径（默认 build/demo.exe）')
    p.add_argument('--map', dest='map_path', default=None,
                   help='map 路径（默认与 --exe 同名 .map）')
    p.add_argument('--json', dest='json_out', default=None,
                   help='结构化结果落盘（JSON）')
    p.add_argument('--quiet', action='store_true')
    p.add_argument('--selftest', action='store_true')
    a = p.parse_args(argv)

    # ## `--quiet` 的真实语义（2026-09-30 补: 原先只写在参数表里、**没有任何效果**）
    #   人类看的是 stdout 的讲解；静默模式的消费者是**门禁/脚本**，
    #   它们只需要 `rc` + `--json`。=> 静默时把 stdout 整体沉掉，但
    #   **失败信息走 stderr 保留**（rc 之外还要留证据）。
    saved, sink = sys.stdout, None
    if a.quiet:
        sink = open(os.devnull, 'w', encoding='utf-8')
        sys.stdout = sink
    try:
        rc = _dispatch(p, a)
    finally:
        sys.stdout = saved
        if sink is not None:
            sink.close()
    if a.quiet and rc != 0:
        sys.stderr.write('[prot_dbg] rc=%d（静默模式；细节见 stdout 或 --json）\n' % rc)
    return rc


def _dispatch(p, a):
    if a.selftest:
        return selftest(a.quiet)

    if not a.args:
        p.print_help()
        return 2
    cmd, operands = a.args[0], a.args[1:]
    if cmd not in ('doctor', 'sym', 'mask', 'exit'):
        print('未知子命令: %s（可选: doctor | sym | mask | exit）' % cmd)
        return 2

    js = {'tool': 'prot_dbg', 'cmd': cmd, 'exe': a.exe or DEFAULT_EXE}
    if cmd == 'exit':
        # exit 不依赖产物 -> 无产物也能用（例如读别人的退出码）
        rc = cmd_exit(None, operands, a.quiet, js)
    else:
        ctx = Ctx(exe=a.exe, map_path=a.map_path)
        if cmd == 'doctor':
            rc = cmd_doctor(ctx, a.quiet, js)
        elif cmd == 'sym':
            if not operands:
                print('sym 需要一个或多个符号名')
                return 2
            rc = cmd_sym(ctx, operands, a.quiet, js)
        else:
            rc = cmd_mask(ctx, operands, a.quiet, js)

    if a.json_out:
        try:
            with open(a.json_out, 'w', encoding='utf-8', newline='\n') as f:
                json.dump(js, f, ensure_ascii=False, indent=2)
            if not a.quiet:
                print('[prot_dbg] JSON 证据已落盘: %s' % a.json_out)
        except OSError as e:
            print('[prot_dbg] JSON 落盘失败: %s' % e)
            return 1
    return rc


if __name__ == '__main__':
    sys.exit(main())
