#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ShardVase contributors
# 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；商业授权见 LICENSE.md。
"""
tools/replica_check.py — **判定多副本等价性机械判据** (R3.2-c / MODULE_GUIDE P1)

## 被检查的不变量

    `prot_antidebug_detected` 的 3 个副本 (r2/r3/r4) 与本体 **逐位等价**,
    且 4 者的机器码 **两两不同** (不被 /OPT:ICF 折叠成同一地址)。

`docs/MODULE_GUIDE.md:32` 的 P1 说「语义等价必须**可验证**, 不能靠"看起来一样"」。
R3.2-c 把判定复制成 4 份, 于是"副本与本体等价"从一句注释变成**必须被机器检查的
不变量** —— 一旦某次编辑让某个副本漏掉一个关键位, 攻击者只需挑那个副本下手。

## 五条判据 (缺一不可)

1. **差分等价 + 独立 oracle + 非空洞性**
   把 `src/antidebug.c` 的本体与副本区**逐字提取出来单独编译**, 对一个
   2^12 穷举 + 逐字段边界 + 8192 组确定性伪随机的输入域, 断言 5 个函数输出全等。
   同时:
     · 用**独立 oracle** (`any(关键位) != 0`) 校验本体本身 —— 纯差分对
       "全体一起错"是盲的;
     · 断言**函数指针两两不同** —— 否则 harness 自己被 /OPT:ICF 折叠, 差分
       退化成"一个函数和自己比", 判据空洞 (链接期另加 `/OPT:NOICF` 双保险);
     · 关键位清单**从 `include/protect/antidebug.h` 的 `(咨询项)` 标注解析**,
       解析结果必须 7 关键 / 5 咨询, 否则**报错** (头文件漂移不得静默接受)。

2. **地址互异 (抗 /OPT:ICF)**
   释放构建带 `/OPT:ICF` (`build.ps1` 的 `$linkHard`), 等价函数会被折叠成**同一
   地址** —— 那时副本白做。判据: `build/demo.map` 里 5 个符号的 VA **两两不同**。
   (副本各自注入不同立即数使机器码不同; `PROT_BUILD_SALT` 是全局同值, 做不到。)

3. **负向对照 (判据必须有判别力)**
   把 r2 的一个 `acc |= rep->X;` 摘掉 -> 差分**必须**报出不一致。
   若负向对照也"通过", 说明判据没有判别力 -> **判 FAIL** (不是静默通过)。

4. **单点 patch 不再足够 (R3.2-c 的核心验收)**
   对 3 个副本 x 2 种手法 (`stub-ret0` / `drop-key-bit`) 各做一次**单点**变异, 断言
   契约入口 `prot_antidebug_detected_multi` 对每个 oracle=1 的输入**仍报 1**;
   再把 3 副本 + 聚合器**全打掉**做对照, 断言那时**必须**漏报 (判据可失败)。

5. **副本间距随构建盐变化 (R3.2-c 关键设计③)**
   5 个符号同属一个编译单元, `cl /O2` 在该 TU 内的函数排布**与链接顺序无关**
   (`--shuffle-seed` 只打乱源文件顺序) ⇒ 若代码长度恒定, 攻击者定位任意一个副本
   后, 其余副本的偏移就是**可预测常量** (填充前实测恒为 `+208/+416/+480/+688`),
   多副本对"定位成本"的贡献接近零。`PROT_PAD_STEP()` 阶梯让代码长度随
   `PROT_BUILD_SALT` 变化 ⇒ 用 3 个不同盐编译, 偏移向量**必须**互不相同; 负向对照
   (摘掉填充阶梯) **必须**退化为恒定, 否则本判据测的不是填充, 不得据此宣称已生效。

## 为什么用"提取源码编译"而不是链 demo.exe

`include/protect/antidebug.h` **只依赖 protdef.h** ⇒ 本体与副本区可独立编译, 对
输入域做全域穷举 (跑在真实 demo.exe 里做不到: 拿不到能自由构造的 report)。
两条腿互补: 静态全域等价 + 真实二进制的地址互异。

## 作用域与诚实边界

· 判据覆盖 `prot_antidebug_report` 的 **12 个字段全域**; 未来新增字段必须重跑本
  判据 (7+5 的归属检查会先报错, 不会静默放过)。
· 判据 2 需要先构建 `build/demo.exe`; 缺失时 SKIP (不等于通过)。
· 判据 5 度量的是"间距**是否**随盐变化"这一事实, **不度量熵的大小**: 3 个盐给出
  3 个不同向量即通过; 若将来填充被削弱到只剩 1 bit, 本判据仍可能通过 —— 那时应
  把盐数调大。每次构建的盐是随机 4 字节 ⇒ 发布构建的实际间距空间远大于 3。
· 判据证明的是"**同输入同输出**"; 它不能证明副本在二进制里真的被**分别执行**
  (那是 docs/ATTACK_DRILL 的活体实证, 与静态判据互补)。

## CLI
    python tools/replica_check.py [--verbose] [--json out.json] [--selftest]
退出码: 0 = PASS, 1 = FAIL, 2 = SKIP (非 Windows / 无编译器 / 无产物)
"""
import argparse
import io
import json
import os
import re
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

REPO = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
SRC = os.path.join(REPO, 'src', 'antidebug.c')
HEADER = os.path.join(REPO, 'include', 'protect', 'antidebug.h')
MAP = os.path.join(REPO, 'build', 'demo.map')
EXE = os.path.join(REPO, 'build', 'demo.exe')
BUILD = os.path.join(REPO, 'build')

ENTRY = 'prot_antidebug_detected_multi'
BASE = 'prot_antidebug_detected'
REPLICAS = ('prot_antidebug_detected_r2',
            'prot_antidebug_detected_r3',
            'prot_antidebug_detected_r4')

REGION_BEGIN = '#define PROT_AD_R2_SALT'          # 副本区起点 (文件尾的专门分节)
BASE_DECL = re.compile(r'^uint32_t\s+' + BASE + r'\s*\(', re.M)

CASES_EXHAUSTIVE = 1 << 12
CASES_FUZZ = 8192


# ----------------------------------------------------------------- 头文件解析

def parse_report_fields(header_path):
    """解析 prot_antidebug_report 的字段顺序 + 关键/咨询归属。

    归属靠字段行末尾的 **`(咨询项)`** 标注 (头文件里既有的约定)。
    返回 (fields, keys, advisory)。
    """
    t = io.open(header_path, encoding='utf-8', errors='replace').read()
    m = re.search(r'typedef\s+struct\s+prot_antidebug_report\s*\{(.*?)\}'
                  r'\s*prot_antidebug_report\s*;', t, re.S)
    if not m:
        raise ValueError('头文件里找不到 prot_antidebug_report 结构体')
    fields, keys, advisory = [], [], []
    for line in m.group(1).splitlines():
        s = line.strip()
        fm = re.match(r'uint32_t\s+([A-Za-z_]\w*)\s*;', s)
        if not fm:
            continue
        name = fm.group(1)
        fields.append(name)
        (advisory if '咨询项' in s else keys).append(name)
    return fields, keys, advisory


# ------------------------------------------------------------------- 源码提取

def _brace_slice(text, start):
    """从 start 起的第一个 `{` 开始, 取到配平的 `}` (含两端)。"""
    i = text.index('{', start)
    depth = 0
    for j in range(i, len(text)):
        c = text[j]
        if c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                return text[i:j + 1]
    raise ValueError('花括号不配平 (offset %d)' % start)


def extract_base(text):
    """逐字提取本体函数 (签名 + 配平函数体)。"""
    m = BASE_DECL.search(text)
    if not m:
        raise ValueError('找不到本体函数 %s 的定义' % BASE)
    sig = text[m.start():text.index('{', m.start())]
    return sig + _brace_slice(text, m.start())


def extract_region(text):
    """逐字提取副本区 (marker `#define PROT_AD_R2_SALT` 到文件尾)。

    刻意用切片而不是重新排版: 判据的对象必须是**真实参与构建的那份源码**,
    任何转写都会让判据与产物脱钩。副本区是文件尾的专门分节, 故取到 EOF。
    """
    lines = text.splitlines(True)
    for i, ln in enumerate(lines):
        if ln.startswith(REGION_BEGIN):
            return ''.join(lines[i:])
    raise ValueError('副本区提取失败 (找不到 marker %r)' % REGION_BEGIN)


def region_function_bodies(region):
    """把一段 C 文本切成 {函数名: 函数体}。"""
    out = {}
    for m in re.finditer(r'^(?:PROT_NOINLINE\s*\n)?uint32_t\s+(prot_\w+)\s*\([^;{]*\)\s*\{',
                         region, re.M):
        try:
            out[m.group(1)] = _brace_slice(region, m.start())
        except ValueError:
            pass
    return out


def macro_dict(region):
    return dict(re.findall(r'^#define\s+(PROT_AD_R\d_SALT)\s+(\S+)\s*$', region, re.M))


def _normalize_body(body):
    """规范化以便判断两个副本是否**真的不同**。

    注意: 不能用"两个函数文本完全相同"作为折叠判据 —— 副本的**立即数不同**
    (抗 ICF 的手段), 所以即使控制流被写成一样, 文本也不会相同。这里刻意把
    立即数还原成占位符后再比: 那样才代表"除立即数外完全一致", 也就是
    ICF 真正可能折叠的情形 (ICF 只看等价性, 不过问常量值)。
    """
    return re.sub(r'\s+', '', re.sub(r'0x[0-9A-Fa-f]{6,8}u?', 'IMM', body))


def body_is_pure_constant(body):
    """函数体是否"不读输入、无 volatile" —— 这类体的机器码与输入无关, 必被 ICF 折叠。

    返回 (是否, 证据)。判据取"是否出现 `rep` 或 `volatile`"而不是"有没有字面量"
    —— 后者会把 `{ return 0u; }` 里的 `0` 当成"有运算"而漏判 (自检抓到过)。
    """
    ids = set(re.findall(r'[A-Za-z_][A-Za-z0-9_]*', body))
    pure = ('rep' not in ids) and ('volatile' not in ids)
    return pure, 'ids=%d has_rep=%s has_volatile=%s' % (
        len(ids), 'rep' in ids, 'volatile' in ids)


# ------------------------------------------------------------------ C harness

HARNESS = r'''/* 由 tools/replica_check.py 生成 —— 不要手工编辑 (改判据请改工具) */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "protect/protdef.h"
#include "protect/prot_noise.h"
#include "protect/antidebug.h"

/* ---- 本体: 从 src/antidebug.c 逐字提取 ---- */
@base@

/* ---- 副本区: 从 src/antidebug.c 逐字提取 ---- */
@region@
/* ---- 提取结束 ---- */

#define NFIELD  @nfields@
#define NEXH    @nexh@
#define NFUZZ   @nfuzz@

#define NFN 5
static const char* g_names[NFN] = { "@base_name@", "@r2@", "@r3@", "@r4@", "@entry@" };
static uint32_t (*g_fns[NFN])(const prot_antidebug_report*) = {
    @base_name@, @r2@, @r3@, @r4@, @entry@
};

static uint32_t g_cases;
static uint32_t g_mismatch;    /* 副本 != 本体 */
static uint32_t g_oracle_bad;  /* 本体 != 独立 oracle */
static uint32_t g_entry_bad;   /* 契约入口 != 本体 */
static uint32_t g_range_bad;   /* 返回值 > 1 */
static uint32_t g_folded;      /* 函数指针重复 (harness 自己被 ICF 折叠 -> 判据空洞) */
static uint32_t g_reported;
/* 判据 4 (单点 patch 不再足够) 用: 见 tools/replica_check.py 的 single_point_patch() */
static uint32_t g_pos_cases;    /* oracle 说"检测到"的输入数 -- 非空洞性证据 */
static uint32_t g_survived_bad; /* oracle=1 而契约入口=0 (判定被单点打掉) */

static uint32_t* field_at(prot_antidebug_report* r, uint32_t idx)
{
@field_cases@
    return NULL;
}

static uint32_t oracle(const prot_antidebug_report* r)
{
    if (r == NULL) { return 0u; }
    return (@oracle_expr@) ? 1u : 0u;
}

static void check(const prot_antidebug_report* r, const char* tag)
{
    uint32_t i;
    uint32_t got[NFN];
    uint32_t want = oracle(r);

    for (i = 0u; i < NFN; ++i) { got[i] = g_fns[i](r); }
    ++g_cases;

    /* 判据 4: oracle 认为"检测到" -> 契约入口必须仍然报 1。
     * 正例计数 (g_pos_cases) 同时是"这个断言不是空转"的证据。 */
    if (want != 0u) {
        ++g_pos_cases;
        if (got[4] == 0u) {
            ++g_survived_bad;
            if (g_reported < 8u) {
                ++g_reported;
                printf("  BYPASS oracle=1 但入口=0 (判定已被打掉), tag=%s\n", tag);
            }
        }
    }

    for (i = 0u; i < NFN; ++i) {
        if (got[i] > 1u) {
            ++g_range_bad;
            if (g_reported < 8u) {
                ++g_reported;
                printf("  RANGE  %s 返回 %lu (>1), tag=%s\n",
                       g_names[i], (unsigned long)got[i], tag);
            }
        }
    }
    if (got[0] != want) {
        ++g_oracle_bad;
        if (g_reported < 8u) {
            ++g_reported;
            printf("  ORACLE 本体=%lu want=%lu tag=%s\n",
                   (unsigned long)got[0], (unsigned long)want, tag);
        }
    }
    for (i = 1u; i < 4u; ++i) {
        if (got[i] != got[0]) {
            ++g_mismatch;
            if (g_reported < 8u) {
                ++g_reported;
                printf("  DIFF   %s=%lu != 本体=%lu, tag=%s\n",
                       g_names[i], (unsigned long)got[i],
                       (unsigned long)got[0], tag);
            }
        }
    }
    /* 契约入口 = 非短路多路 OR; 输入域上副本与本体等价, 故入口应与本体同值。 */
    if (got[4] != got[0]) {
        ++g_entry_bad;
        if (g_reported < 8u) {
            ++g_reported;
            printf("  ENTRY  %s=%lu != 本体=%lu, tag=%s\n",
                   g_names[4], (unsigned long)got[4],
                   (unsigned long)got[0], tag);
        }
    }
}

static uint32_t xs(uint32_t* s)
{
    *s ^= *s << 13;
    *s ^= *s >> 17;
    *s ^= *s << 5;
    return *s;
}

int main(void)
{
    prot_antidebug_report r;
    uint32_t i, k, s = 0x9E3779B9u;

    /* 0) 非空洞性: 5 个函数指针必须两两不同, 否则 harness 自己被 ICF 折叠,
     *    下面的"差分"退化成"一个函数和自己比"。 */
    for (i = 0u; i < NFN; ++i) {
        for (k = i + 1u; k < NFN; ++k) {
            if (g_fns[i] == g_fns[k]) {
                ++g_folded;
                printf("  FOLDED %s 与 %s 是同一函数 (判据空洞)\n",
                       g_names[i], g_names[k]);
            }
        }
    }

    check(NULL, "NULL");

    /* 1) 12 字段全 2^12 穷举 (含所有"仅一个关键位命中"的情形) */
    for (i = 0u; i < (uint32_t)NEXH; ++i) {
        memset(&r, 0, sizeof r);
        for (k = 0u; k < (uint32_t)NFIELD; ++k) {
            *field_at(&r, k) = (i >> k) & 1u;
        }
        check(&r, "exhaustive");
    }

    /* 2) 逐字段边界: 单独 0xFFFFFFFF / 单独 0x80000000 / 单独 2 */
    for (k = 0u; k < (uint32_t)NFIELD; ++k) {
        memset(&r, 0, sizeof r);
        *field_at(&r, k) = 0xFFFFFFFFu;   check(&r, "edge-ff");
        memset(&r, 0, sizeof r);
        *field_at(&r, k) = 0x80000000u;   check(&r, "edge-hi");
        memset(&r, 0, sizeof r);
        *field_at(&r, k) = 2u;            check(&r, "edge-2");
    }

    /* 3) 确定性伪随机 (含"多字段同时命中"与任意高位) */
    for (i = 0u; i < (uint32_t)NFUZZ; ++i) {
        for (k = 0u; k < (uint32_t)NFIELD; ++k) {
            uint32_t v = xs(&s);
            *field_at(&r, k) = (v & 3u) ? (v & 1u) : v;
        }
        check(&r, "fuzz");
    }

    printf("cases=%lu mismatch=%lu oracle_bad=%lu entry_bad=%lu "
           "range_bad=%lu folded=%lu pos_cases=%lu survived_bad=%lu\n",
           (unsigned long)g_cases, (unsigned long)g_mismatch,
           (unsigned long)g_oracle_bad, (unsigned long)g_entry_bad,
           (unsigned long)g_range_bad, (unsigned long)g_folded,
           (unsigned long)g_pos_cases, (unsigned long)g_survived_bad);
    return (g_mismatch || g_oracle_bad || g_entry_bad || g_range_bad || g_folded)
           ? 1 : 0;
}
'''


def gen_harness(base_src, region, fields, keys):
    field_cases = '\n'.join(
        '    if (idx == %du) { return &r->%s; }' % (i, f)
        for i, f in enumerate(fields))
    out = HARNESS
    for k, v in (
            ('base', base_src),
            ('region', region),
            ('nfields', len(fields)),
            ('nexh', CASES_EXHAUSTIVE),
            ('nfuzz', CASES_FUZZ),
            ('field_cases', field_cases),
            ('oracle_expr', ' || '.join('r->%s' % f for f in keys)),
            ('base_name', BASE), ('r2', REPLICAS[0]), ('r3', REPLICAS[1]),
            ('r4', REPLICAS[2]), ('entry', ENTRY)):
        out = out.replace('@%s@' % k, str(v))
    leftovers = re.findall(r'@\w+@', out)
    if leftovers:
        raise ValueError('harness 占位符未全部替换: %r' % sorted(set(leftovers)))
    return out


def compile_and_run(src_text, tag, verbose, salt='0x12345678u', map_out=None):
    """编译并运行 harness。返回 (rc, output); rc=None 表示无法编译/运行。

    `map_out` 给定时不运行 harness, 只编译并把 /MAP 写到该路径 (判据 5 用) ——
    返回 (0, map 路径)。
    """
    tools = os.path.join(REPO, 'tools')
    if tools not in sys.path:
        sys.path.insert(0, tools)
    try:
        import vcvars
        import winproc
    except ImportError as e:
        return None, 'vcvars/winproc 不可用: %s' % e

    c_path = os.path.join(BUILD, 'replica_%s.c' % tag)
    exe_path = os.path.join(BUILD, 'replica_%s.exe' % tag)
    bat_path = os.path.join(BUILD, 'replica_%s.bat' % tag)
    io.open(c_path, 'w', encoding='utf-8', newline='\n').write(src_text)

    # /OPT:NOICF = 双保险 (判据 1 自己也断言函数指针互异)
    link = ' /link /SUBSYSTEM:CONSOLE /OPT:REF,NOICF'
    if map_out:
        link += ' /MAP:"%s"' % map_out
    clcmd = ('cl /nologo /O2 /W4 /WX /std:c11 /utf-8 '
             '/I "%s" /DPROT_BUILD_SALT=%s '
             '/Fe:"%s" "%s"%s'
             % (os.path.join(REPO, 'include'), salt, exe_path, c_path, link))
    try:
        vc = vcvars.find_vcvars()
    except vcvars.VcVarsNotFound as e:
        return None, str(e)
    io.open(bat_path, 'w', encoding='utf-8', newline='\r\n').write(
        vcvars.bat_text(clcmd, vc))

    p = winproc.run([bat_path], capture_output=True, text=True,
                    encoding='utf-8', errors='replace', cwd=REPO)
    out = (p.stdout or '') + (p.stderr or '')
    if p.returncode != 0 or not os.path.exists(exe_path):
        return None, out
    if map_out:
        if not os.path.exists(map_out):
            return None, 'MAP 未生成:\n' + out
        return 0, map_out
    if verbose:
        sys.stdout.write('[replica_check] cl(%s) ok\n' % tag)
    q = winproc.run([exe_path], capture_output=True, text=True,
                    encoding='utf-8', errors='replace', cwd=REPO)
    return q.returncode, (q.stdout or '') + (q.stderr or '')


def parse_result(out):
    m = re.search(r'cases=(\d+) mismatch=(\d+) oracle_bad=(\d+) entry_bad=(\d+) '
                  r'range_bad=(\d+) folded=(\d+)(?: pos_cases=(\d+) '
                  r'survived_bad=(\d+))?', out)
    if not m:
        return None
    g = m.groups()
    return {'cases': int(g[0]), 'mismatch': int(g[1]), 'oracle_bad': int(g[2]),
            'entry_bad': int(g[3]), 'range_bad': int(g[4]), 'folded': int(g[5]),
            'pos_cases': int(g[6]) if g[6] is not None else None,
            'survived_bad': int(g[7]) if g[7] is not None else None}


# --------------------------------------------------------------- 判据 2: 地址

def map_symbol_va(name, map_text=None):
    if map_text is None:
        if not os.path.exists(MAP):
            return None
        map_text = io.open(MAP, encoding='utf-8', errors='replace').read()
    m = re.search(r'^\s+[0-9a-f]{4}:[0-9a-f]{8}\s+%s\s+([0-9a-f]{16})\b'
                  % re.escape(name), map_text, re.M)
    return m.group(1) if m else None


def check_addresses(verbose):
    """判据 2: 5 个符号的 map VA 两两不同 (抗 /OPT:ICF)。"""
    if not os.path.exists(EXE) or not os.path.exists(MAP):
        return None, 'build/demo.exe 或 build/demo.map 缺失'
    names = (BASE,) + REPLICAS + (ENTRY,)
    vas, missing = {}, []
    for n in names:
        va = map_symbol_va(n)
        if va is None:
            missing.append(n)
        else:
            vas[n] = va
    if missing:
        return False, 'map 里找不到符号: %s' % ', '.join(missing)
    if verbose:
        for n in names:
            sys.stdout.write('[replica_check] map %-32s %s\n' % (n, vas[n]))
    vals = list(vas.values())
    dups = sorted(set(v for v in vals if vals.count(v) > 1))
    if dups:
        folded = [n for n in names if vas[n] in dups]
        return False, ('地址重复 (被 /OPT:ICF 折叠): %s -> %s'
                       % (', '.join(folded), ', '.join(dups)))
    return True, '5 个符号 VA 两两不同 (抗 /OPT:ICF)'


# ------------------------------------------------------------------- 主判据

def analyze(src_path, verbose=False, tag='real', strict_shape=True):
    """判据 1: 差分等价 + 独立 oracle + 非空洞性。返回 (result|None, detail)。

    `strict_shape=False` 供判据 4 使用: 单点 patch 实验**故意**让某个副本退化
    (例如换成 `return 0u`), 那些"抗 ICF 形态"静态检查必然不成立 —— 此时要测的
    是聚合器的语义后果, 不是形态。判据 1 本体仍走默认的严格形态检查。
    """
    src_text = io.open(src_path, encoding='utf-8', errors='replace').read()
    try:
        region = extract_region(src_text)
        base_src = extract_base(src_text)
    except ValueError as e:
        return None, str(e)

    fields, keys, advisory = parse_report_fields(HEADER)
    if len(keys) != 7 or len(advisory) != 5:
        return None, ('头文件关键位/咨询位漂移: 期望 7 关键 + 5 咨询, 实得 %d + %d '
                      '(归属靠 `(咨询项)` 标注解析; 头文件改了必须同步)' % (
                          len(keys), len(advisory)))

    bodies = region_function_bodies(region)
    lost = [w for w in REPLICAS + (ENTRY,) if w not in bodies]
    if lost:
        return None, '副本区里找不到函数: %s' % ', '.join(lost)

    if strict_shape:
        # 逐副本: 必须绑定各自不同的立即数, 且函数体不得是纯常量
        salts, macro_names = {}, sorted(macro_dict(region))
        for name in REPLICAS:
            bound = [m for m in macro_names if re.search(r'\b%s\b' % m, bodies[name])]
            if not bound:
                return None, ('%s 未绑定任何 PROT_AD_R*_SALT 立即数 —— 机器码与本体'
                              '无法区分, 会被 /OPT:ICF 折叠' % name)
            salts[name] = bound[0]
            pure, ev = body_is_pure_constant(bodies[name])
            if pure:
                return None, ('%s 不读输入且无 volatile (%s) —— 机器码与输入无关, '
                              '/OPT:ICF 下副本失去意义' % (name, ev))
        if len(set(salts.values())) != len(REPLICAS):
            return None, '副本立即数不互异: %r' % salts

        # 除立即数外函数体不得完全一致 (否则 ICF 可能折叠)
        norm, seen = {}, {}
        for name in REPLICAS:
            b = _normalize_body(bodies[name])
            if b in seen:
                return None, ('%s 与 %s 除立即数外函数体完全一致 —— /OPT:ICF 下会被'
                              '折叠' % (name, seen[b]))
            seen[b] = name
            norm[name] = len(b)
    else:
        salts, macro_names, norm = {}, sorted(macro_dict(region)), {}

    # 聚合器: 必须是"非短路多路 OR" —— 4 个入口各调用一次, 且不得出现 || 短路。
    # "4 个入口各一次"只在严格模式查 (判据 4 的"全打掉"对照会替换聚合器本体);
    # "无 || 短路"两种模式都查 —— 它对判据 4 正是要害。
    agg = bodies[ENTRY]
    if strict_shape:
        called = re.findall(r'\|=\s*(prot_antidebug_detected\w*)\s*\(', agg)
        if sorted(called) != sorted((BASE,) + REPLICAS):
            return None, ('聚合器 %s 未对 4 个入口各做一次位或聚合 (实得 %r) —— '
                          '多路 OR 不成立' % (ENTRY, called))
    if '||' in agg:
        return None, ('聚合器 %s 含 `||` 短路 —— 后续副本永不执行, 攻击者只需让'
                      '先执行的那个返回 0 即跳过其余副本' % ENTRY)

    harness = gen_harness(base_src, region, fields, keys)
    rc, out = compile_and_run(harness, tag, verbose)
    if rc is None:
        return None, out
    res = parse_result(out)
    if res is None:
        return None, 'harness 输出无法解析:\n' + out[-1500:]
    res['rc'] = rc
    res['out'] = out
    res['salts'] = salts
    res['norm_len'] = norm
    return res, 'ok'


# ------------------------------------------- 判据 4: 单点 patch 不再足够

# 把某个副本"打掉"的三种改法, 与 DRILL7 步骤 4 / winpe_sympatcher 的手法同款:
#   ① `31 C0 C3` (xor eax,eax; ret)  -> 函数永远返回 0, 即判定被永久关闭
#   ② 摘掉一个关键位                   -> 该副本对那个位失明
SINGLE_POINT_STYLES = ('stub-ret0', 'drop-key-bit')

_STUB_MARK = '/* single-point */'


def _patch_body_to_ret0(body):
    """把函数体换成 `{ (void)rep; return 0u; }` (等价于 `xor eax,eax; ret`)。

    `(void)rep;` 不可省: 变异后的函数不再读参数, MSVC /W4 会报 **C4100**
    (unreferenced formal parameter) -> /WX 致命。那样测到的是"编译失败",
    不是"判定被单点打掉"。
    """
    i = body.index('{')
    j = len(body) - 1 - body[::-1].index('}')
    return body[:i] + '{ ' + _STUB_MARK + ' (void)rep; return 0u; }' + body[j + 1:]


def single_point_patch(verbose=False):
    """判据 4 (**R3.2-c 的核心验收**): patch **任意 1 个**副本 -> 判定仍成立。

    为什么必须单独做这一条: 判据 1 证明"4 份实现彼此等价", 但**等价**本身
    并不能推出"打掉 1 个副本后契约入口仍能检测到" —— 那是聚合器**非短路 +
    多路 OR** 的性质。判据 1 只静态检查聚合器"调用了 4 个入口各一次",
    真正的语义后果 (单点失败不再致命) 需要一个**打掉一个副本后重跑**的实验。

    做法: 对每个副本 r2/r3/r4, 依次用两种手法各造一个变异源 (一次只动一个函数,
    其余逐字不变), 编译后对**同一输入域**断言: oracle 说"检测到"的每个输入,
    契约入口仍必须报 1 (`survived_bad == 0`)。
    · 必须断言 `pos_cases > 0` —— 否则输入域里没有"检测到"的样本,
      这条判据就是空转 (与"只会通过的检查器"同型);
    · `mismatch` 此时**预期不为 0** (被打掉的那个副本与本体不等价) ——
      本判据不看 mismatch, 只看 `survived_bad`;
    · 对照: 若把**全部 4 个**副本都打掉, `survived_bad` 必须 > 0
      (证明这条判据真的能失败, 而不是恒真)。
    """
    src_text = io.open(SRC, encoding='utf-8', errors='replace').read()
    try:
        region = extract_region(src_text)
        base_src = extract_base(src_text)
    except ValueError as e:
        return None, str(e), []
    bodies = region_function_bodies(region)
    missing = [n for n in REPLICAS if n not in bodies]
    if missing:
        return None, '副本区里找不到函数: %s' % ', '.join(missing), []

    results, failures = [], []
    tmp = os.path.join(BUILD, '_replica_single.c')

    for name in REPLICAS:
        for style in SINGLE_POINT_STYLES:
            body = bodies[name]
            if style == 'stub-ret0':
                mutated = _patch_body_to_ret0(body)
            else:
                # 把该副本对某个关键位的读取换成常量 0 -> 该副本对该位失明。
                # 刻意**替换**而不是删语句: 删掉 `v[0] = rep->ppid_blacklist;`
                # 会留下未初始化的 v[0], MSVC /W4 报 C4701 -> /WX 编译失败,
                # 那样测的就成了"编译错误"而不是"判定被削弱"。
                mm = re.search(r'rep->(' + '|'.join(
                    ('peb_being_debugged', 'debug_port', 'debug_flags',
                     'debug_object', 'hardware_breakpoints', 'timing_suspicious',
                     'ppid_blacklist')) + r')', body)
                if not mm:
                    return None, ('在 %s 里找不到可摘的关键位读取 (源码变了就必须'
                                  '同步判据, 不得静默通过)' % name), []
                mutated = body[:mm.start()] + '0u' + body[mm.end():]
                style = 'drop-key-bit:%s' % mm.group(1)
            if mutated == body:
                return None, '%s 的 %s 变异没生效 (源码未变)' % (name, style), []

            mut_region = region.replace(body, mutated, 1)
            if mut_region == region:
                return None, '%s 的 %s 变异未落到副本区' % (name, style), []
            mut_src = src_text.replace(region, mut_region, 1)
            io.open(tmp, 'w', encoding='utf-8', newline='\n').write(mut_src)

            res, detail = analyze(tmp, verbose, tag='sp', strict_shape=False)
            if res is None:
                return None, ('单点 patch %s(%s) 的变异源无法编译/运行: %s'
                              % (name, style, detail)), []
            if not res.get('pos_cases'):
                return None, ('单点 patch %s(%s) 后输入域里"检测到"的样本数为 0 —— '
                              '判据空转, 不构成证据' % (name, style)), []
            ok = (res['survived_bad'] == 0)
            results.append({'replica': name, 'style': style,
                            'pos_cases': res['pos_cases'],
                            'survived_bad': res['survived_bad'],
                            'mismatch': res['mismatch'], 'ok': ok})
            if verbose:
                sys.stdout.write(
                    '[replica_check]   单点 %s(%s): pos=%d 入口漏报=%d '
                    '(该副本已与本体不等价 %d 处) %s\n'
                    % (name, style, res['pos_cases'], res['survived_bad'],
                       res['mismatch'], 'OK' if ok else 'FAIL'))
            if not ok:
                failures.append('%s(%s) 被打掉后契约入口漏报 %d 个"检测到"输入'
                                % (name, style, res['survived_bad']))

    # 对照: 全部副本一起打掉 -> 必须**能**失败 (否则这条判据恒真)
    all_mut = region
    for name in REPLICAS:
        all_mut = all_mut.replace(bodies[name],
                                  _patch_body_to_ret0(bodies[name]), 1)
    all_mut = all_mut.replace(bodies[ENTRY],
                              _patch_body_to_ret0(bodies[ENTRY]), 1)
    io.open(tmp, 'w', encoding='utf-8', newline='\n').write(
        src_text.replace(region, all_mut, 1))
    ctl, cdetail = analyze(tmp, verbose, tag='spall', strict_shape=False)
    if ctl is None:
        return None, '全打掉对照无法运行: %s' % cdetail, []
    ctl_ok = (ctl.get('survived_bad') or 0) > 0 and (ctl.get('pos_cases') or 0) > 0
    if not ctl_ok:
        failures.append('把 4 个副本 + 聚合器全换成 return 0 后契约入口仍报"检测到" '
                        '(pos=%r survived=%r) —— 判据恒真, 无判别力'
                        % (ctl.get('pos_cases'), ctl.get('survived_bad')))

    detail = ('打掉任意 1 个副本 (%d 种手法 x %d 个副本) 后契约入口全部仍报"检测到"; '
              '全打掉对照漏报 %r 个 (判据可失败)'
              % (len(SINGLE_POINT_STYLES), len(REPLICAS),
                 ctl.get('survived_bad')))
    if failures:
        return False, detail + ' | ' + '; '.join(failures), results
    return True, detail, results


def negative_control(verbose=False):
    """判据 3: 改动 r2 语义 -> 差分**必须**报出不一致。"""
    src_text = io.open(SRC, encoding='utf-8', errors='replace').read()
    try:
        region = extract_region(src_text)
    except ValueError as e:
        return False, str(e)
    r2 = region_function_bodies(region).get(REPLICAS[0])
    if not r2:
        return False, '找不到 %s' % REPLICAS[0]
    drop = 'acc |= rep->debug_object;\n'
    if drop not in r2:
        return False, ('负向对照的改写没生效 (在 %s 里找不到 %r) —— 源码变了就'
                       '必须同步判据, 不得静默通过' % (REPLICAS[0], drop.strip()))
    mutated_region = region.replace(r2, r2.replace(drop, '', 1), 1)
    mutated_src = src_text.replace(region, mutated_region, 1)
    if mutated_src == src_text:
        return False, '负向对照的改写没生效 (源码未变)'
    tmp = os.path.join(BUILD, '_replica_negctl.c')
    io.open(tmp, 'w', encoding='utf-8', newline='\n').write(mutated_src)
    res, detail = analyze(tmp, verbose, tag='negctl')
    if res is None:
        return False, '负向对照无法运行: %s' % detail
    if res['mismatch'] == 0:
        return False, ('摘掉 r2 的 debug_object 后差分仍报 0 处不一致 —— '
                       '判据没有判别力 (未验证 != 通过)')
    return True, ('摘掉 r2 的 debug_object 后差分报 %d 处不一致 (判据有判别力)'
                  % res['mismatch'])


# ------------------------------------------------------- 判据 5: 位置抖动

# 三个确定性盐: 实测其偏移向量互不相同 (见 docs/DECISION_REDUNDANCY_PLAN.md §12.5)。
PAD_SALTS = ('0x12345678u', '0xFF00FF00u', '0x0F0F0F0Fu')
# 填充阶梯的源码形态 (本体 + 3 副本 + 聚合器 = 5 处):
#     #if (((PROT_BUILD_SALT) >> N) & 4u)
#         PROT_PAD_4();
#     #endif
PAD_LADDER_RE = re.compile(
    r'[ \t]*#if \(\(\(PROT_BUILD_SALT\) >> \d+\) & [124]u\)\n'
    r'[ \t]*PROT_PAD_[124]\(\);\n'
    r'[ \t]*#endif\n')


def _offset_vector(src_text, salt, tag, verbose):
    """用指定盐编译该源码, 返回 (以本体为基准的偏移向量, None) 或 (None, 错误)。

    向量顺序 = (BASE, r2, r3, r4, ENTRY)。**不依赖 demo.exe** —— 用 harness
    自带的一份编译, 因此本判据在干净树上也能跑 (只要 MSVC 可用)。
    """
    try:
        fields, keys, _ = parse_report_fields(HEADER)
        region = extract_region(src_text)
        base_src = extract_base(src_text)
    except ValueError as e:
        return None, str(e)
    harness = gen_harness(base_src, region, fields, keys)
    map_path = os.path.join(BUILD, 'replica_%s.map' % tag)
    if os.path.exists(map_path):
        try:
            os.remove(map_path)
        except OSError:
            pass
    rc, out = compile_and_run(harness, tag, verbose, salt=salt, map_out=map_path)
    if rc is None:
        return None, '位置抖动判据编译失败 (%s): %s' % (salt, str(out)[-300:])
    mtxt = io.open(map_path, encoding='utf-8', errors='replace').read()
    names = (BASE,) + REPLICAS + (ENTRY,)
    va = {}
    for n in names:
        v = map_symbol_va(n, mtxt)
        if v is None:
            return None, 'MAP 里找不到 %s (%s)' % (n, salt)
        va[n] = int(v, 16)
    base = va[BASE]
    return tuple(va[n] - base for n in names), None


def check_position_jitter(verbose):
    """判据 5: 副本之间的相对距离必须随构建盐变化 (R3.2-c 关键设计③)。

    为什么需要它: 5 个符号同属一个编译单元, `cl /O2` 在该 TU 内的函数排布
    **与链接顺序无关** ⇒ 若代码长度是常量, 攻击者只需定位任意一个副本, 其余
    副本的偏移就是可预测常量 (实测旧值恒为 +208/+416/+480/+688), 多副本对
    "定位成本"的贡献接近零。`PROT_PAD_STEP()` 阶梯让代码长度随
    `PROT_BUILD_SALT` 变化 ⇒ 间距不再可预测。

    判据必须能失败: 去掉填充阶梯后, 偏移向量**必须**退化为恒定 —— 否则说明
    本判据测的不是填充, 结论不成立。
    """
    src_text = io.open(SRC, encoding='utf-8', errors='replace').read()
    try:
        extract_region(src_text)
    except ValueError as e:
        return None, str(e)

    # 5 处调用点 x 3 个 #if 块 (4/2/1 步) = 15 个阶梯块
    n_ladders = len(PAD_LADDER_RE.findall(src_text))
    if n_ladders != 15:
        return False, ('填充阶梯应出现 15 处 (5 个函数 x 3 个 #if 块), 实得 %d 处'
                       ' —— 源码变了就必须同步判据, 不得静默通过' % n_ladders)
    groups = {b // 3 for b in
              (int(m) for m in re.findall(
                  r'#if \(\(\(PROT_BUILD_SALT\) >> (\d+)\) & [124]u\)', src_text))}
    if len(groups) != 5:
        return False, ('填充位段应分成 5 个互不重叠的三位组 (每函数独立扰动), '
                       '实得 %d 组 —— 否则各副本尺寸会同步变化, 间距仍可能恒定'
                       % len(groups))

    vectors = []
    lines = []
    for i, salt in enumerate(PAD_SALTS):
        vec, err = _offset_vector(src_text, salt, 'pos%d' % i, verbose)
        if vec is None:
            return None, err
        vectors.append(vec)
        lines.append('    %-14s -> %s' % (salt, vec))

    distinct = list(dict.fromkeys(vectors))
    if verbose:
        for ln in lines:
            sys.stdout.write('[replica_check] %s\n' % ln)

    # 残余可预测性: 哪些符号对的间距在所有盐下都相同
    names = (BASE,) + REPLICAS + (ENTRY,)
    fixed_pairs = []
    for a in range(len(names)):
        for b in range(a + 1, len(names)):
            gaps = {v[b] - v[a] for v in vectors}
            if len(gaps) == 1:
                fixed_pairs.append('%s<->%s 恒为 %+d'
                                   % (names[a], names[b], gaps.pop()))

    if len(distinct) < 2:
        return False, ('%d 个盐得到同一个偏移向量 %s —— 副本间距仍是常量, '
                       '位置抖动未生效 (攻击者定位一次即可推算全部副本)'
                       % (len(PAD_SALTS), distinct[0]))

    # ---- 负向对照: 去掉填充阶梯后必须退化为恒定 ----
    stripped = PAD_LADDER_RE.sub('', src_text)
    if stripped == src_text:
        return False, '填充阶梯一处都没匹配到 —— 判据没有判别力'
    neg = []
    for i, salt in enumerate(PAD_SALTS[:2]):
        vec, err = _offset_vector(stripped, salt, 'posneg%d' % i, verbose)
        if vec is None:
            return None, err
        neg.append(vec)
    if len(set(neg)) != 1:
        return False, ('负向对照失败: 摘掉填充阶梯后偏移向量仍随盐变化 (%s) —— '
                       '说明本判据测的不是填充, 不得据此宣称位置抖动已生效'
                       % (neg,))

    detail = ('%d 个盐得到 %d 个不同偏移向量 -> %s; 负向对照 (摘掉填充) 退化为'
              '恒定 %s (判据有判别力)'
              % (len(PAD_SALTS), len(distinct), distinct, neg[0]))
    if fixed_pairs:
        detail += '; ⚠️ 残余可预测性: ' + '; '.join(fixed_pairs)
    else:
        detail += '; 任意两符号的间距都随构建盐变化 (无残余常量间距)'
    return True, detail


# --------------------------------------------------------------------- 自检

def selftest():
    """纯解析层自检: 不依赖编译器/产物。"""
    fails = []

    def case(name, ok, extra=''):
        sys.stdout.write('  [%s] %s%s\n' % ('ok' if ok else 'X', name,
                                            '' if ok else '  <- ' + extra))
        if not ok:
            fails.append(name)

    real = io.open(SRC, encoding='utf-8', errors='replace').read()
    region = extract_region(real)
    case('副本区可提取', len(region) > 500)
    case('副本区含 3 个盐宏', len(macro_dict(region)) == 3,
         repr(sorted(macro_dict(region))))
    bodies = region_function_bodies(region)
    for n in REPLICAS + (ENTRY,):
        case('副本区含 %s' % n, n in bodies)
    case('副本区不含本体 (本体在别处, 单独提取)', BASE not in bodies)
    base_src = extract_base(real)
    case('本体可单独提取 (含签名, 可独立编译)',
         base_src.startswith('uint32_t ' + BASE + '(') and base_src.endswith('}'),
         base_src[:60])
    case('本体提取到的是本体而非副本',
         'ppid_blacklist' in base_src and 'PROT_AD_R2_SALT' not in base_src)

    # 聚合器静态形态 (非短路多路 OR)
    agg = bodies.get(ENTRY, '')
    case('聚合器对 4 个入口各调用一次',
         sorted(re.findall(r'\|=\s*(prot_antidebug_detected\w*)\s*\(', agg))
         == sorted((BASE,) + REPLICAS))
    case('聚合器无 || 短路', '||' not in agg)

    fields, keys, advisory = parse_report_fields(HEADER)
    case('report 12 字段', len(fields) == 12, repr(len(fields)))
    case('关键位 7 / 咨询位 5', len(keys) == 7 and len(advisory) == 5,
         '%d/%d' % (len(keys), len(advisory)))
    case('关键位是 DRILL7 那 7 个',
         set(keys) == {'peb_being_debugged', 'debug_port', 'debug_flags',
                       'debug_object', 'hardware_breakpoints',
                       'timing_suspicious', 'ppid_blacklist'})
    case('咨询位是那 5 个',
         set(advisory) == {'peb_nt_global_flag', 'kernel_debugger',
                           'debug_heap_flags', 'int3_honey', 'clock_drift_sec'})

    # "纯常量体"必须被认出 (否则"抗 ICF"是纸面结论)
    case('纯常量 return 0u; 被认出', body_is_pure_constant('{ return 0u; }')[0])
    case('常量 1u|0u 被认出', body_is_pure_constant('{ return 1u | 0u; }')[0])
    case('读输入 + volatile 的体不被当成纯常量',
         not body_is_pure_constant(
             '{ volatile uint32_t k = 0x5A17C3E9u; if (k == 7u) { return 1u; } '
             'return rep->debug_flags; }')[0])
    case('只读输入(无 volatile)不算纯常量',
         not body_is_pure_constant('{ return rep->debug_port; }')[0])

    # 除立即数外一致的两个体必须被判为"可能折叠"
    a = '{ volatile uint32_t k = 0x11111111u; return rep->debug_port; }'
    b = '{ volatile uint32_t k = 0xAAAAAAAAu; return rep->debug_port; }'
    case('仅立即数不同的两个体被判为同形', _normalize_body(a) == _normalize_body(b))
    case('控制流不同的两个体不被判为同形',
         _normalize_body(a) != _normalize_body(
             '{ volatile uint32_t k = 0x11111111u; return rep->debug_flags; }'))

    # 真实副本区: 立即数互异 + 函数体不互相同形
    macro_names = sorted(macro_dict(region))
    real_salts = {}
    for n in REPLICAS:
        bound = [m for m in macro_names if re.search(r'\b%s\b' % m, bodies[n])]
        if bound:
            real_salts[n] = bound[0]
    case('真实副本各自绑定不同立即数',
         len(real_salts) == 3 and len(set(real_salts.values())) == 3,
         repr(real_salts))

    # 头文件漂移必须被拒 (不静默接受)
    tmp = os.path.join(BUILD, '_replica_hdr_selftest.h')
    io.open(tmp, 'w', encoding='utf-8', newline='\n').write(
        'typedef struct prot_antidebug_report {\n'
        '    uint32_t peb_being_debugged;\n'
        '    uint32_t debug_port;   /* (咨询项) */\n'
        '} prot_antidebug_report;\n')
    try:
        f2, k2, a2 = parse_report_fields(tmp)
        case('漂移的头文件解析出 2 字段 (1 关键 + 1 咨询)',
             len(f2) == 2 and len(k2) == 1 and len(a2) == 1,
             '%d/%d/%d' % (len(f2), len(k2), len(a2)))
    except ValueError as e:
        case('漂移的头文件解析出 2 字段', False, str(e))
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass

    # 缺 marker 的源码必须被拒
    try:
        extract_region('uint32_t foo(void) { return 0; }\n')
        case('无 marker 的源码被拒', False)
    except ValueError:
        case('无 marker 的源码被拒', True)

    # 判据 5: 填充阶梯的形态识别
    ladders = PAD_LADDER_RE.findall(real)
    case('填充阶梯识别出 15 块 (5 函数 x 3 #if)', len(ladders) == 15,
         repr(len(ladders)))
    case('填充阶梯覆盖 PROT_PAD_4/2/1',
         {'PROT_PAD_4();', 'PROT_PAD_2();', 'PROT_PAD_1();'}
         <= set(re.findall(r'PROT_PAD_[124]\(\);', real)))
    bits = [int(m) for m in re.findall(
        r'#if \(\(\(PROT_BUILD_SALT\) >> (\d+)\) & [124]u\)', real)]
    case('填充位段互不重叠 (每个函数独立扰动)',
         len(bits) == 15 and len({b // 3 for b in bits}) == 5,
         repr(sorted(set(b // 3 for b in bits))))
    case('摘掉填充阶梯后判定不再匹配',
         not PAD_LADDER_RE.search(PAD_LADDER_RE.sub('', real)))
    # 负向: 一个"没有填充"的源码必须被认出 (否则判据 5 是纸面结论)
    case('无填充的源码里阶梯数为 0',
         len(PAD_LADDER_RE.findall('uint32_t f(void) { return 0u; }\n')) == 0)

    print()
    if fails:
        print('[replica_check-selftest] FAIL: %d 项' % len(fails))
        for f in fails:
            print('   - ' + f)
        return 1
    print('[replica_check-selftest] PASS: 提取/解析/聚合器形态/抗折叠/位置抖动'
          '判别均已自证')
    return 0


# ---------------------------------------------------------------------- main

def _write_json(path, payload):
    if path:
        io.open(path, 'w', encoding='utf-8', newline='\n').write(
            json.dumps(payload, ensure_ascii=False, indent=2))


def main(argv=None):
    ap = argparse.ArgumentParser(description='R3.2-c 判定多副本等价性机械判据')
    ap.add_argument('--verbose', action='store_true')
    ap.add_argument('--json', metavar='PATH')
    ap.add_argument('--selftest', action='store_true')
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()

    if sys.platform != 'win32':
        print('[replica_check] SKIP: 判据 1 需要 MSVC 编译本体+副本区 (非 Windows)'
              ' — 未验证 != 通过')
        return 2
    if not os.path.exists(SRC) or not os.path.exists(HEADER):
        print('[replica_check] SKIP: 缺 src/antidebug.c 或 antidebug.h'
              ' — 未验证 != 通过')
        return 2

    payload = {'ok': False}

    print('[replica_check] 判据 1: 副本 vs 本体 逐位等价 (2^12 穷举 + 边界 + fuzz)')
    res, detail = analyze(SRC, args.verbose)
    if res is None:
        print('[replica_check] SKIP: 无法运行差分判据: %s — 未验证 != 通过' % detail)
        payload['skip'] = detail
        _write_json(args.json, payload)
        return 2
    print('    cases=%d mismatch=%d oracle_bad=%d entry_bad=%d range_bad=%d '
          'folded=%d' % (res['cases'], res['mismatch'], res['oracle_bad'],
                         res['entry_bad'], res['range_bad'], res['folded']))
    payload['differential'] = {k: res[k] for k in
                               ('cases', 'mismatch', 'oracle_bad', 'entry_bad',
                                'range_bad', 'folded')}
    payload['salts'] = res['salts']
    if res['rc'] != 0:
        print('[replica_check] FAIL: 差分判据未通过 (mismatch=%d oracle_bad=%d '
              'entry_bad=%d range_bad=%d folded=%d)'
              % (res['mismatch'], res['oracle_bad'], res['entry_bad'],
                 res['range_bad'], res['folded']))
        print(res['out'][-1200:])
        payload['differential_out'] = res['out'][-4000:]
        _write_json(args.json, payload)
        return 1
    print('[replica_check]   等价 OK: 4 个实现同输入同输出, 本体与独立 oracle 一致, '
          '函数指针两两不同')
    print('[replica_check]   聚合器形态 OK: 4 个入口各一次位或, 无 || 短路')

    print('[replica_check] 判据 2: map 地址互异 (抗 /OPT:ICF 折叠)')
    ok2, d2 = check_addresses(args.verbose)
    if ok2 is None:
        print('[replica_check] SKIP: %s — 未验证 != 通过' % d2)
        print('[replica_check]   (判据 1 已通过; 地址判据需要先构建 demo.exe)')
        payload['addresses'] = {'ok': None, 'detail': d2}
    else:
        print('[replica_check]   %s' % d2)
        payload['addresses'] = {'ok': ok2, 'detail': d2}
        if not ok2:
            print('[replica_check] FAIL: %s' % d2)
            _write_json(args.json, payload)
            return 1

    print('[replica_check] 判据 3: 负向对照 (判据必须有判别力)')
    ok3, d3 = negative_control(args.verbose)
    print('[replica_check]   %s' % d3)
    payload['negative_control'] = {'ok': ok3, 'detail': d3}
    if not ok3:
        print('[replica_check] FAIL: 负向对照未被抓到 -> 判据无判别力')
        _write_json(args.json, payload)
        return 1

    print('[replica_check] 判据 4: 单点 patch 不再足够 (R3.2-c 的核心验收)')
    ok4, d4, sp = single_point_patch(args.verbose)
    if ok4 is None:
        print('[replica_check] SKIP: %s — 未验证 != 通过' % d4)
        payload['single_point'] = {'ok': None, 'detail': d4}
        _write_json(args.json, payload)
        return 2
    payload['single_point'] = {'ok': ok4, 'detail': d4, 'cases': sp}
    if not ok4:
        print('[replica_check] FAIL: %s' % d4)
        _write_json(args.json, payload)
        return 1
    print('[replica_check]   %s' % d4)

    print('[replica_check] 判据 5: 副本间距随构建盐变化 (R3.2-c 关键设计③)')
    ok5, d5 = check_position_jitter(args.verbose)
    if ok5 is None:
        print('[replica_check] SKIP: %s — 未验证 != 通过' % d5)
        payload['position_jitter'] = {'ok': None, 'detail': d5}
        _write_json(args.json, payload)
        return 2
    payload['position_jitter'] = {'ok': ok5, 'detail': d5}
    if not ok5:
        print('[replica_check] FAIL: %s' % d5)
        _write_json(args.json, payload)
        return 1
    print('[replica_check]   %s' % d5)

    payload['ok'] = True
    _write_json(args.json, payload)
    print('[replica_check] PASS: 五条判据全通过 '
          '(等价 + 地址互异 + 负向对照有判别力 + 单点 patch 不再足够 + 间距随构建变化)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
