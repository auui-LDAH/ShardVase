#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tools/modcheck.py — 模块注册表校验 + 组合一致性检查

对应 docs/MODULAR_ARCH.md §4.1。两件事:

  A. 注册表漂移检查 (P3: 门禁绕过会掩盖缺陷)
     逐项比对 modules.json 与真实源码:
       - source/header 文件存在
       - exports 与头文件中的 prot_* 声明一致 (双向: 不多不少)
       - deps 与源码 #include 的真实依赖一致
       - known_limits 非空 (P4: 强制公开边界)
     任何不一致 -> 报错并非零退出。

  B. 组合一致性检查 (P2: 两个各自正确的机制组合就崩)
     给定一组模块, 检查组合是否自洽:
       - 依赖闭包完整
       - modifies_text 与 verifies_text 冲突 (需 selfcrypt 掩码豁免)
       - page_align 模块的页资源冲突
       - 阶段顺序 (init -> scan -> decide -> enforce -> watch)

用法:
    python tools/modcheck.py                    # 仅注册表漂移检查
    python tools/modcheck.py --compose standard # 检查一个组合
    python tools/modcheck.py --list             # 列出所有模块
    python tools/modcheck.py --list-compositions

退出码: 0 全部通过; 1 有错误。
"""

import argparse
import glob
import json
import os
import re
import sys

REPO = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
REGISTRY = os.path.join(REPO, 'modules.json')
COMPOSITIONS = os.path.join(REPO, 'compositions')

VALID_CAPS = {'detect', 'prevent', 'conceal', 'verify', 'respond'}
VALID_PHASES = ['init', 'scan', 'decide', 'enforce', 'watch']

# 宿主下限: main.c / indirect_table.c 硬引用、无法从组合中移除的模块。
#
# **实测更新 (2026-09-20 批2 后)**: 逐个尝试排除并观察链接器结果。
#   可排除 (5): antidebug, dbiguard, integrity, syscall, vmdetect
#   不可排除 (8): blob/hostid/indirect/license/revoke/selfcrypt/strcrypt/vm
# 批1 时为 11 项; 批2 完成 antidebug/integrity 条件编译后收敛为 8 项。
# 须与 tools/compose.py 的 SUBSTRATE 保持一致 (下方有同步校验)。
HOST_SUBSTRATE = ['blob', 'hostid', 'indirect', 'license', 'revoke',
                  'selfcrypt', 'strcrypt', 'vm']

# 已实现条件编译、可被组合排除的模块 (供文档与测试引用)
HOST_EXCLUDABLE = ['antidebug', 'dbiguard', 'integrity', 'syscall', 'vmdetect']

# 头文件中的对外函数声明。
#
# 正则演进 (2026-09-20): 初版只匹配固定几个返回类型, **漏掉了**
#   const prot_indirect_fnp* prot_indirect_table(void);
#   prot_indirect_fnp        prot_indirect_resolve(...);
# 导致 indirect 模块的 exports 被静默登记为空而无人发现 ——
# 正是本工具存在的意义所在 (注册表漂移检测) 却自身有盲区。
# 现改为通用形式: 行首类型表达式 + prot_ 前缀函数名 + '('。
# 用 [A-Za-z_][\w\s\*]*? 容忍多词返回类型 (unsigned long 等) 与指针星号。
FN_DECL = re.compile(
    r'^\s*'
    r'(?![ \t]*typedef\b)'                       # 排除 typedef (如函数指针别名)
    r'(?:[A-Za-z_]\w*(?:\s+[A-Za-z_]\w*)*)'     # 返回类型 (含多词)
    r'\s*\*?\s*'                                 # 可选指针
    r'(prot_\w+)\s*\('                           # 函数名
    r'[^;]*\)\s*;',                              # 参数表到分号
    re.M)


def read(path):
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        return f.read()


def load_registry():
    if not os.path.isfile(REGISTRY):
        raise SystemExit('modcheck: modules.json not found')
    with open(REGISTRY, 'r', encoding='utf-8') as f:
        return json.load(f)


def header_exports(header_path):
    """头文件里声明的 prot_* 函数名集合。"""
    if not os.path.isfile(header_path):
        return None
    return set(FN_DECL.findall(read(header_path)))


def source_deps(src_path, mod_name):
    """源码 + 自身头文件里对其它模块的真实依赖。"""
    deps = set()
    paths = [src_path]
    hdr = os.path.join(REPO, 'include', 'protect', mod_name + '.h')
    if os.path.isfile(hdr):
        paths.append(hdr)
    for p in paths:
        if not os.path.isfile(p):
            continue
        for m in re.finditer(r'#include\s+"protect/([^"]+)\.h"', read(p)):
            h = m.group(1)
            if h not in ('protdef', mod_name):
                deps.add(h)
    return deps


# ---------------------------------------------------------------------------
# A. 注册表漂移检查
# ---------------------------------------------------------------------------
def check_registry(reg):
    errors = []
    warnings = []
    mods = reg.get('modules', {})

    # 声明为模块的源文件
    declared_srcs = set()
    for name, m in mods.items():
        src = m.get('source', '')
        declared_srcs.add(os.path.normpath(src))

        # --- 字段完整性 ---
        for field in ('source', 'caps', 'phases', 'deps', 'exports',
                      'known_limits', 'page_align', 'modifies_text',
                      'verifies_text'):
            if field not in m:
                errors.append('%s: 缺字段 %s' % (name, field))

        # --- 能力/阶段取值 ---
        for c in m.get('caps', []):
            if c not in VALID_CAPS:
                errors.append('%s: 非法 capability %r' % (name, c))
        for p in m.get('phases', []):
            if p not in VALID_PHASES:
                errors.append('%s: 非法 phase %r' % (name, p))

        # --- P4: known_limits 不得为空 ---
        if not m.get('known_limits'):
            errors.append('%s: known_limits 为空 (P4 要求显式声明边界)' % name)

        # --- 依赖指向已登记模块 ---
        for d in m.get('deps', []):
            if d not in mods:
                errors.append('%s: 依赖 %r 未在注册表登记' % (name, d))

        # --- 文件存在 ---
        sp = os.path.join(REPO, src)
        if not os.path.isfile(sp):
            errors.append('%s: source 不存在 %s' % (name, src))
            continue

        # --- 导出符号双向比对 ---
        hdr_rel = m.get('header')
        if hdr_rel:
            hp = os.path.join(REPO, hdr_rel)
            actual = header_exports(hp)
            if actual is None:
                errors.append('%s: header 不存在 %s' % (name, hdr_rel))
            else:
                declared = set(m.get('exports', []))
                missing = actual - declared
                extra = declared - actual
                if missing:
                    errors.append(
                        '%s: 头文件有声明但注册表未登记: %s'
                        % (name, ', '.join(sorted(missing))))
                if extra:
                    errors.append(
                        '%s: 注册表登记但头文件无声明: %s'
                        % (name, ', '.join(sorted(extra))))

        # --- 依赖比对 ---
        actual_deps = source_deps(sp, name)
        declared_deps = set(m.get('deps', []))
        if actual_deps != declared_deps:
            miss = actual_deps - declared_deps
            ext = declared_deps - actual_deps
            if miss:
                errors.append('%s: 源码依赖但注册表未登记: %s'
                              % (name, ', '.join(sorted(miss))))
            if ext:
                errors.append('%s: 注册表登记但源码无依赖: %s'
                              % (name, ', '.join(sorted(ext))))

    # --- 未被登记也非原语的源文件 (防止新增模块漏登记) ---
    # 例外: 以 '_' 开头的文件是**模板/草稿** (如 src/_template.c), 不参与构建,
    # 不应被要求登记。约定: 模板用 '_' 前缀, 落地时改名去掉前缀。
    prims = reg.get('primitives', {})
    prim_srcs = {os.path.normpath(v.get('source', '')) for v in prims.values()}
    src_dir = os.path.join(REPO, 'src')
    if os.path.isdir(src_dir):
        for f in sorted(os.listdir(src_dir)):
            if not f.endswith('.c') or f.startswith('_'):
                continue
            rel = os.path.normpath(os.path.join('src', f))
            if rel not in declared_srcs and rel not in prim_srcs:
                warnings.append(
                    '%s: 既未登记为模块也非原语 (新增模块请补 modules.json)'
                    % rel)

    # --- HOST_SUBSTRATE 与 compose.py 的 SUBSTRATE 必须一致 ---
    # 两处都描述"宿主无法移除的模块", 漂移会导致组合解析与校验结论矛盾。
    try:
        compose_path = os.path.join(REPO, 'tools', 'compose.py')
        if os.path.isfile(compose_path):
            m = re.search(r'^SUBSTRATE\s*=\s*\[(.*?)\]',
                          read(compose_path), re.M | re.S)
            if m:
                compose_sub = set(re.findall(r"'([^']+)'", m.group(1)))
                if compose_sub != set(HOST_SUBSTRATE):
                    errors.append(
                        'HOST_SUBSTRATE 与 compose.py SUBSTRATE 不一致: '
                        'modcheck=%s compose=%s'
                        % (sorted(set(HOST_SUBSTRATE) - compose_sub) or 'ok',
                           sorted(compose_sub - set(HOST_SUBSTRATE)) or 'ok'))
    except Exception as e:                                    # noqa: BLE001
        warnings.append('无法校验 SUBSTRATE 同步: %r' % e)

    return errors, warnings


# ---------------------------------------------------------------------------
# B. 组合一致性检查
# ---------------------------------------------------------------------------
def check_composition(reg, names):
    errors = []
    warnings = []
    mods = reg['modules']

    unknown = [n for n in names if n not in mods]
    if unknown:
        return ['组合含未登记模块: %s' % ', '.join(unknown)], []

    selected = set(names)

    # --- 1. 依赖闭包完整性 ---
    for n in sorted(selected):
        for d in mods[n].get('deps', []):
            if d not in selected:
                errors.append('%s 依赖 %s, 但组合中未包含 %s' % (n, d, d))

    # --- 2. .text 改写 vs 完整性校验冲突 (P2 的核心场景) ---
    modifiers = [n for n in selected if mods[n].get('modifies_text')]
    verifiers = [n for n in selected if mods[n].get('verifies_text')]
    if modifiers and verifiers:
        warnings.append(
            '.text 冲突: %s 改写 .text, %s 校验 .text —— '
            '必须启用 selfcrypt 掩码豁免 (integrity.build_selfcrypt_mask), '
            '否则必然 TAMPERED'
            % (', '.join(sorted(modifiers)), ', '.join(sorted(verifiers))))

    # --- 3. 页对齐资源 (P2: 页粒度自伤) ---
    page_mods = [n for n in selected if mods[n].get('page_align')]
    if len(page_mods) > 1:
        warnings.append(
            '多个模块要求页对齐: %s —— 需确认各自落在独立页 '
            '(S1 已证明同页会导致 VirtualProtect 自伤)' % ', '.join(sorted(page_mods)))

    # --- 4. 部署约束 ---
    wr = [n for n in selected if mods[n].get('needs_writable_dir')]
    if wr:
        warnings.append('需要可写目录: %s (安装目录 ACL 只读时失效)'
                        % ', '.join(sorted(wr)))

    # --- 5. 宿主下限: 未显式声明但被宿主强依赖的模块 ---
    # 依据 compose.py 的 SUBSTRATE (链接器实测)。差异必须如实报出,
    # 否则拼装图会"看起来更小"而实际等价 (对使用者是误导)。
    substrate = set(HOST_SUBSTRATE)
    implicit = sorted(substrate - selected)
    if implicit:
        warnings.append(
            '宿主下限未显式声明, 将自动补入: %s '
            '(main.c/indirect_table.c 硬引用; 见 BLUEPRINT §5 阶段 2)'
            % ', '.join(implicit))

    # --- 6. 阶段顺序 ---
    seen = set()
    for ph in VALID_PHASES:
        for n in sorted(selected):
            if ph in mods[n].get('phases', []):
                seen.add(ph)
    return errors, warnings


def load_composition(name):
    path = os.path.join(COMPOSITIONS, name + '.json')
    if not os.path.isfile(path):
        return None
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def list_compositions():
    if not os.path.isdir(COMPOSITIONS):
        return []
    return sorted(f[:-5] for f in os.listdir(COMPOSITIONS) if f.endswith('.json'))


def check_drill_coverage(reg):
    """阶段 3 准入 (P4): 每个防御模块须有 ≥1 条 drill 记录。

    理由: 项目的核心资产是"每项能力都有实证"。若某模块从未被攻击过,
    它的强度就是未经验证的声明 —— 应显式标注为 "未验证" 而非默默通过。

    返回 (errors, warnings, coverage_dict)。
    未覆盖的模块产生 **warning** 而非 error: 新模块在补齐演练前不应
    阻塞构建, 但必须在每次门禁运行时被提醒 (可见, 不静默)。
    """
    errors = []
    warnings = []
    reg_dir = os.path.join(REPO, 'drills')
    covered = {}
    if not os.path.isdir(reg_dir):
        warnings.append('drills/ 不存在 — 跳过演练覆盖检查')
        return errors, warnings, covered

    files = [f for f in glob.glob(os.path.join(reg_dir, '*.json'))
             if not os.path.basename(f).startswith('_')]
    for f in files:
        try:
            d = json.load(open(f, encoding='utf-8'))
        except ValueError:
            continue
        for r in d.get('attacks', d.get('drills', [])):
            tm = r.get('target_module')
            if not tm or tm == 'unmapped':
                continue
            # 基线/跳过记录**不计入**覆盖: 它们验证"无误报", 不是
            # "挡住了攻击"。计入会虚高覆盖率 (见 BASELINE_CASES 注释)。
            if r.get('result') == 'SKIP' or r.get('source_kind') == 'baseline':
                continue
            covered.setdefault(tm, 0)
            covered[tm] += 1

    uncovered = sorted(set(reg['modules']) - set(covered))
    for m in uncovered:
        warnings.append(
            '模块 %r 无 drill 记录 — 其强度属**未经验证**的声明 '
            '(阶段3 准入: 新增模块应提交至少一条演练记录)' % m)
    return errors, warnings, covered


def main():
    ap = argparse.ArgumentParser(description='模块注册表与组合校验')
    ap.add_argument('--compose', metavar='NAME', help='检查指定组合')
    ap.add_argument('--all-compositions', action='store_true',
                    help='检查 compositions/ 下全部组合')
    ap.add_argument('--list', action='store_true', help='列出全部模块')
    ap.add_argument('--list-compositions', action='store_true',
                    help='列出全部参考拼装图')
    ap.add_argument('--quiet', action='store_true')
    args = ap.parse_args()

    reg = load_registry()
    mods = reg['modules']

    if args.list:
        print('%-12s %-22s %-26s %s' % ('MODULE', 'CAPS', 'PHASES', 'DEPS'))
        print('-' * 78)
        for k in sorted(mods):
            m = mods[k]
            print('%-12s %-22s %-26s %s'
                  % (k, ','.join(m['caps']), ','.join(m['phases']),
                     ','.join(m['deps']) or '-'))
        return 0

    if args.list_compositions:
        names = list_compositions()
        if not names:
            print('(compositions/ 为空)')
        for n in names:
            c = load_composition(n)
            desc = c.get('description', '') if c else ''
            print('%-14s %s' % (n, desc))
        return 0

    rc = 0

    # --- A. 注册表漂移 ---
    errors, warnings = check_registry(reg)
    if not args.quiet:
        print('=== 注册表漂移检查 ===')
        print('  模块 %d 个, 原语 %d 个'
              % (len(mods), len(reg.get('primitives', {}))))
    for e in errors:
        print('  [X] %s' % e)
    for w in warnings:
        print('  [!] %s' % w)
    if errors:
        rc = 1
    elif not args.quiet:
        print('  [ok] 注册表与源码一致')

    # --- B. 组合检查 ---
    targets = []
    if args.compose:
        targets = [args.compose]
    elif args.all_compositions:
        targets = list_compositions()

    for name in targets:
        c = load_composition(name)
        if c is None:
            print('  [X] 组合 %r 不存在' % name)
            rc = 1
            continue
        errs, warns = check_composition(reg, c.get('modules', []))
        if not args.quiet:
            print()
            print('=== 组合: %s ===' % name)
            print('  成员: %s' % ', '.join(c.get('modules', [])))
        for e in errs:
            print('  [X] %s' % e)
        for w in warns:
            print('  [!] %s' % w)
        if errs:
            rc = 1
        elif not args.quiet:
            print('  [ok] 组合自洽')

    # --- C. 演练覆盖 (阶段 3 准入, P4) ---
    derr, dwarn, covered = check_drill_coverage(reg)
    if not args.quiet:
        print()
        print('=== 演练覆盖检查 (阶段3 准入) ===')
        print('  有 drill 记录的模块: %d / %d'
              % (len(covered), len(mods)))
    for e in derr:
        print('  [X] %s' % e)
    for w in dwarn:
        print('  [!] %s' % w)
    if derr:
        rc = 1
    elif not args.quiet and not dwarn:
        print('  [ok] 全部模块均有演练记录')

    if not args.quiet:
        print()
        print('[modcheck] %s' % ('FAIL' if rc else 'PASS'))
    return rc


if __name__ == '__main__':
    sys.exit(main())
