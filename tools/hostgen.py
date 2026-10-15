#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ShardVase contributors
# 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；商业授权见 LICENSE.md。
"""hostgen.py — 从 `host_hooks` 声明生成宿主分发代码（缺口 #1 原型）

## 目标（缺口 #1）
  让"**加模块不改宿主代码**"成为可能：
    模块在 `modules.json` 声明 `host_hooks`（在哪个时机被调用）
    -> 本工具为宿主生成**分发代码**
    -> 宿主只写固定的钩子点（`prot_host_run_hook(PROT_HOOK_X)`）

## 本原型的范围（**重要**）
  **只生成、不替换**。原因: `demo/main.c` 是 1000 行的核心构建路径，
  被 e2e/attacks/protchain 全面覆盖，全量替换风险高。

  本工具先把"声明 -> 代码"跑通，并输出**可与手写代码对照**的片段，
  为后续"逐模块迁移"建立可验证的中间态（见
  `docs/HOST_HOOK_PROTOCOL.md` §4-§5）。

## 用法
  python tools/hostgen.py --hook post_license      # 生成单个钩子点
  python tools/hostgen.py --all                    # 生成全部
  python tools/hostgen.py --all --out <dir>        # 写文件
  python tools/hostgen.py --selftest
"""
import argparse
import json
import os
import re
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

HOOK_ENUM = {
    'pre_license': 'PROT_HOOK_PRE_LICENSE',
    'post_license': 'PROT_HOOK_POST_LICENSE',
    'pre_business': 'PROT_HOOK_PRE_BUSINESS',
    'post_business': 'PROT_HOOK_POST_BUSINESS',
    'watchdog': 'PROT_HOOK_WATCHDOG',
    'selftest': 'PROT_HOOK_SELFTEST',
    'vm_result': 'PROT_HOOK_VM_RESULT',
}

# 动作 -> 生成代码模板
ACTION_TEMPLATE = {
    'exit': '            return {status};',
    'warn': '            /* warn: 继续执行，但已记录 */',
    'continue': '            /* continue: 明确忽略 */',
    'xor_vm_result': '            /* xor_vm_result: 由宿主自行处理 */',
    'watchdog': '            /* watchdog: 已注册回调 */',
}


def load_registry():
    return json.load(open(os.path.join(REPO, 'modules.json'),
                          encoding='utf-8'))


def collect(reg, hook):
    """收集声明了该钩子的 (模块名, 声明) 列表，按 `ordering.priority` 排序。

    **为什么排序**：与链接顺序一致，保证生成代码的**确定性**
    （同一声明 -> 同一输出，符合项目可复现性纪律）。
    """
    out = []
    for n, m in reg.get('modules', {}).items():
        for h in (m.get('host_hooks') or []):
            if h.get('hook') == hook:
                prio = (m.get('ordering') or {}).get('priority', 9999)
                out.append((prio, n, h))
    out.sort(key=lambda x: (x[0], x[1]))
    return [(n, h) for _, n, h in out]


def gen_hook(reg, hook):
    """为一个钩子点生成分发代码。"""
    items = collect(reg, hook)
    enum = HOOK_ENUM.get(hook, 'PROT_HOOK_%s' % hook.upper())
    L = []
    L.append('/* === 钩子点: %s (由 tools/hostgen.py 生成，勿手改) === */' % hook)
    L.append('/* 声明者: %s */' % (', '.join(n for n, _ in items) or '（无）'))
    L.append('case %s:' % enum)

    if not items:
        L.append('    break;   /* 无模块声明此钩子点 */')
        return '\n'.join(L)

    for n, h in items:
        call = h['call']
        rt = h.get('report_type')
        pred = h.get('predicate')
        trigger = h.get('on_trigger', 'continue')
        status = h.get('status', 'PROT_ERR_INTEGRITY')
        guard = 'PROT_MOD_%s' % n.upper()

        L.append('#ifdef %s' % guard)
        if rt:
            L.append('    {')
            L.append('        %s rep;' % rt)
            L.append('        memset(&rep, 0, sizeof(rep));')
            if h.get('needs_sc_ext'):
                L.append('        /* 该模块需在 selfcrypt 解密窗口外调用 */')
                L.append('        if (sc_ext_enter() != PROT_OK) {')
                L.append('            r->triggered = 1;')
                L.append('            r->status = %s;' % status)
                L.append('            r->action = PROT_ACT_EXIT;')
                # ⚠️ **不可用 `break`** —— 那会跳出整个 switch，
                # 导致**后续模块被静默跳过**（初版缺陷，自检 "case/break 数
                # 不匹配" 抓到）。改用 `goto` 跳过**本模块**的调用。
                L.append('            goto hook_done_%s;' % n)
                L.append('        }')
                L.append('        %s(&rep);' % call)
                L.append('        sc_ext_leave();')
            else:
                L.append('        %s(&rep);' % call)
            if pred:
                L.append('        if (%s(&rep)) {' % pred)
                L.append('            r->triggered = 1;')
                if trigger == 'exit':
                    L.append('            r->status = %s;' % status)
                    L.append('            r->action = PROT_ACT_EXIT;')
                else:
                    L.append('            r->action = PROT_ACT_%s;'
                             % trigger.upper())
                L.append('        }')
            L.append('    }')
            # goto 跳转目标（仅当该模块用了 goto 时才生成标签）
            if h.get('needs_sc_ext'):
                L.append('hook_done_%s: ;' % n)
        else:
            # 无报告结构: 直接调用
            L.append('    %s;' % call if '(' in call else '    %s();' % call)
            if trigger != 'continue':
                L.append('    /* 声明 on_trigger=%s */' % trigger)
        L.append('#endif /* %s */' % guard)

    L.append('    break;')
    return '\n'.join(L)


def gen_all(reg):
    parts = []
    parts.append('/* ============================================================')
    parts.append(' * prot_host_dispatch.c — 宿主钩子分发（由 tools/hostgen.py 生成）')
    parts.append(' *')
    parts.append(' * **为什么生成**: 让"加模块不改宿主代码"成为可能 ——')
    parts.append(' *   模块在 modules.json 声明 host_hooks，本文件随之变化，')
    parts.append(' *   宿主的调用点（prot_host_run_hook）保持不变。')
    parts.append(' *')
    parts.append(' * **勿手工编辑** —— 改 modules.json 后重新生成。')
    parts.append(' * 设计: docs/HOST_HOOK_PROTOCOL.md')
    parts.append(' * ============================================================ */')
    parts.append('#include "protect/protdef.h"')
    parts.append('#include "protect/selfcrypt.h"')
    parts.append('')
    parts.append('/* 钩子点枚举（宿主侧固定，不随模块增减而变）*/')
    parts.append('typedef enum prot_hook {')
    for k, v in HOOK_ENUM.items():
        parts.append('    %s,' % v)
    parts.append('    PROT_HOOK_COUNT')
    parts.append('} prot_hook;')
    parts.append('')
    parts.append('typedef struct prot_hook_result {')
    parts.append('    int triggered;')
    parts.append('    prot_status status;')
    parts.append('    int action;')
    parts.append('} prot_hook_result;')
    parts.append('')
    # ⚠️ **必须有外层函数 + switch**（2026-09-23 编译验证抓到）
    #   初版只输出裸 `case` 标签 -> C2059 语法错误。
    #   **教训: 生成器必须实测编译，"看起来对"不等于"能编译"。**
    parts.append('/* 宿主唯一调用点：加模块**不改此处**，只改 modules.json */')
    parts.append('static void prot_host_run_hook(prot_hook h, '
                 'prot_hook_result* r)')
    parts.append('{')
    parts.append('    if (r == NULL) {')
    parts.append('        return;')
    parts.append('    }')
    parts.append('    r->triggered = 0;')
    parts.append('    r->status = PROT_OK;')
    parts.append('    r->action = 0;')
    parts.append('    switch (h) {')
    for hook in HOOK_ENUM:
        parts.append(gen_hook(reg, hook))
        parts.append('')
    parts.append('    default:')
    parts.append('        break;')
    parts.append('    }')
    parts.append('}')
    return '\n'.join(parts) + '\n'


def selftest():
    """负向测试: 生成器必须能自证正确性。"""
    fails = []

    def case(name, ok):
        print('  %s %-52s' % ('ok ' if ok else '**FAIL**', name))
        if not ok:
            fails.append(name)

    reg = load_registry()

    print('=== 收集声明 ===')
    pl = collect(reg, 'post_license')
    case('post_license 声明者 (%d 个)' % len(pl), len(pl) >= 2)
    case('含 antidebug', any(n == 'antidebug' for n, _ in pl))
    case('含 vmdetect', any(n == 'vmdetect' for n, _ in pl))
    case('排序确定（antidebug 在 vmdetect 前，priority 更小）',
         [n for n, _ in pl].index('antidebug')
         < [n for n, _ in pl].index('vmdetect'))
    empty = collect(reg, 'post_business')
    case('post_business 无声明者', empty == [])

    print()
    print('=== 生成代码检查 ===')
    code = gen_all(reg)
    case('含 7 个钩子枚举', all(v in code for v in HOOK_ENUM.values()))
    case('含 #ifdef 守卫（模块可按组合裁剪）',
         '#ifdef PROT_MOD_ANTIDEBUG' in code)
    case('含 sc_ext 包裹（selfcrypt 交互保留）', 'sc_ext_enter' in code)
    case('含 memset 初始化报告结构', 'memset(&rep, 0, sizeof(rep))' in code)
    case('含 "勿手工编辑" 提示', '勿手工编辑' in code)
    # 确定性: 两次生成必须一致
    case('确定性: 两次生成相同', gen_all(reg) == code)
    # 必须编译得过的形态: 每个 case 有 break
    # （注意: `default: break;` 也贡献一个 break —— 故总数 = case 数 + 1）
    n_case = len(re.findall(r'^\s*case PROT_HOOK_', code, re.M))
    n_break = len(re.findall(r'^\s*break;', code, re.M))
    case('case 数 == break 数 - 1（含 default）(%d/%d)' % (n_case, n_break),
         n_break == n_case + 1)
    # **关键**: 有外层函数 + switch（初版漏了 -> C2059）
    case('含 prot_host_run_hook 函数', 'prot_host_run_hook' in code)
    case('含外层 switch', re.search(r'switch \(h\) \{', code) is not None)
    case('含 default 分支', 'default:' in code)
    # **关键**: sc_ext 失败分支不可用 break（会跳出整个 switch）
    sc_block = re.search(
        r'if \(sc_ext_enter\(\) != PROT_OK\) \{(.*?)\}', code, re.S)
    case('sc_ext 失败分支不用 break（否则跳过后续模块）',
         sc_block is not None and 'break;' not in sc_block.group(1))
    case('sc_ext 失败分支用 goto', 
         sc_block is not None and 'goto ' in sc_block.group(1))
    # 括号平衡
    case('花括号平衡', code.count('{') == code.count('}'))
    case('#ifdef/#endif 配对',
         len(re.findall(r'#ifdef', code)) == len(re.findall(r'#endif', code)))

    print()
    print('=' * 64)
    if fails:
        print('[hostgen-selftest] FAIL: %s' % '; '.join(fails))
        return 1
    print('[hostgen-selftest] PASS: 生成器可自证正确性')
    return 0


def main():
    ap = argparse.ArgumentParser(prog='hostgen.py')
    ap.add_argument('--hook', default=None, help='生成单个钩子点')
    ap.add_argument('--all', action='store_true', help='生成全部')
    ap.add_argument('--out', default=None, help='输出目录/文件')
    ap.add_argument('--selftest', action='store_true')
    ap.add_argument('--quiet', action='store_true')
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    reg = load_registry()
    if args.all:
        code = gen_all(reg)
    elif args.hook:
        if args.hook not in HOOK_ENUM:
            print('[hostgen] FAIL: 未知钩子点 %r（值域: %s）'
                  % (args.hook, list(HOOK_ENUM)), file=sys.stderr)
            return 1
        code = gen_hook(reg, args.hook) + '\n'
    else:
        ap.error('需要 --hook 或 --all')

    if args.out:
        out = args.out
        if os.path.isdir(out):
            out = os.path.join(out, 'prot_host_dispatch.c')
        with open(out, 'w', encoding='utf-8', newline='\n') as f:
            f.write(code)
        if not args.quiet:
            print('hostgen: -> %s (%d 字节)' % (out, len(code)))
    else:
        sys.stdout.write(code)
    return 0


if __name__ == '__main__':
    sys.exit(main())
