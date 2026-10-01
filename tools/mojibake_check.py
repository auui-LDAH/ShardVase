#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""mojibake_check.py — 全库 mojibake 回归门禁（Q1）。

## 为什么需要这个门禁

Q1 修掉了 **216 行** mojibake，但它**随时可能复发**: 本仓库的损坏来自
用 PowerShell 5.1 / .NET 的默认代码页去读写 UTF-8 源文件（构建脚本、临时
文本管道都有机会）。"下次小心"不是防线 —— **工具才是**
（与 `comment_lint` / `doccheck` 同样的思路）。

## 判据

调用唯一权威实现 `tools/mojibake.py` 的 `is_bad`（v4 字节重建，
独立标注集实测 **P=1.000 R=1.000**）。本脚本**不重复实现判据** ——
本仓库已因"判据分叉"踩过坑（旧的 `dump_mojibake.py` 自带一份 v1 判据，
召回只有 0.26）。

## 豁免（**白名单必须显式**，不能靠"跳过某些目录"）

    docs/迁移核验-2026-09-20.md   —— 修复前后对照的**证据引用**

这处的乱码是**故意保留的历史证据**，改写它等于篡改记录。
豁免是**按路径白名单**，且豁免文件里的坏行数会照常打印，
**不会被静默吞掉** —— 若白名单外的文件出现坏行，门禁立即失败。

⚠️ **豁免必须随事实收缩**。本文件曾豁免 `docs/CONTINUATION_PLAN.md`
（因为该计划文档 §2.3 曾引用一段示意乱码）；Q1 写完后 §2.3 改为
"求解而非人工判读"，示意乱码被删除 —— 该豁免随即**失去事实依据**。
经复测其坏行数已为 **0**，故**删除该条豁免**。留着它等于给计划文档
开一个**永久的、无人会再检查的**后门（豁免过宽本身是一种失败模式，
见 `--selftest` 的第 4 项）。

用法:
    python tools/mojibake_check.py            # 扫全库
    python tools/mojibake_check.py --quiet    # 只出结论
    python tools/mojibake_check.py --selftest # 负向自检（注入坏行必须被抓住）
"""
import argparse
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, 'tools'))
import mojibake as M  # noqa: E402

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

EXEMPT = {
    'docs/迁移核验-2026-09-20.md': '证据引用（修复前后对照）',
}

EXT = {'.c', '.h', '.md', '.py', '.ps1', '.json', '.txt', '.s',
       '.asm', '.yml', '.yaml', '.def'}
EXD = {'.git', 'dist', 'archive', 'build', 'node_modules', '.vs', '.vscode'}


def walk_repo():
    for root, dirs, files in os.walk(REPO):
        dirs[:] = [d for d in dirs if d not in EXD]
        for f in files:
            if os.path.splitext(f)[1].lower() not in EXT:
                continue
            rel = os.path.relpath(os.path.join(root, f), REPO).replace('\\', '/')
            yield rel


def _cp(ch):
    """码点表示 —— 报告里一律写码点，不写字形。"""
    return 'U+%04X' % ord(ch)


_FREQ_CACHE = None


def _blind_freqs():
    """重算盲区配对表的校准依据 (freq_img, freq_cand)。

    freq_img[ch]  = 该字符在全库的出现次数
    freq_cand[ch] = 该字符出现在"硬验证候选行"上的次数，候选行定义:
                    `damage(restored_text(line)) == line`
                    （即该行**既能**解释成损坏、**也能**解释成巧合往返）

    采纳条件 `freq_img == freq_cand` 的含义是: **从未观察到合法用法**。
    """
    global _FREQ_CACHE
    if _FREQ_CACHE is not None:
        return _FREQ_CACHE
    freq_img, freq_cand = {}, {}
    watch = set(M._BLIND) | set(M._BLIND.values())
    for rel in walk_repo():
        try:
            with open(os.path.join(REPO, rel), encoding='utf-8') as f:
                text = f.read()
        except (UnicodeDecodeError, OSError):
            continue
        for line in text.replace('\r\n', '\n').split('\n'):
            if not M.NONASCII.search(line):
                continue
            hit = [c for c in line if c in watch]
            if not hit:
                continue
            for c in hit:
                freq_img[c] = freq_img.get(c, 0) + 1
            if M.damage(M.restored_text(line)) == line:
                for c in hit:
                    freq_cand[c] = freq_cand.get(c, 0) + 1
    _FREQ_CACHE = (freq_img, freq_cand)
    return _FREQ_CACHE


def scan():
    """返回 (违规, 已豁免)。违规元素 = (rel, 行号, 原文)。"""
    bad, exempt = [], []
    for rel in walk_repo():
        try:
            with open(os.path.join(REPO, rel), encoding='utf-8') as f:
                text = f.read()
        except (UnicodeDecodeError, OSError):
            continue
        hits = []
        for i, l in enumerate(text.replace('\r\n', '\n').split('\n'), 1):
            if M.is_bad(l):
                hits.append((rel, i, l))
        if not hits:
            continue
        if rel in EXEMPT:
            exempt += hits
        else:
            bad += hits
    return bad, exempt


def selftest(quiet=False):
    """负向自检: 注入的坏行必须被抓住，且**豁免机制本身**必须生效。

    返回 fails 列表; 每项自检**必须能够失败**（写死 4 项的旧写法在豁免收缩后
    分母就不再属实 —— 自检项数本身也必须随代码变化, 不能是魔法数字）。
    """
    fails = []
    n = 0

    def check(cond, msg):
        nonlocal n
        n += 1
        if not cond:
            fails.append(msg)

    # ① 判据层: 已知损坏行必须被判坏（用真实编解码器现算，不留乱码字面量）
    good = '    /* 反射式 CRC32 查找表 (poly 0xEDB88320) */'
    check(M.is_bad(M.damage(good)),
          '判据漏判: damage() 产出的坏行未被告警')

    # ② 门禁层: 在内存里模拟"白名单外文件出现坏行" -> 必须进 bad
    check(not [h for h in [('__selftest__.c', 1, M.damage(good))]
               if h[0] in EXEMPT],
          '门禁漏判: 白名单外文件的坏行未被计入违规')

    # ③ 豁免层: **用真实扫描数据**验证路由，而不是自造一个必然成立的列表。
    # （前身写法是 `hits2 = [(rel2, 1, ...)]` 再断言 rel2 in EXEMPT —— 那是
    #  同义反复，无论 scan() 怎么写都会通过。这里改为跑真 scan()。）
    check(bool(EXEMPT),
          '豁免空: EXEMPT 为空, 无法验证豁免层（且 §2.3 证据引用会被误报）')
    if EXEMPT:
        real_bad, real_exempt = scan()
        # ③a 白名单内的坏行**不得**出现在违规里（否则豁免根本没生效）
        leaked = [h for h in real_bad if h[0] in EXEMPT]
        check(not leaked,
              '豁免失效: 白名单内 %d 行被计入违规 (%s)'
              % (len(leaked), leaked[0][0] if leaked else '?'))
        # ③b 白名单路径必须真实存在且确实被扫到 —— 指向已删除/改名文件的
        #     豁免是"僵尸豁免"，它悄悄放宽了门禁而没人会再检查
        present = set(walk_repo())
        for rel in EXEMPT:
            check(rel in present, '僵尸豁免: %s 不存在或未被扫描' % rel)
        # ③c 豁免文件里的坏行必须**照常被收集**（不是静默丢弃）
        check(bool(real_exempt),
              '豁免空转: EXEMPT 中没有任何文件含坏行 —— '
              '豁免已失去事实依据，应删除该条（豁免过宽）')

    # ④ 干净行不得误报
    check(not M.is_bad(good), '假阳性: 正确的中文行被判坏')

    # ⑤ 盲区层（v5）: 配对表必须非空，且每个"像"确实是对应"原"的损坏像。
    #    （`mojibake.py` 导入时已有同款断言，这里再验一次是为了让**门禁**
    #     也覆盖"表被改坏"这条路 —— 门禁不能依赖被检查对象的自证。）
    check(bool(M._BLIND), '盲区表空: v5 的单字符盲区兜底已失效')
    for img, org in M._BLIND.items():
        check(M.damage(org) == img,
              '盲区表错: damage(%s)=%s != %s' % (_cp(org), _cp(M.damage(org)), _cp(img)))
    #   坏掉的盲区字符必须被判据抓住（这是 v5 相对 v4 补上的**唯一**召回）
    for org in M._BLIND.values():
        check(M.is_bad(M.damage(org)),
              '盲区漏判: %s 的损坏形态未被 is_bad 抓住' % _cp(org))

    # ⑥ 盲区配对表**必须仍然成立**（语料校准的自我复核）。
    #    采纳条件是 freq_img == freq_cand: 像字符的每一次出现都落在"硬验证候选行"
    #    上，即**从未观察到合法用法**。若日后有人在正文里正常写出该字（例如
    #    在某处合法地用了 U+6402），这条就失去依据，门禁必须报错并要求重算 ——
    #    否则白名单会悄悄变成一个越用越松的后门。
    freq_img, freq_cand = _blind_freqs()
    for img, org in M._BLIND.items():
        check(freq_img.get(img, 0) == freq_cand.get(img, 0),
              '盲区校准失效: %s 出现 %d 次但有 %d 次不在候选行上 —— '
              '该字已存在合法用法, 必须从 _BLIND_PAIRS_SRC 撤销 %s->%s'
              % (_cp(img), freq_img.get(img, 0),
                 freq_img.get(img, 0) - freq_cand.get(img, 0), _cp(img), _cp(org)))
        check(freq_img.get(org, 0) >= 5,
              '盲区校准失效: 还原目标 %s 在该语料只出现 %d 次 (<5), 依据不足'
              % (_cp(org), freq_img.get(org, 0)))

    # ⑦ 被**拒绝**的配对不得被偷偷采纳: `实施` 是 `ʵʩ` 假阳性现场（`实` 有
    #    3856 次合法用法），它必须判为正常，且修复器不得动它。
    for clean in ('- [ ] S2-S5 实施', '### 18.3 实施'):
        check(not M.is_bad(clean), '假阳性: 含该字的正常行被判坏 (%s)' % clean)
        check(M.fix_line(clean)[0] == clean,
              '误改: 修复器改动了正常行 (%s)' % clean)

    if not quiet:
        for f in fails:
            print('  [FAIL] %s' % f)
        print('  selftest: %d/%d 通过' % (n - len(fails), n))
    return fails


def main():
    ap = argparse.ArgumentParser(prog='mojibake_check.py')
    ap.add_argument('--quiet', action='store_true')
    ap.add_argument('--selftest', action='store_true', help='只跑负向自检')
    a = ap.parse_args()

    fails = selftest(quiet=a.quiet)
    if a.selftest:
        return 0 if not fails else 1

    bad, exempt = scan()
    if not a.quiet:
        for rel, i, line in bad[:40]:
            print('  [X] %s:%d  %s' % (rel, i, line.strip()[:88]))
        if len(bad) > 40:
            print('  ... 其余 %d 条省略' % (len(bad) - 40))
        for rel in sorted(EXEMPT):
            n = sum(1 for e in exempt if e[0] == rel)
            print('  [豁免] %s  坏行 %d  (%s)' % (rel, n, EXEMPT[rel]))
        print('  [mojibake] 扫描 %d 文件，白名单外坏行 %d，豁免 %d'
              % (len(list(walk_repo())), len(bad), len(exempt)))

    ok = (not fails) and (not bad)
    if not a.quiet:
        if ok:
            print('[mojibake_check] PASS: 白名单外无 mojibake（豁免 %d 行，均显式登记）'
                  % len(exempt))
        else:
            print('[mojibake_check] FAIL: 白名单外 %d 行 mojibake，判据自检 %d 项失败'
                  % (len(bad), len(fails)))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
