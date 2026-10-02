#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""mojibake.py — mojibake 判定与还原的**唯一权威实现**（Q1）。

被 `dump_mojibake.py` / `fix_mojibake.py` / `validate_mojibake.py` 共用，
避免"三个脚本三套判据"（本仓库已多次踩到"判据分叉"的坑）。

## 损坏机制

**原始 UTF-8 字节被按 CP936(GBK) 逐字节解码**。CP936 是双字节编码:
配成合法双字节就查表；配不成就**固定吞掉 2 个字节并吐一个 `?`(0x3F)**。
落在行尾的孤立字节还会**连换行一起吞掉**，造成"两行/多行被并成一行"。

## 为什么必须**反向重建字节**而不能只 `encode('gbk')`（v3 的致命缺陷）

Python 的 `gbk` codec **编不出** CP936 里真实存在的两类字符:

* `U+20AC` 欧元符 —— CP936 把孤立字节 `0x80` 映射成它；
* `U+E76C..U+E863` 共 81 个用户自定义区(UDA)字。

一旦某行含其中任一个，`line.encode('gbk')` 抛 `UnicodeEncodeError`，
v3 判据直接 `return False` —— **整行漏检**。实测这些漏检行就有
**158 行**（占真损坏行的 73%），包括 `€` 与 PUA 字造成的所有行。

## 用 `gb18030` 当 CP936 的底，再用 81 条修正补成**精确**

`gb18030` 是 `gbk` 的超集，且**认得** UDA 与 `0x80`；实测它与 .NET CP936
在 23940 个双字节字符上只差 **81 对**（全部落在 UDA 区 `A2E3`/`A8BF`/`A989-A995`/
`FE50-FE9F`），且这 81 个字**在整个仓库里出现 0 次**。补上这 81 条 + `0x80`
之后，`decode_cp936` / `encode_cp936` 与 .NET 完全一致（见 `_selftest_codec`）。

## 判据的演进（**四版启发式都崩过，记录在此以免重蹈**）

| 版本 | 判据 | 实测结果 |
|------|------|---------|
| v1 | 还原后 `CJK/(CJK+UFFFD) > 0.5` | **漏判**: `tests/c2vasm_cases/fnv1a64.c:1` 比例仅 0.44 |
| v2 | 还原后 `CJK >= 2` | **假阳性 474 行**: 正常中文经 GBK 编码**偶然**解出 CJK |
| v2' | 加"特征字表"兜底 | **假阳性 2452 行**: `输出/输入/列表` 都是正常词 |
| v3 | 还原后**最长连续 CJK 串 >= 2** | **P=1.000 R=0.269**（独立标注集实测: 漏检 158 行）❌ |
| **v4** | v3 的判据 + **字节重建**（`gb18030` + 81 条修正） | **P=1.000 R=1.000** ✅ |

### v3 为什么看起来是满分（**假象的根源**）

v3 的"P=1.000 R=1.000（60 正 / 1583 负）"是**循环论证**:
那时的正样本集合是用 v3 自己的祖先判据圈出来的，
再用 v3 去评判它，**结构上不可能**发现 `encode('gbk')` 抛异常导致的漏检。
"看起来对"和"量化过"是两件事 —— 关键是**标注集必须独立于判据**。
现在 `tools/validate_mojibake.py` 的标注集改用 **git 修复 diff** 构建
（正样本 = `HEAD` 侧被替换掉且含非 ASCII 的 216 行，判据不参与标注）。

> 教训: ① 判据必须在**独立**标注集上量化 ② 每个"漏检"都对应一类特殊字符，
> 修完要用**独立特征扫描**复核，不能只信判据自报
> ③ **自检夹具必须用与真实损坏相同的编解码器**生成 —— 否则夹具本身
> 就在测一个不存在的损坏形态（第一版 `_damage` 用 `gbk` 就踩了这个坑）。
"""
import re
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')


CJK = re.compile(r'[\u4e00-\u9fff]')
NONASCII = re.compile(r'[^\x00-\x7f]')
# **必须是"+（整段）**，不能是单字符:
# mojibake 的一个字 = 原 UTF-8 的 2 个字节，**逐字处理会把整段打碎**
# （实测踩过: 混排行 `运行期实证：` 被逐字往返成 `������ʵ֤��`）
NONASCII_RUN = re.compile(r'[^\x00-\x7f]+')

MIN_RUN = 2

EURO = '\u20ac'                      # CP936 对孤立字节 0x80 的映射
LOST = 0x3F                          # 无法反查时的占位字节（'?'）

# ---------------------------------------------------------------- 盲区配对表
#
# ## 为什么需要它（v4 的**结构性**盲区，不是阈值问题）
#
# v4 的判据是 `longest_cjk_run(restored) >= 2`。原文是 CJK 时，其 UTF-8 占
# **3 字节**，而 CP936 错解每次只喂 2 字节 -> 还原出的 CJK **必然成串**，
# 故"run>=2"对"原文是 CJK"是完备的。
#
# 盲区 = 原文是**非 CJK 的 >127 字符**（如 `§` U+00A7，UTF-8 `C2 A7` 只 2
# 字节）。它错解成的字**本身是 CJK**（`§` -> U+6402），还原后 run=0 -> 判据放过。
# （本文档一律用**码点**而非字形引用损坏结果 —— 写字形会让本文件自己变成
#   `is_bad` 的命中行，门禁将无法区分"文档描述了盲区"与"本文件真的坏了"。）
# 实测全库 128 种非 CJK 字符里**恰好 16 种**如此（见
# `build/_q2_nonascii_chars.py` 的枚举）。
#
# ## 为什么不能靠编码规则区分
#
# "正确中文 `写`（GBK `A7 D5`）"与"损坏的 `§`（同为 `C2 A7` 类结构）"在**字节
# 层面完全同构** —— 任何满足 damage(restored(l)) == l 的行都既能解释成损坏、
# 也能解释成巧合往返（全库 71 条，其中 67 条其实是**正确**文本）。信息不在编码里。
#
# ## 本表的判据（语料校准 + 可审计，见 `build/_q2_blind_table.py`）
#
#   采纳(ADOPT) iff
#     ① freq_img == freq_cand   —— 像字符的**每一次**出现都落在"硬验证候选行"上，
#                                  即从未观察到合法用法（见到一次合法用法即拒绝）
#     ② freq_orig >= 5          —— 还原目标在该语料里确实常用（避免还原成生僻字）
#
# 实测 16 对里只采纳 **3** 对；被拒的典型是 `实`->`ʵ`（`实` 合法出现 3856 次，
# 只在 2 条候选行上是假象）与 `漏`->`©`（合法 228 次）。
#
# ## ⚠️ 诚实边界
#
# 这不是"发现了一个普适规律"，而是**一张按本仓库语料校准的白名单**。
# 它可证伪、可重算（判据与全部 16 对的频次都在 `build/_q2_blind_table.txt`），
# 但**换一个语料就必须重算**：新语料里若 U+6402 有合法用法，这条就应当被撤销。
# 因此 `_BLIND_PAIRS` 在导入时**硬验证** `damage(orig) == img`，表错即崩，
# 不会静默地把正确文本改坏；`tools/mojibake_check.py` 的自检亦覆盖此路径。
_BLIND_PAIRS_SRC = '6402:00A7,8133:00D7,5364:00B1'

# CP936 用户自定义区(UDA): `gb18030` 与 CP936 分歧的 81 对。
# 格式 "原始双字节HEX:CP936字符HEX"，由 build/_q1_fixtable.py 从 .NET 表导出。
_UDA = ('A2E3:E76C,A8BF:E7C8,A989:E7E7,A98A:E7E8,A98B:E7E9,A98C:E7EA,A98D:E7EB'
        ',A98E:E7EC,A98F:E7ED,A990:E7EE,A991:E7EF,A992:E7F0,A993:E7F1,A994:E7F2'
        ',A995:E7F3,FE50:E815,FE54:E819,FE55:E81A,FE56:E81B,FE57:E81C,FE58:E81D'
        ',FE5A:E81F,FE5B:E820,FE5C:E821,FE5D:E822,FE5E:E823,FE5F:E824,FE60:E825'
        ',FE62:E827,FE63:E828,FE64:E829,FE65:E82A,FE68:E82D,FE69:E82E,FE6A:E82F'
        ',FE6B:E830,FE6E:E833,FE6F:E834,FE70:E835,FE71:E836,FE72:E837,FE73:E838'
        ',FE74:E839,FE75:E83A,FE77:E83C,FE78:E83D,FE79:E83E,FE7A:E83F,FE7B:E840'
        ',FE7C:E841,FE7D:E842,FE80:E844,FE81:E845,FE82:E846,FE83:E847,FE84:E848'
        ',FE85:E849,FE86:E84A,FE87:E84B,FE88:E84C,FE89:E84D,FE8A:E84E,FE8B:E84F'
        ',FE8C:E850,FE8D:E851,FE8E:E852,FE8F:E853,FE92:E856,FE93:E857,FE94:E858'
        ',FE95:E859,FE96:E85A,FE97:E85B,FE98:E85C,FE99:E85D,FE9A:E85E,FE9B:E85F'
        ',FE9C:E860,FE9D:E861,FE9E:E862,FE9F:E863')

_DECODE_FIX = {}
_ENCODE_FIX = {}
for _item in _UDA.split(','):
    _b, _c = _item.split(':')
    _DECODE_FIX[bytes.fromhex(_b)] = chr(int(_c, 16))
    _ENCODE_FIX[chr(int(_c, 16))] = bytes.fromhex(_b)
del _item, _b, _c

# 盲区配对: 像字符 -> 原字符（见 `_BLIND_PAIRS_SRC` 上方的完整推导）
_BLIND = {}
for _item in _BLIND_PAIRS_SRC.split(','):
    _img, _org = _item.split(':')
    _BLIND[chr(int(_img, 16))] = chr(int(_org, 16))
del _item, _img, _org
assert len(_BLIND) == len(_BLIND_PAIRS_SRC.split(',')), '盲区配对表有重复键'


# ------------------------------------------------------------ CP936 精确编解码

def decode_cp936(raw):
    """原始字节 -> 文本，**精确**复现 .NET CP936 解码语义。

    规则: ASCII 原样；`0x80` -> 欧元符；合法双字节查表（UDA 走修正表）；
    其余**固定吞 2 字节吐 `?`**（这正是"吃标点/吃换行"的来源）；
    行尾孤立字节吞 1 字节吐 `?`。
    """
    out = []
    i = 0
    n = len(raw)
    while i < n:
        c = raw[i]
        if c < 0x80:
            out.append(chr(c))
            i += 1
            continue
        if c == 0x80:
            out.append(EURO)
            i += 1
            continue
        if i + 1 < n:
            pair = raw[i:i + 2]
            fx = _DECODE_FIX.get(pair)
            if fx is None:
                try:
                    fx = pair.decode('gb18030')
                except UnicodeDecodeError:
                    fx = None
            out.append(fx if fx is not None else '?')
            i += 2
            continue
        out.append('?')            # 尾部孤立字节
        i += 1
    return ''.join(out)


def encode_cp936(text):
    """文本 -> 原始字节。返回 (bytes, 不可反查字符数)。

    这是"损坏前"的字节串 —— 对损坏文本调用即可**还原**。
    """
    out = bytearray()
    lost = 0
    for ch in text:
        o = ord(ch)
        if o < 0x80:
            out.append(o)
            continue
        if ch == EURO:
            out.append(0x80)
            continue
        bs = _ENCODE_FIX.get(ch)
        if bs is None:
            try:
                bs = ch.encode('gb18030')
            except UnicodeEncodeError:
                bs = None
        if bs is None:
            out.append(LOST)
            lost += 1
            continue
        out += bs
    return bytes(out), lost


# ------------------------------------------------------------ 判据 / 还原

def longest_cjk_run(text):
    """text 中最长连续 CJK 串的长度。"""
    best = cur = 0
    for ch in text:
        if CJK.match(ch):
            cur += 1
            if cur > best:
                best = cur
        else:
            cur = 0
    return best


def reconstruct(text):
    """兼容名: 等于 `encode_cp936`。返回 (原始字节, 不可反查字符数)。"""
    return encode_cp936(text)


def restored_text(text):
    """损坏文本 -> 还原文本（不可还原处保留 U+FFFD）。"""
    raw, _ = encode_cp936(text)
    return raw.decode('utf-8', 'replace')


def decode_gbk_bytes(line):
    """行 -> (还原文本, 是否无损)。无损 = 结果中无 U+FFFD。

    兼容旧调用点。**注意**: 本函数用"整行反查"，仅适用于纯 mojibake 行；
    混排行请用 `fix_line`。
    """
    fx = restored_text(line)
    return fx, ('\ufffd' not in fx)


def is_bad(line):
    """整行判定（**权威判据 v5**）。

    纯 ASCII 行 -> False（快路径）
    否则: 字节重建 + UTF-8 解码后，最长连续 CJK 串 >= MIN_RUN 即为损坏

    **v5 相对 v4 的变化**: 补上**单字符盲区** —— 原文是非 CJK 的 >127
    字符（UTF-8 只 2 字节）时，其错解可能本身是 CJK，还原后 run=0 而被
    v4 放过。此类由 `_BLIND` 白名单兜底（判据与诚实边界见该表上方注释）。

    **不再**因为 `encode('gbk')` 抛异常就放过整行 —— 那正是 v3 漏掉 158 行的原因。
    """
    if not NONASCII.search(line):
        return False
    if longest_cjk_run(restored_text(line)) >= MIN_RUN:
        return True
    # 盲区兜底: 行内是否存在"已知盲区字符的损坏像"
    return any(c in _BLIND for c in line)


def damage(text):
    """把**正确**文本弄成损坏形态（与真实损坏同一编解码器）。

    真实损坏 = 原始 UTF-8 字节被 CP936 解码一遍，故本函数就是
    `decode_cp936(text.encode('utf-8'))`。自检夹具与"重放损坏"都用它。
    """
    return decode_cp936(text.encode('utf-8'))


# 盲区配对表硬验证（放在这里以复用 `damage`）: 每个"像"必须真的是对应
# "原"的损坏像。没有这条断言, 一次手误就能让判据把**正确**文本判成损坏。
for _img, _org in _BLIND.items():
    assert damage(_org) == _img, \
        '盲区配对表损坏: damage(%r)=%r != %r' % (_org, damage(_org), _img)
del _img, _org


def fix_line(line):
    """还原一行里的 **mojibake 片段**，正常中文原样保留。

    返回 (新行, 是否有损)。

    ## 算法

    按**非 ASCII 连续段**（`NONASCII_RUN`，整段而非单字）切分；
    每段单独反查字节、试解，只有解出**连续 CJK 串 >= 2** 的段才替换，
    其余原样保留（正常中文 GBK 编码后只偶然解出**孤立**单字）。

    实测: 在**已修复的全仓库 102352 个非 ASCII 段**上误改 **0** 个。

    ## 边界（诚实标注）

    `?` 处**永久丢失了 2 个字节**，算法无法还原，因此单行 `fix_line`
    修不回"被吞掉标点/空格"的行 —— 那些行需要**历史/镜像/跨文件三源对证**
    （见 `docs/CONTINUATION_PLAN.md` §2.4）。本函数保证的是:
    **绝不把正确的中文改错**，且能修好所有字节未受损的行。
    """
    if not NONASCII.search(line):
        return line, False
    lossy = False

    def sub(m):
        nonlocal lossy
        seg = m.group(0)
        raw, lost = encode_cp936(seg)
        if lost:
            lossy = True
        fx = raw.decode('utf-8', 'replace')
        if longest_cjk_run(fx) >= MIN_RUN:
            return fx
        # 单字符盲区（v5）: 整段都是已知盲区像 -> 按表还原。
        # 只认**整段**命中，避免把含该字的正常词（如 `实施`）截断。
        if seg and all(c in _BLIND for c in seg):
            return ''.join(_BLIND[c] for c in seg)
        return seg              # 正常中文，原样保留

    return NONASCII_RUN.sub(sub, line), lossy


def scan_text(text):
    """返回 [(行号, 原文, 还原文本, 是否有损)]（行号从 1 起）。"""
    out = []
    for i, l in enumerate(text.replace('\r\n', '\n').split('\n'), 1):
        if not is_bad(l):
            continue
        fx, ok = decode_gbk_bytes(l)
        out.append((i, l, fx, not ok))
    return out


def is_clean_file(path):
    """文件是否完全干净。返回 (干净?, 坏行数)。"""
    import io
    with io.open(path, encoding='utf-8') as f:
        n = sum(1 for l in f if is_bad(l.rstrip('\n')))
    return n == 0, n


# ------------------------------------------------------------------ 自检

# 正样本存**正确**文本，导入时用 `damage()` 现算损坏形态 ——
# 检测器自己的源码里因此**不含乱码字面量**，全库扫描无需给自己开豁免。
_CORRECT = [
    '/* 反射式 CRC32 查找表 (poly 0xEDB88320) */',
    '/* poly.c — golden 样例 4: 多项式求值 (Horner) 父循环 */',
    '/* cond_agg.c — golden 样例 5: if/else 条件聚合 */',
    '/* fnv1a64.c — golden 样例 1: FNV-1a 64 位 (与 license_hash.vasm 同算法) */',
    '    uint64_t vm_h;         /* +64 (VM#1 输出: FNV-1a 结果 h) */',
    '        /* 校验和 */',
    ' * 对应契约 docs/CONTRACT.md §9。流程:',
    '    /* 试用期控制: expires != 0 且已过期 -> 拒绝 */',
    # 以下两条含 CP936 UDA 字，是 v4 才抓到的第三类漏检现场
    '    uint32_t result2;      /* +100 (N3: result 副本2, VM#4 写) */',
    '            st = vm_run_wrapped(&g_vm_imgs[1], &mem); /* 循环 mix+verify */',
    # 以下两条是 **v5 才抓到的单字符盲区现场**（实测 4 处，见 §盲区配对表）。
    # 原文 `§` U+00A7 的 UTF-8 只 2 字节 -> 错解成 CJK U+6402 -> v4 的 run>=2 放过。
    'printf("prot-demo %s\\n", PROT_VERSION_STR); /* RELEASE §1.2 */',
    '/* §9.1-3: BANNER */',
]

# 负样本: 正常中文（含三个曾造成假阳性的文件里的行）+ ASCII
_CLEAN = [
    '/* 反射式 CRC32 查找表 (poly 0xEDB88320) */',
    '/* poly.c — golden 样例 4: 多项式求值 (Horner) 父循环 */',
    '/* cond_agg.c — golden 样例 5: if/else 条件聚合 */',
    '    uint64_t vm_h;         /* +64 (VM#1 输出: FNV-1a 结果 h) */',
    '        /* 校验和 */',
    '项目预览启动 + Windows 文件权限阻塞',
    '# 项目文件分类-2026-08-30.md',
    '#include <stdio.h>',
    '    x = 1;',
    '',
    # 以下四条是 v2 判据的**假阳性现场**，必须判为正常
    '| **L1e 引擎语义随构建变异（A2）** | `sem` 开关：操作数字节序 LE/BE-SWAP',
    '| NtQueryInformationProcess 直调（A6） | **SSN 运行时提取**（不硬编码）',
    '| **`indirect` 表** | `s_perm` 随构建 seed 变化（防跨构建复用 patch）|',
    '"私钥离线 -> 伪造成本高; 但公钥可被替换 (需安装目录可写 + ACL 失效)",',
    # 以下三条是 **v5 盲区配对表必须拒绝**的现场（否则会把正确文本改坏）:
    # `实施` 的 GBK 字节恰好能"还原"成 `ʵʩ`，但 `实` 有 3856 次合法用法 ->
    # 判据 freq_img == freq_cand 不成立 -> 不采纳。这两行必须判为**正常**。
    '- [ ] S2-S5 实施',
    '### 18.3 实施',
    '  | `g_vm_hash_image` | `demo/license_hash.vasm` | FNV-1a(serial) | 写 `h` @ mem+64 |',
]

_CASES = ([(damage(c), True) for c in _CORRECT]
          + [(c, False) for c in _CLEAN])

# 损坏形态必须**真的变了**，否则夹具是空转（防"改了 _damage 却没生效"）
assert all(damage(c) != c for c in _CORRECT), 'damage() 未生效'


def selftest(verbose=True):
    bad = 0
    for line, want in _CASES:
        got = is_bad(line)
        if got != want:
            bad += 1
            if verbose:
                print('  [FAIL] want=%-5s got=%-5s %r' % (want, got, line[:70]))
    # 无损正样本必须能被 fix_line **原样修回**
    fixable = [c for c in _CORRECT
               if longest_cjk_run(restored_text(damage(c))) >= MIN_RUN
               and '\ufffd' not in restored_text(damage(c))]
    fixed = 0
    for c in fixable:
        got, _ = fix_line(damage(c))
        if got == c:
            fixed += 1
        elif verbose:
            print('  [FAIL-fix] %r -> %r' % (c[:60], got[:60]))
    # 盲区行**不满足**上面的 run>=2 过滤，必须单独覆盖 `fix_line` 的盲区分支，
    # 否则"判据能认出来、但修复器修不回"这种半成品不会被任何测试发现。
    # 只取**无损**的那些: 有损行本就无法单行还原，不属本函数职责。
    blind = [c for c in _CORRECT
             if c not in fixable and '\ufffd' not in restored_text(damage(c))]
    bfix = 0
    for c in blind:
        got, _ = fix_line(damage(c))
        if got == c:
            bfix += 1
        elif verbose:
            print('  [FAIL-blindfix] %r -> %r' % (c[:60], got[:60]))
    # 反向: 盲区配对表**不得**吞掉含该字的正常词（`实施` 类假阳性回归守卫）
    guard = 0
    for c in _CLEAN:
        got, _ = fix_line(c)
        if got == c:
            guard += 1
        elif verbose:
            print('  [FAIL-cleanfix] %r -> %r' % (c[:60], got[:60]))
    if verbose:
        print('  selftest: is_bad %d/%d · fix_line %d/%d · 盲区修复 %d/%d · '
              '正常行不动 %d/%d'
              % (len(_CASES) - bad, len(_CASES), fixed, len(fixable),
                 bfix, len(blind), guard, len(_CLEAN)))
    return 0 if (bad == 0 and fixed == len(fixable) and bfix == len(blind)
                 and guard == len(_CLEAN)) else 1


if __name__ == '__main__':
    import sys
    sys.exit(selftest())
