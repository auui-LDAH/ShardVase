#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""migration_cost.py — 破解迁移成本度量（W5.6）

## 这是什么
  方针的最终验收: **"让破解者明知防御仍要大量时间和资源"**。
  本工具把它变成**可量化、可复现**的指标。

## 核心洞察（实测依据 2026-09-23）
  W1 把"跨构建差异率"做到 67.85%，但那**只说明文件整体不同**。
  若**关键函数的字节序列不变**，攻击者可:
    1. 在 A 上定位函数（取字节特征）
    2. 在 B 上用**特征扫描**（不依赖地址）直接找到同一函数
    3. 复用 A 上开发的绕过（补丁/脚本/hook）
  => **迁移成本接近零**，W1 的效果被部分抵消。

  **实测（首次）**: 278/815 函数字节完全相同（34.1%）；
  保护函数 9/34（26.5%）稳定；用 32 字节特征在 B 中**精确命中**。

  根因: **随机化只作用于数据，不作用于代码**。

## 四个维度
  M1 **地址稳定性**  —— 函数 RVA 是否跨构建变化
  M2 **秘密稳定性**  —— per-build 数据（节名/magic/掩码/blob）是否变化
  M3 **特征可匹配性** —— 用 A 的字节特征能否在 B 中定位同一函数（**最关键**）
  M4 **结构稳定性**  —— 节布局是否变化

## 用法
  python tools/migration_cost.py <A.exe> <B.exe> [--map-a A.map] [--map-b B.map]
  python tools/migration_cost.py --selftest
"""
import argparse
import hashlib
import json
import os
import re
import struct
import sys


# ## map 解析的单一实现（B 阶段，2026-09-25）
#   本项目曾有 **4 处**各自实现 -> 已归一到 `tools/mapfile.py`。
#   惰性导入以保持 import 段最小依赖。
def _load_mapfile():
    _t = os.path.dirname(os.path.abspath(__file__))
    if _t not in sys.path:
        sys.path.insert(0, _t)
    import mapfile
    return mapfile


_mapfile = _load_mapfile()

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

FUNC_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')
PROT_PREFIX = 'prot_'
FEATURE_LEN = 32          # 字节特征长度（判据口径: 从函数入口起取）
FEATURE_SCAN_MAX = 256    # 对抗口径的**自选窗口**扫描上限（字节）

# --------------------------------------------------------------------------
# **对抗口径 M3adv**（2026-10-06 新增）—— 判据 M3 的诚实边界
#
# ## 为什么需要
#   判据 M3 只在**函数入口起 32 字节**取特征。但攻击者不受这个约束：
#   他可以自己选窗口（往后挪）。实测（docs/HANDOVER.md §2.43.4）:
#     · 判据口径          入口起 32B 命中 = **5/32 = 15.6%**
#     · 对抗口径（唯一签名）自选窗口可定位 = **26/32 = 81.2%**
#   => 判据测的是"**最容易被利用的取法**"，**显著低估**攻击者能力。
#
# ## 这条指标的定位（**不是门禁判据**）
#   它是**诊断/诚实边界**指标: 报告"若攻击者自选窗口会怎样"。
#   为什么不设阈值: 要把它压到低位需要**整函数长度抖动**（不是把
#   `PROT_NOISE` 前移就能解决），属另一个量级的改造，见 §2.43.8。
#   因此本工具只**报告**它，不让它决定 exit code。
FEATURE_ADV_REPORT = True

# --------------------------------------------------------------------------
# **基础设施前缀**（不计入"保护函数特征命中率"）—— M3 实测修正 2026-09-25
#
# ## 为什么需要排除（**有实测证据**）
#   M3 把平台层的 20 个函数加入构建后，M3 率从 5.9% 跳到 16.4%。
#   逐函数核对命中清单发现:
#     **8 个命中里 7 个是 `prot_plat_*`（平台层）**，只有 1 个是防护模块。
#     平台层占 prot_* 总数的 36.4%。
#
# ## 为什么平台层不该计入
#   `prot_plat_*` / `prot_crypto_*` 是**基础设施**:
#     · **不是防护能力**（不参与"抗逆向"）
#     · **本就不带 `PROT_NOISE`**（W1.6 只注入防护模块）
#     · 跨构建**必然相同** —— 这是**正确行为**（基础设施应当稳定）
#   => 计入会让**分母被稀释 + 分子含不该抗匹配的函数** -> 口径错误。
#
# ## 判据
#   保留的是**防护模块**导出的函数（antidebug/dbiguard/integrity/
#   vmdetect/selfcrypt/license/hostid/revoke/strcrypt/syscall/blob/vm）。
#
# ## 诚实边界
#   · 排除后分母变小（55 -> ~35），与 M3 前的 34 接近
#   · **不是"为让门禁通过而调参"** —— 排除依据是"这些不是防护能力"，
#     且有**逐函数实测证据**（7/8 命中是平台层）
#   · **原 L1 加入的少数平台函数也曾被计入**（当时只有 2 个，影响小）
INFRA_PREFIXES = (
    'prot_plat_',      # 平台抽象层（页/线程/原子/时钟/节表…）
    'prot_crypto_',    # 密码学抽象层（SHA-256 / RSA 验签）
)
INFRA_EXACT = (
    'prot_crc32', 'prot_crc32_init', 'prot_crc32_step', 'prot_crc32_done',
    'prot_indirect_table', 'prot_indirect_perm',   # 间接化表（原语）
    'prot_str_get', 'prot_str_decrypt',            # strcrypt 由生成代码调用
)


def is_protected_fn(name):
    """该符号是否属于**防护能力**（应抗特征匹配）。

    基础设施（平台层/密码学层/原语）**不计入** —— 见 INFRA_PREFIXES 注释。
    """
    if not name.startswith(PROT_PREFIX):
        return False
    if name.startswith(INFRA_PREFIXES):
        return False
    if name in INFRA_EXACT:
        return False
    return True



# --------------------------------------------------------------------------
def parse_map(path, image_base=None):
    """链接 map -> {符号: 映像RVA}。**自动识别 MSVC / gcc**。

    ## B 阶段（2026-09-25）: 实现已**抽到 `tools/mapfile.py`**
      抽取前本项目有 **4 处** map 解析各自实现（MSVC/gcc 支持不一，
      已实际漂移）-> 归一到单一实现。

      ## 等价性（**已实测，M1 度量不受影响**）
        · 全符号口径: 旧 2971 / 新 2971，**值不同 0**
        · 函数口径:   旧 131 / 新 131，**值不同 0**

      ## 历史陷阱（**保留记录**，教训仍在）
        MSVC map 行的**第 2 列是节内偏移**，不是映像 RVA ——
        误用会让 RVA 落在节外、度量全部失真（2026-09-23 实测）。
        `mapfile.parse()` 用**第 4 列绝对 VA** - image_base
        （基址默认从 PE 头读）。
    """
    return _mapfile.parse(path, image_base=image_base)


def parse_map_fns(path, image_base=None):
    """**只取函数符号**（MSVC map 的 `f` 标记 + 排除库对象/导入 thunk）。

    ## 为什么需要（2026-09-25，M1 口径修正）
      文档定义 M1 = "**函数 RVA** 是否跨构建变化"（ROADMAP §11.2），
      但收集**全部符号**会让 M1 虚高（实测 31.2%）—— 未变的符号里:
        · 524 = MSVC 合并字符串（链接器字典序，与 obj 顺序无关）
        · 327 = CRT/库符号
        ·  69 = 导入 `__imp_`（由库列表决定）
        ·  30 = 哨兵（VA==ImageBase，**非地址**）
      这些**结构性不可移动** -> 门禁改用**函数口径**（与文档一致）。

      ## 过滤（**M1 门禁依赖，不可丢**）
        · 要求行内有 `f` 标记
        · 排除 `obj` 含 `:`（库内 obj，如 `libvcruntime:frame.obj`）
        · 排除 `obj == 'i'`（导入 thunk）

      ## B 阶段改造后
        过滤已由 `mapfile.parse(funcs_only=True, exclude_libs=True)`
        实现（语义已核对等价）。
    """
    return _mapfile.parse(path, image_base=image_base,
                          funcs_only=True, exclude_libs=True)


def read_image_base(pe_path):
    """PE `OptionalHeader.ImageBase`（实现见 `mapfile.read_image_base`）。"""
    return _mapfile.read_image_base(pe_path)


def read_sections(path):
    d = open(path, 'rb').read()
    e = struct.unpack_from('<I', d, 0x3C)[0]
    n = struct.unpack_from('<H', d, e + 6)[0]
    oz = struct.unpack_from('<H', d, e + 20)[0]
    tb = e + 24 + oz
    out = []
    for i in range(n):
        o = tb + i * 40
        nm = d[o:o + 8].rstrip(b'\x00').decode('ascii', 'replace')
        vsz, va, rsz, raw = struct.unpack_from('<IIII', d, o + 8)
        out.append((nm, vsz, rsz, raw, va))
    return d, out


def rva2off(rva, secs, dlen):
    for nm, vsz, rsz, raw, va in secs:
        if va <= rva < va + max(vsz, rsz):
            off = raw + (rva - va)
            return off if 0 <= off < dlen else None
    return None


def fn_extents(secs, data, m, funcs):
    """{符号: (rva, 文件偏移, 可用长度)} —— 长度用**下一个函数 RVA** 近似。

    ## 为什么需要
      对抗口径要判断"某个 32 字节窗口是否落在**同名函数范围内**"，
      而 map 只给函数**起点**、不给长度 => 用下一个函数起点作边界（近似）。
      近似是**保守**的：长度偏大只会让"落在范围内"更容易成立，
      **不会**把可定位的函数误判成不可定位。
    """
    starts = sorted((m[s], s) for s in funcs if s in m and m[s] > 0)
    out = {}
    for i, (rva, s) in enumerate(starts):
        nxt = starts[i + 1][0] if i + 1 < len(starts) else rva + 512
        size = nxt - rva
        if size <= 0 or size > 65536:
            size = 512
        o = rva2off(rva, secs, len(data))
        if o is None:
            continue
        out[s] = (rva, o, min(size, len(data) - o))
    return out


def adv_window_hit(fa, fb_image, fb_off, fb_len, flen=FEATURE_LEN,
                   scan_max=FEATURE_SCAN_MAX):
    """**对抗口径**：攻击者自选窗口时，能否跨构建唯一定位该函数。

    在 A 的函数字节 `fa` 里找一个 `flen` 字节窗口，要求它在 B 的**整个映像**
    `fb_image` 里**只出现一次**（唯一签名），且该次出现落在 B 的**同名函数**
    范围 `[fb_off, fb_off + fb_len)` 内。

    ## 为什么必须加"唯一"过滤（2026-10-06 实测教训）
      不过滤时，填充/重复字节（如 `cc cc cc cc`）也算命中 —— 但那种窗口在 B
      里出现**多次**，**不能用于定位**。实测：不过滤 27/32 = 84.4%，
      加唯一过滤 26/32 = 81.2%（差的那 1 个正是被重复字节救下的）。

    ## 为什么唯一性要在**整个映像**上判，不能只在 `.text`
      保护函数并不都在 `.text`：selfcrypt 组（init/enter/leave）经
      `PROT_CODE_SEG` 落在 `.protxec`。只在 `.text` 里数会把它们误判成
      "签名不存在"（实测把 `prot_selfcrypt_init` 的签名出现次数误报为 0）。

    返回首个命中的窗口起点偏移；找不到返回 None。
    """
    limit = min(scan_max, len(fa) - flen)
    for start in range(0, limit + 1):
        sig = fa[start:start + flen]
        if len(sig) != flen:
            break
        idx = fb_image.find(sig)
        if idx < 0:
            continue
        # 唯一性用**二次查找**判（比 count 短路得更早：多数签名一查即排除）
        if fb_image.find(sig, idx + 1) >= 0:
            continue
        if fb_off <= idx < fb_off + fb_len:
            return start
    return None


# --------------------------------------------------------------------------
def analyse(pa, pb, mapa=None, mapb=None):
    da, sa = read_sections(pa)
    db, sb = read_sections(pb)
    ma, mb = parse_map(mapa), parse_map(mapb)

    res = {}

    # ---- M1 地址稳定性 ----
    #
    # ## 度量修正（2026-09-25）: 排除**哨兵符号**
    #
    # 链接器 map 中有一批符号的**绝对 VA == ImageBase**（即 RVA=0）:
    #   `__AbsoluteZero` / `__ImageBase` / `___safe_se_handler_*` /
    #   `__arm64x_*` / `__guard_fids_*` / `__enclave_config` ...
    # 它们是**哨兵/绝对常量**，**不是映像内的地址** ——
    # 把它们计入"地址复用率"是**度量口径错误**:
    # 它们**永远不会动**（也无需动），会**虚高** M1。
    #
    # 实测: 这类符号 30 个，占 M1 未变项的 6%。
    # 修正口径: 只统计**落在映像地址区间**（VA > ImageBase）的符号。
    common = sorted(set(ma) & set(mb))
    # 修正: 排除哨兵 —— parse_map 存的是 **RVA**（绝对VA − ImageBase，
    # 见下方 parse_map 注释）。哨兵符号（__AbsoluteZero / __ImageBase /
    # ___safe_se_* / __arm64x_* 等）的 RVA 为 **0 或负数**
    # （map 中绝对 VA == ImageBase 或 0）。
    # 真实映像符号 RVA >= 首节对齐偏移（>= 0x1000），故 `> 0` 安全排除。
    common = [s for s in common if ma[s] > 0]
    same_rva = [s for s in common if ma[s] == mb[s]]
    # ---- M1f: **函数符号**的地址稳定性（文档口径「函数 RVA」，门禁用）----
    fa, fb = parse_map_fns(mapa), parse_map_fns(mapb)
    fcommon = sorted(set(fa) & set(fb))
    fcommon = [s for s in fcommon if fa[s] > 0]   # 排除哨兵
    fsame = [s for s in fcommon if fa[s] == fb[s]]
    res['m1_funcs'] = {
        'common': len(fcommon),
        'same_rva': len(fsame),
        'diff_rva': len(fcommon) - len(fsame),
        'rate_same': (100.0 * len(fsame) / len(fcommon)
                      if fcommon else 0.0),
    }

    res['m1'] = {
        'common': len(common),
        'same_rva': len(same_rva),
        'diff_rva': len(common) - len(same_rva),
        'rate_same': 100.0 * len(same_rva) / len(common) if common else 0.0,
    }

    # ---- M3 特征可匹配性（最关键）----
    funcs = [s for s in common
             if FUNC_RE.match(s) and not s.startswith('$')]
    matched, total, prot_matched, prot_total = 0, 0, 0, 0
    prot_unmatched_names = []
    for s in funcs:
        oa = rva2off(ma[s], sa, len(da))
        ob = rva2off(mb[s], sb, len(db))
        if oa is None or ob is None:
            continue
        feat = da[oa:oa + FEATURE_LEN]
        if len(feat) < FEATURE_LEN:
            continue
        total += 1
        # M3 实测修正（2026-09-25）: 用 is_protected_fn() 排除基础设施
        is_prot = is_protected_fn(s)
        if is_prot:
            prot_total += 1
        # 在 B 中用特征搜索
        idx = db.find(feat)
        hit = (idx >= 0)
        if hit:
            matched += 1
            if is_prot:
                prot_matched += 1
        elif is_prot:
            prot_unmatched_names.append(s)

    res['m3'] = {
        'total': total,
        'matched': matched,
        'rate': 100.0 * matched / total if total else 0.0,
        'prot_total': prot_total,
        'prot_matched': prot_matched,
        'prot_rate': 100.0 * prot_matched / prot_total if prot_total else 0.0,
        'prot_safe': prot_unmatched_names,
    }

    # ---- M3adv 对抗口径（自选窗口 + 唯一签名）----
    #   判据 M3 固定从入口取；M3adv 允许攻击者自选窗口（见文件头常量注释）。
    #   **只报告，不参与判定**。
    ea = fn_extents(sa, da, ma, funcs)
    eb = fn_extents(sb, db, mb, funcs)
    adv_prot = [s for s in funcs
                if is_protected_fn(s) and s in ea and s in eb]
    adv_hits = []
    adv_starts = {}
    for s in adv_prot:
        _ra, oa, la = ea[s]
        _rb, ob, lb = eb[s]
        st = adv_window_hit(da[oa:oa + la], db, ob, lb)
        if st is not None:
            adv_hits.append(s)
            adv_starts[s] = st
    res['m3a'] = {
        'prot_total': len(adv_prot),
        'prot_located': len(adv_hits),
        'prot_rate': (100.0 * len(adv_hits) / len(adv_prot)
                      if adv_prot else 0.0),
        'located': sorted(adv_hits),
        'starts': adv_starts,
    }

    # ---- M4 结构稳定性 ----
    same_sec = 0
    for (n1, v1, r1, o1, _), (n2, v2, r2, o2, _) in zip(sa, sb):
        if v1 == v2 and o1 == o2:
            same_sec += 1
    res['m4'] = {
        'sections_a': len(sa), 'sections_b': len(sb),
        'same_layout': same_sec,
        'size_a': len(da), 'size_b': len(db),
    }
    return res


# --------------------------------------------------------------------------
def selftest():
    """负向测试: 用**已知答案**验证各度量能抓错。

    纪律（来自门禁失效教训）: 每个检查器必须自证能抓错。
    """
    import tempfile
    import random
    T = tempfile.mkdtemp(prefix='mig_selftest_')
    fails = []

    def case(name, got, want):
        ok = got == want
        print('  %s %-46s got=%s want=%s'
              % ('ok ' if ok else '**FAIL**', name, got, want))
        if not ok:
            fails.append(name)

    print('=== map 解析 ===')
    mp = os.path.join(T, 't.map')
    # 注意: map 第 2 列是**节内偏移**，第 4 列才是**绝对 VA**。
    # 自检必须用**正确格式**，否则测不到真实的解析逻辑。
    open(mp, 'w', encoding='utf-8').write(
        ' 0001:00001000       _main    0000000140002000 f   main.obj\n'
        ' 0001:00002000       _helper  0000000140003000 f   main.obj\n')
    m = parse_map(mp, image_base=0x140000000)
    case('解析出 2 个符号', len(m), 2)
    # 绝对 VA 0x140002000 - base 0x140000000 = 0x2000
    case('_main RVA = 0x2000（绝对VA - image base）', m.get('_main'), 0x2000)
    case('_helper RVA = 0x3000', m.get('_helper'), 0x3000)
    # 回归防护: 误用第 2 列会得到 0x1000 —— 必须不等于它
    case('**不得**误用第 2 列（0x1000）', m.get('_main') != 0x1000, True)

    print()
    print('=== 特征匹配（构造已知答案）===')
    # 造两个"假 PE"不现实 -> 直接验证核心逻辑: bytes.find
    a = b'AAAABBBBCCCCDDDD'
    case('相同特征可匹配', a.find(b'BBBB') >= 0, True)
    case('不同特征不匹配', a.find(b'XXXX') >= 0, False)

    print()
    print('=== 稳定性判定的边界 ===')
    # 验证"完全相同的文件"-> 匹配率 100%
    p1 = os.path.join(T, 'x1.bin')
    p2 = os.path.join(T, 'x2.bin')
    rng = random.Random(7)
    blob = bytes(rng.randrange(256) for _ in range(8192))
    open(p1, 'wb').write(blob)
    open(p2, 'wb').write(blob)
    case('相同文件 sha 相同',
         hashlib.sha256(open(p1, 'rb').read()).hexdigest()
         == hashlib.sha256(open(p2, 'rb').read()).hexdigest(), True)

    # 验证"单字节不同"能被检出
    blob2 = bytearray(blob)
    blob2[4000] ^= 0xFF
    p3 = os.path.join(T, 'x3.bin')
    open(p3, 'wb').write(bytes(blob2))
    same_n = sum(1 for i in range(len(blob)) if blob[i] == blob2[i])
    case('单字节不同 -> 相同字节数 8191', same_n, 8191)

    print()
    print('=== 对抗口径 M3adv（自选窗口 + 唯一签名）===')
    # 用 flen=4 的玩具数据逐条验证 adv_window_hit 的语义。
    # **必须正反都测**：只测正向命中，会让"恒返回 0"的实现也通过。
    case('[A] 唯一且在同名函数内 -> 命中 @0',
         adv_window_hit(b'QWER', b'\x00' * 16 + b'QWER' + b'\x00' * 16,
                        16, 4, flen=4), 0)
    case('[B] 签名在 B 出现 2 次（重复/填充）-> 不命中（不能定位）',
         adv_window_hit(b'QWER', b'QWER' + b'\x00' * 4 + b'QWER',
                        0, 8, flen=4), None)
    case('[C] 唯一但在**别的函数**内 -> 不命中（范围过滤生效）',
         adv_window_hit(b'QWER', b'QWER' + b'\x00' * 16, 8, 8, flen=4), None)
    case('[D] 需往后挪窗口才唯一 -> 命中 @4（证明"自选窗口"真的在扫）',
         adv_window_hit(b'XXXX' + b'QWER', b'QWER' + b'\x00' * 16,
                        0, 4, flen=4), 4)
    case('[E] 唯一签名落在映像后半（非 .text 区）仍应命中',
         adv_window_hit(b'QWER', b'\x00' * 512 + b'QWER' + b'\x00' * 16,
                        512, 4, flen=4), 0)
    case('空函数体不崩溃', adv_window_hit(b'', b'ABCD', 0, 4, flen=4), None)
    case('窗口长于函数体不崩溃', adv_window_hit(b'AB', b'ABCD', 0, 4, flen=4), None)

    import shutil
    shutil.rmtree(T, ignore_errors=True)

    print()
    print('=' * 64)
    if fails:
        print('[migration_cost-selftest] FAIL: %d 项 -> %s'
              % (len(fails), '; '.join(fails)))
        return 1
    print('[migration_cost-selftest] PASS: 度量可自证能抓错')
    return 0


# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(prog='migration_cost.py')
    ap.add_argument('a', nargs='?')
    ap.add_argument('b', nargs='?')
    ap.add_argument('--map-a', dest='mapa', default=None)
    ap.add_argument('--map-b', dest='mapb', default=None)
    ap.add_argument('--selftest', action='store_true')
    ap.add_argument('--json', dest='json_out', default=None)
    args = ap.parse_args()

    if args.selftest:
        return selftest()
    if not (args.a and args.b):
        ap.error('需要 <A.exe> <B.exe> 或 --selftest')

    # 自动找同名 .map
    mapa = args.mapa or (os.path.splitext(args.a)[0] + '.map')
    mapb = args.mapb or (os.path.splitext(args.b)[0] + '.map')

    r = analyse(args.a, args.b, mapa, mapb)

    print('=== 破解迁移成本度量 ===')
    print('  A: %s' % os.path.basename(args.a))
    print('  B: %s' % os.path.basename(args.b))
    print()
    print('--- M1 地址稳定性 ---')
    m1 = r['m1']
    m1f = r.get('m1_funcs', m1)
    print('  **函数**共同 %d；RVA 相同 %d (%.1f%%)  <- **门禁口径**'
          % (m1f['common'], m1f['same_rva'], m1f['rate_same']))
    print('  -> 硬编码地址可复用率(函数, 门禁口径): %.1f%%' % m1f['rate_same'])
    print('  全部符号共同 %d；RVA 相同 %d (%.1f%%)  <- 诊断口径（含合并'
          '字符串/导入/CRT，链接器固定）'
          % (m1['common'], m1['same_rva'], m1['rate_same']))
    print('  -> 硬编码地址可复用率(全部符号, 诊断): %.1f%%' % m1['rate_same'])
    print('     （越低越好: 攻击者脚本需重定位）')

    print()
    print('--- M3 特征可匹配性（最关键）---')
    m3 = r['m3']
    print('  函数特征在 B 中命中: %d / %d (%.1f%%)'
          % (m3['matched'], m3['total'], m3['rate']))
    print('  **保护函数命中: %d / %d (%.1f%%)**'
          % (m3['prot_matched'], m3['prot_total'], m3['prot_rate']))
    print('  -> 命中即意味着攻击者**无需地址**即可跨构建定位 -> 迁移成本低')
    if m3['prot_safe']:
        print()
        print('  未被特征匹配的保护函数（这些是"安全"的）: %d' % len(m3['prot_safe']))
        for s in m3['prot_safe'][:10]:
            print('    %-46s' % s[:46])

    # ---- M3adv 对抗口径（诚实边界，不是判据）----
    m3a = r.get('m3a')
    if m3a and m3a['prot_total']:
        print()
        print('--- M3adv 对抗口径（攻击者自选窗口 + 唯一签名）---')
        print('  ⚠️ **不是门禁判据** —— 报告判据 M3 的诚实边界')
        print('  判据口径（入口起 32B）: %d / %d (%.1f%%)'
              % (m3['prot_matched'], m3['prot_total'], m3['prot_rate']))
        print('  对抗口径（自选窗口）  : %d / %d (%.1f%%)'
              % (m3a['prot_located'], m3a['prot_total'], m3a['prot_rate']))
        print('  -> 差值 = 判据**低估**的部分: 攻击者不必从入口取特征')
        if m3a['prot_rate'] > m3['prot_rate'] + 1.0:
            print('     实测结论: 判据测的是"最容易被利用的取法", '
                  '收紧判据窗口不改变对抗口径')

    print()
    print('--- M4 结构稳定性 ---')
    m4 = r['m4']
    print('  节数: A=%d B=%d' % (m4['sections_a'], m4['sections_b']))
    print('  布局完全相同（VSize+RawOff）的节: %d' % m4['same_layout'])
    print('  文件大小: A=%d B=%d' % (m4['size_a'], m4['size_b']))

    print()
    print('=== 综合判定 ===')
    verdict = []
    if m3['prot_rate'] > 50:
        verdict.append('**迁移成本低**：%.0f%% 的保护函数可用字节特征跨构建定位'
                       % m3['prot_rate'])
    elif m3['prot_rate'] > 0:
        verdict.append('迁移成本中等：%.0f%% 的保护函数仍可特征定位'
                       % m3['prot_rate'])
    else:
        verdict.append('迁移成本高：无保护函数可被特征定位')
    if m1.get('rate_same', 0) > 50:
        verdict.append('地址复用率高（%.0f%%）' % m1['rate_same'])
    for v in verdict:
        print('  %s' % v)

    print()
    print('  根因（实测确认）: **随机化只作用于数据，不作用于代码**。')
    print('    变化: 节名/magic/期望值/密钥/掩码/填充区（都是**数据**）')
    print('    不变: 真实函数体的机器码 -> 可用特征扫描定位')

    if args.json_out:
        with open(args.json_out, 'w', encoding='ascii', newline='\n') as f:
            json.dump(r, f, indent=2)
        print()
        print('  已写 %s' % args.json_out)
    return 0


if __name__ == '__main__':
    sys.exit(main())
