# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ShardVase contributors
# 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；商业授权见 LICENSE.md。
"""
tests/protchain_check.py — 保护链静态断言 (CI_PLAN §2.2)

对 build\\demo.exe + build\\vm.blob 做**静态**断言 (不运行进程, 无 WDAC 干扰),
防止保护能力 (N1 selfcrypt / N4 间接化 / BLOB_SIGN 签名 / N5 期望值) 被
未来改动静默破坏:

  P1 selfcrypt 密文   .text 目标函数区 (从 .protcry meta 读 rva/len) 为密文
                      (无 x64 序言特征 40 55/48 89 等)
  P2 selfcrypt 掩码   build/selfcrypt_mask.txt 与 meta 一致; 带掩码可复算 .text CRC
  P3 blob v1 签名     vm.blob 头部 "PROTVMB1" + 签名区存在 (256B)
  P4 blob 签名可验    用内嵌公钥 (license_pubkey.c BCRYPT blob) RSA 验签通过
  P5 N4 间接化        反汇编扫描: 4 个关键函数无直接 call rel32 指向
  P6 期望值一致       expect_default.c 生成值与 vm_build.json 一致

用法:
    python tests\\protchain_check.py [--exe build\\demo.exe] [--blob build\\vm.blob]

任一 FAIL -> sys.exit(1)。
"""

import json
import os
import re
import struct
import sys
import zlib


# ## map 解析的单一实现（B 阶段，2026-09-25）
#   本项目曾有 **4 处**各自实现 -> 已归一到 `tools/mapfile.py`。
def _load_mapfile():
    _repo = os.path.dirname(os.path.dirname(
        os.path.abspath(__file__)))
    _t = os.path.join(_repo, "tools")
    if _t not in sys.path:
        sys.path.insert(0, _t)
    import mapfile
    return mapfile


_mapfile = _load_mapfile()

REPO = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
EXE = os.path.join(REPO, 'build', 'demo.exe')

# ## 本次被测的产物路径（A-d，2026-09-25）
#   `--exe` 参数化后，**辅助函数**（`load_section_names` / P6）必须
#   按**实际被测产物**解析生成物目录 —— 否则命令行为 linux 时
#   仍去 `demo/gen/win/` 找（实测 WARN 直指该点）。
#   => 用模块级**可变变量**记录，命令行解析后立即赋值
#      （最小改动，避免改所有函数签名）。
_CURRENT_EXE = EXE
BLOB = os.path.join(REPO, 'build', 'vm.blob')

IMAGE_BASE = 0x140000000

# selfcrypt meta 条目步长 (S1 2026-08-29 起为 24B: rva/len/key0/crc/group).
# 与 src/selfcrypt.c 的 SC_ENTRY_SIZE 必须一致 —— 20B 是 S1 之前的旧格式,
# 用错步长会静默错位 (P1/P2 误报, P5/A10/S3/S4 假绿)。见 docs/迁移核验-2026-09-20.md §3.1。
SC_ENTRY_SIZE = 24
SC_ENTRY_GROUP_OFF = 20


def _platform():
    """本次被测产物所属平台（'win' / 'linux'，A-d）。

    与 `resolve_gen_paths` 用**同一判据**（产物 magic）——
    避免"两处判定不一致"（本项目已踩过同类坑）。
    """
    _gen, _ = resolve_gen_paths(_CURRENT_EXE)
    return 'linux' if _gen.replace('\\', '/').endswith('/linux') else 'win'


def load_section_names(path=None):
    """读取阶段1 生成的随机节名映射（**逻辑名 -> 实际名**）。

    为什么需要（2026-09-23 教训）: 阶段1（第二支柱）把 `.protcry` 等节名
    改为**每构建随机**，而本检查原先**硬编码** `.protcry`/`.protcrypt` ->
    必然找不到节 -> P1/P2/P5 全 FAIL。

    修法: 从 demo/gen/prot_sections.json 按**逻辑名**取实际名。
    未提供时返回 {} -> 调用方回退旧名（向后兼容）。

    ⚠️ 注意: 必须返回**映射**而非"所有名字的集合"。
    初版误返回集合 -> `cry_section_names()` 变成全部随机名 ->
    `next(...)` 匹配到第一个自定义节（`.protxec`）而非 `.protcry`，
    导致 "bad selfcrypt count 149717832" 这类误判。
    """
    import json as _json
    if path is None:
        # ## A-d（2026-09-25）: 生成物目录**按产物格式**解析
        #   （Linux -> demo/gen/linux；不再硬编码 demo/gen）
        #
        #   ⚠️ 注意 `path = ...` 必须在 `if` **内部** ——
        #   初版写在 `if` 外面，会**覆盖调用方显式传入的 path**
        #   （且 path 非 None 时 `_gen` 未定义 -> NameError）。
        _gen, _vmj = resolve_gen_paths(_CURRENT_EXE)
        path = os.path.join(_gen, 'prot_sections.json')
    # ## ⚠️ 编码必须是 **utf-8**（A-d 实测修正）
    #   `prot_sections.json` 含**中文 `_comment` 字段** ——
    #   原用 `encoding='ascii'` 读 -> `UnicodeDecodeError`
    #   （`ValueError` 子类）-> 被 `except (OSError, ValueError)` **吞掉**
    #   -> 返回 `{}` -> 调用方回退固定节名 `.protcry` -> **P1/P2 误报 FAIL**。
    #   实测: 文件存在且内容正确（`protcry=".165460x"`），却读成空。
    #
    #   **教训**: "文件读不到"与"编码假设错"必须区分 ——
    #   前者可回退，后者是**缺陷**（本该用正确编码重试）。
    try:
        with open(path, encoding='utf-8') as f:
            data = _json.load(f)
        secs = data.get('sections', {})
        if isinstance(secs, dict):
            return secs
    except (OSError, ValueError) as _e:
        # **不静默**: 打印以便诊断（调用方仍有回退逻辑，保持兼容）
        sys.stderr.write('protchain: WARN 读取 %s 失败: %s\n'
                         % (path, _e))
    return {}


def crc_section_names():
    """protcrc（烧录 CRC）节的名字候选（随机名优先，回退旧名）。"""
    names = load_section_names()
    live = names.get('protcrc')
    if live:
        return (live,)
    return ('.protcrc',)


def cry_section_names():
    """selfcrypt 密文节的名字候选（随机名优先，回退旧名）。"""
    names = load_section_names()
    live = names.get('protcry')
    if live:
        return (live,)
    return ('.protcrypt', '.protcry')


def selfcrypt_meta(data, secs, entries_only=False):
    """从 .protcry 读 selfcrypt meta 条目 -> [(rva, len, group), ...].

    唯一的 meta 解析入口: 所有测试 (protchain / attacks / attack_drill)
    都经此读取, 避免步长散落成魔数后再次漂移。
    """
    prot = next((s for s in secs if s['name'] in cry_section_names()), None)
    if prot is None:
        return []
    blob = data[prot['ptr_raw']:prot['ptr_raw'] + 256]
    n = struct.unpack_from('<I', blob, 0)[0]
    if n == 0 or n > 16:
        return []
    out = []
    for i in range(n):
        off = 4 + i * SC_ENTRY_SIZE
        if off + SC_ENTRY_SIZE > len(blob):
            break
        rva, ln = struct.unpack_from('<II', blob, off)
        grp = struct.unpack_from('<I', blob, off + SC_ENTRY_GROUP_OFF)[0]
        out.append((rva, ln, grp))
    return out


# ===========================================================================
# ELF 支持（F 阶段，2026-09-25）
#
# ## 为什么只需改节表
#   实测各检查项的依赖分层:
#     P1/P2 需 `.text` 节；P3/P4/P6 **纯格式无关**；P5 需 `.text` + map。
#   => **唯一平台相关处就是节表解析**。
#
# ## 与 PE 的关键差异（**简化**）
#   · `sh_size` 即**实际大小**（无 PE 的 VirtualSize/SizeOfRawData 之分）
#   · `sh_addr` 对 **PIE** 数值即 RVA
# ===========================================================================

ELF_TARGET_SECTIONS = {
    'text': '.text',
    'rodata': '.rodata',
    'pdata': '.eh_frame',      # ELF 的展开信息（PE 的 .pdata 对应物）
}


# ## 平台感知的生成物路径（A-d，2026-09-25）
#
#   背景: A-b 把生成物按平台分目录（`demo/gen/win` + `demo/gen/linux`），
#   本文件读到的是**哪个平台的生成物**取决于 `--exe` 指向的产物。
#   => 按产物**格式**判定平台（本文件本来就知道自己在测什么）。
def resolve_gen_paths(exe_path):
    """按 `--exe` 的格式返回 (gen_dir, vm_build_json)。"""
    import sys as _sys
    import os as _os
    _t = _os.path.join(REPO, 'tools')
    if _t not in _sys.path:
        _sys.path.insert(0, _t)
    import genpaths
    try:
        with open(exe_path, 'rb') as _f:
            _magic = _f.read(4)
        plat = 'linux' if _magic == b'\x7fELF' else 'win'
    except OSError:
        plat = 'win'          # 读不到 -> 按默认（Windows）处理
    p = genpaths.paths(plat)
    return p.gen, p.vm_build_json


def is_elf(data):
    """是否 ELF64 小端。"""
    return (len(data) >= 64 and data[0:4] == b'\x7fELF'
            and data[4] == 2 and data[5] == 1)


def elf_sections(data):
    """解析 ELF64 节表；字段名与 `pe_sections` **一致**（便于共用下游）。"""
    if not is_elf(data):
        raise RuntimeError('not an ELF64-LE file')
    e_shoff = struct.unpack_from('<Q', data, 0x28)[0]
    e_shentsize = struct.unpack_from('<H', data, 0x3A)[0]
    e_shnum = struct.unpack_from('<H', data, 0x3C)[0]
    e_shstrndx = struct.unpack_from('<H', data, 0x3E)[0]
    if e_shoff == 0 or e_shnum == 0:
        raise RuntimeError('ELF has no section table')

    def raw_sh(i):
        return struct.unpack_from('<IIQQQQIIQQ', data,
                                  e_shoff + i * e_shentsize)

    strtab_off = raw_sh(e_shstrndx)[4] if e_shstrndx < e_shnum else 0
    secs = []
    for i in range(e_shnum):
        (nameoff, _stype, _flags, addr, off, size, _link, _info,
         _align, _ent) = raw_sh(i)
        if strtab_off:
            end = data.index(b'\x00', strtab_off + nameoff)
            name = data[strtab_off + nameoff:end].decode('ascii', 'replace')
        else:
            name = ''
        secs.append({
            'name': name,
            'virtual_size': size,     # ELF: sh_size 即实际大小
            'virtual_addr': addr,
            'size_raw': size,
            'ptr_raw': off,
        })
    return secs


def sections_of(data):
    """**按文件类型分派**的节表解析（PE / ELF）。"""
    return elf_sections(data) if is_elf(data) else pe_sections(data)


def pe_sections(data):
    if len(data) < 0x40:
        raise RuntimeError('not a PE file')
    e = struct.unpack_from('<I', data, 0x3C)[0]
    if data[e:e + 4] != b'PE\x00\x00':
        raise RuntimeError('bad PE signature')
    nsec = struct.unpack_from('<H', data, e + 6)[0]
    optsz = struct.unpack_from('<H', data, e + 20)[0]
    table = e + 24 + optsz
    secs = []
    for i in range(nsec):
        off = table + i * 40
        name = data[off:off + 8].rstrip(b'\x00').decode('ascii', 'replace')
        secs.append({
            'name': name,
            'virtual_size': struct.unpack_from('<I', data, off + 8)[0],
            'virtual_addr': struct.unpack_from('<I', data, off + 12)[0],
            'size_raw': struct.unpack_from('<I', data, off + 16)[0],
            'ptr_raw': struct.unpack_from('<I', data, off + 20)[0],
        })
    return secs


def scan_e8_calls(text, text_rva=0, skip_ranges=()):
    """扫描 .text 的 E8 call rel32, 返回**映像 RVA** 目标集合。

    ## ⚠️ M4 实测修正（2026-09-25）—— 本函数原先有**两个缺陷**

    ### 缺陷 1: 坐标系错配（**严重**）
      原实现返回 `i + 5 + rel` —— 这是"**相对 .text 起点**"的偏移；
      而 `selfcrypt_meta()` 给出的 RVA 是"**相对映像基址**"。
      两者相差 `.text` 的 `virtual_addr`（本构建为 0x1000）。

      => P5 的 `fns ∩ targets` 实际是**两个不同坐标系下的数值比较**，
         "命中"纯属**巧合** —— 与"是否间接化"**无关**。
         实测: 含/不含 `text_rva`，命中数从 **1** 变为 **7**。

      **修法**: 加 `text_rva` 参数，返回映像 RVA。

    ### 缺陷 2: 未排除密文噪声
      加密函数体在文件里是**密文**（伪随机字节）——
      其中出现的 `0xE8` **不是调用**，只是巧合的字节。
      原实现把它们也计入 `targets` -> 噪声污染判据。

      **修法**: 加 `skip_ranges`（加密函数区间），跳过这些区域内的字节。

    ## 参数
      `text`        —— .text 的**文件字节**
      `text_rva`    —— .text 的映像 RVA（`virtual_addr`）
      `skip_ranges` —— [(start_rva, end_rva)]，这些区间内的字节**不扫描**
    """
    targets = set()
    for i in range(len(text) - 5):
        if text[i] != 0xE8:
            continue
        call_rva = text_rva + i
        # 缺陷 2 修正: 跳过密文区（那里的 E8 是噪声，不是调用）
        if any(a <= call_rva < b for a, b in skip_ranges):
            continue
        rel = struct.unpack_from('<i', text, i + 1)[0]
        targets.add(call_rva + 5 + rel)   # 缺陷 1 修正: 映像 RVA
    return targets


def p1_selfcrypt_ciphertext(data, secs):
    """P1: .text 加密函数区无 x64 序言特征 (密文)."""
    prot = next((s for s in secs if s['name'] in cry_section_names()), None)
    text = next((s for s in secs if s['name'] == '.text'), None)
    if prot is None or text is None:
        return False, 'no .protcry/.text section'
    blob = data[prot['ptr_raw']:prot['ptr_raw'] + 256]
    n = struct.unpack_from('<I', blob, 0)[0]
    if n == 0 or n > 16:
        return False, 'bad selfcrypt count %d' % n
    for i, (rva, ln, _grp) in enumerate(selfcrypt_meta(data, secs)):
        toff = text['ptr_raw'] + (rva - text['virtual_addr'])
        body = data[toff:toff + ln]
        if len(body) < ln:
            return False, 'fn %d out of range' % i
        head = body[:8]
        # x64 序言特征: 40 55 (push rbp) / 40 56 (push rsi) / 48 89 (mov) / 48 83 (sub)
        for pat in (b'\x40\x55', b'\x40\x56', b'\x40\x57', b'\x48\x89', b'\x48\x83'):
            if head.startswith(pat):
                return False, 'fn %d rva=0x%x has plaintext prologue %s' % (
                    i, rva, pat.hex())
    return True, '%d fns ciphertext (no x64 prologue)' % n


def p2_mask_consistent(data, secs):
    """P2: mask 文件与 meta 一致."""
    prot = next((s for s in secs if s['name'] in cry_section_names()), None)
    text = next((s for s in secs if s['name'] == '.text'), None)
    # ## A-d 补完: 平台专属 build 目录（状态文件隔离）
    #   实测: `build/selfcrypt_mask.txt` 被**两平台都写** ->
    #   跑完 Linux 后此处读到 **Windows 的 mask**（8 项）而 meta 是
    #   Linux 的（5 项）-> P2 误报 FAIL。
    #   => 第 3 个需隔离的状态文件（前两个: vm.blob / license.txt）。
    _bd = os.path.join(REPO, 'build') if _platform() == 'win' \
        else os.path.join(REPO, 'build', 'linux')
    mask_path = os.path.join(_bd, 'selfcrypt_mask.txt')
    if not os.path.isfile(mask_path):
        return False, 'build/selfcrypt_mask.txt missing'
    if prot is None or text is None:
        return False, 'no .protcry/.text section'
    blob = data[prot['ptr_raw']:prot['ptr_raw'] + 256]
    n = struct.unpack_from('<I', blob, 0)[0]
    meta = [(rva, ln) for rva, ln, _grp in selfcrypt_meta(data, secs)]
    masks = []
    for ln in open(mask_path, 'r', encoding='ascii'):
        rva_s, ln_s = ln.strip().split(',')
        masks.append((int(rva_s, 0), int(ln_s, 0)))
    if sorted(meta) != sorted(masks):
        return False, 'meta %s != mask file %s' % (sorted(meta), sorted(masks))
    # 带掩码复算 .text CRC 与烧录值比对
    # 注意: 节名在阶段1 后是随机的 -> 用逻辑名映射（不能硬编码 .protcrc）
    protcrc = next((s for s in secs if s['name'] in crc_section_names()), None)
    if protcrc is None:
        return False, 'no .protcrc section'
    crc_len = min(text['virtual_size'], text['size_raw'])
    raw = bytearray(data[text['ptr_raw']:text['ptr_raw'] + crc_len])
    for (mrva, mlen) in masks:
        o = mrva - text['virtual_addr']
        raw[o:o + mlen] = b'\x00' * mlen
    crc = zlib.crc32(bytes(raw)) & 0xFFFFFFFF
    baked = struct.unpack_from('<I', data, protcrc['ptr_raw'] + 8)[0]
    if crc != baked:
        return False, '.text crc 0x%08x != baked 0x%08x' % (crc, baked)
    return True, 'mask file matches meta; .text CRC verified'


def p3_blob_v1(data):
    """P3: vm.blob v1 签名格式."""
    if len(data) < 20:
        return False, 'blob too small'
    if data[:8] != b'PROTVMB1':
        return False, 'magic %r != PROTVMB1' % data[:8]
    return True, 'PROTVMB1 v1 signed blob'


def p4_blob_signature(data):
    """P4: 用内嵌公钥 RSA 验签 blob (纯 Python 复算 PKCS#1 v1.5 SHA-256)."""
    # 从 license_pubkey.c 读公钥 BCRYPT blob (BCRYPT_RSAPUBLIC_BLOB)
    pub_path = os.path.join(REPO, 'demo', 'gen', 'license_pubkey.c')
    if not os.path.isfile(pub_path):
        return False, 'license_pubkey.c missing'
    src = open(pub_path, 'r', encoding='utf-8').read()
    hexes = re.findall(r'0x([0-9a-fA-F]{2})', src)
    pub = bytes(int(h, 16) for h in hexes)
    if len(pub) < 40:
        return False, 'pubblob too small (%d)' % len(pub)
    # BCRYPT_RSAPUBLIC_BLOB: 16B 头 + 8B 填充 + exponent BE + modulus BE
    eb_len = struct.unpack_from('<I', pub, 8)[0]
    nb_len = struct.unpack_from('<I', pub, 12)[0]
    exp = int.from_bytes(pub[24:24 + eb_len], 'big')
    mod = int.from_bytes(pub[24 + eb_len:24 + eb_len + nb_len], 'big')
    # 定位签名区: 尾部 [CRC4][SIG 384B][SIG_LEN4]
    size = len(data)
    sig_len = struct.unpack_from('<I', data, size - 4 - 384 - 4)[0]
    if sig_len != 384:
        return False, 'sig_len %d != 384' % sig_len
    sig = data[size - 4 - 384:size - 4]
    msg = data[:size - 4 - 384 - 4]
    digest = hashlib_sha256(msg)
    # PKCS#1 v1.5: EM = 00 01 FF..FF 00 T (T = DigestInfo(SHA-256) + digest)
    t = bytes([0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
               0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20]) + digest
    pslen = 384 - len(t) - 3
    if pslen < 8:
        return False, 'pslen too small'
    em = b'\x00\x01' + (b'\xff' * pslen) + b'\x00' + t
    m = int.from_bytes(em, 'big')
    s = int.from_bytes(sig, 'big')
    v = pow(s, exp, mod)
    return (v == m, 'RSA-3072 verify ok' if v == m else 'signature mismatch')


def hashlib_sha256(b):
    import hashlib
    return hashlib.sha256(b).digest()


def parse_map_file(path):
    """链接 map（MSVC / gcc）-> {符号: 映像RVA}。

    ## B 阶段（2026-09-25）: 实现已**抽到 `tools/mapfile.py`**
      抽取前本项目有 **4 处**各自实现（MSVC/gcc 支持不一，**已实际漂移**:
      G 阶段给本文件加了 gcc 支持，而另两处仍是 MSVC-only）
      -> 归一到单一实现，避免再次漂移。

      ## 历史陷阱（**保留记录**，教训仍在）
        MSVC map 行的**第 2 列是节内偏移**，不是映像 RVA ——
        误用会让 RVA 落在节外、度量全部失真（2026-09-23 实测）。
        `mapfile.parse()` 用**第 4 列绝对 VA** - image_base。

      ## 等价性（**已实测**）
        · MSVC: 2973 键一致；gcc: 178/178 完全等价
    """
    return _mapfile.parse(path)


def indirect_slot_symbols():
    """间接表的槽位符号名 —— 从 modules.json 的 `indirect_slots` 读。

    ## 为什么注册表驱动（而非硬编码）
      间接化作用于**宿主的业务函数** -> "哪些函数被间接化"是**宿主属性**
      （见 modules.json 的 _comment 与 docs/PORTABILITY_ASSESSMENT.md）。
      硬编码会在**换宿主时失效**（L3 已踩过: example 因此无法用 indirect）。
    """
    import json
    path = os.path.join(REPO, 'modules.json')
    try:
        d = json.load(open(path, encoding='utf-8'))
    except Exception:
        return []
    slots = d.get('indirect_slots', {})
    out = []
    for k, v in slots.items():
        if k.startswith('_'):
            continue
        sym = v.get('symbol') if isinstance(v, dict) else v
        if sym:
            out.append(sym)
    return out


def p5_indirect_no_direct_call(data, secs, map_path=None):
    """P5: **间接表的槽位函数**不被直接 call（N4 间接化）。

    ## ⚠️ M4 实测重写（2026-09-25）—— 原实现有**四个缺陷**

    | # | 缺陷 | 说明 |
    |---|------|------|
    | 1 | **坐标系错配** | `scan_e8_calls` 返回"相对 .text 起点"的偏移，而 selfcrypt meta 的 RVA 是"相对映像基址"，差 `.text` 的 `virtual_addr`。=> "命中"是**数值巧合**，与间接化无关。 |
    | 2 | **密文噪声** | 加密函数体在文件里是密文，其中的 `0xE8` 不是调用。 |
    | 3 | **函数集合错误** | docstring 说"**4 个关键函数**"，实现却取 **8 个 selfcrypt 加密函数**。 |
    | 4 | **未区分设计允许的调用** | 同组加密函数互相调用是**设计允许**的（同组同时解密，见 `tools/selfcrypt_proto.py`）。 |

    **原实现的实际后果**: 判据退化为"**密文里某个噪声 E8 是否恰好等于某个
    加密函数的 RVA**" —— **纯随机**（M4 前 PASS 也是巧合）。

    ## 修正后的判据（**忠于 docstring 的意图**）
      只检查 **间接表的槽位函数** 不被直接 call ——
      这才是"间接化"的承诺: 宿主通过**表**调用这 4 个入口。

    ## 实测支持（修正的依据）
      4 个槽位（`load_and_verify_license` / `prot_revoke_check` /
      `prot_hostid_get` / `prot_vm_run`）:
```
0 次直接调用   -> N4 间接化**有效**
```
      （而 8 个加密函数被 `vm.c` 内部的 helper 直接调用 ——
       那是**设计允许**的，不应算违规。）

    ## 诚实边界
      · P5 只验证"**没有直接调用**"（**必要条件**），
        **不验证**"调用方真的走了表"（那需要识别表调用模式）。
      · 槽位从 `modules.json` 读（**注册表驱动**）——
        换宿主时自动跟随，无需改本测试。
    """
    text = next((s for s in secs if s['name'] == '.text'), None)
    if text is None:
        return False, 'no .text'
    t = data[text['ptr_raw']:text['ptr_raw'] + text['size_raw']]
    base = text['virtual_addr']

    slots = indirect_slot_symbols()
    if not slots:
        return False, 'no indirect_slots in modules.json'

    # 槽位符号 -> RVA（用 map 反查；无 map 则跳过该项）
    # ## ⚠️ map 路径**必须随被测产物**（2026-09-25 实测修正）
    #
    # **根因**: 原实现**硬编码** `build/demo.map`（Windows 的 map）。
    #   被测产物换成 ELF 后，map 仍是 PE 的 -> **符号 RVA 不匹配**
    #   -> 坐标系错配 -> **误报 `prot_revoke_check` 被直接调用**。
    #
    #   （实测对照: Windows 产物 P5 **PASS** / Linux 产物 P5 **FAIL**
    #     —— 差别只在被测节，map 两边都是同一份 PE map。）
    #
    # **与历史缺陷同类**: P5 曾在 M4 修过"坐标系错配"
    #   （`scan_e8_calls` 的偏移基准）；本次是**同一类错误的另一处**。
    #   **教训**: 修坐标系问题时须**穷尽所有坐标系来源**
    #   （节偏移 / 映像基址 / **map 文件**），不能只修显式报错那处。
    if map_path is None:
        map_path = os.path.join(REPO, 'build', 'demo.map')
    if not os.path.exists(map_path):
        return False, 'no .map at %s (无法定位槽位符号)' % map_path
    ma = parse_map_file(map_path)
    if not ma:
        return False, 'empty .map (%s)' % map_path

    # 密文区间（排除噪声）
    meta = selfcrypt_meta(data, secs)
    crypt = [(rva, rva + ln) for rva, ln, _g in meta]

    # 修正 1+2: 正确坐标系 + 排除密文噪声
    targets = scan_e8_calls(t, text_rva=base, skip_ranges=crypt)

    hits = []
    for sym in slots:
        rva = ma.get(sym)
        if rva is None:
            continue    # 该槽位符号不在本构建（如宿主未提供）
        if rva in targets:
            hits.append(sym)

    if hits:
        return False, ('direct calls to indirect slots: %s '
                       '(应仅通过间接表调用)' % hits)
    return True, ('no direct call to %d indirect slots '
                  '（已修正坐标系/密文噪声/函数集合）' % len(slots))
def p6_expect_consistent():
    """P6: expect_default.c 与 vm_build.json 一致."""
    # ## A-d: **两个**路径都必须按平台解析
    #   `expect_default.c` 与 `vm_build.json` 都在**本次构建的生成物目录**
    #   里 —— 原实现只把 json 参数化，`exp_path` 仍硬编码
    #   `demo/gen/expect_default.c`（旧 flat 路径）
    #   -> 读到 **Windows 遗留的旧值** -> 与 Linux 的 json **不一致** -> 误报。
    #   （实测: 旧值 0x2d27… vs Linux 值 0x2e9f…）
    _gen, json_path = resolve_gen_paths(_CURRENT_EXE)
    exp_path = os.path.join(_gen, 'expect_default.c')
    if not os.path.isfile(exp_path) or not os.path.isfile(json_path):
        return False, 'expect_default.c or vm_build.json missing'
    src = open(exp_path, 'r', encoding='utf-8', errors='replace').read()
    m = re.search(r'g_prot_expect_default\[2\] = \{ (0x[0-9a-fA-F]+)ULL, (0x[0-9a-fA-F]+)ULL \}', src)
    if not m:
        return False, 'cannot parse expect_default.c'
    jb = json.load(open(json_path, 'r', encoding='utf-8'))
    if jb.get('expect1') != m.group(1) or jb.get('expect2') != m.group(2):
        return False, 'expect mismatch: %s/%s vs %s/%s' % (
            m.group(1), m.group(2), jb.get('expect1'), jb.get('expect2'))
    return True, 'expect_default.c matches vm_build.json'


def main():
    import argparse
    parser = argparse.ArgumentParser(prog='protchain_check.py',
                                     description='protection chain static asserts')
    parser.add_argument('--exe', default=EXE)
    parser.add_argument('--blob', default=BLOB)
    parser.add_argument('--map', default=None,
                        help='链接 map（缺省按 --exe 推导）')
    args = parser.parse_args()

    # ## 记录本次被测产物（A-d）—— 供辅助函数解析生成物目录
    global _CURRENT_EXE
    _CURRENT_EXE = args.exe

    results = []
    try:
        data = open(args.exe, 'rb').read()
        secs = sections_of(data)

        # ## map 路径按 `--exe` 推导（平台一致）
        #   build/demo_linux -> build/demo_linux.map
        #   build/demo.exe   -> build/demo.map（向后兼容）
        map_path = args.map
        if map_path is None:
            stem = os.path.splitext(args.exe)[0]
            cand = stem + '.map'
            if not os.path.exists(cand):
                # PE 的 map 名是 `demo.map`（不是 `demo.exe.map`）
                cand2 = os.path.join(os.path.dirname(args.exe), 'demo.map')
                cand = cand2 if os.path.exists(cand2) else cand
            map_path = cand

        checks = [
            ('P1 selfcrypt-ciphertext', p1_selfcrypt_ciphertext, (data, secs)),
            ('P2 selfcrypt-mask-crc', p2_mask_consistent, (data, secs)),
            ('P5 indirect-no-direct-call', p5_indirect_no_direct_call,
             (data, secs, map_path)),
            ('P6 expect-consistent', p6_expect_consistent, ()),
        ]
        for name, fn, args2 in checks:
            try:
                ok, detail = fn(*args2)
            except Exception as e:
                ok, detail = False, repr(e)
            results.append((name, ok, detail))

        blob = open(args.blob, 'rb').read()
        ok, detail = p3_blob_v1(blob)
        results.append(('P3 blob-v1-signed', ok, detail))
        ok, detail = p4_blob_signature(blob)
        results.append(('P4 blob-signature-verify', ok, detail))
    except Exception as e:
        print('protchain_check: error: %s' % e, file=sys.stderr)
        return 2

    failed = False
    for name, ok, detail in results:
        print('%-28s  %-4s  (%s)' % (name, 'PASS' if ok else 'FAIL', detail),
              flush=True)
        if not ok:
            failed = True
    sys.exit(1 if failed else 0)


if __name__ == '__main__':
    main()
