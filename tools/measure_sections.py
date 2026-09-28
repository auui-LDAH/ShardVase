#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""measure_sections.py — 量测 PE 节表（阶段2 归一化用）

用法:
  python tools/measure_sections.py <exe> [--out-json <path>] [--gen-baseline]
  python tools/measure_sections.py --compare a.json b.json ...

输出 JSON: {"file": <大小>, "sections": {"<名>": {"vsize":..,"rawsize":..}}}
节名带随机前缀（.protxxx -> 随机 8 字符），故用**逻辑名**归并:
  · 标准节（.text/.rdata/.data/.pdata/.rsrc/.reloc）按原名
  · 自定义节按**出现顺序**编号（custom0/1/2...）
"""
import argparse
import json
import struct
import sys

STD = {'.text', '.rdata', '.data', '.pdata', '.rsrc', '.reloc'}


def load_name_map(path):
    """读取 gen_sections.py 的节名映射（随机名 -> 逻辑名）。

    **为什么必须用它**（实测教训 2026-09-23）: 早期版本把随机名的自定义节
    按**出现顺序**编号（custom0/1/2...），但各组合的节顺序不同
    （minimal 缺 .protcrc -> 索引整体前移），导致把 minimal 的 protcry
    与 standard 的 protcrc 当作同一节，得出无意义的填充量。
    用该映射按**语义身份**对齐才是正确的。
    """
    if not path:
        return {}
    try:
        import json as _json
        with open(path, encoding='ascii') as f:
            data = _json.load(f)
        secs = data.get('sections', {})
        if not isinstance(secs, dict):
            return {}
        # 反向: 随机名 -> 逻辑名
        return {v: k for k, v in secs.items() if isinstance(v, str)}
    except (OSError, ValueError):
        return {}


def read(path, name_map=None):
    """读产物节尺寸 -> {file, sections}。**自动识别 PE / ELF**。

    ## ELF 分支（2026-09-25 实测补）
      原实现**只认 PE** —— 对 ELF 会按 PE 头解析
      （`e_lfanew` 位置读到垃圾值 -> `struct.error: 越界`）。
      实测后果: `measure_sections` 在 Linux 上**一直失败**（被 `warn` 吞掉）
      -> `section_actual.json` 从未生成 -> `merge_baseline`/`gen_padding`
      连锁失败 -> **填充（第二支柱）在 Linux 上从未生效**。
      => **"被 warn 吞掉的失败"会长期潜伏**（与"静默降级"同类）。

      ## 与 PE 的差异
        · ELF 的 `sh_size` 即**实际大小**（无 vsize/rawsize 之分）
        · 对归一化而言，`vsize/rawsize` 都取 `sh_size`（语义等价）
    """
    d = open(path, 'rb').read()
    if len(d) >= 4 and d[0:4] == b'\x7fELF':
        return _read_elf(d, name_map)
    return _read_pe(d, name_map)


def _read_elf(d, name_map=None):
    """ELF64-LE 的节尺寸读取（字段名与 PE 分支**一致**）。"""
    e_shoff = struct.unpack_from('<Q', d, 0x28)[0]
    e_shentsize = struct.unpack_from('<H', d, 0x3A)[0]
    e_shnum = struct.unpack_from('<H', d, 0x3C)[0]
    e_shstrndx = struct.unpack_from('<H', d, 0x3E)[0]
    if e_shoff == 0 or e_shnum == 0:
        raise ValueError('ELF has no section table')

    def raw_sh(i):
        return struct.unpack_from('<IIQQQQIIQQ', d,
                                  e_shoff + i * e_shentsize)

    strtab_off = raw_sh(e_shstrndx)[4] if e_shstrndx < e_shnum else 0
    out = {}
    idx = 0
    for i in range(e_shnum):
        (nameoff, _stype, _flags, _addr, _off, size, _link, _info,
         _align, _entsize) = raw_sh(i)
        if strtab_off:
            end = d.index(b'\x00', strtab_off + nameoff)
            nm = d[strtab_off + nameoff:end].decode('ascii', 'replace')
        else:
            nm = ''
        if nm in STD:
            key = nm
        elif name_map and nm in name_map:
            key = name_map[nm]
        else:
            key = 'custom%d' % idx
            idx += 1
        # ELF 无 vsize/rawsize 之分 -> 都用 sh_size（语义等价）
        out[key] = {'vsize': size, 'rawsize': size, 'name': nm}
    return {'file': len(d), 'sections': out}


def _read_pe(d, name_map=None):
    e = struct.unpack_from('<I', d, 0x3C)[0]
    n = struct.unpack_from('<H', d, e + 6)[0]
    osz = struct.unpack_from('<H', d, e + 20)[0]
    tbl = e + 24 + osz
    out = {}
    idx = 0
    for i in range(n):
        o = tbl + i * 40
        nm = d[o:o + 8].rstrip(b'\x00').decode('ascii', 'replace')
        vsz, va, rsz, raw = struct.unpack_from('<IIII', d, o + 8)
        if nm in STD:
            key = nm
        elif name_map and nm in name_map:
            # 优先用语义名（protxec/protcrc/...），按真实身份对齐
            key = name_map[nm]
        else:
            # 无映射时退化为按出现顺序编号（会因节顺序差异而失准，仅作兜底）
            key = 'custom%d' % idx
            idx += 1
        out[key] = {'vsize': vsz, 'rawsize': rsz, 'name': nm}
    return {'file': len(d), 'sections': out}


def main():
    ap = argparse.ArgumentParser(prog='measure_sections.py')
    ap.add_argument('exe', nargs='?')
    ap.add_argument('--out-json')
    ap.add_argument('--compare', nargs='*', default=None)
    ap.add_argument('--quiet', action='store_true')
    ap.add_argument('--sections-json', dest='sections_json',
                    # ## ⚠️ 默认值是 **flat 旧路径**（S4 审计, 2026-09-25）
                    #   A 阶段按平台分目录后**漏改**；调用方须显式传
                    #   `--sections-json`（build.sh/build.ps1 都已传）。
                    default='demo/gen/prot_sections.json',
                    help='gen_sections.py 的节名映射（用于按语义对齐）')
    args = ap.parse_args()

    if args.compare:
        datas = [json.load(open(p, encoding='ascii')) for p in args.compare]
        keys = set()
        for d in datas:
            keys |= set(d['sections'])
        files = [d['file'] for d in datas]
        ok = len(set(files)) == 1
        if not args.quiet:
            print('文件大小: %s %s' % (files, '✓一致' if ok else '✗不同'))
            for k in sorted(keys):
                vals = [d['sections'].get(k, {}).get('rawsize') for d in datas]
                same = len(set(vals)) == 1
                if not same:
                    print('  %-12s %s ✗' % (k, vals))
        sys.exit(0 if ok else 1)

    if not args.exe:
        ap.error('需要 <exe> 或 --compare')
    r = read(args.exe, load_name_map(args.sections_json))
    if args.out_json:
        with open(args.out_json, 'w', encoding='ascii', newline='\n') as f:
            json.dump(r, f, indent=2)
        print('measure_sections: %s -> %s（%d 字节, %d 节）'
              % (args.exe, args.out_json, r['file'], len(r['sections'])))
    else:
        print(json.dumps(r, indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
