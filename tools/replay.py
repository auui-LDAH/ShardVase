#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tools/replay.py — 种子重放调试脚本 (P0)

用 seeds.json 里记录的确定性种子, 对单个 VM 镜像做**精确重放**:
重新汇编/加密出与目标构建逐字节一致的 blob, 并打印 key/sem/crc。
用途: 某轮随机构建 e2e/vm_unit 失败时, 用该轮 seeds.json 复现并
在隔离目录调试 (如链接 vm_unit.c 单跑), 而不必整链重建。

CLI:
    python tools/replay.py <seeds.json> <image-name> [--out-dir DIR]
    # 内置镜像名 -> .vasm 映射; 也可 --vasm 指定
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import vmenc  # noqa: E402

REPO = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

# 镜像名 -> (vasm 相对路径)
KNOWN = {
    'g_vm_hash_image': 'demo/license_hash.vasm',
    'g_vm_mix_image': 'demo/license_mix.vasm',
    'g_vm_verify_image': 'demo/license_verify.vasm',
    'g_vm_gate_image': 'demo/license_gate.vasm',
    'g_vm_unit_image': 'tests/unit_vm.vasm',
    'g_vm_unit_brk_image': 'tests/unit_vm_brk.vasm',
}

BIN_NAMES = {
    'g_vm_hash_image': 'hash',
    'g_vm_mix_image': 'mix',
    'g_vm_verify_image': 'verify',
    'g_vm_gate_image': 'gate',
}


def main():
    parser = argparse.ArgumentParser(description='seed replay debug (P0)')
    parser.add_argument('seeds_json', help='build/seeds.json')
    parser.add_argument('image', help='image name (e.g. g_vm_unit_image)')
    parser.add_argument('--out-dir', default=None,
                        help='output dir (default temp under build/replay)')
    parser.add_argument('--vasm', default=None,
                        help='override .vasm path (default from known map)')
    parser.add_argument('--build-json', default='demo/vm_build.json',
                        help='vm_build.json (default demo/vm_build.json)')
    args = parser.parse_args()

    import json
    with open(args.seeds_json, 'r', encoding='utf-8-sig') as f:
        data = json.load(f)
    imgs = data.get('images', {})
    if args.image not in imgs:
        print('replay: error: image %r not in %s (have: %s)'
              % (args.image, args.seeds_json, ', '.join(sorted(imgs))))
        return 1
    s = imgs[args.image]
    key0 = int(s['key0'], 0)
    key1 = int(s['key1'], 0)

    vasm = args.vasm or KNOWN.get(args.image)
    if vasm is None:
        print('replay: error: no vasm mapping for %r, pass --vasm' % args.image)
        return 1
    vasm = os.path.join(REPO, vasm)

    out_dir = args.out_dir or os.path.join(REPO, 'build', 'replay')
    os.makedirs(out_dir, exist_ok=True)
    stem = os.path.join(out_dir, args.image + '_replay')

    with open(vasm, 'r', encoding='utf-8') as f:
        text = f.read()
    symbols = vmenc.load_symbols(os.path.join(REPO, args.build_json))
    perm, slot, sem0, sem1 = vmenc.make_opcode_keymaps(key1)
    if sorted(slot) != list(range(vmenc.OPCODE_SLOTS)):
        print('replay: error: slot permutation broken')
        return 1
    plaintext = vmenc.assemble_source(text, symbols, perm, sem0)
    code_len, _seed, crc = vmenc.write_vm_c(stem + '.c', stem + '.h',
                                            plaintext, key0, key1,
                                            image_name=args.image)
    bin_name = BIN_NAMES.get(args.image)
    if bin_name:
        vmenc.write_vm_bin(stem + '.bin', bin_name, plaintext, key0, key1)

    print('replay: %s (from %s)' % (args.image, args.seeds_json))
    print('replay:   key0=0x%016x key1=0x%016x sem=[%d,%d] len=%d crc=0x%08x'
          % (key0, key1, sem0, sem1, code_len, crc))
    print('replay:   wrote %s.c/.h%s' % (stem, ' + .bin' if bin_name else ''))
    return 0


if __name__ == '__main__':
    sys.exit(main())
