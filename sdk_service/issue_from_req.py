#!/usr/bin/env python3
# issue_from_req.py — 签发侧: .req 申请 -> license.txt (sdk_service A-1)
# 用法: python issue_from_req.py --key keys/prot-priv.json \
#        --req reqs/xxx.req --serial SN-2026-0001 \
#        --out licenses/<客户>/license.txt
# 签发前人工步骤 (不可省略): 核对客户用另一渠道报来的 MACHINE_ID
# 与 .req 内 machine_id_hex 一致。serial 由签发方自定 (对应一份订单)。
import argparse
import datetime
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'tools'))
import vmenc


def load_req(path):
    with open(path, 'r', encoding='utf-8') as f:
        req = json.load(f)
    if req.get('schema') != 'prot-req/1':
        raise vmenc.VasmError('不支持的申请文件 schema: %r'
                              % req.get('schema'))
    mid_text = req.get('machine_id_hex')
    if not mid_text or mid_text in ('0x0', '0'):
        raise vmenc.VasmError('申请文件缺少有效的 machine_id')
    return req, vmenc.parse_machine_id_override(mid_text)


def main():
    ap = argparse.ArgumentParser(
        description='读 .req 申请 -> 用 vmenc issue 签发 license.txt')
    ap.add_argument('--key', dest='key_path', required=True,
                    help='私钥 JSON (keys/prot-priv.json)')
    ap.add_argument('--req', dest='req_path', required=True,
                    help='客户发来的 .req 申请文件')
    ap.add_argument('--serial', dest='serial', required=True,
                    help='订单/序列号 (签发方自定, ASCII)')
    ap.add_argument('--out', dest='license_out', required=True,
                    help='输出 license.txt')
    ap.add_argument('--tier', dest='tier', type=int,
                    default=vmenc.LICENSE_TIER_FULL,
                    help='授权分级 0=trial 1=full(默认) 2=premium')
    ap.add_argument('--expires', dest='expires', type=int, default=0,
                    help='到期 unix 时间戳 (0=永久)')
    ap.add_argument('--log', dest='log', default=None,
                    help='签发日志 (默认 build/issue-log.csv)')
    args = ap.parse_args()

    if not args.serial.isascii():
        sys.exit('error: --serial 必须为 ASCII')
    req, mid = load_req(args.req_path)

    print('issue_from_req: 双通道核对提醒 — 客户另行报来的 MACHINE_ID '
          '应为 %s, 一致再继续' % req['machine_id_hex'])

    with tempfile.NamedTemporaryFile(
            'w', suffix='.json', delete=False) as tf:
        json.dump({'serial': args.serial, 'machine_id': mid}, tf)
        tmp_json = tf.name
    try:
        a = args
        a.json_path = tmp_json
        a.machine_id_override = str(mid)
        a.customer = req['customer']
        a.note = '%s req_nonce=%s req_at=%s' % (
            req.get('note', ''), req.get('nonce', '?'),
            req.get('requested_at', '?'))
        if a.log is None:
            a.log = 'build/issue-log.csv'
        vmenc.cmd_issue(a)
    finally:
        os.unlink(tmp_json)

    print()
    print('issue_from_req: 回执信息 (复制进邮件发给客户):')
    print('  SERIAL     = %s' % args.serial)
    print('  MACHINE_ID = %s' % req['machine_id_hex'])
    print('  TIER       = %d' % args.tier)
    print('  EXPIRES    = %d' % args.expires)
    print('  license    = %s' % os.path.abspath(args.license_out))


if __name__ == '__main__':
    main()