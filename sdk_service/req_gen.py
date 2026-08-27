#!/usr/bin/env python3
# req_gen.py — 客户侧申请文件生成器 (sdk_service A-1)
# 目标机器(Windows)上运行: python req_gen.py --name "公司名"
# 产物 .req 需人工发给签发方; 同时把屏幕打印的 MACHINE_ID 用另一渠道
# (电话/微信) 报给签发方做双通道核对。
import argparse
import datetime
import json
import os
import secrets
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'tools'))
import vmenc


def main():
    ap = argparse.ArgumentParser(
        description='生成 .req 授权申请文件 (machine_id 取自本机)')
    ap.add_argument('--name', dest='customer', required=True,
                    help='申请人/公司名 (写入申请文件, 不可含换行)')
    ap.add_argument('--note', dest='note', default='',
                    help='备注 (如 订单号/联系方式), 可空')
    ap.add_argument('--out', dest='out', default=None,
                    help='输出 .req 路径 (默认 reqs/<nonce8>.req)')
    args = ap.parse_args()

    if '\n' in args.customer or '\r' in args.customer:
        sys.exit('error: --name 不能包含换行符')

    mid = vmenc.hostid()
    if not mid:
        sys.exit('error: machine_id 计算失败 (需 Windows 且可访问系统盘)')

    req = {
        'schema': 'prot-req/1',
        'product': vmenc.LICENSE_PRODUCT,
        'customer': args.customer,
        'machine_id_hex': '0x%x' % mid,
        'requested_at': datetime.datetime.now(
            datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'nonce': secrets.token_hex(8),
        'note': args.note,
    }

    out = args.out
    if out is None:
        base = os.path.dirname(os.path.abspath(__file__))
        out = os.path.join(base, 'reqs', '%s-%s.req'
                           % (req['nonce'][:8], args.customer.strip()))

    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    with open(out, 'w', encoding='utf-8', newline='\n') as f:
        json.dump(req, f, ensure_ascii=False, indent=2)
        f.write('\n')

    print('req_gen: 申请文件已生成: %s' % out)
    print('req_gen: 请将该文件发给签发方; 并用电话/微信另行报出:')
    print('req_gen:   MACHINE_ID = %s' % req['machine_id_hex'])
    print('req_gen:   nonce      = %s' % req['nonce'])


if __name__ == '__main__':
    main()