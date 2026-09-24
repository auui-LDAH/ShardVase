#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""identity.py — 用户身份密钥派生（W4 每用户唯一）

## 目标（商业支点）
  现状: 产物只随**构建**变化（每次构建不同）。
  目标: 产物还随**用户**变化 —— 同一策略的两个用户产物**互不相同**。
  => 破解者无法把一个用户的破解成果迁移给另一个用户，
     也无法靠"买一份正版"来通杀所有用户。

## 设计（**分层派生**，全离线）
```
    发行方主密钥 (vendor master key)
      ├─ 来自 build/keys/license_priv.json 的**密钥材料哈希**（已有材料，无需新造）
      │   （用哈希而非私钥本身 -> 不泄露私钥，且可公开派生）
      ↓ HKDF/SHA-256 派生
    项目密钥 (project key)      <- 每个产品/项目一个
      ↓
    构建种子 (build seed)       <- 每个版本/构建一个
      ↓
    + 用户标识 (user id)        <- 每个客户一个
      ↓
    用户构建种子 (user build seed)
      ↓
    驱动: 节名 / magic / 构建盐 / 模块参数 / 模块选择
```

## 为什么用 HKDF 式**分层派生**而非"一个大随机数"
  · **可追溯**: 从用户产物可推出"这是哪个项目的哪个版本"（发行方算得出，
    攻击者算不出 —— 因为需主密钥）
  · **可吊销**: 泄露一个用户的种子**不影响**其它用户（分层隔离）
  · **可复现**: 同 (项目, 版本, 用户) 恒定产出同一种子 -> 构建可复现（I3 保持）

## 诚实边界
  · 攻击者若拿到**主密钥**，可派生全部用户的种子 -> 故主密钥必须离线保管
    （本项目 `build/keys/` 已在 .gitignore）
  · 用户标识若可猜测（如自增 ID），攻击者仍**无法**派生种子 ——
    因为缺少主密钥。但**弱用户标识会降低社交工程难度**，建议用随机 UUID。
"""
import argparse
import hashlib
import hmac
import json
import os
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def hkdf_expand(prk, info, length=32):
    """RFC 5869 HKDF-Expand（仅 expand，PRK 由调用方给出）。

    为什么自己实现: 项目是 **stdlib-only**（无第三方依赖），
    而 hashlib/hmac 已足够实现 HKDF。
    """
    out = b''
    t = b''
    i = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


def hkdf_extract(salt, ikm):
    """RFC 5869 HKDF-Extract。"""
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def load_master_key(path=None):
    """读取发行方密钥材料 -> 主密钥（IKM）。

    ## 用**哈希**而非私钥本身
      `license_priv.json` 含 RSA 私钥（n/e/d）。直接用它作 IKM 会把
      **私钥材料**牵进派生链（虽不可逆，但无必要）。
      改为: `SHA256(n || e || d || "shardvase-identity-v1")`
      -> 与私钥强绑定（换密钥则全部种子变），但不直接使用私钥。
    """
    if path is None:
        path = os.path.join(REPO, 'build', 'keys', 'license_priv.json')
    if not os.path.exists(path):
        return None
    d = json.load(open(path, encoding='utf-8'))
    h = hashlib.sha256()
    for k in ('n', 'e', 'd', 'bits'):
        h.update(str(d.get(k, '')).encode('utf-8'))
        h.update(b'|')
    h.update(b'shardvase-identity-v1')
    return h.digest()


def derive_seed(master, project, version, user_id, purpose='all'):
    """分层派生用户构建种子。

    ## 分层结构
      master (32B) --extract(salt=project)--> project_prk
                   --extract(salt=version)--> build_prk
                   --expand(info=user_id|purpose)--> user_seed

      **为什么逐层 extract**: 各层之间强隔离 —— 泄露某一层的 PRK
      不会泄露其它项目/版本的 PRK（不同 salt）。
    """
    if master is None:
        raise ValueError('缺少主密钥（build/keys/license_priv.json）')
    prk_p = hkdf_extract(b'shardvase-project|' + project.encode(), master)
    prk_b = hkdf_extract(b'shardvase-version|' + version.encode(), prk_p)
    info = ('shardvase-user|%s|%s' % (user_id, purpose)).encode('utf-8')
    return hkdf_expand(prk_b, info, 32)


def user_seed_hex(master, project, version, user_id, purpose='all'):
    return '0x' + derive_seed(master, project, version, user_id,
                              purpose).hex()


def selftest():
    """负向测试: 派生必须满足**确定性**与**隔离性**。"""
    fails = []

    def case(name, got, want):
        ok = got == want
        print('  %s %-52s %s' % ('ok ' if ok else '**FAIL**',
                                 name, 'ok' if ok else 'got=%r want=%r'
                                 % (got, want)))
        if not ok:
            fails.append(name)

    print('=== HKDF 基本正确性（RFC 5869 测试向量 A.1 简化校验）===')
    # RFC5869 A.1: IKM=0x0b*22, salt=0x000102..0c, info=0xf0f1..f9, L=42
    ikm = bytes.fromhex('0b' * 22)
    salt = bytes.fromhex('000102030405060708090a0b0c')
    info = bytes.fromhex('f0f1f2f3f4f5f6f7f8f9')
    prk = hkdf_extract(salt, ikm)
    case('HKDF-Extract 长度 32', len(prk), 32)
    okm = hkdf_expand(prk, info, 42)
    case('HKDF-Expand 长度 42', len(okm), 42)
    # RFC 5869 A.1 的 OKM 前 8 字节
    case('OKM 前 8 字节匹配 RFC5869',
         okm[:8].hex(), '3cb25f25faacd57a')

    print()
    print('=== 确定性: 同输入 -> 同输出 ===')
    m = hashlib.sha256(b'test-master').digest()
    s1 = derive_seed(m, 'proj', 'v1', 'user-A')
    s2 = derive_seed(m, 'proj', 'v1', 'user-A')
    case('同输入两次派生相同', s1, s2)

    print()
    print('=== 隔离性（每维变化都必须改变输出）===')
    base = derive_seed(m, 'proj', 'v1', 'user-A')
    case('换用户 -> 变', derive_seed(m, 'proj', 'v1', 'user-B') != base, True)
    case('换项目 -> 变', derive_seed(m, 'proj2', 'v1', 'user-A') != base, True)
    case('换版本 -> 变', derive_seed(m, 'proj', 'v2', 'user-A') != base, True)
    case('换用途 -> 变', derive_seed(m, 'proj', 'v1', 'user-A', 'vm')
         != base, True)
    m2 = hashlib.sha256(b'other-master').digest()
    case('换主密钥 -> 变', derive_seed(m2, 'proj', 'v1', 'user-A') != base, True)

    print()
    print('=== 输出质量 ===')
    case('输出 32 字节', len(base), 32)
    case('非全零', base != b'\x00' * 32, True)
    # 雪崩: 用户 id 差 1 位 -> 输出应完全不同
    a = derive_seed(m, 'proj', 'v1', 'user-0000')
    b = derive_seed(m, 'proj', 'v1', 'user-0001')
    diff = sum(1 for x, y in zip(a, b) if x != y)
    case('雪崩: 32 字节中差异 >= 20', diff >= 20, True)

    print()
    print('=' * 66)
    if fails:
        print('[identity-selftest] FAIL: %s' % '; '.join(fails))
        return 1
    print('[identity-selftest] PASS: 派生确定且各层隔离')
    return 0


def main():
    ap = argparse.ArgumentParser(prog='identity.py')
    ap.add_argument('--project', default='shardvase-demo')
    ap.add_argument('--version', default='1')
    ap.add_argument('--user', default=None, help='用户标识（建议随机 UUID）')
    ap.add_argument('--purpose', default='all')
    ap.add_argument('--master', default=None)
    ap.add_argument('--selftest', action='store_true')
    ap.add_argument('--info', action='store_true',
                    help='打印主密钥指纹（不泄露密钥本身）')
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    master = load_master_key(args.master)

    if args.info:
        if master is None:
            print('[identity] 主密钥材料缺失: build/keys/license_priv.json',
                  file=sys.stderr)
            return 1
        fp = hashlib.sha256(master).hexdigest()[:16]
        print('identity: 主密钥指纹 %s（材料存在，长度 %d 字节）'
              % (fp, len(master)))
        print('  （指纹可安全公开；密钥本身不出现在输出中）')
        return 0

    if not args.user:
        ap.error('需要 --user（或用 --selftest / --info）')

    if master is None:
        print('[identity] FAIL: 主密钥材料缺失 %s'
              % (args.master or 'build/keys/license_priv.json'),
              file=sys.stderr)
        return 1

    seed = user_seed_hex(master, args.project, args.version, args.user,
                         args.purpose)
    # 只输出种子（不输出主密钥）
    print(seed)
    return 0


if __name__ == '__main__':
    sys.exit(main())
