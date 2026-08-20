/*
 * license.h — RSA 授权验签 (A1): 公钥验签, 私钥离线签发
 *
 * 定位: docs/PRODUCTION.md A1 / docs/THREATMODEL.md §4 —— 让"伪造合法校验值"
 * 从可计算函数 (FNV/xorshift) 变成 RSA 私钥才能签出 (防伪造)。私钥只存在于
 * 签发侧 (tools/vmenc.py keygen/sign, build/keys/license_priv.json, gitignore),
 * 二进制只嵌公钥 BCRYPT_RSAPUBLIC_BLOB (demo/gen/license_pubkey.c)。
 *
 * 关键判定位仍进 VM: demo 在宿主先算出 license_ok, 再由 VM#4 把它与 result
 * 逐位判定相结合 (见 demo/license_gate.vasm), 不依赖单一宿主调用点可 patch。
 */
#ifndef PROT_LICENSE_H
#define PROT_LICENSE_H

#include <stddef.h>
#include <stdint.h>

/* 产品标识, 参与签名载荷 —— 与 tools/vmenc.py LICENSE_PRODUCT 必须一致 */
#define PROT_LICENSE_PRODUCT "PROT-DEMO-2026"

/* 分级授权 (Phase 4): tier 参与签名载荷, 与 vmenc.py LICENSE_TIER_* 一致 */
#define PROT_LICENSE_TIER_TRIAL   0
#define PROT_LICENSE_TIER_FULL    1
#define PROT_LICENSE_TIER_PREMIUM 2

/* 公钥 blob (BCRYPT_RSAPUBLIC_BLOB, 由 tools/vmenc.py keygen 生成) */
extern const uint8_t g_prot_license_pubblob[];
extern const size_t g_prot_license_pubblob_len;

/*
 * 构建签名载荷 = serial(ascii) || machine_id(LE64) || PRODUCT(ascii) || tier(1B)
 *             || expires(4B LE, unix; 0=永久)。
 * 与 tools/vmenc.py license_message 完全一致。
 */
size_t prot_license_build_message(const char* serial, size_t serial_len,
                                  uint64_t machine_id, uint32_t tier,
                                  uint32_t expires,
                                  uint8_t* out_msg, size_t out_cap);

/*
 * 验签 (RSA-2048 + PKCS#1 v1.5 + SHA-256):
 *   msg:    prot_license_build_message 的结果
 *   msg_len: 载荷长度
 *   sig:    256 字节 RSA 签名 (base64 解码后)
 * 返回 1 签名有效, 0 无效/参数错误/内部失败。
 */
int prot_license_verify(const uint8_t* msg, size_t msg_len,
                        const uint8_t* sig, size_t sig_len);

#endif /* PROT_LICENSE_H */