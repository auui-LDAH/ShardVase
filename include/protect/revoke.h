/*
 * revoke.h — 授权吊销 (I1, 离线黑名单)
 *
 * 黑名单文件 revoke.blob 随 vm.blob 分发渠道下发, 客户端启动时校验:
 * 命中 -> 按策略拒绝 (strict) 或告警 (warn)。无黑名单文件 = 不阻断
 * (离线优先, 不因分发疏漏锁死客户)。
 *
 * 文件格式 (与 tools/vmenc.py revoke 一致):
 *   MAGIC "PROTREVK"(8) | VER u32 LE | COUNT u32 LE
 *   | 每条目: SERIAL[48] (NUL 填充) | TIER u32 (0xFF=全 tier) | REVOKED_AT u64
 *   | BLOB_CRC u32 (prot_crc32 覆盖以上全部)
 */
#ifndef PROT_REVOKE_H
#define PROT_REVOKE_H

#include "protect/protdef.h"

/* 条目 tier: 吊销该 serial 的全部授权等级 */
#define PROT_REVOKE_TIER_ALL 0xFFu

typedef enum prot_revoke_status {
    PROT_REVOKE_OK = 0,      /* 黑名单有效且未命中 */
    PROT_REVOKE_HIT,         /* 命中 (serial+tier) */
    PROT_REVOKE_NO_FILE,     /* 无黑名单文件 (不阻断路径) */
    PROT_REVOKE_CORRUPT,     /* 黑名单损坏 (不阻断 + 告警) */
    PROT_REVOKE_INVALID_ARG
} prot_revoke_status;

/*
 * 校验黑名单并查询 serial/tier 是否被吊销。
 *   path  : revoke.blob 路径
 *   serial: 用户输入的序列号 (ASCII)
 *   tier  : 当前授权等级 (PROT_LICENSE_TIER_*)
 *   out_ver: 成功读到黑名单时输出其版本号 (可 NULL)
 * 返回 PROT_REVOKE_OK/HIT/NO_FILE/CORRUPT/INVALID_ARG。
 */
prot_revoke_status prot_revoke_check(const char* path,
                                     const char* serial, uint32_t tier,
                                     uint32_t* out_ver);

#endif /* PROT_REVOKE_H */
