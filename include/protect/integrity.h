/*
 * integrity.h — 完整性校验: 对自身 .text 段做 CRC32, 与构建期烧录值比对
 *
 * 构建管线 (build.ps1) 最后一步 tools/hashpatch.py 会把 .text 的 CRC32
 * 烧录进二进制 (标记 "PROTCRCP" 处)。运行时任何对代码段的修补都会导致
 * 校验失败。
 */
#ifndef PROT_INTEGRITY_H
#define PROT_INTEGRITY_H

#include "protect/protdef.h"

/* 对自身 .text 段做 CRC32 并与构建期烧录值比对; 一致返回 PROT_OK */
prot_status prot_integrity_check_self(void);

/* 启动后台看门狗线程, 每 interval_ms 检查一次; 失败按 policy 处理 */
prot_status prot_integrity_start_watchdog(prot_policy pol, uint32_t interval_ms);

/* 停止看门狗 (幂等) */
prot_status prot_integrity_stop_watchdog(void);

#endif /* PROT_INTEGRITY_H */