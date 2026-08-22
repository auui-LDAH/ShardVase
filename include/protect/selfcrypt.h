/*
 * selfcrypt.h — 运行时自变形 (N1, 阶段 0 原型)
 *
 * 目标: VM 引擎关键函数 (prot_vm_run 等) 静态是密文, 运行时一次性解密
 * 执行 —— dump/静态反汇编看不到引擎逻辑。
 *
 * 机制 (阶段 0 原型, D2a 启动一次性解密):
 *   1. 构建期 tools/selfcrypt_proto.py 后处理: 定位目标函数体 (构建期 .map),
 *      用 CONTRACT §3 滚动密钥流 XOR 加密, 密文写入 .protcrypt 专用节
 *      (不进 .text/.rdata/.pdata CRC 覆盖区, D1a);
 *      .text 原位保留 5 字节跳板 E9 rel32 -> selfcrypt 解密例程。
 *   2. 运行期 prot_selfcrypt_init(): 定位 .protcrypt 元数据 ->
 *      VirtualProtect RW -> 解密 -> FlushInstructionCache -> RX。
 *      (解密态 CRC 校验 + 看门狗周期重加密为后续阶段, 原型不实现)
 *
 * 降级开关: PROT_SELFCRYPT_DISABLE 编译宏 -> init 空转 (函数体不加密,
 * 跳板在构建期不生成, 直接运行原函数)。
 */
#ifndef PROT_SELFCRYPT_H
#define PROT_SELFCRYPT_H

#include "protect/protdef.h"

/* 密文容器 (demo/main.c 的 .protcrypt 专用节占位)。
 * blob 布局 (构建期 selfcrypt_proto.py 写入):
 *   [count u32 LE][entry * count][密文连续]
 *   entry = { rva u32 | len u32 | key0 u64 | crc u32 } (16B)
 * 运行期 prot_selfcrypt_init 从 blob 头读 meta 并原地解密。 */
extern uint8_t g_prot_selfcrypt_blob[];
extern const uint32_t g_prot_selfcrypt_blob_size;

/*
 * 解密全部目标函数 (一次性, D2a)。main 早期调用。
 * 返回 PROT_OK 或 PROT_ERR_INTEGRITY (解密态 CRC 失败, 阶段 2 实现)。
 */
prot_status prot_selfcrypt_init(void);

#endif /* PROT_SELFCRYPT_H */
