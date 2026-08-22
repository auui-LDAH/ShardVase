/*
 * selfcrypt.h — 运行时自变形 (N1)
 *
 * 目标: VM 引擎关键函数 (prot_vm_run 等) 静态是密文, 运行时解密执行
 * —— dump/静态反汇编看不到引擎逻辑。
 *
 * 机制 (方案 B: 原位加密, D2a 一次性解密; 一期已落地):
 *   1. 构建期 tools/selfcrypt_proto.py 后处理: 定位目标函数体 (构建期 .map
 *      + .pdata 取大小), 用 CONTRACT §3 滚动密钥流 XOR **原位**加密
 *      (不搬移, 无跳板 — 函数内 E8/E9 rel32 不受影响);
 *   2. meta (rva/len/key) 写入 .protcrypt 专用节 (.protcry);
 *   3. 运行期 prot_selfcrypt_init(): 读 meta -> VirtualProtect RW ->
 *      原位解密 -> FlushInstructionCache -> RX。
 *
 * 完整性 (D1b): .text CRC 对加密段掩码 (hashpatch.py --mask +
 * integrity.c build_selfcrypt_mask), 加密态/解密态该段不参与 CRC, 零误报。
 * 解密态 CRC 校验 (II-1) / 调用级解密 (II-2) / 多函数覆盖 (II-3)
 * 为二期增强, 计划见 docs/N1_PHASE2_PLAN.md。
 *
 * 降级开关: PROT_SELFCRYPT_DISABLE 编译宏 -> init 空转 (函数不加密,
 * 直接运行原函数)。
 */
#ifndef PROT_SELFCRYPT_H
#define PROT_SELFCRYPT_H

#include "protect/protdef.h"

/* 密文容器/元数据 (demo/main.c 的 .protcrypt 专用节占位)。
 * blob 布局 (构建期 selfcrypt_proto.py 写入):
 *   [count u32 LE][entry * count]
 *   entry = { rva u32 | len u32 | key0 u64 } (16B; 二期 II-1 加 crc u32 -> 20B)
 * 运行期 prot_selfcrypt_init 从 blob 头读 meta 并原位解密。 */
extern uint8_t g_prot_selfcrypt_blob[];
extern const uint32_t g_prot_selfcrypt_blob_size;

/*
 * 解密全部目标函数 (一次性, D2a)。main 早期调用。
 * 返回 PROT_OK 或 PROT_ERR_INTEGRITY (解密态 CRC 失败, 二期 II-1 实现)。
 */
prot_status prot_selfcrypt_init(void);

#endif /* PROT_SELFCRYPT_H */