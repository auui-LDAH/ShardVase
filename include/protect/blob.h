/*
 * blob.h — VM 镜像 blob 装载器 (DBI launcher, 技术债 #3)
 *
 * 目标: VM 镜像密文不再静态嵌入 exe, 而是由构建期 (tools/vmenc.py pack)
 * 打包为独立 vm.blob 文件, launcher (demo) 启动时装载进内存再交给
 * prot_vm_run —— 静态拿到 exe 拿不到任何 VM 逻辑, 必须同时拿到分发 blob。
 *
 * blob 格式 (与 tools/vmenc.py pack 一致):
 *   MAGIC[8] "PROTVMBL" | COUNT u32 LE
 *   | 每镜像: NAME[16] | CODE_LEN u32 | KEY0 u64 | KEY1 u64 | CRC u32
 *     | CODE[CODE_LEN] (原 key[0] 滚动密钥流加密, 与 s_code 相同)
 *   | BLOB_CRC u32 (覆盖以上全部, 防篡改)
 *
 * 装载缓冲为密文 (非明文), VM 解释器仍按窗口解密, 用后即焚语义不变。
 */
#ifndef PROT_BLOB_H
#define PROT_BLOB_H

#include <stddef.h>
#include <stdint.h>

#include "protect/vm.h"

/*
 * 从 path 装载 blob 并抽出 names 中列出的镜像 (顺序一致)。
 *   out      : 至少 name_count 个 prot_vm_image, 成功时逐个填充
 *              (code 指向 *out_buf 内的密文, 不拷贝)。
 *   out_buf  : 成功时指向 malloc 的装载缓冲 (调用方负责 free);
 *              失败时为 NULL。
 * 返回 PROT_OK; PROT_ERR_BLOB_MISSING (文件缺失) /
 *       PROT_ERR_BLOB_CORRUPT (magic/CRC/长度) /
 *       PROT_ERR_BLOB_NAME (缺所需镜像)。
 */
prot_status prot_vm_blob_load(const char* path,
                              const char* const* names, uint32_t name_count,
                              prot_vm_image* out,
                              void** out_buf, size_t* out_buf_size);

#endif /* PROT_BLOB_H */
