/*
 * vm.h — VM 解释器: 加密字节码 + 栈式虚拟机
 *
 * 关键逻辑 (如序列号校验) 以私有字节码编写, 由 tools/vmenc.py 汇编并加密,
 * 二进制中只存在密文。攻击者面对的是未知指令集, 无法直接读懂/修补。
 */
#ifndef PROT_VM_H
#define PROT_VM_H

#include "protect/protdef.h"

/* 加密的 VM 程序镜像 (由 tools/vmenc.py 生成) */
typedef struct prot_vm_image {
    const uint8_t* code;   /* 加密字节码 */
    uint32_t code_len;     /* 明文长度 */
    uint64_t key[2];       /* 密钥流种子 (key[1] 保留为 0) */
    uint32_t crc;          /* 明文 crc32 */
} prot_vm_image;

/*
 * 运行 VM 程序。
 * img:      加密镜像 (vm_run 先解密并做 CRC 校验, 被篡改即返回 PROT_ERR_VM_CRC)
 * mem_base: 宿主内存基址 (VM 的 load/store 以此为基, 相对寻址)
 * mem_size: 宿主内存大小 (越界访问即返回 PROT_ERR_VM_OUT_OF_BOUNDS)
 * 线程安全: 无共享状态, 可并发调用。
 */
prot_status prot_vm_run(const prot_vm_image* img, void* mem_base, size_t mem_size);

#endif /* PROT_VM_H */