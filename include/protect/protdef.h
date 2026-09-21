/*
 * protdef.h — 反逆向保护套件: 公共定义
 *
 * 自研保护库 (VM 解释器 / 反调试 / 完整性校验 / 字符串加密)。
 * Windows x64, MSVC。用法见 docs/CONTRACT.md 与 README.md。
 */
#ifndef PROT_PROTDEF_H
#define PROT_PROTDEF_H

#include <stdint.h>
#include <stddef.h>

#define PROT_KS_MUL 0x5851F42D4C957F2Du  /* 密钥流乘子 */
#define PROT_KS_ADD 0x14057B7EF767814Fu  /* 密钥流加子 */

typedef enum prot_status {
    PROT_OK = 0,
    PROT_ERR_INVALID_ARG,       /* 参数非法 */
    PROT_ERR_INTERNAL,          /* 内部错误 */
    PROT_ERR_VM_BAD_OPCODE,     /* VM: 未知指令 */
    PROT_ERR_VM_STACK_OVERFLOW, /* VM: 栈溢出 */
    PROT_ERR_VM_STACK_UNDERFLOW,/* VM: 栈下溢 */
    PROT_ERR_VM_OUT_OF_BOUNDS,  /* VM: 内存越界 */
    PROT_ERR_VM_CRC,            /* VM: 程序校验失败(被篡改) */
    PROT_ERR_VM_BREAKPOINT,     /* VM: brk 断言陷阱 (A4: CON!=0 时停机) */
    PROT_ERR_INTEGRITY,         /* 完整性校验失败 */
    PROT_ERR_BLOB_MISSING,      /* VM blob: 文件缺失/打不开 (DBI launcher) */
    PROT_ERR_BLOB_CORRUPT,      /* VM blob: 损坏 (magic/CRC/长度) */
    PROT_ERR_BLOB_NAME          /* VM blob: 缺少所需镜像 */
} prot_status;

typedef enum prot_policy {
    PROT_POLICY_CONTINUE = 0,   /* 检测到仅记录, 不干预 */
    PROT_POLICY_EXIT,           /* 检测到立即终止进程 */
    PROT_POLICY_FAKE            /* 检测到静默返回错误结果 */
} prot_policy;

/* 进程退出码约定 (demo / e2e 依赖) */
#define PROT_EXIT_DEBUG_DETECTED 0xDB    /* 219: 调试环境 */
#define PROT_EXIT_TAMPERED       0xBAD   /* 2989: 被篡改 */
#define PROT_EXIT_BLOB_MISSING   0xB10B  /* 45323: VM blob 缺失/损坏 (DBI launcher) */
#define PROT_EXIT_REVOKED        0xB1E4  /* 45540: 授权已被吊销 (I1 黑名单) */

/* CRC32: 标准多项式, 与 Python zlib.crc32 一致 */
uint32_t prot_crc32(const void* data, size_t len);

/* CRC32 流式接口 (Phase 2b: VM 逐字节校验不入内存):
 * init -> 若干次 step -> done; 与整段 prot_crc32 等价。 */
uint32_t prot_crc32_init(void);
uint32_t prot_crc32_step(uint32_t crc, uint8_t byte);
uint32_t prot_crc32_done(uint32_t crc);

#endif /* PROT_PROTDEF_H */