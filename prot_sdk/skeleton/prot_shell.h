/*
 * prot_shell.h — 保护壳公共契约 (prot_sdk/skeleton)
 *
 * 骨架结构:
 *   app_main.c        保护装配 + 授权门 (从 demo 剥离业务, 保留全部保护链)
 *   business_stub.c   业务层 (向导生成模板, 用户实现)
 *   prot_shell.h      本文件: 壳与业务层的接口
 *
 * 授权门通过后 shell 调用 prot_business_main(ctx), 业务返回其退出码。
 * ctx 为只读摘要: 业务可用 serial/machine_id/tier/expires 做业务级逻辑
 * (如功能分级), 但不得依赖其完成授权判定 (授权判定在壳内完成)。
 */
#ifndef PROT_SHELL_H
#define PROT_SHELL_H

#include <stdint.h>

/* 授权通过后交给业务的上下文 (值传递, 只读语义) */
typedef struct prot_business_ctx {
    const char* serial;      /* 用户输入的序列号 (长度 <= 47) */
    uint32_t    serial_len;
    uint64_t    machine_id;  /* 硬件绑定标识 */
    uint32_t    license_tier;    /* 授权分级 0/1/2 (参与签名, 不可篡改) */
    uint32_t    license_expires; /* 到期 unix 时间戳, 0=永久 */
    uint32_t    license_ok;      /* 本次授权判定结果 (1=通过) */
} prot_business_ctx;

/* 业务入口: 由 business_stub.c 实现; 壳在授权门通过后调用.
 * 返回值为程序最终退出码. */
int prot_business_main(const prot_business_ctx* ctx);

#endif /* PROT_SHELL_H */