/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 ShardVase contributors
 *
 * 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；
 * 商业授权见 LICENSE.md。
 */
/*
 * business_stub.c — 业务层模板 (prot_sdk/skeleton)
 *
 * 用法:
 *   1. 把本文件复制到你的工程 (向导已生成);
 *   2. 在 prot_business_main 中写你的业务逻辑 (在授权门通过后执行);
 *   3. 需要"按授权分级"的功能用 ctx->license_tier 判断 (0 试用/1 正式/2 高级);
 *   4. 需要"业务函数本身被 VM 保护"时, 按 prot_sdk 文档把函数体翻译为
 *      .vasm 指令 (与 demo/license_*.vasm 同模式), 经 vmenc assemble 生成
 *      blob 后由壳装载执行 —— 当前骨架的 VM 链保护"授权判定"链路, 业务
 *      VM 是可选加固 (接入文档有示例)。
 *
 * 本模板演示: 上下文可读 + 一个可被 VM 化的纯计算示例, 供新手起手。
 */
#include <stdio.h>
#include <string.h>

#include "prot_shell.h"

/* tier 上限与壳内定义 (PROT_LICENSE_TIER_PREMIUM=2) 一致 */
#define PROT_BUSINESS_TIER_PREMIUM_HINT 2

/* -- 示例业务函数 A: 纯函数 (适合迁移进 VM, 无 IO 依赖) ------------------ */
static unsigned long long business_calc(const char* serial, uint64_t hwid)
{
    /* 占位业务: 用序列号与机器码做一个确定性的业务种子.
     * 真实业务替换后, 可把本函数体翻译进 .vasm 获得 VM 保护. */
    unsigned long long seed = 1469598103934665603ull; /* FNV basis (示意) */
    size_t i;
    for (i = 0; serial[i] && i < 8; i++) {
        seed ^= (unsigned char)serial[i];
        seed *= 1099511628211ull;
    }
    seed ^= hwid;
    return seed;
}

/* -- 示例业务函数 B: 需要 IO 的业务 (保持在宿主, 由壳的完整性/watchdog 保护) */
static void business_report(const prot_business_ctx* ctx, unsigned long long seed)
{
    printf("  business: serial=%s tier=%u expires=%u seed=0x%016llx\n",
           ctx->serial, ctx->license_tier, ctx->license_expires,
           (unsigned long long)seed);
    /* 此处可调用你的业务核心: 加载数据/启动界面/网络等 */
}

/* -- 业务入口 (壳在授权门通过后调用; 返回值 = 程序退出码) ------------------ */
int prot_business_main(const prot_business_ctx* ctx)
{
    unsigned long long seed;

    if (ctx == NULL || !ctx->license_ok) {
        return 1; /* 防御: 授权未通过不应到达这里 */
    }

    seed = business_calc(ctx->serial, ctx->machine_id);
    /* 分级示例: premium (tier=2) 才展示高级信息 */
    if (ctx->license_tier >= PROT_BUSINESS_TIER_PREMIUM_HINT) {
        printf("  business: premium features enabled\n");
    }
    business_report(ctx, seed);

    return 0; /* 业务正常结束 -> 程序退出码 0 */
}