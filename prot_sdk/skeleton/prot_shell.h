/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 ShardVase contributors
 *
 * 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；
 * 商业授权见 LICENSE.md。
 */
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

/* ==========================================================================
 * 序列号来源提供者 (可选) —— 为 GUI / 无 stdin 场景
 * ==========================================================================
 *
 * 背景 (实测): 保护壳默认从 **stdin** 读序列号。这对控制台程序没问题,
 * 但 **GUI 程序双击运行时没有 stdin** —— 实测结果为序列号为空 ->
 * license: 0 -> 拒绝运行。
 *
 * 解法: 业务层可注册一个"提供者", 壳在需要序列号时**优先**调用它;
 * 未注册时**行为与现在完全一致**(回退 stdin), 故既有工程零影响。
 *
 * 用法 (GUI 程序):
 *   业务层**直接定义**同名函数 prot_shell_serial_provider() 即可。
 *   壳用 MSVC 的 `/alternatename` 弱符号机制解析:
 *     · 业务层**未定义** -> 链接到壳内默认实现(回退 stdin), 行为与现在一致
 *     · 业务层**已定义**   -> 用业务的实现(GUI 弹对话框)
 *   该机制已实测验证(/alternatename:prot_shell_serial_provider=
 *   prot_shell_serial_provider_default)。
 *   构建脚本 (build_skeleton.ps1 -Gui) 会自动加该链接参数。
 *
 * 契约:
 *   · 返回 0 表示已写入序列号(buf 为 NUL 结尾的 ASCII);
 *   · 返回非 0 表示未取得(壳回退 stdin);
 *   · buf 容量至少 48 字节(与壳内 mem.serial 一致)。
 */
#define PROT_SERIAL_BUF_SIZE 48

/* 业务层可实现此函数以接管序列号获取(GUI 弹对话框等)。
 * 不实现则由壳内默认实现回退 stdin。 */
int prot_shell_serial_provider(char* buf, unsigned cap);

#endif /* PROT_SHELL_H */