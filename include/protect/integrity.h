/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 ShardVase contributors
 *
 * 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；
 * 商业授权见 LICENSE.md。
 */
/*
 * integrity.h — 完整性校验: 对自身 .text 段做 CRC32, 与构建期烧录值比对
 *
 * 构建管线 (build.ps1) 最后一步 tools/hashpatch.py 会把 .text 的 CRC32
 * 烧录进二进制 (标记 "PROTCRCP" 处)。运行时任何对代码段的修补都会导致
 * 校验失败。
 *
 * G2 边界 (ATTACK_DRILL2 揭示): .rdata/.pdata CRC 是文件级, loader 写入的
 * IAT 导入地址被掩码排除 —— 运行期 IAT 改写 (hook 导入表) 不在文件 CRC
 * 覆盖内。prot_integrity_check_iat 补此洞: 快照 IAT 初始值, 周期比对。
 */
#ifndef PROT_INTEGRITY_H
#define PROT_INTEGRITY_H

#include "protect/protdef.h"

/* 对自身 .text 段做 CRC32 并与构建期烧录值比对; 一致返回 PROT_OK */
#ifdef __cplusplus
extern "C" {
#endif

prot_status prot_integrity_check_self(void);

/*
 * 运行期 IAT 完整性 (G2 补洞): 比对 IAT 表项与首次调用时的快照。
 * loader 在启动时写入导入地址 (合法), 运行期改写 (hook) 会与快照不一致。
 * 首次调用建立快照返回 PROT_OK; 后续调用比对, 不一致返回 PROT_ERR_INTEGRITY。
 */
prot_status prot_integrity_check_iat(void);

/*
 * R3.2-b (2026-09-29): **判定点序言快照校验**
 *
 * ## 为什么需要
 *   段 CRC 会**先清零 selfcrypt 区**（`build_selfcrypt_mask`）->
 *   落在掩码区内的判定点**改它不影响 CRC**（静态完整性抓不到）。
 *   本校验**不依赖 CRC** -> 对"落掩码区"与"重算 CRC"两种规避**都有效**。
 *
 * ## 语义（仿 `prot_integrity_check_iat`）
 *   首次调用建立快照（各判定函数**序言 16 字节**）；
 *   之后逐字节比对，不一致即 `PROT_ERR_INTEGRITY`。
 *   **只读、无副作用**，可由看门狗周期调用。
 *
 * ## 诚实边界
 *   · D2b（调用级解密）下若函数处于**加密态**，快照/比对的对象是密文 ——
 *     仍能检出 patch（明文 != 密文），但**会随 enter/leave 抖动**；
 *     默认 D2a（init 解密后保持明文）无此问题。
 *   · 快照本身位于可写数据段 —— 能同时改快照的**更强攻击者**不在本校验范围内
 *     （记入 known limits）。
 */
prot_status prot_integrity_check_guards(void);

/*
 * R3.2-b 第2组 (2026-09-29): **判定点注册**（跨模块，**不引入编译期依赖**）
 *
 * ## 为什么用注册而非直接引用
 *   `integrity` 的 deps 只有 `[antidebug, selfcrypt]`。直接 `#include`
 *   `license.h`/`dbiguard.h`/`vmdetect.h` 会**破坏组合裁剪**
 *   （`compositions/minimal` 不含这些模块 -> 链接失败 / modcheck 报 R 项）。
 *   注册式: 由**宿主**在 `#ifdef PROT_MOD_<X>` 下登记，
 *   `integrity.c` **不引用**那些模块的任何符号 -> 裁剪语义完好。
 *
 * ## 判定点清单的**官方来源**
 *   `modules.json` 的 `host_hooks[].predicate`（不另发明清单）:
 *     dbiguard.pre_license.predicate = prot_dbiguard_suspicious
 *     vmdetect.post_license.predicate = prot_vmdetect_suspicious
 *     antidebug.post_license.predicate = prot_antidebug_detected（编译期已含）
 *     integrity.pre_business.predicate = prot_integrity_check_self（编译期已含）
 *   `prot_license_verify` 不在 `host_hooks`（它是**宿主自己的授权门**）。
 *
 * ## 语义
 *   · 必须在本进程**第一次** `prot_integrity_check_guards()` 之前完成登记
 *     （在 `prot_integrity_start_watchdog` 之前，见宿主代码）。
 *   · 超出容量（`PROT_GUARD_CAPACITY`）-> 返回 `PROT_ERR_INVALID_ARG`
 *     **并明确失败**（不静默丢弃 —— 静默丢弃 = 假防护）。
 *   · `fn == NULL` -> 返回 `PROT_ERR_INVALID_ARG`。
 *   · `name`: 仅用于诊断输出（可为 NULL）。
 *
 * ## 诚实边界
 *   · 只快照**序言 `PROT_GUARD_SNAP_LEN` 字节** —— 改函数**中部**
 *     （超出快照窗口）**不在本校验范围内**（记入 known_limits）。
 *   · 注册发生在运行期 -> **能控制宿主的攻击者**可跳过登记（与
 *     "能改快照表的攻击者"同属已知边界）。
 */
#define PROT_GUARD_CAPACITY 12u

prot_status prot_integrity_register_guard(const char* name, const void* fn);

/* 启动后台看门狗线程, 每 interval_ms 检查一次; 失败按 policy 处理 */
prot_status prot_integrity_start_watchdog(prot_policy pol, uint32_t interval_ms);

/* 停止看门狗 (幂等) */
prot_status prot_integrity_stop_watchdog(void);

/* W2 (WIN_ENHANCE): 注册周期回调 —— 看门狗每轮额外调用 (返回 PROT_OK 通过;
 * 非 PROT_OK 按 policy 处理). 用于运行期数据自校验 (N3 冗余/关键字段).
 * callback 必须线程安全; NULL 取消注册. */
typedef prot_status (*prot_wd_callback)(void);
void prot_integrity_set_watchdog_callback(prot_wd_callback cb);


#ifdef __cplusplus
}   /* extern "C" */
#endif
#endif /* PROT_INTEGRITY_H */