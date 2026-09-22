/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 ShardVase contributors
 *
 * 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；
 * 商业授权见 LICENSE.md。
 */
/*
 * _template.h — 模块模板头文件 (阶段5: 生态化)
 *
 * ⚠️ 这是**模板**, 不参与构建。复制为 include/protect/<your_module>.h 后改名。
 *
 * 头文件的两个约定 (见 docs/CONTRACT.md §2):
 *   1. 只 #include "protect/protdef.h" (公共类型), 不引入其它模块头
 *   2. 声明的每个 prot_ 函数都会被 tools/modcheck.py 与 modules.json 双向比对
 *      -> 声明了就必须在注册表登记, 反之亦然
 */
#ifndef PROT_TEMPLATE_H
#define PROT_TEMPLATE_H

#include "protect/protdef.h"

/* -------------------------------------------------------------------------
 * 报告结构: 一次采集的全部结果
 *
 * 命名约定: 字段名即检测项名, 与文档/CONTRACT 保持一致。
 * 关键项与咨询项请在注释中**明确标注** —— 这决定 decide 阶段是否计入。
 * ------------------------------------------------------------------------- */
typedef struct prot_template_report {
    uint32_t example_check;     /* 关键项: 示例检测 */
    uint32_t example_advisory;  /* 咨询项: 只报告不参与判定 */
} prot_template_report;

/* 执行全部检测并填充报告; 永不失败 (返回 PROT_OK) */
prot_status prot_template_scan(prot_template_report* out);

/* 任一「关键」检测项命中即返回非 0 (咨询项不计入) */
uint32_t prot_template_suspicious(const prot_template_report* rep);

/* 按策略响应 (咨询项模块请删除本函数) */
prot_status prot_template_apply_policy(prot_policy pol);

#endif /* PROT_TEMPLATE_H */
