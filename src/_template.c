/*
 * src/_template.c — 模块模板 (阶段5: 生态化)
 *
 * ⚠️ 这是**模板**, 不参与构建。复制到 src/<your_module>.c 后改名使用。
 *
 * ============================================================================
 * 一个「检测器模块」的最小完整实现
 * ============================================================================
 *
 * 本模板演示最常见的模块形态: 采集 -> 判定 (可选: 响应)。
 * 现有三个检测器 (antidebug / dbiguard / vmdetect) 都是这个形状。
 *
 * 落地步骤 (详见 docs/MODULE_GUIDE.md):
 *   1. 复制本文件 -> src/<your_module>.c, 复制 _template.h -> include/protect/<your_module>.h
 *   2. 在 modules.json 登记 (可用 python tools/modcheck.py 验证)
 *   3. 在 demo/main.c 与 prot_sdk/skeleton/app_main.c 加 #ifdef PROT_MOD_<YOUR_MODULE> 调用段
 *   4. 补至少一条 drills/drill<N>.json 演练记录
 *   5. 跑 python tools/modcheck.py  +  build.ps1
 *
 * 设计约束 (违反会导致组合失败或安全回归):
 *   · 只依赖 protect/protdef.h 与自身头文件 (低耦合是既有的优点, 别破坏)
 *   · 不要假设其它模块存在 (可用 requires_caps/deps 声明依赖)
 *   · 检测函数「永不失败」: 返回 PROT_OK, 具体结果放 report 结构里
 *   · 任何「会改写状态」的行为都必须显式声明 (modifies_text / needs_writable_dir)
 *   · 绝不能静默吞掉错误 —— 诚实边界是这个项目的核心资产
 */
#include "protect/protdef.h"
#include "protect/_template.h"

#include <windows.h>
#include <string.h>

/* -------------------------------------------------------------------------
 * 内部状态
 * ------------------------------------------------------------------------- */

/* 最近一次采集的结果。注意: 用 static 而非局部, 便于 decide 阶段读取;
 * 多线程场景请自行加锁 (参考 selfcrypt.c 的 SRWLOCK 用法)。 */
static prot_template_report g_last;
static int g_last_valid = 0;

/* -------------------------------------------------------------------------
 * 采集: 执行全部检测, 填充 report
 *
 * 约定: **永不失败** (返回 PROT_OK)。单项检测失败时该项保持 0 并继续 ——
 * 环境不允许某项检测 (如权限不足) 不等于"检测到问题", 也不等于模块失败。
 * ------------------------------------------------------------------------- */
prot_status prot_template_scan(prot_template_report* out)
{
    if (out == NULL)
        return PROT_ERR_INVALID_ARG;

    memset(out, 0, sizeof(*out));

    /* --- 检测项 1: 示例 —— 检查一个可查询的系统属性 ---
     * 真实模块请替换为有意义的检测 (参考 antidebug.c 的 12 个维度)。 */
    {
        HMODULE h = GetModuleHandleW(NULL);
        if (h != NULL) {
            /* 这里放你的检测逻辑。示例: 记录模块基址是否可读。 */
            out->example_check = 1u;
        }
    }

    /* --- 检测项 2: 示例 —— 一个"咨询项" (advisory) ---
     * advisory = 命中只报告, 不参与判定。用于误报成本高的检测。
     * 现有例子: dbiguard 的 frida 匹配、vmdetect 的整组检测。 */
    out->example_advisory = 0u;

    /* 保存状态供 decide 阶段用 */
    g_last = *out;
    g_last_valid = 1;

    return PROT_OK;
}

/* -------------------------------------------------------------------------
 * 判定: 依据 report 给出"是否可疑"
 *
 * 约定: 返回非 0 = 可疑。**只聚合「关键项」**, 咨询项不计入 ——
 * 这是本项目反调试模块的既有设计 (关键项 7 个 / 咨询项 5 个)。
 * ------------------------------------------------------------------------- */
uint32_t prot_template_suspicious(const prot_template_report* rep)
{
    if (rep == NULL)
        return 0u;

    /* 关键项命中 -> 可疑。用位或而非短路, 便于将来扩展为"命中了几项" */
    return (rep->example_check != 0u) ? 1u : 0u;

    /* 咨询项 (example_advisory) 刻意**不**计入 —— 误报成本高 */
}

/* -------------------------------------------------------------------------
 * 响应 (可选): 按策略处理
 *
 * 如果你的模块是"咨询项"(只报告不阻断), **不要**提供本函数 ——
 * 参考 dbiguard.h / vmdetect.h: 它们只有 scan + suspicious。
 * 需要的模块参考 antidebug.h 的 apply_policy。
 * ------------------------------------------------------------------------- */
prot_status prot_template_apply_policy(prot_policy pol)
{
    if (!g_last_valid)
        return PROT_OK;                 /* 未采集过, 无动作 */

    if (!prot_template_suspicious(&g_last))
        return PROT_OK;                 /* 无可疑, 无动作 */

    switch (pol) {
    case PROT_POLICY_EXIT:
        /* 立即终止。注意: TerminateProcess **不冲刷 stdout**,
         * 宿主需先 printf + fflush 再触发策略 (参考 demo/main.c 的注释)。 */
        TerminateProcess(GetCurrentProcess(), PROT_EXIT_DEBUG_DETECTED);
        return PROT_OK;
    case PROT_POLICY_FAKE:
        /* 静默返回错误结果 (由宿主翻转), 不终止进程。 */
        return PROT_OK;
    case PROT_POLICY_CONTINUE:
    default:
        return PROT_OK;                 /* 只记录 */
    }
}
