/*
 * gate.c — .NET / 托管侧接入门 (native 薄封装)
 *
 * ## 为什么需要这一层
 * 保护库是纯 C，头文件已内建 extern "C"。托管侧 (.NET) 通过 P/Invoke
 * 调用它, 但直接暴露保护库的全部 API 会带来两个问题:
 *   1. **marshalling 复杂**: 保护库的报告结构体字段多 (antidebug 有 12 个),
 *      托管侧要么重复声明, 要么与之绑死。
 *   2. **ABI 脆弱**: 一旦保护库内部结构体变化, 托管侧跟着破。
 *
 * 故本门只暴露**三个最简 API**, 全部是 `int`, marshalling 零负担:
 *   prot_gate_version()  -> 协议版本 (托管侧可校验)
 *   prot_gate_init()     -> 初始化 (返回 0 成功)
 *   prot_gate_check()    -> 检测: 0=通过 1=可疑环境 2=错误
 *
 * ## 能力边界 (务必对 .NET 用户说明)
 * 本层提供的是**运行环境检测与授权门**, **不能保护 IL 本体**:
 *   · .NET 产物是 IL, 本项目是**编译期源码级**保护框架 -> 保护不了 IL
 *   · 防 ILSpy/dnSpy 反编译需要 IL 混淆/加密工具 (如 ConfuserEx 类), 不是本项目
 * 详见 prot_sdk/dotnet/README.md。
 *
 * ## 导出方式
 * 用 .def 文件 (见 protgate.def) 而非 __declspec(dllexport):
 *   · 不改动保护库头文件, 对现有 C 用户零影响
 *   · .def 是纯 ASCII, 便于工具检查导出表
 */
#include <windows.h>
#include <stdint.h>

#include "protect/protdef.h"
#include "protect/antidebug.h"

/* 协议版本: 托管侧 ProtGate.cs 里应与此保持一致 (见 dotnet/README.md) */
#define PROT_GATE_ABI_VERSION 1

int prot_gate_version(void)
{
    return PROT_GATE_ABI_VERSION;
}

/* 初始化: 目前只做一次反调试基线扫描, 便于尽早发现异常环境。
 * 返回 0 = 正常; 非 0 = 保护库报错。 */
int prot_gate_init(void)
{
    prot_antidebug_report rep;
    if (prot_antidebug_scan(&rep) != PROT_OK) {
        return -1;
    }
    return 0;
}

/* 核心检测。返回:
 *   0 = 环境正常
 *   1 = 检测到可疑 (调试/分析环境)
 *   2 = 保护库错误
 * 注意: **不在此处终止进程** —— 终止策略由托管侧决定 (本项目既有教训:
 * TerminateProcess 不冲刷输出, 且托管侧可能有自己的日志/上报逻辑)。 */
int prot_gate_check(void)
{
    prot_antidebug_report rep;
    if (prot_antidebug_scan(&rep) != PROT_OK) {
        return 2;
    }
    /* R3.2-c: 走非短路多副本聚合入口, 单点 patch 一个副本不再足够 */
    return prot_antidebug_detected_multi(&rep) ? 1 : 0;
}
