// Program.cs — .NET 接入门用法示例
//
// 演示: 加载原生保护库 -> 校验 ABI -> 初始化 -> 检测 -> 按结果决定策略。
//
// 编译与运行见 prot_sdk/dotnet/README.md。

using System;
using ShardVase;

internal static class Program
{
    private static int Main(string[] args)
    {
        Console.WriteLine("== ShardVase .NET 接入门示例 ==");

        // ---- 1. 加载原生库 ----
        if (!ProtGate.TryLoad())
        {
            // 生产的建议: 原生库缺失通常意味着**部署不完整或被人为删除**。
            // 这是一个有价值的信号, 不要静默忽略。
            Console.WriteLine($"[失败] 原生库不可用: {ProtGate.LoadError}");
            return 2;
        }
        Console.WriteLine("[通过] 原生库已加载");

        // ---- 2. 校验 ABI 版本 ----
        // 版本不一致说明 DLL 与托管封装不匹配, 应视为部署错误（快速失败,
        // 而不是带着不确定的 ABI 继续跑）。
        int v = ProtGate.Version;
        if (v != ProtGate.ExpectedVersion)
        {
            Console.WriteLine($"[失败] ABI 版本不匹配: DLL={v} " +
                              $"期望={ProtGate.ExpectedVersion}");
            return 3;
        }
        Console.WriteLine($"[通过] ABI 版本 = {v}");

        // ---- 3. 初始化 ----
        if (!ProtGate.Init())
        {
            Console.WriteLine("[失败] 初始化失败");
            return 4;
        }
        Console.WriteLine("[通过] 初始化完成");

        // ---- 4. 检测 ----
        GateResult r = ProtGate.Check();
        Console.WriteLine($"[检测] 结果 = {r}");

        switch (r)
        {
            case GateResult.Ok:
                Console.WriteLine("  环境正常，继续执行业务逻辑。");
                break;

            case GateResult.Suspicious:
                // 处置策略由你决定。示例只降级，不终止 ——
                // 本项目既有教训: 强行终止会丢失日志与上报机会。
                Console.WriteLine("  检测到可疑环境。此处按你的策略处置：");
                Console.WriteLine("    · 降级功能（推荐，误报成本低）");
                Console.WriteLine("    · 记录并上报");
                Console.WriteLine("    · 拒绝执行（误报成本高，慎用）");
                break;

            case GateResult.Error:
                Console.WriteLine("  保护库报错 —— 可能是环境限制，非必然恶意。");
                break;

            default:
                Console.WriteLine("  原生库不可用。");
                break;
        }

        Console.WriteLine("== 示例结束 ==");
        return 0;
    }
}
