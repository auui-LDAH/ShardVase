// ProtGate.cs — ShardVase 托管侧接入门 (.NET / C#)
//
// ## 这是什么
// 保护库是纯 C 的原生 DLL。本文件是它在 .NET 侧的**薄封装**:
// 用 P/Invoke 调用 3 个 int 级 API, 不引入任何结构体 marshalling。
//
// ## 能力边界（务必先读）
// 本门提供的是**运行环境检测与授权门**, **不能保护 IL 本体**:
//   · .NET 产物是 IL（中间语言），本项目是**编译期源码级**保护框架
//   · 防 ILSpy / dnSpy 反编译需要 IL 混淆/加密工具（如 ConfuserEx 类）
//     —— 那不是本项目的能力范围
// 换句话说: 本门能帮你"判断当前是否在被调试/分析", 不能帮你"隐藏代码逻辑"。
//
// ## 用法
//   using ShardVase;
//   if (!ProtGate.TryLoad()) { /* 原生库缺失: 按你的策略处理 */ }
//   if (ProtGate.Version != ProtGate.ExpectedVersion) { /* ABI 不一致 */ }
//   ProtGate.Init();
//   var r = ProtGate.Check();
//   if (r == GateResult.Suspicious) { /* 检测到调试/分析环境 */ }
//
// ## 部署
//   把 protgate.dll 放在 exe 同目录（或系统可搜索路径）。
//   注意 **位数必须匹配**: x64 进程只能加载 x64 的 DLL。

using System;
using System.IO;
using System.Runtime.InteropServices;

namespace ShardVase
{
    /// <summary>检测结果。</summary>
    public enum GateResult
    {
        /// <summary>环境正常。</summary>
        Ok = 0,
        /// <summary>检测到可疑环境（调试器/分析工具）。</summary>
        Suspicious = 1,
        /// <summary>保护库报错（原生层失败）。</summary>
        Error = 2,
        /// <summary>原生库不可用（未加载或导出缺失）。</summary>
        Unavailable = -1,
    }

    /// <summary>
    /// ShardVase 原生保护库的托管封装。
    ///
    /// 线程安全: 底层 prot_antidebug_scan 只读环境、无全局可变状态，
    /// 可并发调用；但 Init 建议只调一次。
    /// </summary>
    public static class ProtGate
    {
        /// <summary>本封装期望的原生 ABI 版本。与 Native/gate.c 的
        /// PROT_GATE_ABI_VERSION 必须一致。</summary>
        public const int ExpectedVersion = 1;

        private const string Dll = "protgate";

        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        private static extern int prot_gate_version();

        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        private static extern int prot_gate_init();

        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        private static extern int prot_gate_check();

        private static bool _loadTried;
        private static bool _loaded;
        private static string _loadError;

        /// <summary>原生库是否已成功加载（含导出符号可用性检查）。</summary>
        public static bool IsLoaded => _loaded;

        /// <summary>加载失败原因（成功时为 null）。用于诊断，不泄露敏感信息。</summary>
        public static string LoadError => _loadError;

        /// <summary>
        /// 尝试加载原生库并校验导出。可重复调用（内部只尝试一次）。
        /// </summary>
        /// <returns>true = 可用；false = 不可用（见 <see cref="LoadError"/>）。</returns>
        public static bool TryLoad()
        {
            if (_loadTried) return _loaded;
            _loadTried = true;

            try
            {
                // 显式探测: 先确认 DLL 文件在预期位置（给出可诊断的错误）
                string dir = AppContext.BaseDirectory;
                string candidate = Path.Combine(dir, Dll + ".dll");
                if (!File.Exists(candidate))
                {
                    _loadError = $"未找到原生库: {candidate}。" +
                                 "请把 protgate.dll 放到程序同目录，" +
                                 "并确认位数与进程匹配（x64 进程需 x64 DLL）。";
                    return false;
                }

                // 调用一次最轻的 API，验证导出符号真的可用
                int v = prot_gate_version();
                if (v <= 0)
                {
                    _loadError = $"原生库返回异常版本号: {v}";
                    return false;
                }

                _loaded = true;
                _loadError = null;
                return true;
            }
            catch (DllNotFoundException ex)
            {
                _loadError = $"DllNotFound: {ex.Message}。" +
                             "常见原因: 缺少 VC++ 运行库，或位数不匹配。";
                return false;
            }
            catch (EntryPointNotFoundException ex)
            {
                _loadError = $"EntryPointNotFound: {ex.Message}。" +
                             "原生库版本过旧，缺少所需导出符号。";
                return false;
            }
            catch (BadImageFormatException ex)
            {
                _loadError = $"BadImageFormat: {ex.Message}。" +
                             "位数不匹配（32 位进程加载 64 位 DLL 或反之）。";
                return false;
            }
        }

        /// <summary>原生库报告的 ABI 版本。未加载时返回 0。</summary>
        public static int Version
        {
            get
            {
                if (!_loaded) return 0;
                try { return prot_gate_version(); }
                catch { return 0; }
            }
        }

        /// <summary>
        /// 初始化（含一次基线扫描）。
        /// </summary>
        /// <returns>true = 初始化成功。</returns>
        public static bool Init()
        {
            if (!_loaded) return false;
            try { return prot_gate_init() == 0; }
            catch { return false; }
        }

        /// <summary>
        /// 执行一次环境检测。**不终止进程** —— 处置策略由调用方决定
        /// （本项目既有教训: 强行终止会丢失日志/上报）。
        /// </summary>
        public static GateResult Check()
        {
            if (!_loaded) return GateResult.Unavailable;
            try
            {
                int r = prot_gate_check();
                return r switch
                {
                    0 => GateResult.Ok,
                    1 => GateResult.Suspicious,
                    2 => GateResult.Error,
                    _ => GateResult.Error,
                };
            }
            catch
            {
                return GateResult.Error;
            }
        }
    }
}
