# ShardVase .NET / C# 接入门

> **一句话**：让 .NET 程序调用 ShardVase 的**原生保护库**，做运行环境检测与授权门。
> **状态**：✅ 端到端实测通过（2026-09-21）。

---

## ⚠️ 先读：能力边界（避免误解）

| 本门**能做** | 本门**不能做** |
|--------------|----------------|
| 检测调试器/分析环境（反调试 12 维）| ❌ **保护 IL 本体** |
| 作为授权门（判断后再放行业务）| ❌ 防 ILSpy / dnSpy 反编译 |
| 与原生侧一致的机器绑定能力 | ❌ 加密 .NET 方法体 |

**为什么不能保护 IL**：本项目是**编译期源码级**保护框架（改源码 + 重编译 +
自加密 + VM），而 .NET 产物是 **IL（中间语言）**，在运行时才 JIT 成本机码。
两者作用对象不同。

> **要保护 IL，请用 IL 混淆/加密工具**（如 ConfuserEx 一类）。
> 本项目与本门**不替代**它们，二者可叠加使用：
> IL 混淆保护"代码不可读"，本门提供"环境可检测 + 授权可控"。

---

## 快速开始

### 1. 构建

```powershell
# 从仓库根运行（产出原生 DLL + 托管示例）
powershell -File tools/build_dotnet_gate.ps1
```

产物在 `build/dotnet-gate/`：

| 文件 | 说明 |
|------|------|
| `protgate.dll` | 原生保护库（3 个导出）|
| `gate_example.exe` | C# 示例 |

> **关于工具链**：脚本优先用 `.NET SDK`（`dotnet`）。
> 若本机**没有** SDK，会自动回退到 **Roslyn `csc.exe`**（VS BuildTools 自带）
> + **.NET Framework**（Windows 自带）—— 本机就是这么验证的。
> 两者都没有时，脚本会**显式 SKIP 并打印原因**（不静默跳过）。

### 2. 运行验证

```powershell
cd build\dotnet-gate
.\gate_example.exe
```

**实测输出**：

```
== ShardVase .NET 接入门示例 ==
[通过] 原生库已加载
[通过] ABI 版本 = 1
[通过] 初始化完成
[检测] 结果 = Ok
    环境正常，继续执行业务逻辑。
== 示例结束 ==
```

### 3. 在你自己的项目里用

把 `ProtGate.cs` 加入你的工程，然后：

```csharp
using ShardVase;

if (!ProtGate.TryLoad())
{
    // 原生库缺失通常意味着部署不完整或被人为删除 —— 是有价值的信号
    Console.WriteLine($"原生库不可用: {ProtGate.LoadError}");
    return 2;
}

if (ProtGate.Version != ProtGate.ExpectedVersion) { /* ABI 不匹配，快速失败 */ }

ProtGate.Init();
switch (ProtGate.Check())
{
    case GateResult.Ok:         /* 正常 */ break;
    case GateResult.Suspicious: /* 按你的策略处置（见下）*/ break;
    case GateResult.Error:      /* 环境限制，非必然恶意 */ break;
}
```

**部署**：把 `protgate.dll` 放在 exe 同目录。
**位数必须匹配** —— x64 进程只能加载 x64 DLL。

---

## 为什么是"薄封装"而不是直接暴露保护库

保护库的报告结构体字段很多（如 `antidebug` 有 12 个）。若直接暴露：

| 问题 | 说明 |
|------|------|
| marshalling 复杂 | 托管侧要重复声明结构体，且字段布局必须逐字节对齐 |
| ABI 脆弱 | 保护库内部结构体一变，托管侧跟着破 |

故本门只暴露 **3 个 `int` 级 API**，marshalling 零负担：

```c
int prot_gate_version(void);  /* -> 1 */
int prot_gate_init(void);     /* -> 0 成功 */
int prot_gate_check(void);    /* -> 0 正常 / 1 可疑 / 2 错误 */
```

**用 `.def` 导出而非 `__declspec(dllexport)`**：不改保护库头文件，
对现有 C 用户零影响。

---

## ⚠️ 一个真实的坑（已修，供你避雷）

`.def` 文件被 MSVC 按 **ANSI/GBK** 读取。**若在 `.def` 里写 UTF-8 中文注释，
会让链接器静默丢掉紧随其后的导出符号**。

实测现象（2026-09-21）：`.def` 里写了中文注释后，DLL 只导出 2/3 个符号
（`prot_gate_version` 消失），C# 侧报：

```
EntryPointNotFound: 无法在 DLL"protgate"中找到名为"prot_gate_version"的入口点
```

**修法**：`.def` 保持**纯 ASCII**（注释也用英文）。
本项目已在脚本里加了导出表校验，符号缺失会直接失败而不是产出一个坏 DLL。

---

## 处置策略建议（检测到可疑环境时）

本门**不替你决定**如何处置，因为误报成本因场景而异：

| 策略 | 误报成本 | 适用 |
|------|----------|------|
| 降级功能 | 低 | **推荐默认** |
| 记录并上报 | 低 | 配合降级 |
| 拒绝执行 | **高** | 仅高价值场景，且需充分测试 |

> 本项目既有教训：`TerminateProcess` 不冲刷 stdout，且托管侧可能有自己的
> 日志/上报逻辑 —— 故**不要**在原生层直接终止进程。

---

## 编译其他语言

本门暴露的是**标准 C ABI**（`cdecl` + `int`），故同样可用于：

- **PowerShell**（`Add-Type` + `DllImport`）
- **Python**（`ctypes.CDLL('protgate').prot_gate_check()`）
- **C++/CLI**、**Rust**、**Go**（cgo）等

---

## 关联文档

| 文档 | 内容 |
|------|------|
| `../../docs/WINDOWS_COVERAGE.md` | 各应用形态覆盖率（含 .NET 边界说明）|
| `../../docs/PLATFORM_EXPANSION_PLAN.md` | 本门在整体路线中的位置 |
| `Native/gate.c` | 原生封装实现（含设计理由）|
| `ProtGate.cs` | 托管封装（含异常分类与诊断）|

---

*2026-09-21 · 端到端实测通过（原生 DLL 3/3 导出、C# P/Invoke 调用成功）*
