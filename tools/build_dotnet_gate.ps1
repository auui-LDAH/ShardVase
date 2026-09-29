# build_dotnet_gate.ps1 — 构建 .NET 接入门（原生 DLL + 托管示例）
#
# 用法:
#   powershell -File tools/build_dotnet_gate.ps1
#   powershell -File tools/build_dotnet_gate.ps1 -SkipManaged   # 只编原生 DLL
#
# 设计要点（实测依据）:
#   · **本机可能没有 .NET SDK**（dotnet CLI 未安装）。此时:
#       - 原生 DLL 仍可构建（只要 MSVC 在）
#       - 托管侧回退用 **Roslyn csc.exe**（VS BuildTools 自带）
#         + **.NET Framework**（Windows 自带）编译运行
#     这样示例仍能**真实验证**，而不是"跳过即当作通过"。
#   · **不可静默跳过**（本项目 P3 教训: 可绕过的检查会掩盖缺陷）。
#     若两者都没有，明确报 SKIP 并打印原因，且退出码为 0 但输出醒目提示。
param(
    [switch]$SkipManaged,
    [string]$Out = ''
)
$ErrorActionPreference = 'Stop'

$REPO = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
if (-not $Out) { $Out = Join-Path $REPO 'build\dotnet-gate' }
New-Item -ItemType Directory -Force $Out | Out-Null

function Fail-Step {
    param([string]$Step, [string]$Hint)
    Write-Host ''
    Write-Host "build_dotnet_gate FAILED: $Step" -ForegroundColor Red
    if ($Hint) {
        Write-Host '可能原因与处理:' -ForegroundColor Yellow
        foreach ($line in ($Hint -split "`n")) { Write-Host "  $line" }
    }
    throw "build_dotnet_gate FAILED: $Step"
}

# ---- vcvars（与其它构建脚本同一探测逻辑）----
$vcvars = $null
foreach ($c in @('D:\environment\VS2022BuildTools\VC\Auxiliary\Build\vcvars64.bat',
                 'C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat',
                 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat',
                 'C:\Program Files (x86)\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat')) {
    if (Test-Path -LiteralPath $c) { $vcvars = $c; break }
}
if (-not $vcvars) { Fail-Step 'vcvars64.bat 未找到' '需要 VS2022 的 C++ 生成工具。' }
Write-Host "build_dotnet_gate: vcvars = $vcvars"

# ---- 1. 编译原生 DLL（.def 导出 + 薄封装）----
$defFile = Join-Path $REPO 'prot_sdk\dotnet\Native\protgate.def'
$gateC   = Join-Path $REPO 'prot_sdk\dotnet\Native\gate.c'
foreach ($f in @($defFile, $gateC)) {
    if (-not (Test-Path -LiteralPath $f)) { Fail-Step "缺少源文件: $f" '' }
}

$dll = Join-Path $Out 'protgate.dll'
# ## L3（2026-09-23）: 这是**刻意的最小集**，非"忘记用组合驱动"
#
# S1-ALLOW: .NET gate 的 C 侧接线只需 antidebug(+syscall 依赖)，strcrypt
# 因 strings.c 需要，crc32 是原语。**不用 standard** 是因为那会引入
# 不必要的模块，增大 DLL 体积。
#
# **实测依据**（2026-09-23）: `prot_sdk/dotnet/Native/gate.c` 只引用
# `prot_antidebug_report` 一个模块符号 -> 真实模块依赖就是 antidebug。
#
# **注意**: 本脚本原有的注释（"用 minimal 以确保接线最小"）与实际
# 列表**不符** —— minimal 实际含 blob/hostid/license/vm 等，**不含**
# antidebug。故 L3 修正注释以反映真实依据。
$srcs = @('src\antidebug.c', 'src\syscall.c', 'src\strcrypt.c',
          'src\crc32.c') | ForEach-Object { Join-Path $REPO $_ }
$srcJoined = ($srcs | ForEach-Object { "`"$_`"" }) -join ' '
$stringsC = Join-Path $REPO 'demo\gen\win\strings.c'   # W5: 平台目录
$incDir = Join-Path $REPO 'include'
$genDir = Join-Path $REPO 'demo\gen'

$clCmd = "cl /nologo /O2 /W4 /WX /std:c11 /utf-8 /I `"$incDir`" /I `"$genDir`" " +
         "/LD /Fe:`"$dll`" `"$gateC`" $srcJoined `"$stringsC`" " +
         "/link /DEF:`"$defFile`" bcrypt.lib user32.lib"
Write-Host "build_dotnet_gate: 编译原生 DLL..."
$log = Join-Path $Out 'native_cl.txt'
cmd /c "`"$vcvars`" >nul 2>&1 && $clCmd" 2>&1 | Tee-Object -FilePath $log | Out-Host
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $dll)) {
    Fail-Step 'cl (原生 DLL)' @"
    常见原因:
    1. 缺少 demo\gen\win\strings.c —— 先在仓库根跑一次 build.ps1 生成。
    2. 保护库 API 变化 —— 检查 Native\gate.c 的 include 与调用。
    3. 详细日志: $log
"@
}
Write-Host "build_dotnet_gate: 原生 DLL OK -> $dll" -ForegroundColor Green

# ---- 2. 校验导出表（P/Invoke 依赖它）----
#
# **这一步不可省略**（实测教训 2026-09-21）: .def 被 MSVC 按 ANSI/GBK 读取,
# 若 .def 里混入 UTF-8 中文注释, 链接器会**静默丢掉紧随其后的导出符号** ——
# 产物是个"看起来正常但少了导出"的坏 DLL, 直到运行期 C# 报
# EntryPointNotFound 才暴露（实测丢了 prot_gate_version）。
#
# 不依赖 dumpbin（本机可能没有）—— 用 Python 直接解析 PE 导出表。
$py = $env:PROT_SDK_PYTHON
if (-not $py) {
    foreach ($c in @('D:\environment\PYTHON\python.exe',
                     'C:\Python311\python.exe', 'C:\Python312\python.exe',
                     'C:\Python313\python.exe')) {
        if (Test-Path -LiteralPath $c) { $py = $c; break }
    }
}
if (-not $py) { $py = 'python' }

$verifyScript = Join-Path $REPO 'tools\dotnet_gate_exports.py'
if ((Test-Path -LiteralPath $verifyScript) -and (Test-Path -LiteralPath $dll)) {
    Write-Host 'build_dotnet_gate: 校验导出表...'
    & $py $verifyScript $dll
    if ($LASTEXITCODE -ne 0) {
        Fail-Step '导出表校验' @"
    DLL 缺少必需的导出符号。最常见原因:
      · Native\protgate.def 里混入了**非 ASCII 字符**（如中文注释）。
        MSVC 按 ANSI/GBK 读 .def, UTF-8 多字节注释会破坏后续行解析,
        导致其后的导出被静默丢弃。
      修法: .def 保持纯 ASCII（注释也用英文）。
      详见 prot_sdk\dotnet\README.md 的「一个真实的坑」一节。
"@
    }
    Write-Host 'build_dotnet_gate: 导出校验 OK (3/3)' -ForegroundColor Green
} else {
    Write-Host 'build_dotnet_gate: 校验脚本缺失 - 未校验导出（建议补上）' -ForegroundColor Yellow
}

if ($SkipManaged) {
    Write-Host "build_dotnet_gate: DONE (仅原生) -> $dll"
    exit 0
}

# ---- 3. 托管侧编译 ----
# 优先 .NET SDK（现代、跨平台）; 无则回退 Roslyn csc + .NET Framework。
$protGateCs = Join-Path $REPO 'prot_sdk\dotnet\ProtGate.cs'
$programCs  = Join-Path $REPO 'prot_sdk\dotnet\example\Program.cs'
$dotnet = Get-Command dotnet -ErrorAction SilentlyContinue

if ($dotnet) {
    Write-Host "build_dotnet_gate: 使用 .NET SDK ($($dotnet.Source))"
    $csproj = Join-Path $REPO 'prot_sdk\dotnet\example\ProtGate.Example.csproj'
    if (Test-Path -LiteralPath $csproj) {
        Push-Location (Split-Path -Parent $csproj)
        & $dotnet.Source build -c Release -o $Out
        $rc = $LASTEXITCODE
        Pop-Location
        if ($rc -ne 0) { Fail-Step 'dotnet build' "查看上面的 MSBuild 输出。" }
        Write-Host "build_dotnet_gate: DONE (.NET SDK) -> $Out" -ForegroundColor Green
        exit 0
    }
    Write-Host 'build_dotnet_gate: 未找到 csproj - 回退 csc' -ForegroundColor Yellow
}

# 回退: Roslyn csc（VS BuildTools 自带）+ .NET Framework（Windows 自带）
$candidates = @()
$candidates += Get-ChildItem "${env:ProgramFiles(x86)}\Microsoft Visual Studio" `
    -Filter csc.exe -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match 'Roslyn' }
$candidates += Get-ChildItem 'D:\environment\VS2022BuildTools' `
    -Filter csc.exe -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match 'Roslyn' }

if ($candidates.Count -eq 0) {
    Write-Host ''
    Write-Host 'build_dotnet_gate: 托管侧 SKIPPED' -ForegroundColor Yellow
    Write-Host '  原因: 既无 dotnet SDK，也无 Roslyn csc.exe。' -ForegroundColor Yellow
    Write-Host '  影响: 原生 DLL 已构建并通过导出校验；托管侧示例**未验证**。' -ForegroundColor Yellow
    Write-Host '  处理: 装 .NET SDK 后重跑本脚本。' -ForegroundColor Yellow
    Write-Host '  （注意: 这是显式 SKIP 并说明原因，不是静默跳过。）' -ForegroundColor DarkGray
    exit 0
}

$csc = $candidates | Sort-Object FullName -Descending | Select-Object -First 1
Write-Host "build_dotnet_gate: 使用 Roslyn csc ($($csc.FullName))"
$exe = Join-Path $Out 'gate_example.exe'
$cscCmd = "`"$($csc.FullName)`" /nologo /target:exe /platform:x64 " +
          "/out:`"$exe`" /r:System.Runtime.dll /r:System.Console.dll " +
          "`"$protGateCs`" `"$programCs`""
cmd /c "$cscCmd" 2>&1 | Out-Host
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $exe)) {
    Fail-Step 'csc (托管示例)' @"
    Roslyn 编译失败。常见原因:
    1. C# 语言版本 —— 本示例用了 switch 表达式（C# 8+）,
       .NET Framework 的旧 csc 可能不支持。
    2. 引用缺失 —— 按需增加 /r: 参数。
"@
}
Write-Host "build_dotnet_gate: 托管示例 OK -> $exe" -ForegroundColor Green
Write-Host ''
Write-Host '运行验证:'
Write-Host "  cd $Out; .\gate_example.exe"
Write-Host ''
Write-Host "build_dotnet_gate: DONE (Roslyn + .NET Framework) -> $Out" -ForegroundColor Green
