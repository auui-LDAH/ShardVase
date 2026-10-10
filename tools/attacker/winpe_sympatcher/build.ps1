# build.ps1 — 构建 WinPE-SymPatcher (攻防工具, 仅自有产物演练)
#
# 用法: powershell -ExecutionPolicy Bypass -File build.ps1
# 输出: 本目录 winpe_sympatcher.exe
#
# 说明: 目录名可能含空格, cmd 拼 cl 命令需 8.3 短路径 (运行时自动计算)。

$ErrorActionPreference = 'Stop'

# 1. 定位 vcvars64.bat: vswhere 自动探测 (支持任意 VS 安装路径), 常见路径兜底
function Find-VcVars {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path -LiteralPath $vswhere) {
        $install = & $vswhere -latest -products * `
            -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
            -property installationPath 2>$null
        if ($install) {
            $cand = Join-Path $install 'VC\Auxiliary\Build\vcvars64.bat'
            if (Test-Path -LiteralPath $cand) { return $cand }
        }
    }
    foreach ($p in @(
        'C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat',
        'C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat',
        'C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat'
    )) {
        if (Test-Path -LiteralPath $p) { return $p }
    }
    throw 'cannot locate vcvars64.bat — install VS 2022 Build Tools (C++ workload) first'
}

# 2. 计算脚本目录的 8.3 短路径 (供 cmd/cl 使用, 避免空格转义问题)
$fso = New-Object -ComObject Scripting.FileSystemObject
$dir = $fso.GetFolder($PSScriptRoot).ShortPath

$vcvars = Find-VcVars
$src = @('symparse.c', 'mempatch.c', 'main.c') | ForEach-Object { "$dir\$_" }

cmd /c "`"$vcvars`" >nul 2>&1 && cl /nologo /O2 /W3 /std:c11 /utf-8 /I $dir $src /link /SUBSYSTEM:CONSOLE /OUT:$dir\winpe_sympatcher.exe"
if ($LASTEXITCODE -ne 0) { throw 'build failed' }

Write-Host "built: $PSScriptRoot\winpe_sympatcher.exe"
