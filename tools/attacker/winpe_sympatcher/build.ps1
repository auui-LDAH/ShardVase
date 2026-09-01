# build.ps1 — 构建 WinPE-SymPatcher (攻防工具, 仅自有产物演练)
#
# 用法: powershell -ExecutionPolicy Bypass -File build.ps1
# 输出: tools/attacker/winpe_sympatcher/winpe_sympatcher.exe

$ErrorActionPreference = 'Stop'

$vc = 'D:\environment\VS2022BuildTools'
$vcvars = "$vc\VC\Auxiliary\Build\vcvars64.bat"
if (-not (Test-Path $vcvars)) { throw "vcvars64.bat not found: $vcvars" }

$dir = 'D:\SPECIF~1\REVERS~1\tools\attacker\WINPE_~1'
$src = @('symparse.c', 'mempatch.c', 'main.c') | ForEach-Object { "$dir\$_" }

cmd /c "`"$vcvars`" >nul 2>&1 && cl /nologo /O2 /W3 /std:c11 /utf-8 /I $dir $src /link /SUBSYSTEM:CONSOLE /OUT:$dir\winpe_sympatcher.exe"
if ($LASTEXITCODE -ne 0) { throw "build failed" }

Write-Host "built: $dir\winpe_sympatcher.exe"
