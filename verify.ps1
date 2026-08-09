# verify.ps1 — 一键验证脚本 (基础设施, 2026-08-09)
#
# 把"多轮随机重建 + e2e + VM 单测 + 攻击模拟 + Python 语法检查"封装成一条命令,
# 生成带时间戳/种子指纹/SHA 的 JSON 报告 (默认 verify-report.json)。
# 任意一步失败 -> 退出码非 0, 供本地回归与 CI 复用。
#
# 用法:
#   powershell -ExecutionPolicy Bypass -File verify.ps1 [-Rounds 3] [-KeepArtifacts] [-SkipPyCompile] [-Minimal]
param(
    [int]$Rounds = 3,
    [switch]$KeepArtifacts,
    [switch]$SkipPyCompile,
    [switch]$Minimal
)

$ErrorActionPreference = 'Stop'

Set-Location -LiteralPath (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Root = (Get-Location).Path
$Time = Get-Date -Format 'yyyyMMdd-HHmmss'
$RptPath = Join-Path $Root 'verify-report.json'
$ArtsRoot = Join-Path $Root 'verify-artifacts'
if ($Minimal) { $Rounds = 1 }

$PyFiles = @('tools\vmenc.py', 'tools\strgen.py', 'tools\hashpatch.py',
             'tests\e2e.py', 'tests\attacks.py')

function Write-Step([string]$msg) { Write-Host "[verify] $msg" -ForegroundColor Cyan }

$results = @()
$allGreen = $true

# --- 0. Python 语法检查 -----------------------------------------------------
if (-not $SkipPyCompile) {
    Write-Step "py_compile: $($PyFiles -join ', ')"
    foreach ($f in $PyFiles) {
        if (Test-Path -LiteralPath $f) {
            python -m py_compile $f
            if ($LASTEXITCODE -ne 0) { $allGreen = $false; Write-Host "  py_compile FAIL: $f" -ForegroundColor Red }
        }
    }
} else {
    Write-Step 'skip py_compile'
}

# --- 辅助: 每轮种子指纹 (从 demo\gen blob 的 .c 提取各镜像 key) -----------
function Get-SeedFingerprint {
    $parts = @()
    foreach ($c in Get-ChildItem -LiteralPath 'demo\gen' -Filter 'vm_*_blob.c') {
        $raw = Get-Content -LiteralPath $c.FullName -Raw
        $m = [regex]::Matches($raw, '0x([0-9a-fA-F]{16})')
        if ($m.Count -gt 0) { $parts += ($m[0].Groups[1].Value) }
    }
    return ($parts -join ',')
}

# --- 单轮验证: build -> e2e -> vm_unit -> attacks ---------------------------
function Invoke-Once([int]$i, [int]$tot) {
    $ent = [ordered]@{
        round = $i; build = 'PASS'; e2e = 'PASS'; vm_unit = 'PASS'; attacks = 'PASS'
        seeds = ''; log = $null
    }
    Write-Step "round $i/$tot : build.ps1"
    $bl = & powershell -ExecutionPolicy Bypass -File .\build.ps1 2>&1
    if ($LASTEXITCODE -ne 0) { $ent.build = 'FAIL'; $ent.log = $bl; return $ent }

    Write-Step "round $i/$tot : python tests\e2e.py"
    $eo = @(python tests\e2e.py 2>&1)
    if ($LASTEXITCODE -ne 0) { $ent.e2e = 'FAIL'; $ent.log = $eo; return $ent }

    Write-Step "round $i/$tot : build\vm_unit.exe"
    $vu = @(& .\build\vm_unit.exe 2>&1)
    if ($LASTEXITCODE -ne 0) { $ent.vm_unit = 'FAIL'; $ent.log = $vu; return $ent }

    Write-Step "round $i/$tot : python tests\attacks.py (非真机攻击模拟)"
    if (Test-Path -LiteralPath 'tests\attacks.py') {
        $at = @(python tests\attacks.py 2>&1)
        if ($LASTEXITCODE -ne 0) { $ent.attacks = 'FAIL'; $ent.log = $at }
    }

    $ent.seeds = Get-SeedFingerprint
    $ent.e2e_lines = ($eo -join ' | ')

    if ($KeepArtifacts) {
        $d = Join-Path $ArtsRoot ("r{0:d2}" -f $i)
        if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d | Out-Null }
        Copy-Item -Path 'demo\gen\*' -Destination $d -Force
        Copy-Item -Path 'build\demo.exe' -Destination $d -Force
    }
    return $ent
}

for ($i = 1; $i -le $Rounds; $i++) {
    $ent = Invoke-Once $i $Rounds
    $results += $ent
    if ($ent.build -ne 'PASS' -or $ent.e2e -ne 'PASS' -or $ent.vm_unit -ne 'PASS' -or $ent.attacks -ne 'PASS') {
        $allGreen = $false
        Write-Host ("[verify] round {0} FAILED (build={1} e2e={2} vm_unit={3} attacks={4})" -f $i, $ent.build, $ent.e2e, $ent.vm_unit, $ent.attacks) -ForegroundColor Red
    }
}

# --- 报告 JSON --------------------------------------------------------------
$j = [ordered]@{
    tool      = 'verify.ps1'
    timestamp = $Time
    rounds    = $Rounds
    sha       = (git rev-parse --short HEAD 2>$null)
    allGreen  = $allGreen
    results   = $results
}
$dir = Split-Path -Parent $RptPath
if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
$j | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $RptPath -Encoding utf8

Write-Host ''
Write-Host "[verify] $Rounds round(s) summary:"
$results | ForEach-Object {
    Write-Host ("  r{0}: build={1} e2e={2} vm_unit={3} attacks={4} seeds=[{5}]" -f $_.round, $_.build, $_.e2e, $_.vm_unit, $_.attacks, $_.seeds)
}
Write-Host "[verify] report: $RptPath"
if (-not $allGreen) { Write-Host '[verify] FAIL' -ForegroundColor Red; exit 1 }
Write-Host '[verify] PASS' -ForegroundColor Green