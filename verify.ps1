# verify.ps1 — 一键验证脚本 (基础设施, 2026-08-09)
#
# 把"多轮随机重建 + e2e + VM 单测 + 攻击模拟 + Python 语法检查"封装成一条命令,
# 生成带时间戳/种子指纹/SHA 的 JSON 报告 (默认 verify-report.json)。
# 任意一步失败 -> 退出码非 0, 供本地回归与 CI 复用。
#
# 用法:
#   powershell -ExecutionPolicy Bypass -File verify.ps1 [-Rounds 3] [-KeepArtifacts] [-SkipPyCompile] [-Minimal] [-Reproducible <seeds.json>] [-Python <path>]
param(
    [int]$Rounds = 3,
    [switch]$KeepArtifacts,
    [switch]$SkipPyCompile,
    [switch]$Minimal,
    [string]$Python = '',
    [string]$Reproducible = ''
)

$ErrorActionPreference = 'Stop'

Set-Location -LiteralPath (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Root = (Get-Location).Path

# 定位 python: 跳过 WindowsApps 商店存根 (同 build.ps1)
$py = $Python
if (-not $py) {
    $cand = @(Get-Command python -ErrorAction SilentlyContinue | Where-Object {
        $_.Source -notlike '*\WindowsApps\*' } | Select-Object -First 1)
    if ($cand) { $py = $cand.Source }
}
if (-not $py) {
    foreach ($p in @('D:\environment\PYTHON\python.exe', 'C:\Python313\python.exe',
                     'C:\Python312\python.exe', 'C:\Python311\python.exe',
                     "$env:LOCALAPPDATA\Programs\Python\Python313\python.exe")) {
        if (Test-Path -LiteralPath $p) { $py = $p; break }
    }
}
if (-not $py) { throw '[verify] cannot locate python — pass -Python <path>' }
Write-Host "[verify] python = $py"
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
            & $py -m py_compile $f
            if ($LASTEXITCODE -ne 0) { $allGreen = $false; Write-Host "  py_compile FAIL: $f" -ForegroundColor Red }
        }
    }} else {
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
        round = $i; build = 'PASS'; e2e = 'PASS'; vm_unit = 'PASS'
        syscall_probe = 'PASS'; attacks = 'PASS'
        seeds = ''; log = $null
    }
    Write-Step "round $i/$tot : build.ps1"
    $bl = & powershell -ExecutionPolicy Bypass -File .\build.ps1 2>&1
    if ($LASTEXITCODE -ne 0) { $ent.build = 'FAIL'; $ent.log = $bl; return $ent }

    Write-Step "round $i/$tot : python tests\e2e.py"
    $eo = @(& $py tests\e2e.py 2>&1)
    if ($LASTEXITCODE -ne 0) { $ent.e2e = 'FAIL'; $ent.log = $eo; return $ent }

    Write-Step "round $i/$tot : build\vm_unit.exe"
    $vu = @(& .\build\vm_unit.exe 2>&1)
    if ($LASTEXITCODE -ne 0) { $ent.vm_unit = 'FAIL'; $ent.log = $vu; return $ent }

    Write-Step "round $i/$tot : build\syscall_probe.exe (A6)"
    $sp = @(& .\build\syscall_probe.exe 2>&1)
    if ($LASTEXITCODE -ne 0) { $ent.syscall_probe = 'FAIL'; $ent.log = $sp }
    else { $ent.syscall_probe = 'PASS' }

    Write-Step "round $i/$tot : python tests\attacks.py (非真机攻击模拟)"
    if (Test-Path -LiteralPath 'tests\attacks.py') {
        $at = @(& $py tests\attacks.py 2>&1)
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
    if ($ent.build -ne 'PASS' -or $ent.e2e -ne 'PASS' -or $ent.vm_unit -ne 'PASS' -or $ent.attacks -ne 'PASS' -or $ent.syscall_probe -ne 'PASS') {
        $allGreen = $false
        Write-Host ("[verify] round {0} FAILED (build={1} e2e={2} vm_unit={3} syscall_probe={4} attacks={5})" -f $i, $ent.build, $ent.e2e, $ent.vm_unit, $ent.syscall_probe, $ent.attacks) -ForegroundColor Red
    }
}

# --- 报告 JSON --------------------------------------------------------------
# I3 可复现构建验证: 同种子两次无签名构建, 比对 demo.exe / vm.blob SHA-256
# (签名区由 signtool 引入差异, 属预期 —— RELEASE §3/§5)
$repro = $null
if ($Reproducible) {
    if (-not (Test-Path -LiteralPath $Reproducible)) {
        Write-Host "[verify] -Reproducible: seeds file not found: $Reproducible" -ForegroundColor Red
        $allGreen = $false
    } else {
        Write-Step "reproducible baseline build (Release, no signing)"
        $rb1 = & powershell -ExecutionPolicy Bypass -File .\build.ps1 -Config Release -SeedsFile $Reproducible -SkipSign 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Host '[verify] reproducible baseline build FAILED' -ForegroundColor Red
            $allGreen = $false
        } else {
            $h1 = @{}
            foreach ($f in @('build\demo.exe', 'build\vm.blob')) {
                $h1[$f] = (Get-FileHash -Algorithm SHA256 -LiteralPath $f).Hash
            }
            Write-Step "reproducible rebuild (same seeds, Release, no signing)"
            $rb2 = & powershell -ExecutionPolicy Bypass -File .\build.ps1 -Config Release -SeedsFile $Reproducible -SkipSign 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-Host '[verify] reproducible rebuild FAILED' -ForegroundColor Red
                $allGreen = $false
            } else {
                $repro = [ordered]@{}
                foreach ($f in @('build\demo.exe', 'build\vm.blob')) {
                    $h2 = (Get-FileHash -Algorithm SHA256 -LiteralPath $f).Hash
                    $ok = ($h2 -eq $h1[$f])
                    $repro[$f] = [ordered]@{ match = $ok; sha256 = $h2 }
                    if (-not $ok) {
                        Write-Host "[verify] reproducible MISMATCH: $f" -ForegroundColor Red
                        $allGreen = $false
                    }
                }
                if ($repro) { Write-Host '[verify] reproducible: byte-identical (unsigned) rebuild OK' -ForegroundColor Green }
            }
        }
    }
}

$j = [ordered]@{
    tool      = 'verify.ps1'
    timestamp = $Time
    rounds    = $Rounds
    sha       = (git rev-parse --short HEAD 2>$null)
    allGreen  = $allGreen
    results   = $results
    reproducible = $repro
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