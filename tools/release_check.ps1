# tools/release_check.ps1 — 发布前置检查 gate (INFRA_PLAN I3)
#
# 一键确认发版所有前置条件:
#   1. git 工作区干净
#   2. Release 构建成功 (含签名, 若有 pfx)
#   3. 可复现 (repro_check)
#   4. 测试全绿 (e2e/attacks/vm_unit/vmc/example/protchain)
#   5. manifest.json 版本正确
#
# 用法:
#   powershell -ExecutionPolicy Bypass -File tools\release_check.ps1 [-SkipTest]
param(
    [switch]$SkipTest,
    [string]$Python = ''
)

$ErrorActionPreference = 'Continue'
$MyDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath (Join-Path $MyDir '..')
$Root = (Get-Location).Path

$py = $Python
if (-not $py) {
    $cand = @(Get-Command python -ErrorAction SilentlyContinue | Where-Object {
        $_.Source -notlike '*\WindowsApps\*' } | Select-Object -First 1)
    if ($cand) { $py = $cand.Source }
}
if (-not $py) { foreach ($p in @('D:\environment\PYTHON\python.exe','C:\Python313\python.exe')) { if (Test-Path -LiteralPath $p) { $py = $p; break } } }

$checks = @()
$pass = 0; $fail = 0

function Check([string]$name, [scriptblock]$cond) {
    try {
        $ok = & $cond
        if ($ok) { $script:pass++; Write-Host ("[ok]  {0}" -f $name) -ForegroundColor Green }
        else { $script:fail++; Write-Host ("[X]  {0}" -f $name) -ForegroundColor Red }
    } catch {
        $script:fail++; Write-Host ("[X]  {0}: {1}" -f $name, $_.Exception.Message) -ForegroundColor Red
    }
}

Write-Host '=== Release Gate ===' -ForegroundColor Yellow

Check 'git 工作区干净' {
    ($(git status --porcelain 2>$null) -eq '') -or ($null -eq $LASTEXITCODE)
}

Check 'manifest.json 版本非占位' {
    $m = Get-Content -LiteralPath 'build\manifest.json' -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json
    $m -and $m.version -and ($m.version -ne '?') -and $m.version
}

if (-not $SkipTest) {
    Check 'Release 构建 (build.ps1 -Config Release)' {
        powershell -ExecutionPolicy Bypass -File .\build.ps1 -Config Release -RecordSeeds -SkipSmoke
        $LASTEXITCODE -eq 0
    }
    Check '可复现 (repro_check)' {
        powershell -ExecutionPolicy Bypass -File .\tools\repro_check.ps1
        $LASTEXITCODE -eq 0
    }
    Check 'e2e T1-T28' { & $py tests\e2e.py; $LASTEXITCODE -eq 0 }
    Check 'attacks A1-A12' { & $py tests\attacks.py; $LASTEXITCODE -eq 0 }
    Check 'vm_unit' { .\build\vm_unit.exe; $LASTEXITCODE -eq 0 }
    Check 'vmc' { & $py tests\vmc_tests.py; $LASTEXITCODE -eq 0 }
    Check 'example E1-E7' {
        powershell -ExecutionPolicy Bypass -File .\examples\tool_demo\build_example.ps1
        if ($LASTEXITCODE -ne 0) { return $false }
        & $py examples\tool_demo\test_example.py; $LASTEXITCODE -eq 0
    }
    Check 'protchain P1-P6' { & $py tests\protchain_check.py; $LASTEXITCODE -eq 0 }
}

if (Test-Path -LiteralPath 'build\keys\codesign.pfx') {
    Check '签名验证 (signtool verify /pa)' {
        $signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue | Sort-Object FullName -Descending | Select-Object -First 1
        if (-not $signtool) { return $false }
        & $signtool.FullName verify /pa build\demo.exe 2>&1 | Out-Null
        $LASTEXITCODE -eq 0
    }
} else {
    Write-Host '[info] 无 codesign.pfx - 跳过签名验证 (仅演示/无签名发布)' -ForegroundColor DarkYellow
}

Write-Host ''
if ($fail -gt 0) {
    Write-Host ("[release_check] FAIL: {0}/{1} 未通过" -f $fail, ($pass + $fail)) -ForegroundColor Red
    exit 1
}
Write-Host ("[release_check] PASS: {0} 项检查全通过" -f $pass) -ForegroundColor Green
exit 0