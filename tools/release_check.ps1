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
    $dirty = git status --porcelain 2>$null
    [string]::IsNullOrEmpty(($dirty -join ''))
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
    # 模块化框架 (docs/MODULAR_ARCH.md): 注册表须与源码一致 + 参考组合自洽。
    # 放在门禁内而非可选脚本 —— P3 教训: 可绕过的门禁会掩盖缺陷。
    Check '模块契约 (modcheck)' { & $py tools\modcheck.py --all-compositions; $LASTEXITCODE -eq 0 }
    # 阶段 3 (攻防对称): 演练记录须符合 schema 且 target_module 有效。
    Check '攻防记录 (drills lint)' { & $py tools\drills.py lint; $LASTEXITCODE -eq 0 }
}

# 签名: 可复现 (repro) 要求 SkipSign 重建, 与 Authenticode 互斥 (签名改 SHA,
# RELEASE §3/§5 已知). 发版顺序 = 确认可复现后单独签名. 这里只提示不 FAIL.
if (Test-Path -LiteralPath 'build\keys\codesign.pfx') {
    $sig = Get-AuthenticodeSignature -LiteralPath 'build\demo.exe' -ErrorAction SilentlyContinue
    if ($sig -and $sig.Status -ne 'NotSigned') {
        $script:pass++; Write-Host ('[ok]  签名有效 ({0})' -f $sig.Status) -ForegroundColor Green
    } else {
        Write-Host '[info] 未签名 (可复现构建产物) — 发版时 signtool 单独签名' -ForegroundColor DarkYellow
        $script:pass++  # 视为通过 (签名在可复现后单独做)
    }
} else {
    Write-Host '[info] codesign.pfx absent - sign check skipped (demo/unsigned build only)' -ForegroundColor DarkYellow
}

Write-Host ''
if ($fail -gt 0) {
    Write-Host ("[release_check] FAIL: {0}/{1} 未通过" -f $fail, ($pass + $fail)) -ForegroundColor Red
    exit 1
}
Write-Host ("[release_check] PASS: {0} 项检查全通过" -f $pass) -ForegroundColor Green
exit 0