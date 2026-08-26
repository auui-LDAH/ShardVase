# tools/ci_sim.ps1 — 本地 CI 模拟器 (INFRA_PLAN I1)
#
# 在无 GitHub 远程时, 本地等效执行 .github/workflows/ci.yml 的步骤,
# 验证 CI 配置的步骤顺序/命令可执行/可复现判定。
#
# 步骤映射 (保持与 ci.yml 同步; 每次改 ci.yml 必须同步这里):
#   job build-and-verify:
#     Build (Release) + RecordSeeds
#     e2e T1-T28 / attacks A1-A12 / vm_unit / vmc / example E1-E7
#     protchain P1-P6 / py_compile
#   job reproducible:
#     用 seeds.json 同种子重建 (Release, SkipSign) + SHA-256 比对 demo.exe/vm.blob
#
# 用法:
#   powershell -ExecutionPolicy Bypass -File tools\ci_sim.ps1 [-SkipTest] [-Python <path>]
param(
    [switch]$SkipTest,   # 跳过测试步骤 (只验证 build + repro)
    [string]$Python = ''
)

$ErrorActionPreference = 'Stop'
$MyDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath (Join-Path $MyDir '..')
$Root = (Get-Location).Path

# 定位 python (同 build.ps1)
$py = $Python
if (-not $py) {
    $cand = @(Get-Command python -ErrorAction SilentlyContinue | Where-Object {
        $_.Source -notlike '*\WindowsApps\*' } | Select-Object -First 1)
    if ($cand) { $py = $cand.Source }
}
if (-not $py) {
    foreach ($p in @('D:\environment\PYTHON\python.exe', 'C:\Python313\python.exe',
                     'C:\Python312\python.exe')) {
        if (Test-Path -LiteralPath $p) { $py = $p; break }
    }
}
if (-not $py) { throw '[ci_sim] cannot locate python' }

$fails = 0
function Step([string]$name, [scriptblock]$body) {
    Write-Host ("[ci_sim] step: {0}" -f $name) -ForegroundColor Cyan
    try {
        & $body
        if ($LASTEXITCODE -ne 0) {
            Write-Host ("[ci_sim]   FAIL (exit={0})" -f $LASTEXITCODE) -ForegroundColor Red
            $script:fails++
        } else {
            Write-Host '[ci_sim]   ok' -ForegroundColor Green
        }
    } catch {
        Write-Host ("[ci_sim]   FAIL: {0}" -f $_.Exception.Message) -ForegroundColor Red
        $script:fails++
    }
}

Write-Host '[ci_sim] === job build-and-verify ===' -ForegroundColor Yellow

Step 'Build (Release) + RecordSeeds' {
    powershell -ExecutionPolicy Bypass -File .\build.ps1 -Config Release -RecordSeeds -SkipSign
}

if (-not $SkipTest) {
    Step 'e2e T1-T28' { & $py tests\e2e.py }
    Step 'attacks A1-A12' { & $py tests\attacks.py }
    Step 'vm_unit' { .\build\vm_unit.exe }
    Step 'vmc M2/M3' { & $py tests\vmc_tests.py }
    Step 'example E1-E7' {
        powershell -ExecutionPolicy Bypass -File .\examples\tool_demo\build_example.ps1
        if ($LASTEXITCODE -eq 0) { & $py examples\tool_demo\test_example.py }
    }
    Step 'protchain P1-P6' { & $py tests\protchain_check.py }
    Step 'py_compile all' {
        & $py -m py_compile tools\vmenc.py tools\strgen.py tools\hashpatch.py `
            tools\indirect.py tools\selfcrypt_proto.py tools\vmc.py tools\mock_server.py `
            tools\selfcrypt_elf.py tools\vm_reduce.py tools\procdump_like.py `
            tools\residency_guard.py tests\e2e.py tests\attacks.py tests\vmc_tests.py `
            tests\protchain_check.py examples\tool_demo\test_example.py
    }
}

Write-Host '[ci_sim] === job reproducible ===' -ForegroundColor Yellow
Write-Host '[ci_sim] (下载 seeds 等 GH 特有步骤由本地等价: 直接读取 build\seeds.json)'

Step 'Reproducible rebuild (same seeds + key, no signing)' {
    if (-not (Test-Path -LiteralPath 'build\seeds.json')) {
        throw 'build\seeds.json not found (RecordSeeds build required)'
    }
    # 统一判定用 repro_check.ps1 (INFRA_PLAN I2): 同种子两次构建 SHA-256 比对
    powershell -ExecutionPolicy Bypass -File .\tools\repro_check.ps1 -SeedsFile build\seeds.json
}

Write-Host ''
if ($fails -gt 0) {
    Write-Host ("[ci_sim] FAIL: {0} step(s) failed" -f $fails) -ForegroundColor Red
    exit 1
}
Write-Host '[ci_sim] PASS (all steps)' -ForegroundColor Green
exit 0