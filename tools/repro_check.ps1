# tools/repro_check.ps1 — 可复现构建判定 (INFRA_PLAN I2)
#
# 统一: verify.ps1 -Reproducible 与 CI reproducible job 的判定逻辑.
# 用 seeds.json 同种子两次构建 (Release, SkipSign), 比对 demo.exe + vm.blob
# 的 SHA-256. 一致 = PASS.
#
# 用法:
#   powershell -ExecutionPolicy Bypass -File tools\repro_check.ps1 [-SeedsFile build\seeds.json]
param(
    [string]$SeedsFile = 'build\seeds.json'
)

$ErrorActionPreference = 'Stop'
$MyDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath (Join-Path $MyDir '..')
$Root = (Get-Location).Path

if (-not (Test-Path -LiteralPath $SeedsFile)) {
    Write-Host "[repro_check] FAIL: $SeedsFile not found (先 -RecordSeeds 构建)" -ForegroundColor Red
    exit 1
}

Write-Host '[repro_check] baseline build (Release, skip sign)'
powershell -ExecutionPolicy Bypass -File .\build.ps1 -Config Release -SeedsFile $SeedsFile -SkipSign -SkipSmoke
if ($LASTEXITCODE -ne 0) { Write-Host '[repro_check] FAIL: baseline build' -ForegroundColor Red; exit 1 }

# 记录首次产物 hash
$h1 = @{}
foreach ($f in @('build\demo.exe', 'build\vm.blob')) {
    if (Test-Path -LiteralPath $f) { $h1[$f] = (Get-FileHash -Algorithm SHA256 -LiteralPath $f).Hash }
}

Write-Host '[repro_check] rebuild (same seeds, skip sign)'
powershell -ExecutionPolicy Bypass -File .\build.ps1 -Config Release -SeedsFile $SeedsFile -SkipSign -SkipSmoke
if ($LASTEXITCODE -ne 0) { Write-Host '[repro_check] FAIL: rebuild' -ForegroundColor Red; exit 1 }

$all = $true
foreach ($f in @('build\demo.exe', 'build\vm.blob')) {
    if (-not $h1.ContainsKey($f)) { continue }
    $h2 = (Get-FileHash -Algorithm SHA256 -LiteralPath $f).Hash
    $ok = ($h1[$f] -eq $h2)
    $all = $all -and $ok
    Write-Host ("  {0}: {1}" -f $f, $(if ($ok) { 'identical' } else { 'MISMATCH' }))
}

if (-not $all) {
    Write-Host '[repro_check] FAIL: non-reproducible build' -ForegroundColor Red
    exit 1
}
Write-Host '[repro_check] PASS: reproducible (demo.exe + vm.blob SHA-256 identical)' -ForegroundColor Green
exit 0