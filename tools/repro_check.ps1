# tools/repro_check.ps1 — 可复现构建判定 (INFRA_PLAN I2)
#
# 统一: verify.ps1 -Reproducible 与 CI reproducible job 的判定逻辑.
# 用 seeds.json 同种子两次构建 (Release, SkipSign), 比对 demo.exe + vm.blob
# 的 SHA-256. 一致 = PASS.
#
# 用法:
#   powershell -ExecutionPolicy Bypass -File tools\repro_check.ps1 [-SeedsFile build\seeds.json]
#   powershell -ExecutionPolicy Bypass -File tools\repro_check.ps1 -BaselineDir build_artifacts\build
#
# -BaselineDir: 与一个**既有产物**比对 (CI reproducible job 的真实形态:
#   下载第一构建 -> 同种子重建 -> 比对), 而不是自己建两次.
#   CI 的 `Compare SHA-256 with first build` 步与本开关判据一致.
param(
    [string]$SeedsFile = 'build\seeds.json',
    [string]$BaselineDir = ''
)

$ErrorActionPreference = 'Stop'
$MyDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath (Join-Path $MyDir '..')
$Root = (Get-Location).Path

if (-not (Test-Path -LiteralPath $SeedsFile)) {
    Write-Host "[repro_check] FAIL: $SeedsFile not found (先 -RecordSeeds 构建)" -ForegroundColor Red
    exit 1
}

# 被比对的**必需**文件。一个都不能少 —— 见下方 "缺失即 FAIL" 注释。
$Files = @('build\demo.exe', 'build\vm.blob')

if ($BaselineDir) {
    # ---- 形态 B: 与既有产物比对 (CI reproducible job) ----
    # 缺陷 7 的教训 (2026-10-02): 产物 `actions/upload-artifact` 会**保留目录
    # 结构** (公共祖先 = 仓库根), 解压后是 `build_artifacts\build\demo.exe`
    # 而不是 `build_artifacts\demo.exe`。故这里显式要求调用方给出**正确**目录,
    # 并在缺失时把实际结构打出来, 免得下一轮又要靠猜。
    if (-not (Test-Path -LiteralPath $BaselineDir)) {
        Write-Host "[repro_check] FAIL: BaselineDir '$BaselineDir' not found" -ForegroundColor Red
        exit 1
    }

    Write-Host '[repro_check] build (Release, same seeds, skip sign)'
    powershell -ExecutionPolicy Bypass -File .\build.ps1 -Config Release -SeedsFile $SeedsFile -SkipSign -SkipSmoke
    if ($LASTEXITCODE -ne 0) { Write-Host '[repro_check] FAIL: build' -ForegroundColor Red; exit 1 }

    $all = $true
    foreach ($f in $Files) {
        $name = Split-Path -Leaf $f
        $bp = Join-Path $BaselineDir $name
        if (-not (Test-Path -LiteralPath $bp)) {
            Write-Host ("  {0}: FAIL (基线缺文件 {1})" -f $f, $bp) -ForegroundColor Red
            Write-Host ("    目录 {0} 实际内容:" -f $BaselineDir)
            Get-ChildItem -LiteralPath $BaselineDir -ErrorAction SilentlyContinue |
                ForEach-Object { Write-Host ("      " + $_.Name) }
            $all = $false
            continue
        }
        if (-not (Test-Path -LiteralPath $f)) {
            Write-Host ("  {0}: FAIL (重建未产出该文件)" -f $f) -ForegroundColor Red
            $all = $false
            continue
        }
        $a = (Get-FileHash -Algorithm SHA256 -LiteralPath $bp).Hash
        $b = (Get-FileHash -Algorithm SHA256 -LiteralPath $f).Hash
        $ok = ($a -eq $b)
        $all = $all -and $ok
        Write-Host ("  {0}: {1}" -f $f, $(if ($ok) { 'identical' } else { 'MISMATCH' }))
        if (-not $ok) {
            Write-Host ("    baseline {0}" -f $a)
            Write-Host ("    rebuilt  {0}" -f $b)
        }
    }
    if (-not $all) {
        Write-Host '[repro_check] FAIL: non-reproducible build (vs baseline)' -ForegroundColor Red
        exit 1
    }
    Write-Host '[repro_check] PASS: reproducible vs baseline (demo.exe + vm.blob SHA-256 identical)' -ForegroundColor Green
    exit 0
}

# ---- 形态 A: 同种子自建两次并比对 ----
Write-Host '[repro_check] baseline build (Release, skip sign)'
powershell -ExecutionPolicy Bypass -File .\build.ps1 -Config Release -SeedsFile $SeedsFile -SkipSign -SkipSmoke
if ($LASTEXITCODE -ne 0) { Write-Host '[repro_check] FAIL: baseline build' -ForegroundColor Red; exit 1 }

# 记录首次产物 hash
$h1 = @{}
foreach ($f in $Files) {
    if (Test-Path -LiteralPath $f) { $h1[$f] = (Get-FileHash -Algorithm SHA256 -LiteralPath $f).Hash }
}

Write-Host '[repro_check] rebuild (same seeds, skip sign)'
powershell -ExecutionPolicy Bypass -File .\build.ps1 -Config Release -SeedsFile $SeedsFile -SkipSign -SkipSmoke
if ($LASTEXITCODE -ne 0) { Write-Host '[repro_check] FAIL: rebuild' -ForegroundColor Red; exit 1 }

$all = $true
foreach ($f in $Files) {
    # ⚠️ 这里曾经是 `if (-not $h1.ContainsKey($f)) { continue }` ——
    #    **产物缺失 = 静默跳过 = 判 PASS**。即"什么都没建出来"也算可复现。
    #    这是典型的**假绿**: 判据必须要求"每一个必需文件都真的被比对过"。
    if (-not $h1.ContainsKey($f)) {
        Write-Host ("  {0}: FAIL (首次构建未产出该文件)" -f $f) -ForegroundColor Red
        $all = $false
        continue
    }
    if (-not (Test-Path -LiteralPath $f)) {
        Write-Host ("  {0}: FAIL (重建未产出该文件)" -f $f) -ForegroundColor Red
        $all = $false
        continue
    }
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