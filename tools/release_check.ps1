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
#   powershell -ExecutionPolicy Bypass -File tools\release_check.ps1 [-SkipTest] [-SkipDirtyCheck]
#
# -SkipDirtyCheck: 跳过"git 工作区干净"检查。
#   仅用于 CI —— CI 的构建步骤会在工作区产生产物（build/ 等虽被 ignore,
#   但 demo/gen/ 等生成物可能被 git 探测到），导致该检查在 CI 中恒失败。
#   本地发版**不要**用它: 工作区干净是发版纪律的一部分。
param(
    [switch]$SkipTest,
    [switch]$SkipDirtyCheck,
    # W5: 启用检查器变异测试（较慢，约 2-4 分钟；发版/CI 建议启用）
    [switch]$WithMutation,
    # W5.7: 启用迁移成本门禁（需两次构建，约 1-2 分钟；发版/CI 建议启用）
    [switch]$WithMigration,
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
        # ⚠️ 必须只取 scriptblock 的**最后一个值**来判断成败。
        #
        # 严重教训（2026-09-23 实测）: 原写法 `$ok = & $cond` 会把 scriptblock
        # 的**全部输出**赋给 $ok —— 包括被测命令打印的所有 stdout。
        # 于是 `Check 'X' { & $tool; $LASTEXITCODE -eq 0 }` 得到的是
        # 「多行文本 + 布尔」的**数组**，而 PowerShell 中**非空数组恒为真**
        # -> `if ($ok)` 永远成立 -> **该项从不真正检查退出码**。
        #
        # 实测证据: 造一个必然失败（exit 1 + 有输出）的工具
        #   旧写法 -> [ok]（谎报通过）
        #   修正后 -> [X]（正确）
        #
        # 影响面: 当时 13 项中有 7 项属于此模式（e2e/attacks/vmc/protchain/
        # modcheck/drills lint/doccheck），即**门禁大半失效**。
        #
        # 修法: 收集 scriptblock 输出，**只取最后一个值**作为判定结果。
        $out = @(& $cond)
        $ok = if ($out.Count -gt 0) { $out[-1] } else { $null }
        # 末值必须是布尔；若拿到字符串（说明 scriptblock 末句不是布尔判断）
        # 则视为检查写法错误 -> **失败而非静默通过**（P3: 不设可绕过的门禁）。
        if ($ok -isnot [bool]) {
            $script:fail++
            Write-Host ("[X]  {0}: 检查写法错误（末值非布尔: {1}）" -f `
                $name, ($ok | Out-String).Trim()) -ForegroundColor Red
            return
        }
        if ($ok) { $script:pass++; Write-Host ("[ok]  {0}" -f $name) -ForegroundColor Green }
        else { $script:fail++; Write-Host ("[X]  {0}" -f $name) -ForegroundColor Red }
    } catch {
        $script:fail++; Write-Host ("[X]  {0}: {1}" -f $name, $_.Exception.Message) -ForegroundColor Red
    }
}

Write-Host '=== Release Gate ===' -ForegroundColor Yellow

Check 'git 工作区干净' {
    if ($SkipDirtyCheck) {
        Write-Host '      (已按 -SkipDirtyCheck 跳过)' -ForegroundColor DarkGray
        return $true
    }
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
    # 阶段 5 (M5): 对外材料数字不得与内部能力漂移
    #   (门禁项数 / 轮次口径 / 模糊表述 / 死链)。2026-09-20 核对时发现
    #   "0 破防点"、"release_check 11/11"、"8+ 轮 vs 6 轮" 三类漂移,
    #   本检查防止其复发。
    Check '对外材料 (doccheck)' { & $py tools\doccheck.py; $LASTEXITCODE -eq 0 }
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

# W5(验证框架): 检查器**变异测试** —— 每个检查器必须自证能抓错。
#
# **为什么这是门禁的一部分**（2026-09-23 教训）: 本门禁曾因
# PowerShell 数组恒真而 **7/13 项失效**（必然失败的工具被报 [ok]），
# 持续很久无人察觉。**一个只会通过的检查器比没有更危险。**
#
# 本项故意破坏各检查器的输入 -> 若它仍 PASS，则该项**盲**（never-fails）。
#
# 注: 默认跳过（较慢，约 2-4 分钟）。发版检查用 -WithMutation 启用；
#     CI 可常态启用。**跳过时会明确标注，不静默通过。**
if ($WithMutation) {
    Check '检查器变异测试 (mutate_check)' {
        & $py tools\mutate_check.py; $LASTEXITCODE -eq 0
    }
} else {
    Write-Host '[info] 检查器变异测试未运行 (加 -WithMutation 启用) — 未验证 != 通过' -ForegroundColor DarkYellow
}

# W6.2(协议治理): **兼容性套件自检 + 对本仓库注册表的合规检查**。
#
# **为什么入门禁**: conformance.py 是**第三方准入的唯一标准**。
#   若它自身失效（如本门禁曾 7/13 静默通过），第三方会拿到错误结论。
#   故必须每次门禁都跑，且**含负向自检**（自证能抓错）。
Check '协议兼容性 (conformance)' {
    & $py tools\conformance.py --selftest --quiet
    if ($LASTEXITCODE -ne 0) { return $false }
    & $py tools\conformance.py modules.json --quiet; $LASTEXITCODE -eq 0
}

# W5.7(验证框架): **迁移成本门禁** —— 防止 W1.6 的成果回退。
#
# **为什么需要**: W1.6 把"保护函数特征命中率"(M3) 从 **55.9% 降到 5.9%**。
# 但**没有检查器的指标会悄悄退化** —— W5.6 之前，M3 的 55.9% 无人知晓，
# 直到专门度量才发现。本项把它固化为判据。
#
# 判据（实测标定，3 轮完全可复现）:
#   M3 保护函数特征命中率 <= 25%    （当前 5.9%；无注入时 55.9% 必被抓）
#   M1 地址复用率         <= 25%    （当前 1.1%）
#
# 注: 默认跳过（需两次构建，约 1-2 分钟）。发版检查用 -WithMigration 启用；
#     **跳过时明确标注，不静默通过**。
if ($WithMigration) {
    Check '迁移成本 (migration_gate)' {
        & $py tools\migration_gate.py --quiet; $LASTEXITCODE -eq 0
    }
} else {
    Write-Host '[info] 迁移成本门禁未运行 (加 -WithMigration 启用) — 未验证 != 通过' -ForegroundColor DarkYellow
}

Write-Host ''
if ($fail -gt 0) {
    Write-Host ("[release_check] FAIL: {0}/{1} 未通过" -f $fail, ($pass + $fail)) -ForegroundColor Red
    exit 1
}
Write-Host ("[release_check] PASS: {0} 项检查全通过" -f $pass) -ForegroundColor Green
exit 0