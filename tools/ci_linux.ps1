# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ShardVase contributors
#
# 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；
# 商业授权见 LICENSE.md。
#
# =============================================================================
# ci_linux.ps1 — **Linux 端到端验证**（独立入口，不在门禁内）
#
# ## 为什么独立于 release_check.ps1（**本轮实测的根本结论**）
#   门禁各检查项**共享可变状态**（`demo/gen/`、`build/`、`vm_build.json`）。
#   Linux 完整验证**必须**跑 `build.sh` —— 否则 `demo/gen` 是 Windows 值
#   -> 期望值/节名不一致 -> **必然失败**。而跑 build.sh 会：
#     ① **把 demo/gen 改为 Linux 值** -> 污染门禁其它检查项
#        （实测: 连带 e2e / mutate_check 失败）
#     ② 若不跑 -> 与本项自身判据矛盾（实测: 只读模式必然失败）
#
#   => **两者不可兼得**。这不是"顺序/模式"能解决的，而是**分层问题**:
#     · **门禁**（release_check.ps1）= Windows 侧快速回归，**状态自洽**
#     · **本脚本** = Linux 端到端，**自建 + 自验**，独立调用
#
#   ## 与既有实践一致
#     `linux_compile_check`（**只编译**、不改 demo/gen）**留在**门禁 ✅
#     本脚本（**要构建**、改 demo/gen）**移出** ✅
#
# ## 用法
#   powershell -File tools\ci_linux.ps1              # 完整（含 build.sh）
#   powershell -File tools\ci_linux.ps1 -SkipBuild   # 只用已有产物
#   powershell -File tools\ci_linux.ps1 -Selftest    # 只跑负向自检
#
# ## 前置
#   WSL + Ubuntu-24.04 + gcc + libssl-dev
# =============================================================================
param(
    [switch]$SkipBuild,
    [switch]$Selftest,
    # 显式指定 python 路径（缺省自动探测，排除 Store 别名）
    [string]$Python = ''
)

# ## D2（2026-09-29）: **验证互斥锁**
#
#   本脚本与另一侧验证（门禁 <-> ci_linux）**共享可变状态**
#   （demo/gen/、build/、demo/vm_build.json）-> 并发会造成**假失败**
#   （把判据本身误报为坏的；实测已 3 次误判）。
#
#   语义: 拿不到锁 -> **报错退出**（含持有者 PID/时长），**不排队**
#   （串行可预测 + 日志不交错）；过期锁(>45min)自动清除（崩溃兜底）。
#
#   **释放放 finally** —— 实测 PowerShell 的 `exit`/`throw`/正常结束
#   **都会触发 finally**，故释放不漏（**不依赖"记得释放"**）。
& "$PSScriptRoot\verify_lock.ps1" -Holder 'ci_linux'
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
try {

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

# ## Python 探测（**复用 release_check.ps1 的已验证逻辑**）
#
# ⚠️ 必须**排除 Windows Store 的别名存根**（`*\WindowsApps\*`）——
#   它是 0 字节的转发器，被执行会打印"Python was not found"
#   并返回非 0（实测踩过）。
$py = $Python
if (-not $py) {
    $cand = @(Get-Command python -ErrorAction SilentlyContinue |
              Where-Object { $_.Source -notlike '*\WindowsApps\*' } |
              Select-Object -First 1)
    if ($cand) { $py = $cand.Source }
}
if (-not $py) {
    foreach ($p in @('D:\environment\PYTHON\python.exe',
                     'C:\Python313\python.exe')) {
        if (Test-Path -LiteralPath $p) { $py = $p; break }
    }
}
if (-not $py) { throw 'ci_linux: cannot locate python（用 -Python 指定）' }

Write-Host '=== ShardVase Linux 端到端验证 ===' -ForegroundColor Cyan
Write-Host ("  python = {0}" -f $py)

# WSL 可用性（不可用 -> 明确失败，不静默通过）
$wslOk = $false
try {
    & wsl.exe --version 2>&1 | Out-Null
    $wslOk = ($LASTEXITCODE -eq 0)
} catch { $wslOk = $false }
if (-not $wslOk) {
    Write-Host '[FAIL] WSL 不可用 —— Linux 端到端验证无法执行' -ForegroundColor Red
    exit 1
}

if ($Selftest) {
    Write-Host ''
    Write-Host '--- 负向自检 ---' -ForegroundColor Cyan
    & $py tools\verify_linux_runtime.py --selftest
    exit $LASTEXITCODE
}

$args2 = @()
if ($SkipBuild) { $args2 += '--skip-build' }

Write-Host ''
Write-Host '--- 运行时验证（12 项）---' -ForegroundColor Cyan
& $py tools\verify_linux_runtime.py @args2
$rc = $LASTEXITCODE


# ## D1（2026-09-29）: **平台无关检查器镜像 + 检查器变异测试**
#
# ## 为什么加
#   此前 ci_linux **只有运行时验证** —— 那 7 个"纯逻辑"检查器
#   （modcheck/conformance/attackcheck/...）**只在 Windows 门禁跑**：
#   若有人**只跑 Linux 入口**，它们就**完全不被验证**（覆盖缺口）。
#   同理，Linux 侧的检查器（protchain/e2e/attacks）**从未自证能抓错**
#   —— 即"判据可能已经变盲"没有守护（`mutate_check --platform linux` 补此）。
#
# ## 不镜像 migration_gate 的理由
#   它 **96s + 跑 2 次 Windows 构建**（`demo.exe` 引用=1，非纯逻辑）——
#   与"Linux 端到端验证"的定位不符；**已在门禁**（第 22 项），不重复。
Write-Host ''
Write-Host '--- 平台无关检查器镜像（D1, 7 项）---' -ForegroundColor Cyan
$mirrorFail = 0
$mirrors = @(
    @('modcheck',        @('tools/modcheck.py', '--all-compositions')),
    @('drills',          @('tools/drills.py', 'lint')),
    @('doccheck',        @('tools/doccheck.py')),
    @('conformance',     @('tools/conformance.py', '--selftest', '--quiet')),
    @('comment_lint',    @('tools/comment_lint.py', '--quiet')),
    @('attackcheck',     @('tools/attackcheck.py')),
    @('skeleton_check',  @('tools/skeleton_check.py'))
)
foreach ($m in $mirrors) {
    $name = $m[0]
    $cmd = $m[1]
    & $py @cmd
    if ($LASTEXITCODE -eq 0) {
        Write-Host ("  ok   {0}" -f $name) -ForegroundColor Green
    } else {
        Write-Host ("  FAIL {0} (rc={1})" -f $name, $LASTEXITCODE) -ForegroundColor Red
        $script:mirrorFail++
    }
}

Write-Host ''
Write-Host '--- 检查器变异测试（platform=linux；**Linux 侧自证能抓错**）---' -ForegroundColor Cyan
& $py tools\mutate_check.py --platform linux
$mutRc = $LASTEXITCODE
if ($mutRc -eq 0) {
    Write-Host '  ok   mutate_check (linux): 6 健康 / 0 盲' -ForegroundColor Green
} else {
    Write-Host '  FAIL mutate_check (linux)' -ForegroundColor Red
    $script:mirrorFail++
}

Write-Host ''
$allOk = ($rc -eq 0 -and $script:mirrorFail -eq 0)
if ($allOk) {
    Write-Host '[ci_linux] PASS（运行时 + 镜像检查 + 检查器健康）' -ForegroundColor Green
    exit 0
} else {
    $msg = '[ci_linux] FAIL（runtime={0}, 镜像/变异失败={1}）' -f $rc, $script:mirrorFail
    Write-Host $msg -ForegroundColor Red
    exit 1
}
} finally {
    # D2: 释放锁（**finally 覆盖 exit/throw/正常**）
    & "$PSScriptRoot\verify_lock.ps1" -Holder 'ci_linux' -Release
}
