# tools/verify_lock.ps1 — **验证互斥锁**（D2, 2026-09-29）
#
# ## 为什么需要（**实测的结构性浪费**）
#   门禁（release_check.ps1）与 Linux 端到端验证（ci_linux.ps1）**共享
#   可变状态**（`demo/gen/`、`build/`、`demo/vm_build.json`）。两者**并发**时
#   会互相污染 -> **假失败**（把判据本身误报为坏了）。
#   实测记录: 本项目已有 **3 次**因此误判（§25 记录 2 次、后续 1 次）。
#
# ## 语义
#   acquire（默认）: 锁空闲 -> 拿到并写 PID/持有者/时间；锁被占 -> **报错退出 1**
#   -Release       : 释放（**只释放自己持有的** —— 防止误删别人的锁）
#   过期(>45min)    : 视为 stale（持锁进程已崩溃）-> **清除并继续拿**
#
# ## 为什么"报错"而非"排队等待"
#   本项目要求**串行可预测**: 等待会把两个慢任务（门禁 ~4 分钟、ci ~10 分钟）
#   串成更慢的，且**日志交错**难以定位问题。
#   => 明确拒绝 + 告知**谁**持有（PID/持有者/已等待时长），由人决定。
#
# ## 用法
#   powershell -File tools\verify_lock.ps1 -Holder release_check
#       -> 拿到锁: exit 0 ；已被占: exit 1（打印持有者）
#   powershell -File tools\verify_lock.ps1 -Holder release_check -Release
#       -> 释放自己持有的锁；不是自己的则不动作（exit 0）
#
# ## 设计要点
#   · 锁文件 <repo>/build/.verify.lock（build/ 已 gitignore -> 不污染 git）
#   · 内容为**单行 JSON**（读写原子性比 YAML 好）
#   · 过期阈值 45 分钟（门禁/最长 ci 均 < 15 分钟；留足余量）
#   · **stale 也打印**（不静默清除 —— 需让人知道曾崩溃过）
param(
    [string]$Holder = '',
    [switch]$Release,
    # 内部: 指定锁文件路径（**自检用独立锁**，绝不碰真锁 —— 见下）
    [string]$LockPath = '',
    # 抑制所有 `[lock]` 信息行（自检子调用用：
    #  `Write-Host` 走宿主 UI 流 -> `| Out-Null` 捕获不到 ->
    #  自检的拒绝行会污染门禁输出，让读者误以为门禁被拒）
    [switch]$Quiet,
    # D2: **自检**（每个 checker 需负向自检 —— 本项目纪律）
    #   覆盖: 获取/并发拒绝/非持有者不动/持有者释放/过期清除/无残留
    [switch]$Selftest
)

$ErrorActionPreference = 'Stop'
if (-not $Selftest -and -not $Holder) {
    if (-not $Quiet) { Write-Host '[lock] -Holder 必填（或用 -Selftest）' -ForegroundColor Red }
    exit 2
}
$repo = Split-Path -Parent $PSScriptRoot
$buildDir = Join-Path $repo 'build'
if (-not (Test-Path $buildDir)) { New-Item -ItemType Directory -Path $buildDir | Out-Null }
$LOCK = if ($LockPath) { $LockPath } else { Join-Path $buildDir '.verify.lock' }
$STALE_MIN = 45


function Out-Lock {
    param([string]$Msg, [string]$Color = 'DarkGray')
    if (-not $Quiet) { Write-Host $Msg -ForegroundColor $Color }
}

function Read-Lock {
    if (-not (Test-Path $LOCK)) { return $null }
    try {
        $raw = Get-Content -LiteralPath $LOCK -Raw
        if (-not $raw.Trim()) { return $null }
        return ($raw | ConvertFrom-Json)
    } catch {
        return $null        # 损坏的锁 -> 视为可覆盖（见主流程）
    }
}

if ($Release) {
    $d = Read-Lock
    if ($d -ne $null -and $d.holder -eq $Holder) {
        Remove-Item -LiteralPath $LOCK -Force -ErrorAction SilentlyContinue
        Out-Lock ('[lock] 已释放: {0} (pid {1})' -f $d.holder, $d.pid)
    } elseif ($d -ne $null) {
        # 不是自己持有的 -> **不动**（可能别人的会话），只提示
        Out-Lock ('[lock] 不释放（持有者是 {0}，非 {1}）' -f $d.holder, $Holder) 'DarkYellow'
    }
    exit 0
}


# ---------------------------------------------------------------------------
# 自检（D2, 2026-09-29）
# ---------------------------------------------------------------------------
# ## 为什么要自检
#   锁是"**验证互斥**"的基础设施 —— 它若自身坏了（**拿得到锁却不去重**），
#   后续所有并发保护都是**假的**（"一个只会通过的检查器比没有更危险"的同类）。
#   => 自检含 **3 个负向**（并发必须被拒 / 非持有者不能删 / 过期必须清）。
function Invoke-Selftest {
    $script:me = 'selftest_probe'
    $fail = 0
    # `$MyInvocation.MyCommand.Path` 在**函数内为 null**（PowerShell 语义）
    # -> 用 `$PSScriptRoot`（脚本所在目录，函数内可用，PowerShell 3+）
    $here = $PSScriptRoot

    function Case($name, $cond, $detail) {
        if ($cond) { Write-Host ("  ok  {0}" -f $name) -ForegroundColor Green }
        else       { Write-Host ("  **FAIL** {0}  {1}" -f $name, $detail) -ForegroundColor Red; $script:fail++ }
    }

    Write-Host '=== verify_lock 自检 ==='
    # ## ⚠️ 自检用**独立锁文件**（修: 接入门禁前的隐患）
    #   原来这里 `Remove-Item $LOCK` 会**删掉门禁自己的锁** ->
    #   门禁中途失锁 -> **互斥失效**。
    #   => 自检全程用 `build/.verify.lock.selftest`，**绝不碰真锁**。
    $script:LOCK = Join-Path $buildDir '.verify.lock.selftest'
    if (Test-Path $script:LOCK) { Remove-Item $script:LOCK -Force }

    # T1 正向: 首次获取成功
    & $here\verify_lock.ps1 -Holder t1 -LockPath $script:LOCK -Quiet | Out-Null
    Case 'T1 首次获取 rc=0' ($LASTEXITCODE -eq 0) "rc=$LASTEXITCODE"
    Case 'T1b 锁文件已创建' (Test-Path $LOCK) '缺失'

    # T2 负向: 并发获取必须被拒
    & $here\verify_lock.ps1 -Holder t2 2>&1 -LockPath $script:LOCK -Quiet | Out-Null
    Case 'T2 **负向** 并发获取被拒 rc=1' ($LASTEXITCODE -eq 1) "rc=$LASTEXITCODE"

    # T3 负向: 非持有者释放不能删锁
    & $here\verify_lock.ps1 -Holder t2 -Release -LockPath $script:LOCK -Quiet | Out-Null
    Case 'T3 **负向** 非持有者释放**不动**锁' (Test-Path $LOCK) '锁被误删'

    # T4 正向: 持有者释放
    & $here\verify_lock.ps1 -Holder t1 -Release -LockPath $script:LOCK -Quiet | Out-Null
    Case 'T4 持有者释放后锁消失' (-not (Test-Path $LOCK)) '锁仍存在'

    # T5 负向: 过期锁必须被清除
    $stale = @{ holder='dead'; pid=1; time=((Get-Date).AddMinutes(-46)).ToString('yyyy-MM-dd HH:mm:ss') }
    ($stale | ConvertTo-Json) | Set-Content -LiteralPath $LOCK -Encoding UTF8
    & $here\verify_lock.ps1 -Holder t5 2>&1 -LockPath $script:LOCK -Quiet | Out-Null
    Case 'T5 **负向** 过期锁(46min)自动清除并拿到' ($LASTEXITCODE -eq 0) "rc=$LASTEXITCODE"
    & $here\verify_lock.ps1 -Holder t5 -Release -LockPath $script:LOCK -Quiet | Out-Null

    # T6 无残留
    Case 'T6 最终**无残留**锁' (-not (Test-Path $LOCK)) '锁残留'

    # 自检锁的兜底清理（T6 已断言，此处防异常路径残留）
    if (Test-Path $script:LOCK) { Remove-Item $script:LOCK -Force -ErrorAction SilentlyContinue }

    Write-Host ''
    if ($fail -gt 0) {
        Write-Host ('[verify_lock-selftest] FAIL: {0} 项' -f $fail) -ForegroundColor Red
        return 1
    }
    Write-Host '[verify_lock-selftest] PASS: 6 项（含 3 负向）' -ForegroundColor Green
    return 0
}

if ($Selftest) {
    $rc = Invoke-Selftest
    exit $rc
}

# ---- acquire ----
$d = Read-Lock
if ($d -ne $null) {
    $ageMin = ((Get-Date) - [datetime]$d.time).TotalMinutes
    if ($ageMin -lt $STALE_MIN) {
        $msg = '[lock] 拒绝: 验证互斥锁已被占用' + "`n" +
               ('持有者={0}  PID={1}  启动={2}  已占 {3:N1} 分钟' -f $d.holder, $d.pid, $d.time, $ageMin) + "`n" +
               '           本项目要求**串行**验证（门禁与 ci_linux 共享可变状态；' + "`n" +
               '           并发会造成假失败）。请等对方结束，或确信其已崩溃时手动删除:' +
               "`n" + '           del build\.verify.lock'
        if (-not $Quiet) { Write-Host $msg -ForegroundColor Red }
        exit 1
    }
    # 过期（>45 分钟）-> stale：持锁进程多半已崩溃
    $ageTxt = '{0:N0}' -f $ageMin
    Out-Lock ('[lock] 清除**过期**锁: {0} (pid {1}, 已占 {2} 分钟)' -f $d.holder, $d.pid, $ageTxt) 'DarkYellow'
    Remove-Item -LiteralPath $LOCK -Force -ErrorAction SilentlyContinue
}

$obj = @{
    holder = $Holder
    pid    = $PID
    time   = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
}
try {
    ($obj | ConvertTo-Json) | Set-Content -LiteralPath $LOCK -Encoding UTF8
} catch {
    if (-not $Quiet) { Write-Host ('[lock] 写锁失败: {0}' -f $_.Exception.Message) -ForegroundColor Red }
    exit 1
}
Out-Lock ('[lock] 已获取: {0} (pid {1})' -f $Holder, $PID)
exit 0
