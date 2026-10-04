# tools/gate_log.ps1 — **门禁落日志**（2026-09-30）
#
# ## 为什么需要（**实测的事故**）
#   门禁（release_check.ps1）与 Linux 端到端验证（ci_linux.ps1）**不落日志**。
#   实测事故: 一次门禁报「1/29 未通过」，但调用方只截取了 `-Last 6` 行，
#   失败项名与详情**永久丢失** -> 同一失败此后连跑 5 轮**无法复现、无法定位**。
#   这与 R2.3 记名的「诊断信息不可丢失」是**同型问题**:
#   **判据失败时留下的证据，比判据本身更值钱**（否则只能靠运气重跑）。
#
# ## 语义
#   start（默认）: 开启转录 -> 本轮**所有**输出（含 Write-Host 写的宿主 UI 流）
#                  落盘到 <Dir>/<Name>_<yyyyMMdd_HHmmss>.log，并写入会话变量
#    -Stop       : 停止转录，**返回该日志的完整路径**（供调用方打印给用户）
#    -Selftest   : 自检（正向 + 负向）
#
# ## 设计要点
#   · **不改变门禁输出** —— start 只多打印一行 `[log] <路径>`（`-Quiet` 可抑制）
#   · **失败不致命**: 无法建目录/无法转录 -> 只告警，**绝不中断门禁**
#     （日志是辅助证据，不能成为新的失败源）
#   · 路径存在**会话变量** `$global:__GateLogPath`（跨脚本调用有效 —— 实测）,
#     不落状态文件 -> 无陈旧状态可残留
#   · 日志目录在 `build/` 下（已 gitignore -> 不污染 git）
#   · 文件名带**时间戳** -> 多次运行不互相覆盖（失败可回溯到当时那一轮）
#   · **转录文件是异步落盘的**: `Start-Transcript` 返回后文件可能还不可见
#     （实测可见延迟 0..28 毫秒）-> 任何'开启后立刻检查文件'的断言必须
#     用**有界等待**，否则就是拿调度抖动当缺陷（T1 曾因此间歇性 FAIL）
#   · 为什么用 `Start-Transcript` 而不是自己 tee:
#     实测（%TEMP%\z5_transcript_probe2.ps1）**忠实复刻门禁的 `Check` 函数**
#     （`$out = @(& $cond); $ok = $out[-1]`）后验证: `Write-Host` 裸调用、
#     `& { Write-Host … } | Out-Null`、`Check` 内部详情行、`[ok]`/`[X]` 行、
#     `Write-Output` —— **五行全部进日志**。
#     => 无需改写门禁里上百处 Write-Host（改动越小，越不会引入新缺陷）。
#
# ## 用法
#   & "$PSScriptRoot\gate_log.ps1" -Dir <日志目录> -Name release_check
#       -> 开启转录；失败只告警
#   $log = & "$PSScriptRoot\gate_log.ps1" -Stop
#       -> 停止转录并返回日志路径（未开启时返回空串）
param(
    # 日志目录（绝对路径；调用方用 $PSScriptRoot 拼，避免受当前目录影响）
    [string]$Dir = '',
    # 文件名前缀（区分 release_check / ci_linux）
    [string]$Name = 'gate',
    # 停止转录并返回日志路径
    [switch]$Stop,
    # 抑制 `[log]` 信息行（自检子调用用 —— 同 verify_lock 的 -Quiet 理由）
    [switch]$Quiet,
    # 自检（本项目纪律: 每个 checker 必须带**负向**自检）
    [switch]$Selftest
)

$ErrorActionPreference = 'Stop'
$STATE_VAR = '__GateLogPath'

function Out-Gl {
    param([string]$Msg, [string]$Color = 'DarkGray')
    if (-not $Quiet) { Write-Host $Msg -ForegroundColor $Color }
}

# ## -Stop: 停止转录并交还路径
if ($Stop) {
    $p = [string](Get-Variable -Name $STATE_VAR -Scope Global -ValueOnly -ErrorAction SilentlyContinue)
    if (-not $p) {
        Out-Gl '[log] 未开启转录（-Stop 无动作）' 'DarkYellow'
        exit 0
    }
    try { Stop-Transcript | Out-Null } catch {
        # 已停止 / 未开启 -> 非致命
        Out-Gl ("[log] 停止转录时告警: {0}" -f $_.Exception.Message) 'DarkYellow'
    }
    Set-Variable -Name $STATE_VAR -Scope Global -Value $null
    # 只输出路径（供调用方 `$log = & …` 捕获）
    Write-Output $p
    exit 0
}

# ## 自检（不依赖仓库状态 -> 无需 SKIP）
if ($Selftest) {
    # ## ⚠️ 自检必须**隔离会话**（同 verify_lock「自检删掉门禁自己的锁」那类事故）
    #
    #   本自检要 start/stop 转录；而 `Start-Transcript`/`Stop-Transcript` 是
    #   **会话级**的。若门禁自己已经开着转录（它正是这么用的），自检在**同一会话**
    #   里跑 -> T2 的 `-Stop` 会把**门禁那一轮**的日志掐断，门禁末尾的总结行
    #   与 FAIL 详情就**永远不会落盘** —— 恰好毁掉本工具存在的理由。
    #   => 检测到外层转录时，**换子进程**跑自检（子进程会话干净，互不干扰）。
    $outer = [string](Get-Variable -Name $STATE_VAR -Scope Global -ValueOnly -ErrorAction SilentlyContinue)
    if ($outer -and -not $env:__GATE_LOG_CHILD) {
        $env:__GATE_LOG_CHILD = '1'
        Write-Host '[gate_log] 检测到外层转录 -> 自检改在子进程会话运行（不干扰门禁日志）' -ForegroundColor DarkGray
        # ## ⚠️ 子进程的诊断**必须显式回显到父会话**（2026-10-02 修正）
        #
        #   实测缺陷: CI 上报 `[X]  门禁日志自检 (gate_log)`，而门禁日志里
        #   **只有上面那一行 + `[X]` 行**，T1..T5 的逐项结果**一行都没有** ——
        #   即"失败了，但失败理由永久丢失"。这与本文件头记录的那次事故同型。
        #
        #   机制: 子进程的 `Write-Host` 写在**子进程自己的宿主**上。调用方
        #   `Check` 把它包成 `@(& $cond)` 并把 `| Out-Null` 接在后面
        #   （`release_check.ps1` 的门禁项正是这么写的），于是子进程的输出
        #   既不进 `$out`（`Write-Host` 走**信息流**，不是成功流），
        #   也不进父会话的 `Start-Transcript`（转录只记录**本会话**的宿主输出）。
        #   => 子进程静默，父会话只看到冷冰冰的 `[X]`。
        #
        #   修法: 把子进程的输出**捕获后由父会话重新 `Write-Host`** ——
        #   这样它同时进入 ① 控制台 ② 父会话的转录（= 门禁日志）。
        #   并且**先取出退出码再回显**: 回显过程里的任何写入都不会污染
        #   `$LASTEXITCODE`（早先依赖 `exit $LASTEXITCODE` 直接读全局变量，
        #   在多一层管道/包装时不可靠）。
        $childOut = @(& powershell -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath -Selftest 2>&1)
        $rc = $LASTEXITCODE
        foreach ($line in $childOut) { Write-Host ([string]$line) }
        exit $rc
    }
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('gate_log_st_{0}' -f (Get-Date -Format 'HHmmssfff'))
    $npass = 0; $nfail = 0
    # 有界等待路径出现（仅 T1 用）
    #   见 T1 注释: `Start-Transcript` 的转录文件是**异步**落盘的,
    #   立即 `Test-Path` 测的是调度抖动, 不是缺陷。
    function Wait-Path([string]$Path, [int]$TimeoutMs = 2000) {
        if (-not $Path) { return $false }
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        while (-not (Test-Path -LiteralPath $Path)) {
            if ($sw.ElapsedMilliseconds -ge $TimeoutMs) { return $false }
            Start-Sleep -Milliseconds 20
        }
        return $true
    }
    function Chk([string]$name, [scriptblock]$cond) {
        $out = @(& $cond)
        $ok = $out[-1]
        if ($ok) { Write-Host ("  ok  {0}" -f $name) -ForegroundColor Green; $script:npass++ }
        else { Write-Host ("  [X] {0}" -f $name) -ForegroundColor Red; $script:nfail++ }
    }
    try {
        # T1 正向: 开启
        #   ⚠️ `Start-Transcript` 的转录文件是**异步**落盘的 —— 紧跟其后 `Test-Path`
        #   测到的是调度抖动，不是缺陷。实测（build/_glP2.ps1, 紧接调用即断言）:
        #   40 次里 38 次报"文件不存在"，而目录里 `st.log` **确实已经在了**；
        #   文件可见延迟实测 0,18,7,25,25,25,25,23,28,20,21,2 毫秒（build/_glRace.ps1）。
        #   真 T1 里中间隔了一次脚本调用 + `Get-Variable`，通常已够时间刷出
        #   -> 本地几乎总是通过，但它是**间歇性**失败: CI 第 16 跑就是这么红的
        #   （`exists=False` 而 `p` 非空、T2..T5 全 ok —— 同型签名已在本地复现）。
        #   => 用**有界等待**替代立即断言。判据不变（文件最终还是得出现）；
        #      真正"开启失败"的路径由 `$p -ne ''` 挡住（Start-Transcript 抛错时
        #      `$p` 不会被赋值），故判别力不受影响。T6 守住等待本身不空转。
        Chk 'T1 开启转录 rc=0 且返回文件已创建' {
            & $PSCommandPath -Dir $tmp -Name st -Quiet
            $rc1 = $LASTEXITCODE
            $p = [string](Get-Variable -Name $STATE_VAR -Scope Global -ValueOnly -ErrorAction SilentlyContinue)
            ($rc1 -eq 0) -and ($p -ne '') -and (Wait-Path -Path $p -TimeoutMs 2000)
        }
        # T2 **正向对照**: 开启后写的行必须落进文件（证"链路是通的"）
        #    没有这一条，"日志里没有"就无法区分「没写」与「没记」
        Chk 'T2 正向对照: 开启后的 Write-Host 必须落盘' {
            $marker = '[gate_log 自检] 正向对照标记（应落盘）: ' + [guid]::NewGuid().ToString('N').Substring(0, 8)
            Write-Host $marker
            $p = [string](Get-Variable -Name $STATE_VAR -Scope Global -ValueOnly)
            # 转录按块刷盘 -> 先停止再读（停止后文件闭合，读得可靠）
            $null = & $PSCommandPath -Stop
            (Get-Content -LiteralPath $p -Raw -ErrorAction SilentlyContinue) -match [regex]::Escape($marker)
        }
        # T3 **负向**: 停止后写的行**不得**进日志
        Chk 'T3 负向: 停止后写的行不得进日志' {
            & $PSCommandPath -Dir $tmp -Name st2 -Quiet
            $null = & $PSCommandPath -Stop
            $p2 = (Get-ChildItem -LiteralPath $tmp -Filter 'st2_*.log' | Sort-Object LastWriteTime | Select-Object -Last 1)
            $after = '[gate_log 自检] 停止后标记（不应落盘）: ' + [guid]::NewGuid().ToString('N').Substring(0, 8)
            Write-Host $after
            $txt = Get-Content -LiteralPath $p2.FullName -Raw -ErrorAction SilentlyContinue
            ($p2 -ne $null) -and ($txt -notmatch [regex]::Escape($after))
        }
        # T4 **负向**: 未开启就 -Stop -> 不崩溃、返回空串
        Chk 'T4 负向: 未开启时 -Stop 返回空串且不报错' {
            Set-Variable -Name $STATE_VAR -Scope Global -Value $null
            $r = & $PSCommandPath -Stop -Quiet
            ($LASTEXITCODE -eq 0) -and ([string]::IsNullOrEmpty([string]$r))
        }
        # T5 **负向**: 目录不可用 -> 只告警、**不中断**（exit 0）
        #    日志是辅助证据，不能成为新的失败源。
        #    注意用「把已存在的**文件**当目录」造必然失败 —— 若用多级路径，
        #    `New-Item -Force` 会**自动补建中间目录**，测试就变成空转
        #    （本项目已多次栽在"看似在测、其实没测"上）。
        Chk 'T5 负向: 目录不可用时不致命 (rc=0)' {
            $asFile = Join-Path $tmp 'iam_a_file.txt'
            Set-Content -LiteralPath $asFile -Value 'x' -Encoding ascii
            & $PSCommandPath -Dir $asFile -Name st3 -Quiet
            $LASTEXITCODE -eq 0
        }
        # T6 **负向**: 有界等待不得"永远返回真"
        #   否则 T1 的等待等于把断言取消掉（本仓库反复记名的
        #   "看似在测、其实没测"）。同时守住空串路径不抛异常。
        Chk 'T6 负向: 有界等待对不存在的路径返回假且空串不抛' {
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $absent = Join-Path $tmp ('absent_{0}.log' -f [guid]::NewGuid().ToString('N'))
            $r1 = Wait-Path -Path $absent -TimeoutMs 300
            $el = $sw.ElapsedMilliseconds
            $r2 = Wait-Path -Path '' -TimeoutMs 50
            (-not $r1) -and (-not $r2) -and ($el -ge 250)
        }
    } finally {
        $null = & $PSCommandPath -Stop -Quiet
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
    }
    Write-Host ''
    Write-Host ("[gate_log-selftest] {0}: {1} 项（含 4 负向）" -f $(if ($nfail -eq 0) { 'PASS' } else { 'FAIL' }), ($npass + $nfail)) -ForegroundColor $(if ($nfail -eq 0) { 'Green' } else { 'Red' })
    exit $(if ($nfail -eq 0) { 0 } else { 1 })
}

# ## start
if (-not $Dir) {
    Out-Gl '[log] -Dir 必填（或用 -Stop / -Selftest）' 'Red'
    exit 2
}
$logPath = ''
try {
    if (-not (Test-Path -LiteralPath $Dir)) { New-Item -ItemType Directory -Force -Path $Dir | Out-Null }
    $logPath = Join-Path $Dir ('{0}_{1}.log' -f $Name, (Get-Date -Format 'yyyyMMdd_HHmmss'))
    Start-Transcript -Path $logPath -Force | Out-Null
    Set-Variable -Name $STATE_VAR -Scope Global -Value $logPath
    Out-Gl ("[log] 本轮完整输出: {0}" -f $logPath)
} catch {
    # **不致命**: 日志失败不能把门禁本身变成失败
    Out-Gl ("[log] 无法开启日志（{0}）—— 继续，但失败现场不会落盘" -f $_.Exception.Message) 'DarkYellow'
}
exit 0
