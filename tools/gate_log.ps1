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
        & powershell -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath -Selftest
        exit $LASTEXITCODE
    }
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('gate_log_st_{0}' -f (Get-Date -Format 'HHmmssfff'))
    $npass = 0; $nfail = 0
    function Chk([string]$name, [scriptblock]$cond) {
        $out = @(& $cond)
        $ok = $out[-1]
        if ($ok) { Write-Host ("  ok  {0}" -f $name) -ForegroundColor Green; $script:npass++ }
        else { Write-Host ("  [X] {0}" -f $name) -ForegroundColor Red; $script:nfail++ }
    }
    try {
        # T1 正向: 开启
        Chk 'T1 开启转录 rc=0 且返回文件已创建' {
            & $PSCommandPath -Dir $tmp -Name st -Quiet
            $p = [string](Get-Variable -Name $STATE_VAR -Scope Global -ValueOnly -ErrorAction SilentlyContinue)
            ($LASTEXITCODE -eq 0) -and ($p -ne '') -and (Test-Path -LiteralPath $p)
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
    } finally {
        $null = & $PSCommandPath -Stop -Quiet
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
    }
    Write-Host ''
    Write-Host ("[gate_log-selftest] {0}: {1} 项（含 3 负向）" -f $(if ($nfail -eq 0) { 'PASS' } else { 'FAIL' }), ($npass + $nfail)) -ForegroundColor $(if ($nfail -eq 0) { 'Green' } else { 'Red' })
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
