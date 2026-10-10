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
    # 骨架回归（2026-09-23）: 构建一次骨架工程，验证 **DIY 用户路径**可用。
    # 约 30-60 秒；发版/CI 建议启用。
    [switch]$WithSkeleton,
    [string]$Python = '',
    # ST2.3: 只跑名字匹配该正则的检查项; 空 = 全跑。
    #   被过滤的项**不执行判据**、如实记为未运行(仍留一枚 [info] 证据行)。
    [string]$Only = ''
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
& "$PSScriptRoot\verify_lock.ps1" -Holder 'release_check'
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# ## 门禁落日志（2026-09-30）: **失败现场不再丢失**
#
#   实测事故: 一次门禁报「1/29 未通过」，但调用方只截了 `-Last 6` 行，
#   失败项名与详情**永久丢失** -> 此后**连跑 5 轮无法复现、无法定位**。
#   这与 R2.3 记名的「诊断信息不可丢失」是**同型问题**。
#
#   => 本轮全部输出（含 `Write-Host` 的宿主 UI 流）落盘到
#      `build/logs/release_check_<时间戳>.log`（build/ 已 gitignore）。
#      开启失败**只告警、不中断**（日志是辅助证据，不能变成新的失败源）。
#      详见 `tools/gate_log.ps1` 文件头。
& "$PSScriptRoot\gate_log.ps1" -Dir (Join-Path (Split-Path -Parent $PSScriptRoot) 'build\logs') -Name release_check
try {

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

# ST2.1(2026-10-10): 结构化出口。先前这里是**死变量** `$checks = @()`(全文再无第二处引用),
#   现改为承载每项结果, 供 NDJSON 出口与总结处的双面对照使用。
$results = @()
$pass = 0; $fail = 0; $skip = 0
$notrun = 0
# ⚠️ 不要在这里写 `$only = ''` —— PowerShell 变量名**大小写不敏感**,
#   那与 param 的 `[string]$Only` 是**同一个变量**, 会把调用方传的值抹掉,
#   于是 -Only 被静默忽略(看起来「过滤没生效」而不是报错)。
$gateStamp = Get-Date -Format 'yyyyMMdd_HHmmss'

# ── 诊断打印（`Check` 的失败/跳过分支共用）────────────────────────────────
#
# ## 为什么必须有（2026-10-02 实测事故）
#   CI 上本门禁报 `FAIL: 5/30 未通过`，而五项失败**一行原因都没有** ——
#   日志里只有五个孤零零的 `[X]  <名字>`。原因（被测进程的 stdout）在
#   `Check` 里被 `$out[-1]` 截断丢掉了，而 `tools/gate_log.ps1` 的转录
#   只忠实记录"被打印出来的东西"。
#   => 拿到"哪一项失败"，拿不到"为什么失败"，**无法定位**。检查项本身
#      大多用 `--quiet` 或 `| Out-Null` 抑制了输出，于是现场彻底空白。
#   这与 `tools/gate_log.ps1` 文件头记名的「失败项名与详情**永久丢失**」
#   是**同型事故** —— 只是这次丢的恰好是详情。
#
# ## 判据
#   `$out` 的**末值就是判据本身**（布尔或 `'SKIP'`），其余全部是被测进程
#   的输出 -> 逐行缩进打印。**限长**以免一个失败的构建把日志刷爆 ——
#   但**绝不静默**（无输出时明确说明）。
#
# ## ⚠️ 限长规则本身出过一次事故（2026-10-02，同一天）
#   第一版限长写的是**盲取末 12 行**（`Select-Object -Last 12`）。CI 第四跑
#   立刻证明它**恰好丢掉了唯一有用的那一行**: `e2e T1-T28` 失败时，被测
#   脚本先逐项打印 27 行用例、**再**打印汇总行 —— 于是"末 12 行"全是
#   `T16..T26 PASS` 的噪声，真正含 `FAIL` 的那一行（在 T1..T15 区间）
#   被当作"前 N 行"省略了。日志里只有:
#       [X]  e2e T1-T28
#       ... 省略前 17 行诊断 ...
#       | T16 revoke-clean  PASS …
#   => **拿到了"哪一项失败"，依然拿不到"为什么失败"**，与本次修复的初衷
#      完全同型地失败了第二次。
#   **教训: "限长"不能只按位置取（末 N 行），必须按**相关性**取** ——
#   含失败标记的行优先于普通行，位置只用作同优先级内的次序。
#
# ## 选择规则
#   ① 收集全部诊断行（展开多行字符串），滤掉 `$null` 与空行；
#   ② **信号行优先**: 匹配 `FAIL|ERROR|Traceback|Exception|[X]|✗|未通过|
#      错误|失败` 的行先入选（若信号行多于预算，取**靠后**的 —— 靠近结论
#      的更相关）；
#   ③ 预算未满时再从**尾部**补齐（去重），保持原始行序输出；
#   ④ 只要有省略就**如实报告总行数**（"诊断共 N 行，此处显示 M 行"），
#      绝不让读者以为已经看到了全部。
function Show-Diag($out, [string]$prefix = '      | ') {
    $diag = @()
    if ($out.Count -gt 1) { $diag = @($out[0..($out.Count - 2)]) }

    # 展开为行（一个元素可能是多行字符串）
    $lines = @()
    foreach ($d in $diag) {
        if ($null -eq $d) { continue }
        foreach ($ln in ([string]$d -split "`r?`n")) {
            $t = $ln.TrimEnd()
            if ($t -ne '') { $lines += $t }
        }
    }
    if ($lines.Count -eq 0) {
        Write-Host '      (该项无额外诊断输出 —— 它只返回了判据本身)' -ForegroundColor DarkGray
        return
    }

    $budget = 12
    $re = '(?i)FAIL|ERROR|Traceback|Exception|\[X\]|✗|未通过|错误|失败'

    # ② 信号行优先（多则取靠后的）
    $sig = @()
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match $re) { $sig += $i }
    }
    $pick = @()
    if ($sig.Count -gt 0) {
        $start = [Math]::Max(0, $sig.Count - $budget)
        for ($k = $start; $k -lt $sig.Count; $k++) { $pick += $sig[$k] }
    }
    # ③ 未满则从尾部补齐（去重，保持原序）
    if ($pick.Count -lt $budget) {
        for ($i = $lines.Count - 1; $i -ge 0 -and $pick.Count -lt $budget; $i--) {
            if ($pick -notcontains $i) { $pick += $i }
        }
    }
    $pick = @($pick | Sort-Object)

    # ④ 有省略就如实报总数
    if ($pick.Count -lt $lines.Count) {
        $sigNote = if ($sig.Count -gt 0) { '，含失败标记的行已优先保留' } else { '' }
        Write-Host ("      ... 诊断共 {0} 行，此处显示 {1} 行{2} ..." -f `
            $lines.Count, $pick.Count, $sigNote) -ForegroundColor DarkGray
    }
    foreach ($i in $pick) {
        $ln = $lines[$i]
        if ($ln.Length -gt 400) { $ln = $ln.Substring(0, 400) + ' …' }
        Write-Host ($prefix + $ln) -ForegroundColor DarkGray
    }
}

function Get-GateWhy($out) {
    # ST2.1: 失败原因取"最后一个非空诊断行" —— 与 Show-Diag 取值口径同源。
    if ($null -ne $out -and $out.Count -gt 1) {
        for ($i = $out.Count - 2; $i -ge 0; $i--) {
            $t = ([string]$out[$i]).Trim()
            if ($t -ne '') {
                if ($t.Length -gt 200) { $t = $t.Substring(0, 200) + ' …' }
                return $t
            }
        }
    }
    return $null
}

function Add-GateResult([string]$name, [string]$status, $seconds, $why) {
    # ST2.1(2026-10-10): 门禁结果的**结构化**出口。
    #   它与 Write-Host 的文本出口在**同一个分支里**产生, 因此天然同源;
    #   总结处的"双面对照"比对 JSON 计数与文本侧计数器, 抓的是
    #   "某天有人给文本加了新分支却忘了记录"(或反之)。
    #   ⚠️ 真正的**独立**对账是 `tools/gate_results.py --verify`:
    #   它去读 transcript 里的**实际行**, 而不是信任这里的计数器。
    #   status 取值与文本记号一一对应:
    #     pass=[ok] / fail=[X] / error=[X]检查写法错误 /
    #     skip=[skip] / not-run=[info] 未运行
    $r = [ordered]@{
        seq     = $script:results.Count + 1
        name    = $name
        status  = $status
        seconds = [math]::Round([double]$seconds, 3)
        why     = $why
    }
    $script:results += , $r
}

function Check([string]$name, [scriptblock]$cond) {
    # ST2.3(2026-10-10): `-Only <正则>` 只跑匹配项, 其余如实记为未运行。
    #   ⚠️ 过滤必须在 **scriptblock 之前**发生 —— "未运行"要真的是没运行,
    #   不能跑完再假装没跑。仍打印一枚 `[info] ... 未运行` 证据行:
    #   docclaim 的 T7 不变量要求**每个静态 Check 调用点在运行期恰好留下
    #   一枚证据行**(通过/失败/跳过/未运行)。
    if ($script:Only -and $name -notmatch $script:Only) {
        $script:notrun++
        Add-GateResult $name 'not-run' 0 ('--Only 过滤 (不匹配 /{0}/)' -f $script:Only)
        Write-Host ("[info] {0} 未运行 (--Only 过滤) — 未验证 != 通过" -f $name) -ForegroundColor DarkYellow
        return
    }
    $t0 = Get-Date
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
        $sec = ((Get-Date) - $t0).TotalSeconds

        # ── SKIP 判据（2026-10-02）────────────────────────────────────────
        #
        # ## 为什么需要第三态
        #   CI（Windows-only runner，无 WSL 发行版）上四项检查**必然**因为
        #   "前置产物不存在"而失败: `check_state_platform`（要 linux 产物）、
        #   `docclaim`（要 build/demo_linux）、`perf_baseline`（要
        #   build/perf/full.exe）、`linux_compile_check`（要 WSL 发行版）。
        #   它们报的是 `[X]` —— 于是**门禁在干净克隆上永远不可能变绿**，
        #   而"永远红"的门禁与没有门禁等价（都会被无视）。
        #
        #   但**不能改成通过**: 前置不存在时判据从未执行，"未运行"必须与
        #   "已通过"可区分（本项目反复记名的「未验证 != 通过」）。
        #   => 第三态 `'SKIP'`: 单独计数、单独文案、**不计入 PASS 项数**，
        #      且**只有在明确标注理由时**才允许（见下面的纪律）。
        #
        # ## 纪律（防止 SKIP 变成新的静默通道）
        #   ① 检查项必须**显式** `return 'SKIP'` —— 不按退出码隐式映射
        #      （隐式映射会把"工具坏掉返回 2"也算成跳过）。
        #   ② 跳过时**必须**先 `Write-Host` 说明缺什么、怎么补（下面强制）。
        #   ③ SKIP 计入独立的 `$skip` 计数，并在总结里**单独列出**，
        #      与 `[info] 未运行 — 未验证 != 通过` 同纪律。
        if ($ok -is [string] -and $ok -eq 'SKIP') {
            $script:skip++
            Add-GateResult $name 'skip' $sec '前置不满足（判据从未执行）'
            Write-Host ("[skip] {0} —— 前置不满足，本项未验证（未验证 != 通过）" -f $name) -ForegroundColor DarkYellow
            Show-Diag $out
            return
        }

        # 末值必须是布尔；若拿到字符串（说明 scriptblock 末句不是布尔判断）
        # 则视为检查写法错误 -> **失败而非静默通过**（P3: 不设可绕过的门禁）。
        if ($ok -isnot [bool]) {
            $script:fail++
            $__why = ($ok | Out-String).Trim()
            Add-GateResult $name 'error' $sec ('检查写法错误（末值非布尔: {0}）' -f $__why)
            Write-Host ("[X]  {0}: 检查写法错误（末值非布尔: {1}）" -f `
                $name, ($ok | Out-String).Trim()) -ForegroundColor Red
            return
        }
        if ($ok) { $script:pass++; Add-GateResult $name 'pass' $sec $null; Write-Host ("[ok]  {0}" -f $name) -ForegroundColor Green }
        else {
            $script:fail++
            Add-GateResult $name 'fail' $sec (Get-GateWhy $out)
            Write-Host ("[X]  {0}" -f $name) -ForegroundColor Red
            Show-Diag $out
        }
    } catch {
        $script:fail++; Add-GateResult $name 'fail' ((Get-Date) - $t0).TotalSeconds $_.Exception.Message
        Write-Host ("[X]  {0}: {1}" -f $name, $_.Exception.Message) -ForegroundColor Red
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
    # ## 缺陷 ⑥（2026-10-03 修）: 下面两项原本各建各的, 且**第 3 项的产物无人比对**。
    #
    #   原形态:
    #     :250 `-Config Release -RecordSeeds -SkipSmoke`   (无 -SeedsFile -> 随机盐,
    #                                                      且**签名** -> A)
    #     :254 `repro_check.ps1`（形态 A, 自建两次 -SeedsFile -SkipSign -> B, C,
    #                                                      **只断言 B == C**）
    #   => 一次门禁做 **三次** Release 构建, 其中 A 的 demo.exe **从未与任何东西比过**
    #      （实测 A=3EBCDE6D… / B=C=197550898… ⇒ A != B）, 纯白烧; 且 A 写了
    #      `build\seeds.json`（**这份才是被 CI 上传的**）, 而留在磁盘上的是 C 的
    #      demo.exe —— 上传物来自哪次构建全靠"顺序的副产品"。
    #
    #   修法（本次）: 让第 3 项成为**唯一权威构建**, 第 4 项拿它当基线去比。
    #     · 第 3 项加 `-SkipSign`。**这不改变上传物** —— 原形态下 A 签出来的 exe
    #       本来就会被 repro_check 的第一次构建 100% 覆盖掉, 磁盘上留的一直是
    #       未签名产物（实测 :319 的 Authenticode 项看到的也一直是"未签名"）。
    #       加 -SkipSign 只是不再白烧一次 signtool（实测签名路径约 +98s）。
    #       ⚠️ 代价（如实记）: 门禁内**不再演练 signtool 路径**。签名验证改由
    #       :319 `签名 (Authenticode)` 观测 + 发版流程"确认可复现后单独签名"
    #       承担（见 :306-308）。CI runner 无 pfx, 本就不演练。
    #     · 第 4 项改 `-BaselineDir build\_gate_baseline`（CI reproducible job 的
    #       同一种形态）=> 只重建**一次**, 断言 A' == Y。
    #     · 由此断言换成**更强**的那条: 不只是"同命令跑两次一致", 而是
    #       **「`-RecordSeeds` 记下的种子表, 足以重建出记下它的那个产物」** ——
    #       这正是 CI reproducible job 依赖的前提（它拿上传的 seeds.json 重建
    #       再跟上传的 demo.exe 比）。实测 D1(-RecordSeeds -SkipSign) == D2
    #       (-SeedsFile -SkipSign) 成立。
    #     · 纯"同命令两次一致"（旧 B==C）在 CI 由 reproducible job 独立覆盖:
    #       它拿本次门禁留在磁盘上的产物当基线, 在自己机器上重建再比。
    #   净效果: 3 次构建 -> 2 次, **且两次的产物都承重**（0 个无人比对的产物）。
    Check 'Release 构建 (build.ps1 -Config Release)' {
        powershell -ExecutionPolicy Bypass -File .\build.ps1 -Config Release -RecordSeeds -SkipSign -SkipSmoke
        if ($LASTEXITCODE -ne 0) { return $false }
        # 快照本次产物当第 4 项的基线 —— repro_check 会用 -SeedsFile 重建并
        # **覆盖** build\demo.exe, 所以必须先存下来。
        $snap = 'build\_gate_baseline'
        Remove-Item -LiteralPath $snap -Recurse -Force -ErrorAction SilentlyContinue
        New-Item -ItemType Directory -Force -Path $snap | Out-Null
        Copy-Item -LiteralPath 'build\demo.exe' -Destination (Join-Path $snap 'demo.exe')
        Copy-Item -LiteralPath 'build\vm.blob' -Destination (Join-Path $snap 'vm.blob')
        Write-Host ("      基线快照 -> {0}（供下一项比对）" -f $snap) -ForegroundColor DarkGray
        return $true
    }
    Check '可复现 (repro_check)' {
        powershell -ExecutionPolicy Bypass -File .\tools\repro_check.ps1 -BaselineDir build\_gate_baseline
        $LASTEXITCODE -eq 0
    }
    Check 'e2e T1-T30' { & $py tests\e2e.py; $LASTEXITCODE -eq 0 }
    Check 'attacks A1-A12' { & $py tests\attacks.py; $LASTEXITCODE -eq 0 }
    Check 'vm_unit' { .\build\vm_unit.exe; $LASTEXITCODE -eq 0 }
    Check 'vmc' { & $py tests\vmc_tests.py; $LASTEXITCODE -eq 0 }
    Check 'example E1-E7' {
        powershell -ExecutionPolicy Bypass -File .\examples\tool_demo\build_example.ps1
        if ($LASTEXITCODE -ne 0) { return $false }
        & $py examples\tool_demo\test_example.py; $LASTEXITCODE -eq 0
    }
    Check 'protchain P1-P6' { & $py tests\protchain_check.py; $LASTEXITCODE -eq 0 }
    # §2.16 (T11 教训): 「加密目标的调用点必须落在配对 enter/leave 之间」。
    #
    # **为什么必须入门禁**: D2b 下 enter/leave 之外执行的是**磁盘密文** ——
    #   密文首字节恰为 0xC3(`ret`) 时静默空转(不崩、不报错、行为改变),
    #   否则 0xC0000005。T11 就是这样在生产构建里崩的, 而 P5
    #   (`indirect-no-direct-call`) 只扫 `0xE8` 直接调用, **看不见 `call rax`**,
    #   所以这条不变量此前**没有任何静态检查**。
    # 负向对照 (`build/_wc_negctl.py`, 不入库): 把 e6917a2 之前的
    #   `src/integrity.c` 放回仓库副本, 判据必须报出那处 A5 间接调用;
    #   当前树必须 0 报。判据自证能抓错。
    Check '加密封装窗口 (window_check)' {
        # 含负向自检: 先跑 --selftest 证明本判据有判别力(自检不通过即本项 FAIL), 再跑主判据。
        & $py tools\window_check.py --selftest | Out-Null
        if ($LASTEXITCODE -ne 0) { return $false }
        & $py tools\window_check.py; $LASTEXITCODE -eq 0
    }
    # 模块化框架 (docs/MODULAR_ARCH.md): 注册表须与源码一致 + 参考组合自洽。
    # 放在门禁内而非可选脚本 —— P3 教训: 可绕过的门禁会掩盖缺陷。
    Check '模块契约 (modcheck)' {
        # 含负向自检: 先跑 --selftest 证明本判据有判别力(自检不通过即本项 FAIL), 再跑主判据。
        & $py tools\modcheck.py --selftest --quiet
        if ($LASTEXITCODE -ne 0) { return $false }
        & $py tools\modcheck.py --all-compositions; $LASTEXITCODE -eq 0
    }
    # 阶段 3 (攻防对称): 演练记录须符合 schema 且 target_module 有效。
    Check '攻防记录 (drills lint)' { & $py tools\drills.py lint; $LASTEXITCODE -eq 0 }
    # 阶段 5 (M5): 对外材料数字不得与内部能力漂移
    #   (门禁项数 / 轮次口径 / 模糊表述 / 死链)。2026-09-20 核对时发现
    #   "0 破防点"、"release_check 11/11"、"8+ 轮 vs 6 轮" 三类漂移,
    #   本检查防止其复发。
    #
    # ⚠️ 为什么先跑 `--selftest`(2026-10-02 补): 本判据含 **7 类豁免**
    #    (代码块/日期语境/自带日期/沿革/序号/转述他文/计划验收)。
    #    豁免越多越容易"宽到什么都不报" —— 只验"仓库当前 PASS"是无法
    #    发现判据失效的, **一个恒返回空的检查器同样 PASS**。
    #    `--selftest` 逐条注入缺陷并要求报错(负向注入), 且要求合规写法
    #    不被误报(合规豁免), 其中一项直接改真实文档
    #    `publish/01-关于ShardVase.md` 的现时项数 -> 必须 FAIL。
    #    ⚠️ 此处**不写用例条数**: 自检用例随判据增长而增长(2026-10-06 又加
    #    了 README 门禁清单的 5 条), 写死数字必然在下一次失效 ——
    #    同 §2.36.7 记的"doccheck 自计数写进被它检查的文件"那条教训。
    #    要数字就直接看 `--selftest` 的输出行(它是算出来的)。
    #    失败时才打印自检明细, 成功时静默 —— 门禁日志不被 21 行 [ok] 淹没。
    Check '对外材料 (doccheck)' {
        $st = & $py tools\doccheck.py --selftest
        if ($LASTEXITCODE -ne 0) { $st | Write-Host; return $false }
        & $py tools\doccheck.py
        $LASTEXITCODE -eq 0
    }
}

# 签名: 可复现 (repro) 要求 SkipSign 重建, 与 Authenticode 互斥 (签名改 SHA,
# RELEASE §3/§5 已知). 发版顺序 = 确认可复现后单独签名 -> **未签名不算失败**,
# 但必须产出证据行。
#
# ⚠️ 严重教训 (2026-10-01 实测): 本块原为普通 `if`, 在"pfx 存在但未签名"分支里
#    只 `$script:pass++` 而**不打印 [ok]** -> 门禁报 "31 项"而日志只有 30 条 [ok]:
#    有一个通过**没有证据行**。且项数**环境相关**(pfx 不存在时同一份代码报 30)。
#    更糟的是两个检查器各自用不同方式"补"这 1 项 (tools/doccheck.py 硬编码 +1、
#    tools/docclaim_check.py 把上面注释里的示例 `Check 'X'` 误匹配成一项
#    —— 该示例**当时**在 L79, 现值在 **L170**; 改用行锚定后与行号无关),
#    于是 publish/*.md 声称 31、两个检查器实测 31 —— **三方一致但三方都错**。
#    这是「自洽 != 正确」的第 5 次重演。
#    修法: 改为真正的 Check, 任何环境都产出 [ok] 行 -> 静态调用点数 =
#    运行期项数 = [ok] 行数, 三者恒等且与环境无关。
Check '签名 (Authenticode)' {
    if (-not (Test-Path -LiteralPath 'build\keys\codesign.pfx')) {
        Write-Host '      (无 codesign.pfx — demo/未签名构建; 未签名不 FAIL)' -ForegroundColor DarkGray
        return $true
    }
    $sig = Get-AuthenticodeSignature -LiteralPath 'build\demo.exe' -ErrorAction SilentlyContinue
    if ($sig -and $sig.Status -ne 'NotSigned') {
        Write-Host ('      签名有效 ({0})' -f $sig.Status) -ForegroundColor DarkGray
        return $true
    }
    Write-Host '      (未签名 — 可复现构建产物; 发版时 signtool 单独签名)' -ForegroundColor DarkGray
    return $true
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
    $script:notrun++
    Add-GateResult '检查器变异测试 (mutate_check)' 'not-run' 0 '加 -WithMutation 启用'
    Write-Host '[info] 检查器变异测试 (mutate_check) 未运行 (加 -WithMutation 启用) — 未验证 != 通过' -ForegroundColor DarkYellow
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

# Linux 编译覆盖率（M1-A0, 2026-09-25）: 度量 + **防回退**。
#
# ## 为什么入门禁
#   "可移植"必须有**可度量的指标**，否则只是口号。
#   本项逐个源文件在 WSL/Linux 上 `gcc -c -Werror` 编译，输出覆盖率。
#
# ## 门禁策略（**关键设计**）
#   **M1–M5 已完成: 18/18（全部源文件跨平台）** —— 下限即 18。
#   设**下限 = 当前基线**，随计划推进逐步上调（**M2 已达 15**）:
#     M1: 13  [OK]  ->  M2: 15  [OK]  ->  M3: 16  [OK]  ->  M4: 17  [OK]  ->  M5: 18  [OK]  **全部完成**  ->  M5: 18
#   => 门禁现在通过；**回退会被抓住**（跌破下限即失败）。
#
# ## 依赖
#   需要 WSL + Ubuntu-24.04 + gcc。**若 WSL 不可用则明确跳过**
#   （不静默通过 —— 与"未验证 != 通过"一致）。
#
# 含**负向自检**（能报出 windows.h 失败 / 语法错误 / 不误报合法文件）。
Check 'Linux 编译覆盖 (linux_compile_check)' {
    # ── 前置探测（2026-10-02 修正）────────────────────────────────────────
    #
    # ## 修什么（实测：CI 上本项必然 FAIL）
    #   原判据 `& wsl.exe --version; $LASTEXITCODE -eq 0` 只证明 **wsl.exe
    #   二进制在**，**不证明发行版可用**。在 Windows-only runner 上:
    #     · `wsl.exe --version` 能跑（WSL 组件随 runner 镜像存在）
    #     · 但**没有安装任何发行版** -> 后续 `--selftest` / `--min 18`
    #       因无法进入 Ubuntu-24.04 而失败 -> 报 `[X]`
    #   => 门禁在干净克隆 / 干净 runner 上**永远不可能变绿**。
    #      "永远红的门禁" == 没有门禁（会被无视，实测 CI 已连续两次因此变红）。
    #
    # ## 为什么改成探测 `-d <发行版>`
    #   实测（本机）:
    #     `wsl.exe --version`            rc=0   （只证明二进制在）
    #     `wsl.exe -l -q`                `[Ubuntu-24.04]`
    #     `wsl.exe -d Ubuntu-24.04 -- true`  rc=0
    #     `wsl.exe -d NoSuchDistro_zzz -- true` rc=-1 + `WSL_E_DISTRO_NOT_FOUND`
    #   => 只有 `-d <distro>` 才真正回答"能不能跑 Linux 编译"。
    #   必须设 `$env:WSL_UTF8='1'`，否则 `wsl.exe -l` 输出 UTF-16 会乱码。
    #
    # ## 为什么跳过而不是通过
    #   发行版不存在时**本项从未执行** —— "未运行"必须与"已通过"可区分
    #   （本项目反复记名的「未验证 != 通过」）。
    #   => `return 'SKIP'`（第三态，见 `Check` 的 SKIP 判据与纪律）。
    #
    # ## 为什么跳过不会留下覆盖空白
    #   Linux 编译覆盖在 CI 上由**独立 job `linux-portability`** 真正验证
    #   （`.github/workflows/ci.yml:340-393`: gcc 编纯逻辑模块 + 平台层
    #   conformance + 合同检查，ubuntu-latest）。Windows runner 上的本项
    #   只是**重复**且需要 WSL，跳过不产生无覆盖的空白。
    #
    # ## ⚠️ `$LASTEXITCODE` 陈旧值陷阱（实测）
    #   进程**不存在**时 `& unknownExe` 抛非终止错误 -> 被 catch；
    #   而 `$LASTEXITCODE` **保持上一次的值**（实测: `exit 3` 后跑不存在的
    #   exe 再读 -> 仍是 3）。=> 绝不能只看 `$LASTEXITCODE` 判"可用"，
    #   必须先确认命令存在（`Get-Command`）。
    #
    # ## 🔴 更严重的陷阱: **绝不要在这个 scriptblock 里给 `$LASTEXITCODE` 赋值**
    #   （2026-10-02 我自己踩中并已在 CI 上复现的假通过）
    #   第一版修法写了 `$LASTEXITCODE = 0` 来"清掉陈旧值"，结果它在本
    #   scriptblock 的作用域内**投下一个影子变量**，随后的原生命令
    #   （`wsl.exe` / `python`）**都不再更新它** -> 之后每一次读取都是 0。
    #   实测（ps5.1 与 pwsh7 **一致**）:
    #       先 `$LASTEXITCODE = 0` 再跑 `exit 2` 的程序 -> 读出来仍是 **0**
    #       不赋值、直接跑 `exit 2` 的程序        -> 读出来是 **2**
    #   后果: 该分支**永远判 ok** —— `wslOk` 恒真，且末尾 `--min 18` 的
    #   退出码也被读成 0 => 本项在**无 WSL 发行版的 CI 上谎报通过**。
    #   CI 第四跑的原样现场（正是此 bug）:
    #       [linux_compile_check] SKIP: WSL 发行版 Ubuntu-24.04 不可用 …
    #       [ok]  Linux 编译覆盖 (linux_compile_check)      <- 工具报了 SKIP，门禁却说 ok
    #   => 正确修法: **不赋值**，改为每次调用**立刻**把退出码捕获进自己的
    #      变量（`$rc = $LASTEXITCODE`），后续一律只读 `$rc`。
    #      实测: 捕获式在 rc=2 -> SKIP、rc=1 -> FAIL、rc=0 -> ok 三态全对。
    $distro = 'Ubuntu-24.04'
    $wslOk = $false
    if (Get-Command wsl.exe -ErrorAction SilentlyContinue) {
        $env:WSL_UTF8 = '1'
        $rc = $null
        try { & wsl.exe -d $distro -- true 2>&1 | Out-Null; $rc = $LASTEXITCODE } catch { $rc = $null }
        $wslOk = ($rc -eq 0)
    }
    if (-not $wslOk) {
        Write-Host ("      前置不满足: WSL 发行版 '{0}' 不可用（`wsl.exe -d {0} -- true` 非 0）。" -f $distro, $distro) -ForegroundColor DarkGray
        Write-Host ("      补齐方式: `wsl --install -d {0}`；或此环境本就不跑 Linux 编译 -> 由 CI 的 linux-portability job 覆盖。" -f $distro) -ForegroundColor DarkGray
        return 'SKIP'
    }
    # ## 为什么下面每一步都要显式判 2
    #   工具自身也有同样的前置探测（`wsl_distro_ok`），两处**互为冗余**:
    #   上面这段负责"门禁这一侧的诚实"（打印补齐方式），工具那侧负责
    #   "任何人直接调用时也诚实"。任何一环判出前置不满足 -> SKIP。
    #   **显式判 2，不做全局隐式映射**（隐式映射会把"工具坏掉返回 2"也算跳过）。
    #   注意: 每步调用后**立刻**捕获 `$rc`，不读 `$LASTEXITCODE`（见上面的陷阱）。
    & $py tools\linux_compile_check.py --selftest --quiet
    $rc = $LASTEXITCODE
    if ($rc -eq 2) { return 'SKIP' }
    if ($rc -ne 0) { return $false }
    & $py tools\linux_compile_check.py --quiet --min 18
    $rc = $LASTEXITCODE
    if ($rc -eq 2) { return 'SKIP' }
    $rc -eq 0
}

# C 注释词法检查（L6b, 2026-09-25）: 防"注释里的符号序列"陷阱。
#
# **为什么需要**: 本项目**三次**同类问题（都靠编译报错才发现）:
#   ① `*/` 提前闭合 —— include/protect/prot_platform.h（L5b）
#   ② `*/` 提前闭合 —— src/platform/prot_platform_linux.c（L5c）
#   ③ `/*` 嵌套开启 —— include/protect/prot_sections.h（L6b）
#
# 三次都因**在注释里写路径通配**（`src/*.c`、`/sys/block/*/x`）时，
# 忘了 `/*` 与 `*/` 在注释内**仍被词法器识别**。
#
# => 用工具检测，比"记得小心"可靠（与 R20/S1 同样的思路）。
# **含负向自检**（6 个用例，含"路径通配只警告不报错"）。
Check 'C 注释词法 (comment_lint)' {
    & $py tools\comment_lint.py --selftest --quiet
    if ($LASTEXITCODE -ne 0) { return $false }
    & $py tools\comment_lint.py --quiet; $LASTEXITCODE -eq 0
}

# mojibake 全库回归（Q1, 2026-10-01）: 源码/文档里的 GBK 错解残留。
#
# **为什么需要**: `prot_sdk/skeleton/app_main.c` 与 `demo/main.c` 曾带着
#   **216 行** GBK 错解残留入库（HEAD 实测），且**旧判据漏检其中的 73%**:
#   旧判据 `l.encode('gbk')` 在遇到 PUA 字（U+E000 区）时**抛异常**，
#   被 `except` 吞掉 -> 整行**静默放过**。独立标注集实测:
#     旧判据 P=1.000 **R=0.2685**（漏 158/216）  vs  字节重建判据 P=1.000 R=1.000
#   => "满分"来自循环论证的标注集（正样本就是用该判据的祖先圈出来的）。
#
# **本项判据**: `tools/mojibake.py` —— 把行按 CP936 语义**重新编码再解码**
#   （`decode_cp936` 精确复刻 .NET CP936: 非法双字节对**固定吞 2 字节**吐 '?'，
#   这正是"吃标点/吃换行"与 k 行合并的来源），还原文本里**最长连续中文串 >= 2**
#   即判坏。该判据对 23940 条双字节全表 **decode/encode mismatch 均为 0**，
#   且在全库 30548 条正确中文行上**假阳性 0**。
#
# **含负向自检**（7 项: 判据层漏判 / 门禁层漏判 / 豁免失效 / 豁免空 /
#   僵尸豁免 / 豁免空转 / 干净行假阳性）—— 每项都经变异测试证明**可以失败**
#   （`build/_q1_selftest_falsify.py`: 5 项变异各自被对应检查捕获，无恒真装饰）。
# **豁免**必须**显式按路径登记**（`tools/mojibake_check.py` 的 EXEMPT，
#   含理由），且豁免行数**照常打印** —— 不允许静默吞掉。
#   豁免**必须随事实收缩**: 本项上线时曾豁免 `docs/CONTINUATION_PLAN.md`
#   （其 §2.3 引用过一段示意乱码）；Q1 写完、§2.3 改写后该文件坏行已为 0，
#   故**删除该条豁免**，避免留下无人复查的永久后门。
Check 'mojibake 全库回归 (mojibake_check)' {
    & $py tools\mojibake_check.py --selftest --quiet
    if ($LASTEXITCODE -ne 0) { return $false }
    & $py tools\mojibake_check.py --quiet; $LASTEXITCODE -eq 0
}

# 平台层契约测试（L4-A, 2026-09-23）: 定义"**什么算合规的平台实现**"。
#
# **为什么需要**: L4 目标是"实现 Linux 平台层"。但新平台实现是否正确，
#   若靠人工判断就会变成"看起来对" —— 正是本项目反复批判的。
#
#   本项把"平台层是否正确"变成**可执行的验收条件**:
#     **任何平台实现，只要能通过本测试，就视为契约合规。**
#     => 把"实现 Linux"从**写代码**变成**通过测试**。
#
# 内容: 30 项断言，覆盖 capabilities 自洽 / 页管理往返 / 调试原语契约 /
#   进程枚举容量语义 / 单调时钟 / 自身映像路径。
# **含负向验证**: 已实测注入缺陷（alloc 恒 NULL）能被抓到。
Check '平台层契约 (platform conformance)' {
    $pcDir = Join-Path $env:TEMP 'shardvase_platconf'
    New-Item -ItemType Directory -Force -Path $pcDir | Out-Null
    $pcExe = Join-Path $pcDir 'platconf.exe'
    # ## CI 暴露的缺陷（2026-10-02）: 原为两次硬编码查找
    #   （`Get-ChildItem 'C:\Program Files (x86)\...\2022'` + 回退
    #   `D:\environment\VS2022BuildTools\...`），**无 vswhere 兜底、
    #   也不检查 `cl` 是否已在 PATH**。
    #   GitHub windows-latest 的 MSVC 在 `Microsoft Visual Studio\18\Enterprise`
    #   （不在上述范围内），且 CI 用 `ilammy/msvc-dev-cmd` 把 `cl` 放进 PATH
    #   -> 该硬编码查找必然落空。统一走 `tools\vcvars.py` 的单一实现。
    $vc = $null
    try {
        $vcLine = & $py tools\vcvars.py --print
        if ($LASTEXITCODE -eq 0 -and $vcLine) { $vc = $vcLine.Trim() }
    } catch { $vc = $null }
    if (-not $vc) { return $false }
    $bat = Join-Path $pcDir 'b.bat'
    $log = Join-Path $pcDir 'cl.log'
    $cl = "cl /nologo /O2 /W4 /std:c11 /utf-8 /I include /Fe:`"$pcExe`" tests\platform_conformance.c src\platform\prot_platform_win.c /link /SUBSYSTEM:CONSOLE advapi32.lib winhttp.lib"
    # 'CL_ON_PATH' 哨兵 = cl 已在 PATH, **不写 call 行**
    #   （`call "" >nul 2>&1` 会静默失败并让后续 cl 找不到）
    $head = ''
    if ($vc -ne 'CL_ON_PATH') { $head = "call `"$vc`" >nul 2>&1`r`n" }
    $body = "cd /d `"$((Get-Location).Path)`"`r`n$cl > `"$log`" 2>&1"
    Set-Content -Path $bat -Value ($head + $body) -Encoding ASCII
    cmd /c $bat | Out-Null
    if (-not (Test-Path $pcExe)) { return $false }
    & $pcExe
    $LASTEXITCODE -eq 0
}

# 攻击技契约（缺口#2, 2026-09-23）: 攻防**契约层对称**。
#
# **为什么需要**: 此前"攻防对称"只到**数据层**（drills 记录），
#   攻击技本身**无契约** —— 57 个 drill 函数散在 5 个脚本里，
#   无法列举、无法校验、无法组合。
#
#   本项与 modcheck 对称:
#     modcheck    -> modules.json（防御模块契约）
#     attackcheck -> attacks.json（攻击技契约）
#
# 含**负向自检**（7 条规则自证能抓错）。
Check '攻击技契约 (attackcheck)' {
    & $py tools\attackcheck.py --selftest --quiet
    if ($LASTEXITCODE -ne 0) { return $false }
    & $py tools\attackcheck.py --quiet; $LASTEXITCODE -eq 0
}

# 骨架回归（2026-09-23）: 验证 **DIY 用户路径**可用。
#
# **为什么是门禁的一部分**: 本项目曾发生一次**阻断级缺陷** ——
#   `prot_sdk/skeleton/strings.txt` 未随 strcrypt.h 枚举同步，
#   导致**所有走骨架路径的用户构建失败**，而门禁**完全没抓到**，
#   因为**门禁从不构建骨架**（只构建 demo）。
#
#   => **骨架路径（= 用户真正使用的路径）此前回归覆盖为零。**
#
# 本项用非交互方式完整走一遍骨架构建（见 tools/skeleton_check.py），
# 并对已知缺陷做过**双向验证**（复现 -> FAIL；恢复 -> PASS）。
if ($WithSkeleton) {
    Check '骨架回归 (skeleton_check)' {
        & $py tools\skeleton_check.py --quiet; $LASTEXITCODE -eq 0
    }
} else {
    $script:notrun++
    Add-GateResult '骨架回归 (skeleton_check)' 'not-run' 0 '加 -WithSkeleton 启用'
    Write-Host '[info] 骨架回归 (skeleton_check) 未运行 (加 -WithSkeleton 启用) — 未验证 != 通过' -ForegroundColor DarkYellow
}

# W5.7(验证框架): **迁移成本门禁** —— 防止 W1.6 的成果回退。
#
# **为什么需要**: W1.6 把"保护函数特征命中率"(M3) 从 **55.9% 降到 5.9%**。
# 但**没有检查器的指标会悄悄退化** —— W5.6 之前，M3 的 55.9% 无人知晓，
# 直到专门度量才发现。本项把它固化为判据。
#
# 判据（实测标定，3 轮完全可复现）:
#   M3 保护函数特征命中率 <= 12%    （全注入 5.9%；部分移除 20.6% / 无注入 55.9% 必被抓）
#   M1 地址复用率         <= 12%    （当前 1.1%）
#
# ⚠️ 阈值是 **12%** 不是 25%：2026-09-23 反向验证发现 25% 会漏检「禁用 6/16 文件
#    的部分移除」（只升到 20.6%）。详见 tools/migration_gate.py 文件头。
#
# ⚠️ 抖动（2026-10-06 记，见 docs/HANDOVER.md §2.43）：同一份代码在本机
#    MSVC 14.44.35207 实测 M3 = 15.6%（FAIL），CI MSVC 14.51.36231 实测 6.2%（PASS）。
#    机制 = 本判据只在函数入口起 32 字节内取特征，而位置抖动落在序言之后，
#    工具链改变序言长度即可把结果推到阈值两侧 —— 阈值附近的抖动敏感, 非能力差异。
#
# 注: 默认跳过（需两次构建，约 1-2 分钟）。发版检查用 -WithMigration 启用；
#     **跳过时明确标注，不静默通过**。
if ($WithMigration) {
    Check '迁移成本 (migration_gate)' {
        # 含负向自检: 先跑 --selftest 证明本判据有判别力(自检不通过即本项 FAIL), 再跑主判据。
        & $py tools\migration_gate.py --selftest --quiet
        if ($LASTEXITCODE -ne 0) { return $false }
        & $py tools\migration_gate.py --quiet; $LASTEXITCODE -eq 0
    }
} else {
    $script:notrun++
    Add-GateResult '迁移成本 (migration_gate)' 'not-run' 0 '加 -WithMigration 启用'
    Write-Host '[info] 迁移成本 (migration_gate) 未运行 (加 -WithMigration 启用) — 未验证 != 通过' -ForegroundColor DarkYellow
}

# 构建状态自检（A-d，2026-09-25）
#
# ## 查什么（**跨平台错配**）
#   `demo/gen/<plat>/prot_sections.json` 的**必需三节**
#   （protcrc/protcry/protpad —— 两平台功能必需）必须出现在对应产物里。
#   错配（win json + linux 产物 / 反之）-> FAIL。
#   + expect_default.c 与 vm_build.json 的 expect 一致性。
#
# ## 为什么放门禁
#   **只读**（不改任何状态），且双向检查（win 与 linux 各自目录内自洽）——
#   不依赖"最新是哪个平台"。
#
# ## 判据按**事实**分层（源码 + map + readelf 三处确证）
#   · protxec: PROT_CODE_SEG 在 gcc = **文档化 no-op** -> Linux 设计上不存在
#   · fptable 随机名: PROT_SEC_FPT **全库无使用者** -> 两平台都不存在
#   => 这两个缺失 = **info 提示，不判 FAIL**；必需三节 = 硬判据。
#
# ## 自检: 正向 + 4 负向（每个负向**断言失败原因**，防"因错误原因通过"）
Check '构建状态自检 (check_state_platform)' {
    # 退出码 2 = **前置不足（本平台产物未构建）** -> SKIP（见 Check 的 SKIP 纪律）。
    # 显式判 2，**不做全局隐式映射**（否则"工具坏掉返回 2"也会被当跳过）。
    & $py tools\check_state_platform.py --selftest --quiet
    if ($LASTEXITCODE -eq 2) { return 'SKIP' }
    if ($LASTEXITCODE -ne 0) { return $false }
    & $py tools\check_state_platform.py
    if ($LASTEXITCODE -eq 2) { return 'SKIP' }
    $LASTEXITCODE -eq 0
}

# 平台适配公共层自检（S6, 2026-09-25）
#
# ## 为什么入门禁
#   `tests/_platform.py` 是 **e2e 与 attacks 的共同基础**
#   （平台解析 / 归一化 / WSL 直执）。它若有缺陷 -> **两套测试同时失效**。
#   => 其自检（9 项含 **3 负向**）随门禁常跑（只读、快）。
#
# ## 自检含的负向（**为什么重要**）
#   · T3: 两平台归一化结果**必须不同**（若相同 -> 归一化无意义）
#   · T7: WSL 路径**不得**被二次转换
#   · T9: 缺 `--platform` 时**必须**用默认
Check '平台层自检 (_platform)' {
    & $py tests\_platform.py --selftest
    $LASTEXITCODE -eq 0
}

# 验证互斥锁自检（D2, 2026-09-29）
#
# ## 为什么入门禁
#   锁是"**验证互斥**"的基础设施 —— 它若自身坏了（拿得到锁却不去重），
#   后续所有并发保护都是**假的**（"只会通过的检查器比没有更危险"同类）。
#   自检含 **3 个负向**（并发必须被拒 / 非持有者不能删 / 过期必须清）。
#
# ## 为什么能安全地在门禁内跑
#   自检用**独立锁文件**（build/.verify.lock.selftest）——
#   **绝不碰门禁自己的真锁**（否则会中途失锁 -> 互斥失效）。
Check '验证互斥锁自检 (verify_lock)' {
    & "$PSScriptRoot\verify_lock.ps1" -Selftest
    $LASTEXITCODE -eq 0
}

# 文档断言一致性（R1, 2026-09-29）
#
# ## 为什么入门禁（**这是治"记录漂移"的机制**）
#   本项目已 **5 次**出现"修复落地了，但声称它的文档没同步"
#   （V3 / V1 / S4 / SCDBG / §22-§29-§35 标题）——
#   后果是**持续低估自身能力** + 误导后续工作（曾差点重复实现 V2）。
#
#   本项把"**文档说的话**"变成**可执行断言**:
#     · 产物不得含 SCDBG 调试串（文档曾称"无条件输出"）
#     · publish 声称的门禁项数 == 实际 Check 块数（**值从文档解析**）
#     · 等共 7 条（每条写明来源文档 -> 防悬空断言）
#
#   **一旦实测与文档不符 -> 门禁直接红**，不再等人发现。
#
#   ## 2026-09-30 加固: 断言探针的"元数据占位符"判据
#     实测缺陷: 3 份关键文档把「最后核实」的提交字段写成 `提交 \`pending\``，
#     而**旧版探针放行**（它只校验日期与方法）。
#     => 一个"为防形式主义而写"的检查器，被**形式主义本身**骗过。
#     现在提交字段**必须是 7-40 位十六进制 sha**；自检 T6 用 6 个占位符
#     （pending/TBD/—/todo/空/HEAD）+ 3 个真 sha 做正负对照，并**先证明
#     修复前的形态会 FAIL**（不是自说自话）。
Check '文档断言一致性 (docclaim)' {
    # 含负向自检: 先跑 --selftest 证明本判据有判别力(自检不通过即本项 FAIL), 再跑主判据。
    # 退出码 2 = 有断言因**前置产物缺失**未执行（如干净克隆上无 build/demo_linux）
    #   -> SKIP，**不谎报通过**（判据从未执行）。CI 的 Windows runner 上这条
    #   必然触发，若按 FAIL 处理则门禁在干净克隆上永远红。
    & $py -X utf8 tools\docclaim_check.py --selftest --quiet
    if ($LASTEXITCODE -ne 0) { return $false }
    & $py -X utf8 tools\docclaim_check.py --quiet
    if ($LASTEXITCODE -eq 2) { return 'SKIP' }
    $LASTEXITCODE -eq 0
}

# 部署加固自检（R2.1, 2026-09-29）
#
# ## 为什么入门禁
#   `USABILITY §3.3` 的 5 项显式破防里 **2 项**（`D5` DLL 劫持 / `L3` 公钥替换）
#   的前置条件都是"**安装目录可写**"，而此前**无任何 ACL 工具**。
#   本项证明 `deploy_harden.ps1` **能区分加固/未加固**（含**负向**:
#   未加固目录下攻击必须成功 —— 否则检测恒真），并**实测属主绕过**这一诚实边界。
Check '部署加固自检 (deploy_harden)' {
    & powershell -NoProfile -ExecutionPolicy Bypass -File tools\deploy_harden.ps1 -Selftest | Out-Null
    $LASTEXITCODE -eq 0
}

# 性能基准自检（R2.2, 2026-09-29）
#
# ## 为什么入门禁
#   `USABILITY §5` 曾把三项性能指标标为"**未测量**"。本项守护
#   `perf_baseline.py` 的**负向自检**（产物缺失必须标 NA，**不编数据**）。
#   > **注意**: 这里只跑自检，**不跑完整基准**（需 3 次组合构建，太慢）；
#   > 完整数据由发版前手工执行并将结果写入 `USABILITY §1.2`。
Check '性能基准自检 (perf_baseline)' {
    # 退出码 2 = T1 正向因 `build/perf/full.exe` 缺失未验证 -> SKIP。
    #   CI 的 Windows runner 从不构建 perf 产物（该项只在发版前手工跑），
    #   若按 FAIL 处理则门禁在 CI 上永远红。T2/T3/T4（负向 + 映射）仍会执行，
    #   它们的通过**不**被这条 SKIP 掩盖 —— SKIP 单列且不计入 PASS 分子。
    & $py -X utf8 tools\perf_baseline.py --selftest | Out-Null
    if ($LASTEXITCODE -eq 2) { return 'SKIP' }
    $LASTEXITCODE -eq 0
}

# 判定点快照校验自检（R3.2-b, 2026-09-29）
#
# ## 为什么入门禁（**防"快照校验退化为恒真"**）
#   `prot_integrity_check_guards` 若退化为恒真（比较写错 / 序言读取被编译器
#   折叠成常量 / 快照时机错），**所有其它测试仍会全绿** ——
#   这正是本项目最警惕的失败模式（"只会通过的检查器比没有更危险"）。
#
#   本项**实证它能抓到 patch**:
#     · 正向: 不 patch -> 进程**不得**因篡改退出
#     · 负向: patch `prot_antidebug_detected` 序言 (`31 C0 C3`) ->
#             **必须**以 PROT_EXIT_TAMPERED(0xBAD=2989) 退出
#   手法与 `ATTACK_DRILL7` 步骤 4 **同款**（OpenProcess + WriteProcessMemory）。
#
# ## 为什么能安全地跑
#   用的是**独立进程**（demo.exe），不污染构建状态；非 Windows 上 SKIP。
Check '判定点快照校验自检 (guard_selftest)' {
    & $py -X utf8 tools\guard_selftest.py --quiet
    $LASTEXITCODE -eq 0
}
# ── 30. 调试控制台自检（`docs/DEBUG_CONSOLE_PLAN.md` 第 1 步, 2026-09-30）────
#
# ## 为什么把它当"检查项"而不是"顺手的便利工具"
#   这个工具的全部价值就是**挡住本项目反复踩到的"测量类错误"**，
#   所以它自己必须先被证明 —— 否则它会变成新的假阳性来源:
#     · map 正则形态假设错 -> 只解析出 948/2989 个符号
#       -> 差点下结论"符号被优化掉了"（实际是量错了）
#     · 用链接偏好基址去读 ASLR 之后的进程 -> 全部 err=299 -> 采样 0 轮
#     · 采样窗口 120ms >> 微秒级事件 -> 判据恒为"没看到"
#   => 判据落成 **"读不到 != 不存在"**:
#      **正向对照**（map 符号必须能落进产物节区间）+ 空/畸形输入**必须报错**。
#
# ## 自检覆盖（1 前置 + 4 正向 + 4 负向; 详见 `tools/prot_dbg.py` 文件头）
#   T5 负向: 不存在的符号 -> 必须 rc=1     T6 负向: 未定义退出码 -> 必须判未知
#   T7 负向: **空 map** -> 必须 FAIL（本项缺陷正是被 T7 逼出来的）
#   T8 负向: 非空但格式不识别 -> 必须报"读不到 != 不存在"
#   T9 负向: 掩码归属不得恒真/恒假（区内点必在 / 区外点必不在）
#
# ## 为什么可以放进仓库门禁
#   **纯只读**（只读产物 / map / C 头文件；自检用临时目录），
#   不触构建状态、不启进程、不写 build/ -> 与既有检查项无相互污染。
Check '调试控制台自检 (prot_dbg)' {
    & $py -X utf8 tools\prot_dbg.py --selftest --quiet
    $LASTEXITCODE -eq 0
}

# 门禁日志自检（2026-09-30）
#   本工具存在的理由就是「判据失败要留下证据」，故它自己必须先被证明。
#   ⚠️ 它要在**同一会话**里 start/stop 转录；而门禁此刻正开着转录 ——
#      直接跑会把**门禁这一轮**的日志掐断（同 verify_lock 自检删掉门禁自己的
#      锁那类事故）。`gate_log.ps1` 自己检测到外层转录时会**换子进程**运行，
#      此处按普通项调用即可（隔离性另有实测证据，见该文件头）。
#   T2 正向对照: 开启后 Write-Host 必须落盘（否则'日志里没有'分不清是
#      '没写'还是'没记'）; T3/T4/T5 负向: 停止后不得落盘 / 未开启 -Stop 返回空
#      / 目录不可用时不致命。
Check '门禁日志自检 (gate_log)' {
    & "$PSScriptRoot\gate_log.ps1" -Selftest | Out-Null
    $LASTEXITCODE -eq 0
}

# ── 32. 调试控制台**活体**自检（`docs/DEBUG_CONSOLE_PLAN.md` 第 2 步, 2026-10-01）──
#
# ## 为什么单独一项（不与第 32 项合并）
#   第 32 项是**纯只读**的（只读产物/map/C 头，不启进程）—— 那是它敢进门禁的前提。
#   第 2 步新增的 `read`/`patch`/`watch` 会 **OpenProcess + WriteProcessMemory**，
#   性质完全不同（需要权限、会拉起进程、会改目标内存），必须**分开**评估与记录。
#
# ## 它挡的是什么（本轮真实事故）
#   活体自检的 L4 原本断言"不改页保护写 `.text` 只读页必须失败"。
#   **该断言是错的** —— 2026-10-01 实测:
#     · 映像页(`MEM_IMAGE`, 写时复制): RX/RWX **能**直接写成功; R 失败 err=998
#     · 私有页(`VirtualAllocEx`): RX/RW **能**写; R/NOACCESS 失败 err=998
#   => `WriteProcessMemory` 的返回值**是可信的**，纪律 ⑦ 原先的理由
#      ("系统会返回成功却没写进去")**未复现**。是一次**自检把我自己的错误断言抓了出来**。
#   修法: L4 改用**自建私有只读页**做对照，并加 L4b（同一页解锁后必须写得进去）
#         —— 证明 L4 的失败**确实来自"页保护"**，而不是"地址非法/长度越界"。
#   没有 L4b，L4 的"失败"可以被"地址算错了"解释，那就**没有判别力**。
#
# ## 为什么能安全地跑
#   用**独立进程**（demo.exe，自拉自杀），不污染构建状态、不写 build/；
#   非 Windows 上 SKIP（返回 2，**未验证 != 通过**，门禁按非 0 处理 -> 见下）。
Check '调试控制台活体自检 (prot_dbg live)' {
    if ($env:OS -ne 'Windows_NT') {
        Write-Host '      (非 Windows — 只读自检已覆盖静态部分; 活体部分 SKIP)' -ForegroundColor DarkGray
        return $true
    }
    & $py -X utf8 tools\prot_dbg.py --selftest-live --quiet
    $LASTEXITCODE -eq 0
}

# 判定多副本等价性（R3.2-c, 2026-10-03）
#
# ## 为什么入门禁（**防"副本悄悄退化成不等价"**）
#   R3.2-c 把 `prot_antidebug_detected` 复制成 4 份（本体 + r2/r3/r4）并把宿主
#   切到非短路聚合器 `prot_antidebug_detected_multi`。于是"副本与本体等价"从
#   一句注释变成了**必须被机器检查的不变量**（MODULE_GUIDE P1）:
#     一次顺手编辑若让某个副本漏掉一个关键位，**所有其它测试仍会全绿**
#     —— 攻击者只需挑那个副本 patch 即可，冗余归零而无人察觉。
#   同 `guard_selftest` 的理由: 冗余的价值全靠等价性，故等价性必须入门禁。
#
# ## 三条判据（缺一不可; 详见 `tools/replica_check.py` 文件头）
#   ① 差分等价 + 独立 oracle + 非空洞性
#      本体与副本区逐字提取后独立编译，2^12 穷举 + 逐字段边界 + 8192 组 fuzz，
#      断言 5 个实现同输入同输出；用独立 oracle（任一关键位非 0）校验**本体
#      本身**（纯差分对"全体一起错"是盲的）；并断言函数指针两两不同 —— 否则
#      harness 自己被 /OPT:ICF 折叠，差分退化成"一个函数和自己比"（判据空洞）。
#   ② 地址互异（抗 /OPT:ICF）
#      释放构建带 `/OPT:ICF`，等价函数会被折叠成同一地址 -> 副本白做。
#      判据: `build/demo.map` 里 5 个符号 VA 两两不同。
#   ③ 负向对照（判据必须有判别力）
#      摘掉 r2 的一个关键位 -> 差分**必须**报出不一致；否则判 FAIL，
#      不静默通过（这是本项目反复记名的「只会通过的检查器比没有更危险」）。
#
# ## 为什么能安全地跑
#   只读 `src/antidebug.c` + `include/protect/antidebug.h` + `build/demo.map`；
#   编译与运行的临时产物落在 gitignored 的 `build/`（`replica_real.*` 等），
#   不触碰 demo.exe / seeds.json / 掩码文件。缺 demo.exe 时判据 ② 走 SKIP 并
#   打印「未验证 != 通过」，判据 ①③ 仍会执行。
Check '判定多副本等价性 (replica_check)' {
    # 含负向自检: 先跑 --selftest 证明本判据有判别力(自检不通过即本项 FAIL), 再跑主判据。
    & $py -X utf8 tools\replica_check.py --selftest | Out-Null
    if ($LASTEXITCODE -ne 0) { return $false }
    & $py -X utf8 tools\replica_check.py
    $LASTEXITCODE -eq 0
}

# CRC 目标表下标一致性（2026-10-04，DRILL9 收口）: 防止「条数对得上、语义对不上」的静默失效。
#
# **为什么是门禁的一部分**: 修 `docs/ATTACK_DRILL9.md` §5 的 `.protxec` 盲区时,
#   把 `.protxec` 加为第 4 个 CRC 目标, 踩到一个**静默失效**的形态:
#   `.protxec` 的节名自阶段1 起每构建随机（`gen_sections.py` 写
#   `#undef PROT_SEC_XEC` + `#define PROT_SEC_XEC ".xxxxxxxx"`），而
#   `tools/hashpatch.py` 的 `TARGET_NAMES` 里写的是默认名 `.protxec`
#   -> `next((s for s in secs if s['name'] == target_names[i]), None)` 永远
#   返回 None -> 走 `hashpatch: %s section absent — skip` 分支
#   -> 烧录字段恒为 0, **不报错、构建成功、门禁全绿**。
#   若不修, 这次「加第 4 目标」会变成**纯粹的装饰**: 段 CRC 看着有 4 项,
#   实际只校验 3 项, 攻击面比改动前一点没变, 而所有既有检查器都发现不了。
#
#   这和本项目记名的另一类事故同型: 「门禁项数 32 看起来完全正确,
#   但其中一项的语义已经空了」。只数条数的检查（doccheck / docclaim）看不见,
#   必须有一项**跨文件比对下标语义**的判据。
#
# ## 被检查的不变量
#   CRC 目标表的 `下标 -> 节名 -> magic` 在**四处**必须一致:
#     ① `tools/hashpatch.py`  MAGICS / TARGET_NAMES / TARGET_LOGICAL
#     ② `src/integrity.c`     g_prot_baked_crc[] + 两处 `j < N` 循环上界
#     ③ `src/platform/prot_platform_win.c` / `prot_platform_linux.c`
#                             prot_plat_crc_target_name() 的 names[]
#     ④ `include/protect/prot_sections.h` 的 PROT_MAGIC_* / _BYTES 默认值
#        （+ `tools/gen_sections.py` 的生成与写入顺序）
#
# ## 平台不对称是**显式**的, 不是漏配
#   Linux 侧刻意只有 3 个目标: ELF 下 `PROT_CODE_SEG()` 展开为空
#   （`include/protect/prot_compiler.h`: PE 段布局是平台概念），检查器本来就落在
#   `.text` 里, 已被下标 0 覆盖 -> 不需要第 4 个目标。判据要求这个不对称
#   **写在代码里**（3 项不含它, 或 4 项末位是它），而不是"恰好少一个"。
#
# ## 含负向自检
#   8 条变异（改节名 / 删 magic / 删在位调用 / 改声明长度 / 改循环上界 /
#   字节数组不一致 / win 退回 3 项 / linux 谎报 4 项）必须全部被抓;
#   抓不住任何一条即 FAIL（这是本项目反复记名的「只会通过的检查器比没有更危险」）。
#
# ## 为什么能安全地跑
#   纯文本解析, 只读源码、**不编译、不写任何产物**（`--selftest` 只在内存里变异文本）。
Check 'CRC 目标表一致性 (crc_targets)' {
    & $py -X utf8 tools\check_crc_targets.py --selftest --quiet
    if ($LASTEXITCODE -ne 0) { return $false }
    & $py -X utf8 tools\check_crc_targets.py --quiet; $LASTEXITCODE -eq 0
}

# 静态未定义名审计（2026-10-05）: 抓「引用但未绑定」的全局名 —— py_compile 与运行测试都抓不到。
#
# **为什么是门禁的一部分**（两起真实事故, 都不是假想风险）:
#
#   ① `tests/e2e.py` 的 T3 块调用 `DebugAttacher()`, 而该类已在 `22826c5`
#      （2026-09-28, C-3）被**整体删除**、调用点却留在 `tests/e2e.py:515`。
#      `py_compile` 只查**语法**, 这种名字**运行时必然 NameError**, 但编译期
#      全绿、门禁也全绿 —— 潜伏 7 个月, 直到 S6 把 preflight 改成对派生子进程
#      附加、那条 `else` 分支**第一次**被执行才暴露。
#
#   ② `tools/guard_selftest.py` 的诊断分支引用了 `run_by_hits()` 的**局部**名
#      `cont` / `exit_pol`（修 guard_selftest 假红时顺带抓到）。
#
#   两者的共同形态: **只在失败路径上执行的代码**。
#   运行测试永远走不到它（走到就意味着别处红了）, 所以**静态审计而非
#   运行测试才是它的正确防线**。本项就是这个防线。
#
# ## 与既有检查的分工
#     py_compile    语法      —— 抓不到 NameError
#     运行测试      走到的路径 —— 抓不到"从未被执行"的分支
#     本项          名字绑定   —— **与是否执行无关**
#
# ## 判据
#   每个 `.py` 的每个作用域里, `Load` 的名字必须在
#   「内建 ∪ 模块级绑定 ∪ 外层作用域绑定」中。
#   作用域语义必须正确（类体名字对方法不可见 / 推导式首个 iter 用外层 /
#   装饰器与默认值在外层求值 / `global`·`nonlocal` 算已绑定 /
#   **嵌套作用域节点本身也是本作用域的绑定**）—— 否则产生**假阳**,
#   而假阳会让维护者关掉检查器, 比漏报更危险。开发中踩过 4 轮, 全部记在
#   `tools/check_undef.py` 文件头的"实现要点"里。
#
# ## 含负向自检
#   4 条变异（删模块级绑定 / 嵌套局部不可见 / 真未定义引用 / 类体引用不存在名）
#   必须全部被抓, 且 4 类已知假阳源必须**不**报;
#   抓不住任何一条即 FAIL（「只会通过的检查器比没有更危险」）。
#
# ## 为什么能安全地跑
#   纯 AST 解析, **只读源码、不导入被测文件、不执行任何代码、不写产物**。
Check '静态未定义名审计 (undef_check)' {
    & $py -X utf8 tools\check_undef.py --selftest --quiet
    if ($LASTEXITCODE -ne 0) { return $false }
    & $py -X utf8 tools\check_undef.py --quiet; $LASTEXITCODE -eq 0
}

# Android 交叉编译 (android_compile_check, 2026-10-06): 防"Android 侧从未被编译过"。
#
# **为什么需要**: 2026-10-06 用真 NDK r28 交叉编译才发现 —— 攻击侧两个 patcher
#   自 `c941c9c` 落地起**从未被任何目标编译过**，源码有两个真缺陷:
#     · `patcher_jni.c:23` `#include "../elfparse/elfparse.h"` 路径指到目录外
#     · 两文件裸调 `process_vm_writev`（bionic 标 `__INTRODUCED_IN(23)`）
#   而 `tools/attacker/android_jniptrace/README.md` 记的"宿主编译验证"命令
#   **只编了 `elfparse.c` + `elfdump.c`** —— 即"声称验证过的代码"与
#   "实际验证过的代码"不是同一份。`examples/cross_platform/android/` 另有
#   3 处从未经 `-Wall -Wextra -Werror` 的缺陷。
#   旧门禁为何看不见: `linux_compile_check.py:88 SCAN_DIRS = ['src']` 只扫 `src/`；
#   CI 全文搜 `ndk|android|aarch64` 零命中。
#
# ## ⚠️ 判据必须锚定**文档声明的最低 API (21)** —— 这是本项存在的全部理由
#   实测同一份源码（裸 `process_vm_writev`）:
#     api21 -> rc=1（`call to undeclared function`）
#     api23 -> rc=0
#     api28 -> rc=0
#   bionic 在 API 21/22 上**根本不声明**该函数，23+ 才声明。
#   => "挑一个现代 API 编一遍"会**放过**这个缺陷 —— 它潜伏至今正是因为
#      所有人都用现代 API 试。工具默认 `DEFAULT_APIS = (21, 28)`，21 在前。
#
# ## 为什么这里不能只看退出码的"0 或非 0"
#   2026-10-06 自测抓到工具**自身的假通过**: 文件编不过时它打印了 `FAIL` 与
#   `[API_GATED: 需要回退]`，但 `--quiet` 仍 rc=0（第一版只在传 `--min` 时
#   才判失败）=> 门禁会报 `[ok]`。这正是本项目反复记名的形态
#   「工具报 FAIL，门禁说 ok」（同本文件 `$LASTEXITCODE` 影子变量事故）。
#   已修: 把关点抽成 `exit_code_for()`，默认编不过即非 0，并补 T10-T13 回归自检
#   （T11 专门断言"不传 `--min` 时编不过也返回 1"）。
#
# ## 为什么跳过而不是失败
#   找不到 NDK 时本项**从未执行**，必须与"已通过"可区分（「未验证 != 通过」）。
#   工具自身已判 2，这里**显式判 2 -> SKIP**，不做全局隐式映射。
#
# ## 为什么跳过不会留下覆盖空白
#   CI runner **预装 NDK**（`ubuntu-latest` 实测含 `27.3.13750724` /
#   **`28.2.13676358`**（与本机同版本）/ `29.0.14206865`），故本项在 CI 上
#   由 `linux-portability` job 的 Android 步骤**真正执行**，不是恒 SKIP。
#
# ## ⚠️ 与 `linux_compile_check` 相同的 `$LASTEXITCODE` 纪律
#   每步调用后**立刻**捕获进 `$rc`，绝不读 `$LASTEXITCODE`、
#   绝不在本 scriptblock 内给它赋值（见上面第 18 项的陷阱记录）。
Check 'Android 交叉编译 (android_compile_check)' {
    & $py tools\android_compile_check.py --selftest --quiet
    $rc = $LASTEXITCODE
    if ($rc -eq 2) { return 'SKIP' }
    if ($rc -ne 0) { return $false }
    & $py tools\android_compile_check.py --quiet
    $rc = $LASTEXITCODE
    if ($rc -eq 2) { return 'SKIP' }
    $rc -eq 0
}

# ── 39. selfcrypt 驻留期密文态（D2c 不变量, 2026-10-06）────────────────────────
#
# ## 为什么需要（**补的正是 §2.35.6 自己记名的空白**）
#   D2b 的旧实现把**全部** n 条解密并**留在明文态** —— 从
#   `prot_selfcrypt_init()` 返回到首次 `leave(组)` 之间存在一个**全量明文
#   驻留窗口**: 实测自然路径 ~0.66s、`--wait-ms 6000` 时 ~6.67s
#   （`docs/HANDOVER.md` §2.35）。这段时间里本项目的承诺
#   「运行期非调用时刻内存中函数为密文, dump 抓不到明文引擎」
#   （`docs/N1_PHASE2_PLAN.md` 威胁边界）**不成立**。
#
#   D2c 修法（`c2666b9`）: init 逐条解密 + 逐条 CRC 校验, **校验完立即回密**。
#   但当时那轮验证是**一次性手工探针**（脚本落在 gitignored 的 `build/` 下）
#   => 门禁里**没有**自动判据 => 这条不变量**回归了不会有测试变红**,
#      而它恰恰是 D2b 那片注释块反复承诺的东西。
#   与 §2.32「陈旧复选框」、T11 的「P5 只判不得直接 E8 调用」同型:
#   **机制在、门禁不在**。本项把这个空白补上。
#
# ## 判据
#   ① 组 0（VM 引擎调用链）条目数 > 0 —— 否则判据空转, 直接 FAIL;
#   ② `g_sc_d2b_enabled == 1` —— 回密循环在 `#ifdef PROT_SELFCRYPT_D2B` 内,
#      单列这条是为了让"没编译进来"与"回归了"在报告里可区分;
#   ③ 采样轮数足够 —— **「读不到」 != 「不存在」**: 一条采样都没拿到、
#      或读内存失败, 必须 FAIL, 不许读成"没发现问题";
#   ④ 每一轮采样里, 组 0 **每一条目**的内存字节都**逐字节**等于
#      `build/demo.exe` 中同区间的字节（即磁盘密文）。任何一条不符即 FAIL,
#      并报出首个不符的轮次与字节位（可定位"只回密了一部分"）。
#   判据**失效安全**: 地址算错 / 节名解析错 / 读内存失败 / 读错区间,
#   结果一律是"内存 != 磁盘" => 红。**绿**只有一种达成方式: 地址对、字节真一致。
#
# ## 组 1（EXT 扩展组）**不在判据内**
#   看门狗每轮自己开/关一次 EXT 窗口（`src/integrity.c:188` enter / `:256` leave）,
#   窗口内它**就该**是明文。工具会把"组 1 明文出现多少轮"打出来做**诊断**
#   （这是采样器能分辨两态的活体旁证）, 但**不做门禁要求**。
#
# ## 含负向自检
#   判据 `judge()` 是**纯函数**（只吃条目 / 采样 / 磁盘参考）, 故自检在内存里
#   造数据即可 —— **不启进程、不写盘、不编译**。4 条变异必须全部被抓:
#     M1 组 0 某条某一轮内存改成"与磁盘不同"（= 回密没生效的签名）
#     M2 采样列表清空（无证据不得通过）
#     M3 组 0 某条某一轮取不到（只等到一部分）
#     M4 磁盘参考改 1 个字节（证明是逐字节比较, 不是只看长度/前缀）
#   基线（真实形态的合成数据）必须全绿 —— 只红不绿的判据同样是坏的。
#
# ## 为什么能安全地跑
#   只读目标进程（只 `ReadProcessMemory`）与 `build/demo.exe` / `.map`;
#   起的是**独立进程**（demo.exe `--wait-after` 驻留）, 不写 `build/`、
#   不编译、不改产物。经 `tools/winproc.py` 启动（CREATE_NO_WINDOW）。
#
# ## 为什么跳过而不是失败
#   非 Windows（OpenProcess / Toolhelp32）、缺产物、或该产物未接 selfcrypt
#   （meta 条目 n=0）时判据**从未执行**, 必须与"已通过"可区分
#   （「未验证 != 通过」）。工具自身判 2, 这里**显式判 2 -> SKIP**。
#
# ## 诚实边界
#   负向自检证明的是**比较器与判据**有判别力（纯数据变异）, **不是**端到端地
#   另编一个"无 D2c"的产物来证明"回归必然变红" —— 那需要第二次构建,
#   与本项目"门禁只读、不编译"的纪律冲突。端到端那一半由本项的**正向运行**
#   背书: 它真的起进程、真的读内存、真的与磁盘逐字节比。
Check 'selfcrypt 驻留期密文态 (selfcrypt_residency)' {
    & $py -X utf8 tools\selfcrypt_residency_check.py --selftest --quiet
    $rc = $LASTEXITCODE
    if ($rc -eq 2) { return 'SKIP' }
    if ($rc -ne 0) { return $false }
    & $py -X utf8 tools\selfcrypt_residency_check.py --quiet
    $rc = $LASTEXITCODE
    if ($rc -eq 2) { return 'SKIP' }
    $rc -eq 0
}

# ## 为什么需要（2026-10-08 实测，不是假想的风险）
#   `docs/N1_PHASE2_PLAN.md:36` 逐字写着「meta 布局改动必须同步
#   `selfcrypt_proto.py`（写）与 `selfcrypt.c`（读）、
#   `integrity.c build_selfcrypt_mask`（读 rva/len 偏移），三侧一致。」
#   —— 这句是**人工承诺**，四方**没有任何代码在读两侧并比较**。
#   实测三类漂移:
#     · py 读侧 SC_ENTRY_SIZE 24->20 : protchain **红**（端到端有兜底）
#     · C  读侧 SC_ENTRY_SIZE 24u->20u: protchain **绿**、e2e 30/30 **绿**
#     · py 读侧 SC_ENTRY_GROUP_OFF 20->16: protchain **绿**、e2e 30/30 **绿**
#   后两类今天**没有任何检查会红** —— 因为 `tests/protchain_check.py:336`/`:368`
#   把 group 解出来又丢掉（写成 `_grp`），**没有任何判据在用这个字段**；
#   而 C 侧改错时 protchain 读的是**它自己文件里的**常量，看不见 C。
#
# ## 判据（全部由 `struct.pack` 的格式串**推导**，不抄字面量）
#   ① 写侧格式串 -> 步长与逐字段偏移（`<IIQII` -> 24 / rva@0 len@4 key0@8 crc@16 group@20）
#   ② 写侧 `hdr` 与 `e_off` 的步长 == 推导值
#   ③ `src/selfcrypt.c` 的 `SC_ENTRY_SIZE` / `SC_ENTRY_GROUP_OFF`
#      以及 `sc_do_range` 里四个字段的 `memcpy` 偏移 == 推导值
#   ④ `tests/protchain_check.py` 的 `SC_ENTRY_SIZE` / `SC_ENTRY_GROUP_OFF` == 推导值
#   ⑤ `src/integrity.c` 的 `build_selfcrypt_mask()` 里裸步长与 rva/len 偏移 == 推导值
#   ⑥ **每一侧都必须被找到**：锚点消失即 FAIL —— 失锚**不得**读成"没有漂移"
#
# ## 含负向自检
#   `--selftest` 对文本做 9 条变异（不碰仓库文件），每条都必须被抓；
#   基线（真实源文件）必须全绿。
#
# ## 为什么能安全地跑
#   纯文本只读；不执行被测代码；不写任何文件。
#
# ## 诚实边界
#   判据比对的是**源码文本**：若常量被挪到别的头文件，本项会报"找不到锚点"
#   而不是误绿。只覆盖步长与 rva/len/key0/crc/group 偏移；不覆盖 Linux 侧
#   （`src/selfcrypt.c` 平台无关，两侧共用）。

Check 'selfcrypt meta 布局四方一致 (selfcrypt_meta)' {
    & $py -X utf8 tools\selfcrypt_meta_check.py --selftest --quiet
    $rc = $LASTEXITCODE
    if ($rc -eq 2) { return 'SKIP' }
    if ($rc -ne 0) { return $false }
    & $py -X utf8 tools\selfcrypt_meta_check.py --quiet
    $rc = $LASTEXITCODE
    if ($rc -eq 2) { return 'SKIP' }
    $rc -eq 0
}

# 休眠自检审计 (selftest_audit) —— 「登记了自检」不等于「自检被执行」
#
# ## 判据
#   `tools/selftest_audit.py` 用 **AST** 判定每个 tools/ tests/ 下的 .py 是否
#   **登记**了自检入口（add_argument('--selftest') 或 add_parser('selftest')），
#   再在入口清单（本文件 / ci_sim / ci_linux / ci.yml / ci-linux.yml / build.ps1）
#   里做**可达链**搜索: 只有真的以自检参数被调用才算有执行者。
#   登记了、却找不到任何执行者 => 孤儿 => FAIL。
#   另判「**执行得对不对**」: 覆盖语句里出现的每个长旗标都必须被该工具
#   登记过（判据④）。这条是 2026-10-09 本项**首跑就抓到我自己**的:
#   我给 6 个孤儿统一加了 `--quiet`，而只有 `hostgen.py` / `solve_profile.py`
#   登记了它 ⇒ `identity.py: error: unrecognized arguments: --quiet`。
#   「有没有执行者」判住了，「执行得对不对」当时没有任何判据在管。
#
# ## 缘起
#   2026-10-06 §2.42 给 5 个"休眠自检"接线后，本轮做**全量对账**，又查出 6 个
#   工具（genpaths / hostgen / identity / migration_cost / solve_profile /
#   observability）**登记了自检、写了负向用例、却没有任何执行者**。
#   `docs/PROTOCOL_GOVERNANCE.md:174-175` 的强制纪律只说了"能自证会抓错"，
#   没有说"自证必须被执行" —— 本项就是那条纪律的**执行面**。
#
# ## 本项同时是那 6 个自检的执行者
#   判据通过后逐个内联执行它们的自检（合计约 0.4s，不写任何仓库文件，
#   实测连跑后 `git status` 完全干净）。
#   ⚠️ 这也是自洽性检查: 注册本项后，审计自己的孤儿名单里
#      `tools/selftest_audit.py` 与这 6 个**应当**同时消失。
#
# ## 含负向自检
#   `--selftest` 13 条变异全部被抓: 孤儿面 8 条（只在注释里被提到 / 被调用但
#   不带自检参数 / 只在 docstring 里被提到 / 传递可达但中间一跳不带参数 /
#   子命令形态 等）+ 旗标面 5 条（未登记旗标必报 / 只传已登记的不得报 /
#   工具登记过之后不得报 / **别的工具的旗标不得算到本工具头上** /
#   源码不可解析必须跳过）。
#
# ## 诚实边界
#   · 只认**入口清单内**的可达链。若某工具靠 CI 之外的手工调用活着，
#     本项会把它报成孤儿 —— 这是刻意的: 宁可报出来让人写明理由。
#   · 入口清单是硬编码的 6 个文件（`selftest_audit.py` 的 HARNESS 常量），
#     新增入口须同步，否则判据会失锚（失锚时判据①/②先 FAIL，不会静默）。
#   · 只判"有没有执行者"，不判自检本身是否**充分**。
#   · 判据④ 只比对 `--` 开头的长旗标，且只认 `add_argument` 字面量登记的名字;
#     位置参数、`-x` 短旗标、由父解析器继承的旗标都不在射程内。

Check '休眠自检审计 (selftest_audit)' {
    & $py -X utf8 tools\selftest_audit.py --selftest --quiet
    $rc = $LASTEXITCODE
    if ($rc -eq 2) { return 'SKIP' }
    if ($rc -ne 0) { return $false }
    # 以下 6 个自检此前没有任何执行者，本项即其执行者。逐一显式调用。
    & $py -X utf8 tools\genpaths.py --selftest
    if ($LASTEXITCODE -ne 0) { return $false }
    & $py -X utf8 tools\hostgen.py --selftest --quiet
    if ($LASTEXITCODE -ne 0) { return $false }
    & $py -X utf8 tools\identity.py --selftest
    if ($LASTEXITCODE -ne 0) { return $false }
    & $py -X utf8 tools\migration_cost.py --selftest
    if ($LASTEXITCODE -ne 0) { return $false }
    & $py -X utf8 tools\solve_profile.py --selftest --quiet
    if ($LASTEXITCODE -ne 0) { return $false }
    & $py -X utf8 tools\observability.py selftest
    if ($LASTEXITCODE -ne 0) { return $false }
    & $py -X utf8 tools\selftest_audit.py --quiet
    $rc = $LASTEXITCODE
    if ($rc -eq 2) { return 'SKIP' }
    $rc -eq 0
}

# Studio 契约（ST0, 2026-10-09）—— 后端先行: 能力必须先能**无头调用**
#
# ## 这一项在防什么
#   `tools/studio_core.py` 是纯逻辑层, `tools/studio_cli.py` 是 NDJSON 进程边界。
#   两者都带 `--selftest`, 但**带了自检不等于自检被执行** —— 这正是第 41 项
#   (`selftest_audit`) 自身要防的事: 一个登记了自检却没有任何执行者的工具,
#   会在 README 里看起来"有验证", 而那条验证从未运行过。
#   本项即这两个自检的执行者。
#
# ## 为什么两个都要跑
#   · `studio_core` 证的是**契约与负向**(未知命令 / 参数类型 / 读缺失文件都不许静默回退)
#   · `studio_cli` 证的是**进程边界**(退出码三态 0/1/2、坏请求行不中断会话、
#     中文不被 \uXXXX 转义) —— 它会**真的起子进程**验证, 因为管道接错
#     是只测函数测不出来的。
#
# ## 退出码三态
#   `studio_cli.py` 的 2 = 用法/输入错误（门禁读成 SKIP）, 1 = 命令失败（读成 FAIL）。
#   两者**必须分开**: 把用法错误当失败会让一次参数笔误显示成"防御失效";
#   反过来把失败当跳过会让真的失败变成"未验证"。详见 `docs/STUDIO_PROTOCOL.md` §7。

Check 'Studio 契约 (studio)' {
    & $py -X utf8 tools\studio_core.py --selftest --quiet
    $rc = $LASTEXITCODE
    if ($rc -eq 2) { return 'SKIP' }
    if ($rc -ne 0) { return $false }
    & $py -X utf8 tools\studio_cli.py --selftest --quiet
    $rc = $LASTEXITCODE
    if ($rc -eq 2) { return 'SKIP' }
    if ($rc -ne 0) { return $false }
    # ST4: VM 级调试器。解释器与 src/vm.c 的语义漂移**只有**这条能抓 ——
    # 判据是 tests/vm_unit.c 的六个宿主内存断言 (在**真机**上由 vm_unit
    # 独立断言, 门禁第 7 项)。这里跑的是同一份断言的解释器侧复算。
    & $py -X utf8 tools\vm_debug.py --selftest --quiet
    $rc = $LASTEXITCODE
    if ($rc -eq 2) { return 'SKIP' }
    if ($rc -ne 0) { return $false }

    # ST2: 测试面板的机读出口。它读的是**实际日志行**(而不是信任门禁自己的
    # 计数器), 所以能抓"某天有人给 Write-Host 加了新行却既没记 JSON 也没加
    # 计数器" —— 那正是门禁内部"双面对照"抓不到的那一类。
    & $py -X utf8 tools\gate_results.py --selftest --quiet
    $rc = $LASTEXITCODE
    if ($rc -eq 2) { return 'SKIP' }
    if ($rc -ne 0) { return $false }
    $rc -eq 0
}

# Linux **运行时**验证（C 阶段, 2026-09-25）—— **放在最末**
#
# ## 与"编译覆盖"的区别
#   `linux_compile_check` 只验证**能编译**；
#   本项验证**能运行且保护链生效**:
#     · build.sh 端到端构建（生成链 + 两轮编译 + selfcrypt + 烧录）
#     · vm_unit（VM 指令集单测）
#     · 平台层契约测试
#     · **端到端授权链**（license 验签 + VM 校验 -> "校验通过"）
#     · 第二支柱（节名随机化）
#
# ## ⚠️ 为什么放在**最末**（实测教训）
#   本项会跑完整 `build.sh` -> **把 demo/gen 与 vm_build.json 改成 Linux 值**。
#   若它之后还有依赖 **Windows 产物**的检查项，会被**污染**
#   （实测: 放中间时 e2e/protchain 等被连带影响）。
#
# ## 为什么**不加 --skip-build**
#   门禁顺序执行时，前面的检查项跑过 Windows 构建 ->
#   `demo/gen/*` 是 **Windows 机器**的值，而 Linux 产物更早 ->
#   **期望值不匹配 -> 授权链失败**（实测）。
#   => 本项必须**自己完整构建**。代价: 慢，但**正确性优先**。
#
# ## 为什么默认跳过
#   慢（数分钟）。跳过时**明确标注**（未运行 != 通过）—— 与 -WithMutation 同纪律。
#
# ## 含负向自检
#
# ⚠️ **2026-10-01 修复**: 上面那个 `} else {` 曾**被误删**（提交 `abc5edc` 把
#   本段的注释块插进了 `if ($WithMigration)` 的 body，**吃掉了它的 `} else {`**）。
#   后果: 门禁第 23~32 项（含本节自身）**全部被嵌套进 `if ($WithMigration)`**，
#   只有显式传 `-WithMigration` 才会跑。实测证据（同一脚本、同一台机器）:
#     · 不带任何开关                 -> `PASS: 19 项`（第 23 项起全没跑）
#     · `-WithSkeleton -WithMutation -WithMigration` -> `PASS: 30 项`
#   即**默认调用下门禁自己静默跳过约 10 项，PASS 文案照打** —— 正是本项目反复
#   记名的"未验证 != 通过"被违反，且**门禁项数（32）看起来完全正确**。
#
#   教训: **纯注释块插进 `if` 体，解析器发现不了**（`Parser::ParseFile` 报 0 error）。
#   只有**结构断言**能抓住。而既有两个数门禁项数的检查器（第 26 项 `docclaim`、
#   第 31 项 `gate_log`）都只数 `Check` 的**出现次数**（32 个全对），
#   **没有一个断言它们在顶层**；更糟的是这两项**自己就落在被嵌套的区间里**，
#   复发时根本不会运行。=> 结构断言必须放在**不受该 bug 影响**的靠前项。
#   已补: `tools/doccheck.py`（门禁第 13 项，默认必跑）新增"每个 `Check` 必须
#   在顶层"的断言。

Write-Host ''
# 门禁落日志: 把路径再报一次（人读的是结尾；失败时尤其关键）
$__log = [string](Get-Variable -Name '__GateLogPath' -Scope Global -ValueOnly -ErrorAction SilentlyContinue)
if ($__log) { Write-Host ("[log] 本轮完整输出: {0}" -f $__log) -ForegroundColor DarkGray }

# ## ST2.1(2026-10-10): 门禁的**第二个出口** —— NDJSON, 以及**双面对照**
#   文本出口是给人读的, 也是 docclaim T7 的锚; NDJSON 出口是给面板与
#   历史趋势读的。两者在 `Add-GateResult` 处同源产生, 这里在同一轮内对账。
#   ⚠️ 本段输出**不得**以 [ok]/[X]/[skip]/[info] 开头 —— T7 按**行首**
#   锚定这些记号, 多一枚就会被判成"某个调用点留下了两行证据"。
#   ⚠️ 本轮 ndjson 在**总结之后**才写完, 所以"读日志做独立对账"只能验
#   **上一轮**的配对 —— 那是 `tools/gate_results.py --verify` 的职责;
#   这里的对照比的是 JSON 计数与文本侧计数器(同一来源, 抓单边漏改)。
$jsonPath = ''
if ($__log) { $jsonPath = [System.IO.Path]::ChangeExtension($__log, '.ndjson') }
else { $jsonPath = Join-Path $Root ('build\logs\release_check_{0}.ndjson' -f $gateStamp) }
$nok = @($results | Where-Object { $_.status -eq 'pass' }).Count
$nx  = @($results | Where-Object { $_.status -eq 'fail' -or $_.status -eq 'error' }).Count
$nsk = @($results | Where-Object { $_.status -eq 'skip' }).Count
$nnr = @($results | Where-Object { $_.status -eq 'not-run' }).Count
$jsonErr = ''
try {
    $jdir = Split-Path -Parent $jsonPath
    if (-not (Test-Path -LiteralPath $jdir)) { New-Item -ItemType Directory -Force -Path $jdir | Out-Null }
    if (Test-Path -LiteralPath $jsonPath) { Remove-Item -LiteralPath $jsonPath -Force }
    # ⚠️ 必须显式 UTF8Encoding($false): `Add-Content -Encoding UTF8` 实测会写
    #    BOM(前 3 字节 ef bb bf), 而 BOM 会让 json.loads 首行直接报
    #    "Unexpected UTF-8 BOM"。NDJSON 每行都必须能独立解析。
    $enc = New-Object System.Text.UTF8Encoding $false
    $sb = New-Object System.Text.StringBuilder
    foreach ($r in $results) { [void]$sb.AppendLine(($r | ConvertTo-Json -Compress -Depth 4)) }
    [System.IO.File]::WriteAllText($jsonPath, $sb.ToString(), $enc)
} catch { $jsonErr = $_.Exception.Message }
if ($jsonErr -ne '') {
    # ST2.5: 出口损坏**必须报错**, 不得静默产出一个空文件让面板显示"0 项全过"。
    Write-Host ("[json] FAIL: NDJSON 出口损坏 — {0}" -f $jsonErr) -ForegroundColor Red
    exit 1
}
if ($nok -ne $pass -or $nx -ne $fail -or $nsk -ne $skip -or $nnr -ne $notrun) {
    Write-Host ("[json] FAIL: 双面对照不一致 — JSON(pass={0} fail={1} skip={2} not-run={3}) vs 文本(pass={4} fail={5} skip={6} not-run={7})" -f $nok, $nx, $nsk, $nnr, $pass, $fail, $skip, $notrun) -ForegroundColor Red
    exit 1
}
Write-Host ("[json] {0} 项 -> {1}" -f $results.Count, $jsonPath) -ForegroundColor DarkGray
Write-Host ("[json] 双面对照: pass={0} fail={1} skip={2} not-run={3}" -f $nok, $nx, $nsk, $nnr) -ForegroundColor DarkGray
# ## 总结必须**如实分开**三态（2026-10-02）
#   `[skip]` 项既不是通过也不是失败: 它的判据**从未执行**。
#   若把它算进 PASS 的分子，"N 项检查全通过"就会**谎报**（`docclaim` 的
#   T7 不变量正是拿这句话与 `[ok]` 行数对账的）。
#   => `PASS: N 项检查全通过` 的 N **只数 `[ok]`**；跳过项单独一行列出，
#      并保留「未验证 != 通过」的定性。
if ($skip -gt 0) {
    Write-Host ("[skip] {0} 项因前置不满足未验证（未验证 != 通过）" -f $skip) -ForegroundColor DarkYellow
}
if ($fail -gt 0) {
    Write-Host ("[release_check] FAIL: {0}/{1} 未通过" -f $fail, ($pass + $fail)) -ForegroundColor Red
    exit 1
}
Write-Host ("[release_check] PASS: {0} 项检查全通过" -f $pass) -ForegroundColor Green
exit 0
} finally {
    # 门禁落日志: 停止转录（**finally 覆盖 exit/throw/正常** —— 同锁的理由）
    & "$PSScriptRoot\gate_log.ps1" -Stop | Out-Null
    # D2: 释放锁（**finally 覆盖 exit/throw/正常**）
    & "$PSScriptRoot\verify_lock.ps1" -Holder 'release_check' -Release
}
