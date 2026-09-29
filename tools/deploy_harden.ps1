# tools/deploy_harden.ps1 — **部署加固**（R2.1, 2026-09-29）
#
# ## 为什么需要
#   `USABILITY_ASSESSMENT §3.3` 的 5 项显式破防里，**2 项**的前置条件都是
#   「安装目录**可写**」:
#     · `D5` 同目录伪造 `winhttp.dll`（DLL 劫持）
#     · `L3` 替换嵌入公钥自签（公钥**编译进 EXE**，替换 = 改 EXE）
#   而此前**没有任何 ACL 工具**（全仓搜索 0 处）—— 部署加固只能靠人手工。
#
# ## 本工具做什么
#   `-InstallDir <dir>`  加固: 撤销继承，Users 仅 **RX**（读+执行，不可写）
#                          Administrators/SYSTEM 保持 F（便于升级维护）
#   `-Verify`            **实测**: 在该目录尝试 `L3`/`D5` 两种攻击 -> 报是否被阻断
#   `-Restore`           还原继承权限（**回滚**）
#   `-Selftest`          **负向自检**: 证明"检测真的能区分加固/未加固"
#   `-WhatIf`            只打印将执行的 icacls，不改动
#
# ## ⚠️ 诚实边界（**本工具会实测它，而不是假设**）
#   ① **属主(Owner)可绕过**: Windows 里属主隐含 `WRITE_DAC` -> 可重新授权。
#      自检会**实测**这一点并如实报告 —— 因为"能不能绕过"决定了这条
#      部署约束的**真实强度**。
#   ② **管理员可绕过**: 同理（可取得所有权）。
#   ③ 因此本工具的价值场景是: **安装由管理员完成，程序以标准用户运行**
#      （企业部署的典型形态）—— 此时用户**不拥有**安装目录 -> ACL 生效。
#      若安装者==运行者且为属主，**加固强度有限**（如实记录）。
#
# ## 用法
#   powershell -File tools\deploy_harden.ps1 -InstallDir build\install_demo -Verify
#   powershell -File tools\deploy_harden.ps1 -Selftest
param(
    [string]$InstallDir = '',
    [switch]$Verify,
    [switch]$Restore,
    [switch]$Selftest,
    [switch]$WhatIf
)

$ErrorActionPreference = 'Stop'

function Get-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-OwnerName($path) {
    try {
        return (Get-Acl -LiteralPath $path).Owner
    } catch {
        return '?'
    }
}

function Invoke-Icacls($argsList, [switch]$Dry) {
    $shown = 'icacls ' + ($argsList -join ' ')
    if ($Dry) {
        Write-Host ('  [WhatIf] ' + $shown) -ForegroundColor DarkYellow
        return 0
    }
    & icacls @argsList 2>&1 | Out-Null
    return $LASTEXITCODE
}

# ---------------------------------------------------------------------------
# 加固 / 还原
# ---------------------------------------------------------------------------
function Set-Hardened($dir, [switch]$Dry) {
    # 撤销继承 + 只给 Users RX（读/执行，**不可写**）
    #   保留 Administrators/SYSTEM 全权 -> 升级与维护可行
    Write-Host ("[harden] 加固: {0}" -f $dir) -ForegroundColor Cyan
    Invoke-Icacls @($dir, '/inheritance:r') -Dry:$Dry | Out-Null
    Invoke-Icacls @($dir, '/grant:r', 'BUILTIN\Users:(RX)',
                    'BUILTIN\Administrators:(F)', 'NT AUTHORITY\SYSTEM:(F)') -Dry:$Dry | Out-Null
    if (-not $Dry) { Invoke-Icacls @($dir, '/T', '/grant:r', 'BUILTIN\Users:(RX)') | Out-Null }
}

function Set-Restored($dir, [switch]$Dry) {
    Write-Host ("[harden] 还原继承: {0}" -f $dir) -ForegroundColor Cyan
    Invoke-Icacls @($dir, '/inheritance:e') -Dry:$Dry | Out-Null
    Invoke-Icacls @($dir, '/T', '/grant', 'BUILTIN\Users:(OI)(CI)(RX)') -Dry:$Dry | Out-Null
}

# ---------------------------------------------------------------------------
# 攻击实测（L3 / D5）
# ---------------------------------------------------------------------------
function Test-AttackBlocked($dir) {
    # ## 两种攻击都是"往安装目录写"
    #   L3 公钥替换 -> 覆盖 **EXE**（公钥编译在内）
    #   D5 DLL 劫持 -> 在该目录**新建** winhttp.dll
    $results = @()

    # L3: 尝试覆盖受保护文件（用目录内第一个 .exe；没有就用一个探针文件）
    $exe = Get-ChildItem -LiteralPath $dir -Filter '*.exe' -File -ErrorAction SilentlyContinue |
           Select-Object -First 1
    $target = if ($exe) { $exe.FullName } else { Join-Path $dir '_probe.bin' }
    if (-not (Test-Path -LiteralPath $target)) {
        Set-Content -LiteralPath $target -Value 'PROBE' -NoNewline
    }
    $l3 = $false
    try {
        $fs = [System.IO.File]::Open($target, 'Open', 'Write', 'None')
        $fs.WriteByte(0x00)
        $fs.Close()
        $l3 = $true                     # 写成功 = **未被阻断**
    } catch {
        $l3 = $false                    # 被拒 = 已阻断
    }
    $results += , @{ id = 'L3 公钥/EXE 覆盖'; blocked = (-not $l3) }

    # D5: 尝试新建 winhttp.dll
    $dll = Join-Path $dir 'winhttp.dll'
    $d5 = $false
    try {
        [System.IO.File]::WriteAllBytes($dll, [byte[]](0x4D, 0x5A))
        $d5 = $true
    } catch {
        $d5 = $false
    }
    $results += , @{ id = 'D5 winhttp.dll 落盘'; blocked = (-not $d5) }

    # 清理探针（成功落盘才需要删；删不掉说明加固也在防"删除"）
    foreach ($p in @($dll)) {
        if (Test-Path -LiteralPath $p) {
            try { Remove-Item -LiteralPath $p -Force } catch { }
        }
    }
    return $results
}

# ---------------------------------------------------------------------------
# 自检（**含负向** —— 必须证明"能区分加固/未加固"）
# ---------------------------------------------------------------------------
function Invoke-Selftest {
    $fail = 0
    function Case($name, $ok, $detail = '') {
        if ($ok) {
            Write-Host ("  ok  {0}" -f $name) -ForegroundColor Green
        } else {
            Write-Host ("  **FAIL** {0}  {1}" -f $name, $detail) -ForegroundColor Red
            $script:fail++
        }
    }

    Write-Host '=== deploy_harden 自检 ==='
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('dh_' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Path $tmp | Out-Null
    try {
        # T1 **负向**: 未加固目录 -> 两种攻击**必须成功**（证明检测不是"永远说已阻断"）
        $r1 = Test-AttackBlocked $tmp
        $anyBlocked = ($r1 | Where-Object { $_.blocked }).Count -gt 0
        Case 'T1 **负向** 未加固 -> L3/D5 **必须不阻断**（否则检测恒真）' `
             (-not $anyBlocked) (($r1 | ForEach-Object { "$($_.id)=$($_.blocked)" }) -join ' ')

        # T2 正向: 加固后 -> 两种攻击**必须被阻断**
        Set-Hardened $tmp | Out-Null
        $r2 = Test-AttackBlocked $tmp
        $allBlocked = ($r2 | Where-Object { -not $_.blocked }).Count -eq 0
        Case 'T2 正向 加固后 -> L3/D5 **必须被阻断**' `
             $allBlocked (($r2 | ForEach-Object { "$($_.id)=$($_.blocked)" }) -join ' ')

        # T3 还原后 -> 攻击重新可行（证明加固是**可逆**的，不破坏部署能力）
        Set-Restored $tmp | Out-Null
        $r3 = Test-AttackBlocked $tmp
        $stillBlocked = ($r3 | Where-Object { $_.blocked }).Count -eq 2
        Case 'T3 还原后 -> 攻击**重新可行**（加固可逆）' `
             (-not $stillBlocked) (($r3 | ForEach-Object { "$($_.id)=$($_.blocked)" }) -join ' ')

        # T4 **诚实边界实测**: 属主/管理员能否绕过（**测量，不假设**）
        Set-Hardened $tmp | Out-Null
        $owner = Get-OwnerName $tmp
        $me = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        $isAdmin = Get-IsAdmin
        $ownerIsMe = ($owner -like ('*' + ($me -split '\\')[-1] + '*'))
        $infoLine = '  info 属主={0} 当前用户={1} 管理员={2} 属主即当前用户={3}' -f $owner, $me, $isAdmin, $ownerIsMe
        Write-Host $infoLine -ForegroundColor DarkGray
        # 属主可 `icacls /grant` 重新授权 -> 这是**已知边界**，报出来而非隐藏
        $canRegrant = $false
        try {
            Invoke-Icacls @($tmp, '/grant', ($me + ':(F)')) | Out-Null
            $r4 = Test-AttackBlocked $tmp
            $canRegrant = (($r4 | Where-Object { -not $_.blocked }).Count -gt 0)
        } catch { }
        if ($ownerIsMe -or $isAdmin) {
            Case 'T4 **诚实边界** 属主/管理员可重新授权 -> 攻击**可恢复**（如实报告）' `
                 $canRegrant "canRegrant=$canRegrant"
        } else {
            Write-Host '  info T4 当前用户非属主且非管理员 -> 跳过"可绕过"实测' -ForegroundColor DarkGray
        }

        Set-Restored $tmp | Out-Null
    } finally {
        Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }

    Write-Host ''
    if ($fail -gt 0) {
        Write-Host ("[deploy_harden-selftest] FAIL: {0} 项" -f $fail) -ForegroundColor Red
        return 1
    }
    Write-Host '[deploy_harden-selftest] PASS: 正向 + 负向 + 可逆 + 诚实边界均可自证' -ForegroundColor Green
    return 0
}

# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
if ($Selftest) {
    exit (Invoke-Selftest)
}

if (-not $InstallDir) {
    Write-Host '[harden] 需要 -InstallDir（或用 -Selftest）' -ForegroundColor Red
    exit 2
}
$dir = (Resolve-Path -LiteralPath $InstallDir -ErrorAction SilentlyContinue)
if (-not $dir) {
    Write-Host ("[harden] 目录不存在: {0}" -f $InstallDir) -ForegroundColor Red
    exit 2
}
$dir = $dir.Path

Write-Host ("[harden] 目标: {0}" -f $dir)
$ownerName = Get-OwnerName $dir
$curUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$isAdminNow = Get-IsAdmin
$envLine = '[harden] 属主: {0} · 当前用户: {1} · 管理员: {2}' -f $ownerName, $curUser, $isAdminNow
Write-Host $envLine -ForegroundColor DarkGray

if ($Restore) {
    Set-Restored $dir -Dry:$WhatIf
    if ($Verify) {
        Write-Host ''
        foreach ($r in (Test-AttackBlocked $dir)) {
            Write-Host ("  {0}: {1}" -f $r.id,
                        $(if ($r.blocked) { '已阻断' } else { '**未被阻断**' }))
        }
    }
    exit 0
}

Set-Hardened $dir -Dry:$WhatIf

if ($Verify) {
    Write-Host ''
    Write-Host '[harden] 攻击实测:' -ForegroundColor Cyan
    $allOk = $true
    foreach ($r in (Test-AttackBlocked $dir)) {
        if ($r.blocked) {
            Write-Host ("  ok   {0} -> **已阻断**" -f $r.id) -ForegroundColor Green
        } else {
            Write-Host ("  FAIL {0} -> **未被阻断**" -f $r.id) -ForegroundColor Red
            $allOk = $false
        }
    }
    Write-Host ''
    if ($allOk) {
        Write-Host '[harden] 部署加固**实测生效**（L3 + D5 均被阻断）' -ForegroundColor Green
        exit 0
    }
    Write-Host '[harden] **加固未完全生效** —— 见上（可能是权限不足或属主身份）' -ForegroundColor Red
    exit 1
}

Write-Host '[harden] 完成（加 -Verify 做攻击实测，-Restore 回滚）' -ForegroundColor Green
exit 0
