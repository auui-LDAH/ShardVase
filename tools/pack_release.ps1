# pack_release.ps1 — 发版打包（docs/RELEASE.md §4.1 步 3-7 + §4.2 分发物）
#
# 一键产出 build\release-vX.Y.Z\ {demo.exe, vm.blob, license.txt, ReadMe.txt, SHA256SUMS}
# 并自校验 Get-FileHash 与 SHA256SUMS 一致（§4.2 验收）。
#
# 步骤映射（§4.1）:
#   3. build.ps1 -Config Release -RecordSeeds  (-SkipBuild 跳过, 复用现有产物)
#   4. dumpbin 三查（§2.2: 无 CODEVIEW 调试目录 / 无 PDB / 无 COFF 内部符号）
#   5. signtool 签名 + verify /pa（§2.4; 已签且指纹匹配则只验不重签）
#   6. verify.ps1 -Reproducible（可选, 默认关, -Reproducible 开）
#   7. 打包分发物 + SHA256SUMS + 自校验
#
# 版本号单一事实来源: include/protect/version.h 的 PROT_VERSION_STR（禁止二次硬编码）。
# 签名: 自签证书 build\keys\codesign.pfx + sign.pass; 默认不带时间戳（离线+可复现,
#   见 build.ps1 注释）; 需要时间戳时设 $env:PROT_TIMESTAMP_URL。
param(
    [switch]$SkipBuild,     # 跳过 §4.1 步3（复用 build\demo.exe 等现有产物）
    [switch]$SkipSign,      # 跳过 §4.1 步5（不签名、不验证）
    [switch]$Reproducible,  # §4.1 步6 可选审计项（verify.ps1 -Reproducible, 耗时）
    [string]$VcVars = ''    # 显式 vcvars64.bat 路径（缺省自动探测）
)

$ErrorActionPreference = 'Stop'
$repo   = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Definition)
$exe    = Join-Path $repo 'build\demo.exe'
$vmBlob = Join-Path $repo 'build\vm.blob'
$lic    = Join-Path $repo 'build\license.txt'

# 版本单一来源: version.h
$vhPath = Join-Path $repo 'include\protect\version.h'
$vhText = [System.IO.File]::ReadAllText($vhPath)
if ($vhText -notmatch '#define\s+PROT_VERSION_STR\s+"([^"]+)"') {
    throw 'pack FAILED: 无法从 include/protect/version.h 解析 PROT_VERSION_STR'
}
$ver = $Matches[1]
Write-Host "pack: version = $ver (version.h PROT_VERSION_STR)"

function Fail([string]$msg) { throw "pack FAILED: $msg" }

try {
    # ---- §4.1 步3: Release 构建（-SkipBuild 时复用现有产物）----
    if (-not $SkipBuild) {
        Write-Host 'pack: [3/7] build.ps1 -Config Release -RecordSeeds ...'
        $bargs = @('-Config', 'Release', '-RecordSeeds')
        if ($SkipSign)  { $bargs += '-SkipSign' }
        if ($VcVars)    { $bargs += @('-VcVars', $VcVars) }
        & (Join-Path $repo 'build.ps1') @bargs
        if ($LASTEXITCODE -ne 0) { Fail "build.ps1 rc=$LASTEXITCODE" }
    } else {
        Write-Host 'pack: [3/7] 跳过构建（-SkipBuild, 复用现有产物）'
    }
    foreach ($f in @($exe, $vmBlob, $lic)) {
        if (-not (Test-Path -LiteralPath $f)) { Fail "缺少产物: $f" }
    }
    # §2.3 版本资源与 version.h 一致
    $fv = (Get-Item -LiteralPath $exe).VersionInfo.FileVersion
    if (-not ($fv -eq $ver -or $fv -like "$ver*")) { Fail "FileVersion '$fv' != version.h '$ver'" }
    Write-Host "pack: FileVersion = $fv 与 version.h 一致"

    # ---- §4.1 步4: dumpbin 三查（§2.2）----
    Write-Host 'pack: [4/7] dumpbin 符号/调试三查 ...'
    # 定位 vcvars64.bat（与 build.ps1 Find-VcVars 同源候选表）
    if (-not $VcVars) {
        $candidates = @(
            'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat',
            'C:\Program Files (x86)\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat',
            'C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat',
            'C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat',
            'D:\environment\VS2022BuildTools\VC\Auxiliary\Build\vcvars64.bat'
        )
        $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
        if (Test-Path -LiteralPath $vswhere) {
            $install = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
            if ($install) { $candidates += (Join-Path $install 'VC\Auxiliary\Build\vcvars64.bat') }
        }
        $VcVars = $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
        if (-not $VcVars) { Fail 'cannot locate vcvars64.bat（装 VS2022 C++ 工具集或传 -VcVars）' }
    }
    # 检查1: 无 CODEVIEW(cv) 调试目录（repro/coffgrp 属 Release 正常项, 不算）
    $hdr = cmd /c "`"$VcVars`" >nul 2>&1 && dumpbin /headers `"$exe`" 2>&1"
    if ($LASTEXITCODE -ne 0) { Fail "dumpbin /headers rc=$LASTEXITCODE" }
    $cv = @($hdr) | Where-Object { $_ -match '^\s*[0-9A-Fa-f]{8}\s+cv\s' }
    if ($cv) { Fail ('dumpbin /headers: 存在 CODEVIEW 调试目录: ' + ($cv -join '; ')) }
    Write-Host 'pack:   [1/3] 无 CODEVIEW 调试目录 (仅 coffgrp/repro) OK'
    # 检查2: 无 PDB
    $pdbs = @(Get-ChildItem (Join-Path $repo 'build\*.pdb') -ErrorAction SilentlyContinue)
    if ($pdbs.Count -ne 0) { Fail ("build\ 下存在 PDB: " + (($pdbs | ForEach-Object Name) -join ', ')) }
    Write-Host 'pack:   [2/3] 无 PDB OK'
    # 检查3: 无 COFF 内部符号表（Release 下 dumpbin /symbols 只应有节 Summary）
    $sym = cmd /c "`"$VcVars`" >nul 2>&1 && dumpbin /symbols `"$exe`" 2>&1"
    if ($LASTEXITCODE -ne 0) { Fail "dumpbin /symbols rc=$LASTEXITCODE" }
    if (@($sym) | Where-Object { $_ -match 'COFF SYMBOL TABLE' }) {
        Fail 'dumpbin /symbols: 存在 COFF SYMBOL TABLE（内部符号泄露）'
    }
    Write-Host 'pack:   [3/3] 仅外部符号（无 COFF 符号表）OK'

    # ---- §4.1 步5: 签名 + verify /pa（§2.4）----
    if (-not $SkipSign) {
        Write-Host 'pack: [5/7] signtool 签名 + verify /pa ...'
        $pfx = Join-Path $repo 'build\keys\codesign.pfx'
        $cer = Join-Path $repo 'build\keys\codesign.cer'
        if (-not (Test-Path -LiteralPath $pfx)) {
            Write-Host 'pack:   codesign.pfx 缺失 — 跳过签名（§2.4 有证书时签）'
        } else {
            $cerThumb = (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $cer).Thumbprint
            $sig = Get-AuthenticodeSignature -LiteralPath $exe
            $alreadySigned = ($sig.Status -eq 'Valid') -and ($sig.SignerCertificate -and $sig.SignerCertificate.Thumbprint -eq $cerThumb)
            if (-not $alreadySigned) {
                $signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
                    Sort-Object FullName -Descending | Select-Object -First 1
                if (-not $signtool) { Fail 'signtool.exe not found（Windows Kits 10 SDK）' }
                $pass = '/p ' + (Get-Content -LiteralPath (Join-Path $repo 'build\keys\sign.pass') -Raw).Trim()
                $tsArg = ''
                if ($env:PROT_TIMESTAMP_URL) { $tsArg = "/t $($env:PROT_TIMESTAMP_URL)" }
                cmd /c "`"$($signtool.FullName)`" sign /fd SHA256 /f `"$pfx`" $pass $tsArg `"$exe`""
                if ($LASTEXITCODE -ne 0) { Fail 'signtool sign 失败（证书/口令/时间戳网络）' }
                $sig = Get-AuthenticodeSignature -LiteralPath $exe
            } else {
                Write-Host 'pack:   已签名且指纹匹配 — 只验证不重签'
            }
            # 验收: verify /pa + 指纹 == codesign.cer
            $signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
                Sort-Object FullName -Descending | Select-Object -First 1
            cmd /c "`"$($signtool.FullName)`" verify /pa `"$exe`""
            if ($LASTEXITCODE -ne 0) { Fail 'signtool verify /pa 失败' }
            if (-not ($sig.SignerCertificate -and $sig.SignerCertificate.Thumbprint -eq $cerThumb)) {
                Fail "签名指纹 $($sig.SignerCertificate.Thumbprint) != codesign.cer $cerThumb"
            }
            Write-Host "pack:   verify /pa OK（自签, 指纹 $cerThumb）"
        }
    } else {
        Write-Host 'pack: [5/7] 跳过签名（-SkipSign）'
    }

    # ---- §4.1 步6: 可选可复现审计 ----
    if ($Reproducible) {
        Write-Host 'pack: [6/7] verify.ps1 -Reproducible ...'
        & (Join-Path $repo 'verify.ps1') -Reproducible
        if ($LASTEXITCODE -ne 0) { Fail "verify.ps1 -Reproducible rc=$LASTEXITCODE" }
    } else {
        Write-Host 'pack: [6/7] 跳过可复现审计（可选, -Reproducible 开启）'
    }

    # ---- §4.1 步7: 打包分发物 + SHA256SUMS（§4.2）----
    Write-Host 'pack: [7/7] 打包分发物 ...'
    $outDir = Join-Path $repo ("build\release-v$ver")
    if (Test-Path -LiteralPath $outDir) {
        $full = [System.IO.Path]::GetFullPath($outDir)
        $base = [System.IO.Path]::GetFullPath((Join-Path $repo 'build'))
        if (-not $full.StartsWith($base, [System.StringComparison]::OrdinalIgnoreCase)) {
            Fail "拒绝删除 build\ 之外的目录: $full"
        }
        Remove-Item -LiteralPath $outDir -Recurse -Force
    }
    New-Item -ItemType Directory -Path $outDir | Out-Null
    Copy-Item -LiteralPath $exe    -Destination (Join-Path $outDir 'demo.exe')
    Copy-Item -LiteralPath $vmBlob -Destination (Join-Path $outDir 'vm.blob')
    Copy-Item -LiteralPath $lic    -Destination (Join-Path $outDir 'license.txt')

    # 溯源信息
    $sha = 'unknown'
    try { $sha = (git -C $repo rev-parse --short HEAD 2>$null) } catch { }
    $licText = [System.IO.File]::ReadAllText($lic)
    $serial = ''
    if ($licText -match 'SERIAL=(\S+)') { $serial = $Matches[1] }
    $date = Get-Date -Format 'yyyy-MM-dd HH:mm:ss K'

    # ReadMe.txt（UTF-8 无 BOM）
    $readme = @"
ShardVase 演示分发包 v$ver
============================

生成时间 : $date
源码提交 : $sha（AGPL-3.0-or-later, 见仓库 LICENSE）

文件清单
--------
  demo.exe    演示主程序（Release 构建, 自签代码签名, 版本 $ver）
  vm.blob     与 demo.exe 同构建的 VM 数据（不可混用其他构建的 blob）
  license.txt 演示授权示例（绑定示例 MACHINE_ID, 实际授权经签发流程签发）
  ReadMe.txt  本文件
  SHA256SUMS  以上全部文件的 SHA-256 校验和

序列号
------
  SERIAL=$serial（授权文件: license.txt）

运行
----
  Windows x64, 免安装, 直接运行 demo.exe。
  SmartScreen/杀软提示属自签证书预期行为（RELEASE.md §5）。

校验
----
  PowerShell:  Get-FileHash -Algorithm SHA256 .\demo.exe    与 SHA256SUMS 对照
  cmd:         certutil -hashfile demo.exe SHA256
  （或 Linux:  sha256sum -c SHA256SUMS）

签名
----
  demo.exe 由自签证书（build\keys\codesign.cer, CN=PROT Demo Dev）签名;
  如需系统级信任, 将 codesign.cer 导入"受信任的根证书颁发机构"。
"@
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText((Join-Path $outDir 'ReadMe.txt'), $readme, $utf8NoBom)

    # SHA256SUMS（sha256sum -c 兼容: <hash>␣␣<name>）
    $names = @('demo.exe', 'vm.blob', 'license.txt', 'ReadMe.txt')
    $lines = @()
    foreach ($n in $names) {
        $h = (Get-FileHash -LiteralPath (Join-Path $outDir $n) -Algorithm SHA256).Hash.ToLower()
        $lines += ($h + '  ' + $n)
    }
    [System.IO.File]::WriteAllText((Join-Path $outDir 'SHA256SUMS'), (($lines -join "`n") + "`n"), $utf8NoBom)

    # 自校验: 重算 Get-FileHash 与 SHA256SUMS 逐条比对（§4.2 验收）
    $sumPath = Join-Path $outDir 'SHA256SUMS'
    $sumLines = [System.IO.File]::ReadAllLines($sumPath) | Where-Object { $_.Trim() -ne '' }
    if ($sumLines.Count -ne $names.Count) { Fail "SHA256SUMS 条数 $($sumLines.Count) != $($names.Count)" }
    foreach ($ln in $sumLines) {
        $m = [regex]::Match($ln, '^([0-9a-fA-F]{64})\s+(\S+)$')
        if (-not $m.Success) { Fail "SHA256SUMS 格式非法: $ln" }
        $expect = $m.Groups[1].Value.ToLower()
        $file   = Join-Path $outDir $m.Groups[2].Value
        if (-not (Test-Path -LiteralPath $file)) { Fail "SHA256SUMS 引用缺失文件: $($m.Groups[2].Value)" }
        $actual = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLower()
        if ($actual -ne $expect) { Fail "哈希不一致: $($m.Groups[2].Value) expect=$expect actual=$actual" }
    }
    Write-Host "pack: SHA256SUMS 自校验通过（$($sumLines.Count) 个文件）"
    Write-Host "pack: 产物 $outDir :"
    Get-ChildItem $outDir | ForEach-Object { Write-Host ("pack:   {0,10}  {1}" -f $_.Length, $_.Name) }
    Write-Host '[pack_release] PASS: 发版打包完成（§4.1 步 3-7 + §4.2 验收通过）'
    exit 0
}
catch {
    Write-Host "[pack_release] FAIL: $($_.Exception.Message)"
    exit 1
}
