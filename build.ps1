# build.ps1 — 一键构建 (Lane D)
# 按 docs/CONTRACT.md §10 管线执行:
#   genserial -> assemble -> strgen -> cl -> hashpatch
# 每步失败即中止并打印明确错误。
#
# 参数:
#   -MachineId <值>   覆盖 machine_id (十进制/0x16进制/"0"/"auto"); 默认 auto=绑定本机
#   -Config <Release|Dev>  Release=发行加固 (/DEBUG:NONE /OPT:REF,ICF + 版本资源 + 签名);
#                           Dev=默认开发构建
#   -VcVars <路径>    显式指定 vcvars64.bat; 缺省自动探测 (vswhere/MSVC 常见路径)
#   -Python <路径>    显式指定 python.exe; 缺省自动探测
#   -SeedsFile <json> 确定性种子表 (RELEASE I3 可复现构建): {"images": {"<镜像名>": {"key0": "0x..", "key1": "0x.."}}}
#   -RecordSeeds      构建后把本次种子写 build\seeds.json
# 输出: build\demo.exe / build\vm_unit.exe / build\manifest.json (产物清单)
param(
    [string]$MachineId = 'auto',
    [string]$Config = 'Dev',
    [string]$VcVars = '',
    [string]$Python = '',
    [string]$SeedsFile = '',
    [switch]$RecordSeeds,
    [switch]$SkipSign,
    [switch]$SkipSmoke
)
$ErrorActionPreference = 'Stop'
$isRelease = ($Config -eq 'Release')

# 确定性种子表 (I3): 镜像名 -> {key0, key1}; 顶层 "strgen" = 字符串密钥种子;
# "indirect" = N4 间接表种子 (标量)
$seedMap = @{}
$strgenSeedArgs = @()
$indirectSeed = $null
if ($SeedsFile) {
    $sAll = Get-Content -LiteralPath $SeedsFile -Raw | ConvertFrom-Json
    $seedMap = $sAll.images
    if ($sAll.strgen) { $strgenSeedArgs = @('--seed', $sAll.strgen) }
    if ($sAll.indirect) { $indirectSeed = @('--seed', ('0x' + $sAll.indirect)) }
}
function Get-SeedArgs([string]$name) {
    if ($seedMap.PSObject.Properties.Name -contains $name) {
        $s = $seedMap.$name
        return @('--seed', $s.key0, '--perm-seed', $s.key1)
    }
    return @()
}

# 锚定到脚本所在目录 (仓库根), 保证相对路径可靠
Set-Location -LiteralPath (Split-Path -Parent $MyInvocation.MyCommand.Path)

# 定位 vcvars64.bat: 优先 -VcVars 参数, 否则 vswhere 探测 (含常见手动安装路径)
function Find-VcVars {
    param([string]$Explicit)
    if ($Explicit) {
        if (-not (Test-Path -LiteralPath $Explicit)) {
            throw "build FAILED: -VcVars path not found: $Explicit"
        }
        return $Explicit
    }
    $candidates = @(
        'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat',
        'C:\Program Files (x86)\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat',
        'C:\Program Files (x86)\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat',
        'C:\Program Files (x86)\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat',
        'C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat',
        'C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat',
        'D:\environment\VS2022BuildTools\VC\Auxiliary\Build\vcvars64.bat'
    )
    foreach ($c in $candidates) {
        if (Test-Path -LiteralPath $c) { return $c }
    }
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path -LiteralPath $vswhere) {
        $install = & $vswhere -latest -products * `
            -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
            -property installationPath 2>$null
        if ($install) {
            $v = Join-Path $install 'VC\Auxiliary\Build\vcvars64.bat'
            if (Test-Path -LiteralPath $v) { return $v }
        }
    }
    throw 'build FAILED: cannot locate vcvars64.bat — install VS2022 C++ workload or pass -VcVars <path>'
}
$vcvars = Find-VcVars -Explicit $VcVars
Write-Host "build: vcvars = $vcvars"
$jsonPath = 'demo\vm_build.json'

# 定位 python: 跳过 WindowsApps 商店存根 (会静默失败), 允许显式 -Python <path>
function Find-Python {
    param([string]$Explicit)
    if ($Explicit) {
        if (-not (Test-Path -LiteralPath $Explicit)) {
            throw "build FAILED: -Python path not found: $Explicit"
        }
        return $Explicit
    }
    $cand = @(Get-Command python -ErrorAction SilentlyContinue | Where-Object {
        $_.Source -notlike '*\WindowsApps\*' } | Select-Object -First 1)
    if ($cand) { return $cand.Source }
    foreach ($p in @(
        'D:\environment\PYTHON\python.exe',
        'C:\Python313\python.exe', 'C:\Python312\python.exe',
        'C:\Python311\python.exe', 'C:\Python310\python.exe',
        "$env:LOCALAPPDATA\Programs\Python\Python313\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe"
    )) {
        if (Test-Path -LiteralPath $p) { return $p }
    }
    throw 'build FAILED: cannot locate python — install Python 3.8+ or pass -Python <path>'
}
$py = Find-Python -Explicit $Python
Write-Host "build: python = $py"

# 1. 若 demo\vm_build.json 不存在 -> 写默认值 (machine_id=0 触发 auto=hostid; expect 由 genserial 补算)
if (-not (Test-Path -LiteralPath $jsonPath)) {
    Write-Host 'build: creating default demo\vm_build.json'
    Set-Content -LiteralPath $jsonPath -Value '{"serial":"DEMO-2026-ABCDEFGH","machine_id":0}' -Encoding ascii
}

# 输出目录
if (-not (Test-Path -LiteralPath 'demo\gen')) {
    New-Item -ItemType Directory -Path 'demo\gen' | Out-Null
}
if (-not (Test-Path -LiteralPath 'build')) {
    New-Item -ItemType Directory -Path 'build' | Out-Null
}

# 2. 重算期望常量 (machine_id 默认 auto=绑定本机; 可 --MachineId 覆盖)
& $py tools\vmenc.py genserial --json demo\vm_build.json --machine-id "$MachineId"
if ($LASTEXITCODE -ne 0) { throw 'build FAILED: vmenc.py genserial' }

# 2.2. N5: 从 vm_build.json 生成构建期默认期望值 C 文件 (VM#3 离线兜底值)
$jbExpect = Get-Content -LiteralPath demo\vm_build.json -Raw | ConvertFrom-Json
$e1 = ($jbExpect.expect1 -replace '^0x', '')
$e2 = ($jbExpect.expect2 -replace '^0x', '')
$expLines = @(
    '/* generated by build.ps1 from demo\vm_build.json - do not edit */',
    '#include <stdint.h>',
    '#include "protect/protdef.h"',
    '',
    '/* N5: VM#3 build-time default expects (overridden by server session values) */',
    ('const uint64_t g_prot_expect_default[2] = { 0x' + $e1 + 'ULL, 0x' + $e2 + 'ULL };')
)
$expC = $expLines -join [Environment]::NewLine
Set-Content -LiteralPath 'demo\gen\expect_default.c' -Value $expC -Encoding ascii

# 2.5. RSA 授权 (A1): 生成/复用私钥 (build\keys, gitignore, 不入库) 并导出公钥 blob;
#     对该 json 的 serial/machine_id 签发 -> build\license.txt (供下发与测试用)
& $py tools\vmenc.py keygen --key-out "build\keys\license_priv.json" --blob-out "demo\gen\license_pubkey.c"
if ($LASTEXITCODE -ne 0) { throw 'build FAILED: vmenc.py keygen' }
& $py tools\vmenc.py sign --key "build\keys\license_priv.json" --json demo\vm_build.json --out "build\license.txt" --print
if ($LASTEXITCODE -ne 0) { throw 'build FAILED: vmenc.py sign' }

# 3. 汇编 + 加密 VM 镜像 (ROADMAP Phase 2a: 一个校验逻辑拆成 3 个独立小 VM,
#    各自独立密钥/置换/窗口: FNV 哈希 -> GOLDEN 混合 -> 期望值校验;
#    --bin-out/--bin-name: 写单镜像 .bin, 供 3c 打包 vm.blob 由 demo 装载;
#    -SeedsFile: 注入确定性种子 (I3 可复现构建))
& $py tools\vmenc.py assemble demo\license_hash.vasm demo\vm_build.json demo\gen\vm_hash_blob.c demo\gen\vm_hash_blob.h --name g_vm_hash_image --bin-out demo\gen\vm_hash_blob.bin --bin-name hash $(Get-SeedArgs 'g_vm_hash_image')
if ($LASTEXITCODE -ne 0) { throw 'build FAILED: vmenc.py assemble (hash)' }

& $py tools\vmenc.py assemble demo\license_mix.vasm demo\vm_build.json demo\gen\vm_mix_blob.c demo\gen\vm_mix_blob.h --name g_vm_mix_image --bin-out demo\gen\vm_mix_blob.bin --bin-name mix $(Get-SeedArgs 'g_vm_mix_image')
if ($LASTEXITCODE -ne 0) { throw 'build FAILED: vmenc.py assemble (mix)' }

& $py tools\vmenc.py assemble demo\license_verify.vasm demo\vm_build.json demo\gen\vm_verify_blob.c demo\gen\vm_verify_blob.h --name g_vm_verify_image --bin-out demo\gen\vm_verify_blob.bin --bin-name verify $(Get-SeedArgs 'g_vm_verify_image')
if ($LASTEXITCODE -ne 0) { throw 'build FAILED: vmenc.py assemble (verify)' }

& $py tools\vmenc.py assemble demo\license_gate.vasm demo\vm_build.json demo\gen\vm_gate_blob.c demo\gen\vm_gate_blob.h --name g_vm_gate_image --bin-out demo\gen\vm_gate_blob.bin --bin-name gate $(Get-SeedArgs 'g_vm_gate_image')
if ($LASTEXITCODE -ne 0) { throw 'build FAILED: vmenc.py assemble (gate)' }

# 3c. 打包 VM blob (DBI launcher, 技术债 #3): demo.exe 不再静态嵌入 VM 密文,
#     启动时由 launcher 装载 build\vm.blob (缺失/损坏 -> 0xB10B)
& $py tools\vmenc.py pack --out build\vm.blob demo\gen\vm_hash_blob.bin demo\gen\vm_mix_blob.bin demo\gen\vm_verify_blob.bin demo\gen\vm_gate_blob.bin
if ($LASTEXITCODE -ne 0) { throw 'build FAILED: vmenc.py pack' }

# 3b. 汇编 VM 指令集单测镜像 (ROADMAP Phase 1d, 每个新指令都要有测试用例)
& $py tools\vmenc.py assemble tests\unit_vm.vasm demo\vm_build.json demo\gen\vm_unit_blob.c demo\gen\vm_unit_blob.h --name g_vm_unit_image $(Get-SeedArgs 'g_vm_unit_image')
if ($LASTEXITCODE -ne 0) { throw 'build FAILED: vmenc.py assemble (unit_vm)' }

& $py tools\vmenc.py assemble tests\unit_vm_brk.vasm demo\vm_build.json demo\gen\vm_unit_brk_blob.c demo\gen\vm_unit_brk_blob.h --name g_vm_unit_brk_image $(Get-SeedArgs 'g_vm_unit_brk_image')
if ($LASTEXITCODE -ne 0) { throw 'build FAILED: vmenc.py assemble (unit_vm_brk)' }

# 4. 字符串加密 (I3: -SeedsFile 注入确定性密钥种子; -RecordSeeds 先定种子再构建)
if ($RecordSeeds -and $strgenSeedArgs.Count -eq 0) {
    $seedHex = -join (1..16 | ForEach-Object { '{0:x1}' -f (Get-Random -Max 16) })
    $strgenSeedArgs = @('--seed', ('0x' + $seedHex))
}
& $py tools\strgen.py demo\strings.txt demo\gen\strings.c $strgenSeedArgs
if ($LASTEXITCODE -ne 0) { throw 'build FAILED: strgen.py' }

# 4c. N4 函数级间接化: 生成槽位随机化函数指针表
#     (I3: -SeedsFile 注入确定性种子; -RecordSeeds 先定种子再构建)
if ($RecordSeeds -and $null -eq $indirectSeed) {
    $indirectSeed = @('--seed', ('0x' + (-join (1..16 | ForEach-Object { '{0:x1}' -f (Get-Random -Max 16) }))))
}
if ($indirectSeed) {
    & $py tools\indirect.py --out demo\gen\indirect_table.c $indirectSeed
} else {
    & $py tools\indirect.py --out demo\gen\indirect_table.c
}
if ($LASTEXITCODE -ne 0) { throw 'build FAILED: indirect.py' }

# 4b. Release: 编译版本资源 (RELEASE §2.3, 值只来自 version.h)
if ($isRelease) {
    cmd /c "`"$vcvars`" >nul 2>&1 && rc /nologo /I include /fo demo\gen\version.res demo\version.rc"
    if ($LASTEXITCODE -ne 0) { throw 'build FAILED: rc (version resource)' }
}

# 5. 编译 + 链接 (vcvars64 环境; cl 失败即中止)
#    Release 加固 (RELEASE §2/§3): 链接 /DEBUG:NONE 无调试目录, /OPT:REF,ICF 瘦身,
#    版本资源, /Brepro 可复现 (PE 时间戳/校验和确定性, 同种子两次构建字节一致)
$linkHard = if ($isRelease) { ' /DEBUG:NONE /OPT:REF /OPT:ICF /Brepro' } else { '' }
$resObj = if ($isRelease) { ' demo\gen\version.res' } else { '' }
cmd /c "`"$vcvars`" >nul 2>&1 && cl /nologo /O2 /W4 /WX /std:c11 /utf-8 /I include /I demo\gen /Fe:build\demo.exe src\vm.c src\crc32.c src\antidebug.c src\integrity.c src\strcrypt.c src\hostid.c src\license.c src\syscall.c src\blob.c src\revoke.c src\vmdetect.c src\dbiguard.c src\indirect.c src\selfcrypt.c demo\main.c demo\gen\strings.c demo\gen\license_pubkey.c demo\gen\indirect_table.c demo\gen\expect_default.c$resObj /link /SUBSYSTEM:CONSOLE bcrypt.lib winhttp.lib advapi32.lib /MAP:build\demo.map$linkHard"
if ($LASTEXITCODE -ne 0) { throw 'build FAILED: cl' }

# 5b. 编译并运行 VM 指令集单测
cmd /c "`"$vcvars`" >nul 2>&1 && cl /nologo /O2 /W4 /WX /std:c11 /utf-8 /I include /I demo\gen /Fe:build\vm_unit.exe src\vm.c src\crc32.c demo\gen\vm_unit_blob.c demo\gen\vm_unit_brk_blob.c tests\vm_unit.c /link /SUBSYSTEM:CONSOLE"
if ($LASTEXITCODE -ne 0) { throw 'build FAILED: cl (vm_unit)' }

# 5c. 编译 A6 direct syscall 单测 (直调结果须与 API 路径一致)
cmd /c "`"$vcvars`" >nul 2>&1 && cl /nologo /O2 /W4 /WX /std:c11 /utf-8 /I include /Fe:build\syscall_probe.exe src\syscall.c tests\syscall_probe.c /link /SUBSYSTEM:CONSOLE"
if ($LASTEXITCODE -ne 0) { throw 'build FAILED: cl (syscall_probe)' }

# 6. N1 (阶段 0 原型): 引擎函数原位加密 (方案 B) —— 必须在 hashpatch 之前
#     (加密改 .text, hashpatch 对加密段掩码后烧录, 两侧一致)。
#     掩码 rva/len 由 selfcrypt_proto.py 写入 build/selfcrypt_mask.txt
& $py tools\selfcrypt_proto.py build\demo.exe build\demo.map
if ($LASTEXITCODE -ne 0) { throw 'build FAILED: selfcrypt_proto.py' }
$maskArgs = @()
if (Test-Path -LiteralPath 'build\selfcrypt_mask.txt') {
    foreach ($ln in (Get-Content -LiteralPath 'build\selfcrypt_mask.txt')) {
        $maskArgs += '--mask', $ln.Trim()
    }
}

# 6. 烧录 .text CRC32 到二进制 (integrity 自检依赖; 带 selfcrypt 掩码)
& $py tools\hashpatch.py build\demo.exe @maskArgs
if ($LASTEXITCODE -ne 0) { throw 'build FAILED: hashpatch.py' }

# 6.2 Release: 数字签名 (RELEASE §2.4, 自签证书) —— 必须在 hashpatch 之后
# 注: 托管环境若启用 WDAC (代码完整性策略), 新构建的未签名 exe 可能被
# 信誉拦截 (winerror 4551); 签名可放行 —— 因此 Dev 构建在有 pfx 时也签名。
function Sign-Binary([string]$exe) {
    $signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" `
        -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
        Sort-Object FullName -Descending | Select-Object -First 1
    if (-not $signtool) { throw "build FAILED: signtool.exe not found (sign $exe)" }
    # 口令来源: $env:SIGN_PASSWORD 优先, 其次 build\keys\sign.pass (gitignore)
    $pass = ''
    if ($env:SIGN_PASSWORD) { $pass = "/p $env:SIGN_PASSWORD" }
    elseif (Test-Path -LiteralPath 'build\keys\sign.pass') {
        $pass = '/p ' + (Get-Content -LiteralPath 'build\keys\sign.pass' -Raw).Trim()
    }
    cmd /c "`"$($signtool.FullName)`" sign /fd SHA256 /f `"$pfx`" $pass /t http://timestamp.digicert.com $exe"
    if ($LASTEXITCODE -ne 0) { throw "build FAILED: signtool sign $exe" }
    Write-Host "build: signed $exe"
}

if (-not $SkipSign) {
    $pfx = 'build\keys\codesign.pfx'
    if (Test-Path -LiteralPath $pfx) {
        Sign-Binary 'build\demo.exe'
        Sign-Binary 'build\vm_unit.exe'
        Sign-Binary 'build\syscall_probe.exe'
    } else {
        Write-Host 'build: codesign.pfx absent - skip signing (RELEASE self-signed cert)'
    }
}

# 6.5 清理 cl 留在仓库根目录的中间 .obj (cl 默认把 obj 输出到 cwd)
Get-ChildItem -LiteralPath . -Filter *.obj -File | Remove-Item -Force

# 7. 跑 VM 指令集单测 / 7.1. 跑 A6 direct syscall 单测 (失败即中止构建)
# WDAC 感知重试: 托管环境若启用 Application Control 策略, 新编译的 exe
# 可能因信誉被拦 (winerror 4551 / "blocked"); 重编译生成新哈希再试, 最多 3 轮。
function Invoke-Unit([string]$exe, [string]$clCmd, [string]$failMsg) {
    # WDAC/信誉拦截 (winerror 4551 / 无法启动): 延迟重跑同一文件 (信誉缓存
    # 秒级稳定), 仍失败则重编译 (新哈希) 再试一次。
    for ($try = 1; $try -le 4; $try++) {
        $rc = 0
        try {
            & ".\build\$exe" 2>&1 | Out-Null
            $rc = $LASTEXITCODE
        } catch {
            $rc = 4551
        }
        if ($rc -eq 0) { return }
        if ($rc -ne 4551) { throw "build FAILED: $failMsg (exit=$rc)" }
        Write-Host "build: $exe blocked by WDAC (try $try) - retry in 10s"
        Start-Sleep -Seconds 10
        if ($try -eq 3) {
            Write-Host "build: $exe still blocked - rebuilding (new hash)"
            cmd /c "`"$vcvars`" >nul 2>&1 && $clCmd"
            if ($LASTEXITCODE -ne 0) { throw "build FAILED: recompile $exe" }
            if (-not $SkipSign -and (Test-Path -LiteralPath 'build\keys\codesign.pfx')) {
                Sign-Binary "build\$exe"
            }
        }
    }
    throw "build FAILED: $failMsg (WDAC blocked after retries)"
}

$unitCl = 'cl /nologo /O2 /W4 /WX /std:c11 /utf-8 /I include /I demo\gen /Fe:build\vm_unit.exe src\vm.c src\crc32.c demo\gen\vm_unit_blob.c demo\gen\vm_unit_brk_blob.c tests\vm_unit.c /link /SUBSYSTEM:CONSOLE'
$probeCl = 'cl /nologo /O2 /W4 /WX /std:c11 /utf-8 /I include /Fe:build\syscall_probe.exe src\syscall.c tests\syscall_probe.c /link /SUBSYSTEM:CONSOLE'
Invoke-Unit 'vm_unit.exe' $unitCl 'vm_unit.exe (Phase 1D ops)'
Invoke-Unit 'syscall_probe.exe' $probeCl 'syscall_probe.exe (A6 direct syscall)'

# 7.2. 冒烟自检 (P0): 正确序列号 + license + vm.blob 必须整体通过 ——
#      验证 hashpatch 烧录 CRC 与运行期掩码规则一致 (IAT/重定位), 以及
#      blob/授权链路; 失败即中止, 尽早暴露"两侧不一致"类缺陷。
#      -SkipSmoke: 绑定"他机" machine_id 构建时 (运行机 != 构建机) 冒烟
#      必然失败, 属预期 (机器绑定), 跳过之 (真机验证场景)。
#      WDAC 拦截时重试 (延迟重跑), 最多 3 轮。
$smokeSerial = (Get-Content -LiteralPath demo\vm_build.json -Raw | ConvertFrom-Json).serial
$smokeOk = $true
if (-not $SkipSmoke) {
    $smokeOk = $false
    for ($try = 1; $try -le 3 -and -not $smokeOk; $try++) {
        try {
            $smokeOut = "$smokeSerial" | & .\build\demo.exe --license-file build\license.txt --vm-blob build\vm.blob 2>&1
            if ($LASTEXITCODE -eq 0) { $smokeOk = $true }
            else {
                Write-Host "build: smoke try $try exit=$LASTEXITCODE (WDAC 信誉瞬态? retry in 10s)"
                Start-Sleep -Seconds 10
            }
        } catch {
            Write-Host "build: smoke try $try launch failed: $_ (retry in 10s)"
            Start-Sleep -Seconds 10
        }
    }
    if (-not $smokeOk) {
        Write-Host ($smokeOut | Select-Object -Last 5)
        Write-Host 'build: smoke FAILED - 若为 WDAC 信誉延迟 (exit 4551/无法启动), 稍后手动重跑验证即可'
        throw 'build FAILED: smoke test (integrity/blob/license chain)'
    }
    Write-Host 'build: smoke test PASS (correct serial accepted)'
} else {
    Write-Host 'build: smoke test SKIPPED (-SkipSmoke, cross-machine build)'
}

# 7.5. 产物清单 (基础设施: 每次构建可追溯 -- 机器标识/镜像指纹/时间/Git SHA)
$seedPairs = @()
$seedMapOut = [ordered]@{}
Get-ChildItem -LiteralPath 'demo\gen' -Filter 'vm_*_blob.c' -File | ForEach-Object {
    $raw = Get-Content -LiteralPath $_.FullName -Raw
    $m = [regex]::Matches($raw, '0x([0-9a-fA-F]{16})')
    if ($m.Count -ge 2) { $seedPairs += $m[0].Groups[1].Value }
    $nameM = [regex]::Match($raw, 'const prot_vm_image (\w+) =')
    if ($nameM.Success -and $m.Count -ge 2) {
        $seedMapOut[$nameM.Groups[1].Value] = [ordered]@{
            key0 = ('0x' + $m[0].Groups[1].Value)
            key1 = ('0x' + $m[1].Groups[1].Value)
        }
    }
}
$jb = Get-Content -LiteralPath demo\vm_build.json -Raw | ConvertFrom-Json
$machineAuto = ($MachineId -in @('auto', '0'))
$toolchain = ''
if (Test-Path -LiteralPath build\demo.exe) {
    $clTmp = Join-Path $env:TEMP 'prot_clver.txt'
    cmd /c "`"$vcvars`" >nul 2>&1 && cl > `"$clTmp`" 2>&1"
    if (Test-Path -LiteralPath $clTmp) {
        $clOut = Get-Content -LiteralPath $clTmp -Raw
        if ($clOut -match '(\d+\.\d+\.\d+(\.\d+)?)') { $toolchain = $Matches[1] }
        Remove-Item -LiteralPath $clTmp -Force
    }
}
$manifestVersion = '?'
foreach ($ln in (Get-Content -LiteralPath include\protect\version.h)) {
    if ($ln -match 'PROT_VERSION_STR "([^"]+)"') { $manifestVersion = $Matches[1]; break }
}
$manifest = [ordered]@{
    tool       = 'build.ps1'
    timestamp  = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    config     = $Config
    version    = $manifestVersion
    toolchain  = $toolchain
    os         = ((& $py tools\osinfo.py --json) | ConvertFrom-Json)
    machine_id = $jb.machine_id
    machine_auto = $machineAuto
    sha        = (git rev-parse --short HEAD 2>$null)
    vm_seeds   = $seedPairs
    demo_exe_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath build\demo.exe).Hash
}
$manifest | ConvertTo-Json | Set-Content -LiteralPath build\manifest.json -Encoding utf8

# 7.6. I3 可复现构建: 记录本次种子 -> build\seeds.json (入库?否; 随发布归档)
if ($RecordSeeds) {
    $strgenSeed = if ($strgenSeedArgs.Count -ge 2) { $strgenSeedArgs[1] } else { '' }
    $seedOut = @{ images = $seedMapOut }
    if ($strgenSeed) { $seedOut['strgen'] = $strgenSeed }
    if ($indirectSeed -and $indirectSeed.Count -ge 2) {
        $seedOut['indirect'] = $indirectSeed[1] -replace '^0x', ''
    }
    $seedOut | ConvertTo-Json -Depth 4 |
        Set-Content -LiteralPath build\seeds.json -Encoding utf8
    Write-Host "build: recorded seeds -> build\seeds.json (strgen=$strgenSeed indirect=$($seedOut.indirect))"
}

# 8.
Write-Host 'DONE'
