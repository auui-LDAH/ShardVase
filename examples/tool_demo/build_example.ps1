# build_example.ps1 — 接入示例构建 (examples/tool_demo)
#
# 展示"你的工具"如何接入保护套件:
#   1. genserial: 为该工具生成序列号/机器标识/期望值 (demo\vm_build.json 复用,
#      生产应每工具独立 json)
#   2. assemble: check.vasm -> 加密 VM 镜像 (.c/.h + .bin)
#   3. pack:     单镜像 -> vm.blob (exe 内无 VM 逻辑, 断源)
#   4. cl:       工具源码 + 保护库 (src/*.c) 链接
#   5. hashpatch: 烧录三节 CRC (防篡改)
#   6. 冒烟:     正确序列号必须通过
#
# 用法:
#   powershell -ExecutionPolicy Bypass -File build_example.ps1 [-MachineId <v>] [-VcVars <path>] [-Python <path>]
param(
    [string]$MachineId = 'auto',
    [string]$VcVars = '',
    [string]$Python = ''
)
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location ..\..

function Find-VcVars {
    param([string]$Explicit)
    if ($Explicit) {
        if (-not (Test-Path -LiteralPath $Explicit)) { throw "vcvars not found: $Explicit" }
        return $Explicit
    }
    $candidates = @(
        'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat',
        'C:\Program Files (x86)\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat',
        'D:\environment\VS2022BuildTools\VC\Auxiliary\Build\vcvars64.bat'
    )
    foreach ($c in $candidates) { if (Test-Path -LiteralPath $c) { return $c } }
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
    throw 'cannot locate vcvars64.bat'
}
function Find-Python {
    param([string]$Explicit)
    if ($Explicit) {
        if (-not (Test-Path -LiteralPath $Explicit)) { throw "python not found: $Explicit" }
        return $Explicit
    }
    $cand = @(Get-Command python -ErrorAction SilentlyContinue | Where-Object {
        $_.Source -notlike '*\WindowsApps\*' } | Select-Object -First 1)
    if ($cand) { return $cand.Source }
    foreach ($p in @('D:\environment\PYTHON\python.exe', "$env:LOCALAPPDATA\Programs\Python\Python313\python.exe")) {
        if (Test-Path -LiteralPath $p) { return $p }
    }
    throw 'cannot locate python'
}
$vcvars = Find-VcVars -Explicit $VcVars
$py = Find-Python -Explicit $Python
Write-Host "example: vcvars=$vcvars python=$py"

if (-not (Test-Path -LiteralPath 'demo\gen')) { New-Item -ItemType Directory -Path 'demo\gen' | Out-Null }
if (-not (Test-Path -LiteralPath 'build')) { New-Item -ItemType Directory -Path 'build' | Out-Null }

# 1. 期望值 (示例复用 demo\vm_build.json 的 serial; 生产每工具独立)
& $py tools\vmenc.py genserial --json demo\vm_build.json --machine-id "$MachineId"
if ($LASTEXITCODE -ne 0) { throw 'example FAILED: genserial' }

# 1b. RSA 公钥 (license 验签; 私钥只在 build\keys, 不入库)
& $py tools\vmenc.py keygen --key-out build\keys\license_priv.json --blob-out demo\gen\license_pubkey.c
if ($LASTEXITCODE -ne 0) { throw 'example FAILED: keygen' }

# 2. 汇编 check.vmc -> check.vasm (M2: 类 C 源码自动编译)
& $py tools\vmc.py examples\tool_demo\check.vmc examples\tool_demo\check.vasm build\tool_check.layout.json
if ($LASTEXITCODE -ne 0) { throw 'example FAILED: vmc' }

# 2b. assemble check.vasm -> 镜像
& $py tools\vmenc.py assemble examples\tool_demo\check.vasm demo\vm_build.json demo\gen\tool_check_blob.c demo\gen\tool_check_blob.h --name g_tool_check_image --bin-out demo\gen\tool_check_blob.bin --bin-name check
if ($LASTEXITCODE -ne 0) { throw 'example FAILED: assemble' }

# 3. 打包 vm.blob (断源; BLOB_SIGN: --sign v1, 装载器强制 v1)
& $py tools\vmenc.py pack --sign build\keys\license_priv.json --out build\tool_vm.blob demo\gen\tool_check_blob.bin
if ($LASTEXITCODE -ne 0) { throw 'example FAILED: pack' }

# 4. 编译 + 链接 (工具源码 + 保护库)
#
# L2（2026-09-23）: 加入平台层两个源文件。
#
# **为什么必须加**: `src/license.c` 的密码学已抽到
#   `src/platform/prot_crypto_win.c`（L2 解耦）——
#   本脚本的源文件列表是**硬编码**的，若不加入则会:
#     `LNK2019: 无法解析的外部符号 prot_crypto_rsa_verify_sha256`
#   这正是门禁 `example E1-E7` **抓到**的（L1 时我漏检了这条路径）。
#
# **教训**: 硬编码源文件列表有**三处**（build.ps1 / build_skeleton.ps1 /
#   build_example.ps1）—— 新增平台层必须**三处同改**。
#   （同类问题在本项目已出现多次: SOURCE_ORDER 硬编码、INFRA_HEADERS 白名单。）
cmd /c "`"$vcvars`" >nul 2>&1 && cl /nologo /O2 /W4 /WX /std:c11 /utf-8 /I include /Fe:build\tool_demo.exe src\vm.c src\crc32.c src\antidebug.c src\integrity.c src\hostid.c src\license.c src\blob.c src\revoke.c src\syscall.c src\selfcrypt.c src\platform\prot_platform_win.c src\platform\prot_crypto_win.c examples\tool_demo\main.c demo\gen\license_pubkey.c /link /SUBSYSTEM:CONSOLE bcrypt.lib winhttp.lib advapi32.lib"
if ($LASTEXITCODE -ne 0) { throw 'example FAILED: cl' }
# 清理 cl 留在 cwd 的 .obj。注意 "nul.obj": 'nul' 是 Windows 保留设备名,
# Get-ChildItem 会列出它但 Remove-Item 无法删除 (报 PathNotFound 刷屏)。
# 用 -ErrorAction SilentlyContinue 容忍; 不影响判定。
Get-ChildItem -LiteralPath . -Filter *.obj -File -ErrorAction SilentlyContinue |
    Remove-Item -Force -ErrorAction SilentlyContinue

# 5. 烧录完整性 CRC
& $py tools\hashpatch.py build\tool_demo.exe
if ($LASTEXITCODE -ne 0) { throw 'example FAILED: hashpatch' }

# 6. 冒烟: 正确序列号 + license 必须通过 (跳过 = 跨机构建时)
$serial = (Get-Content -LiteralPath demo\vm_build.json -Raw | ConvertFrom-Json).serial
if ($MachineId -in @('auto', '0')) {
    # 为示例签发 license (本机构建 -> 本机绑定)
    & $py tools\vmenc.py sign --key build\keys\license_priv.json --json demo\vm_build.json --out build\license.txt
    if ($LASTEXITCODE -ne 0) { throw 'example FAILED: sign' }
    Set-Content -LiteralPath build\smoke.txt -Value 'hello protected tool' -Encoding ascii
    & build\tool_demo.exe --serial $serial --license-file build\license.txt --vm-blob build\tool_vm.blob --encrypt build\smoke.txt 2>&1 | Select-Object -Last 3
    if ($LASTEXITCODE -ne 0) { throw 'example FAILED: smoke' }
    & build\tool_demo.exe --serial $serial --license-file build\license.txt --vm-blob build\tool_vm.blob --decrypt build\smoke.txt 2>&1 | Select-Object -Last 2
    if ($LASTEXITCODE -ne 0) { throw 'example FAILED: smoke decrypt' }
} else {
    Write-Host "example: smoke skipped (cross-machine build)"
}
Write-Host 'example: DONE - build\tool_demo.exe + build\tool_vm.blob'
