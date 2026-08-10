# build.ps1 — 一键构建 (Lane D)
# 按 docs/CONTRACT.md §10 管线执行:
#   genserial -> assemble -> strgen -> cl -> hashpatch
# 每步失败即中止并打印明确错误。
#
# 参数:
#   -MachineId <值>   覆盖 machine_id (十进制/0x16进制/"0"/"auto"); 默认 auto=绑定本机
#   -Config <Release> 保留扩展位 (当前仅 Release)
#   -VcVars <路径>    显式指定 vcvars64.bat; 缺省自动探测 (vswhere/MSVC 常见路径)
# 输出: build\demo.exe / build\vm_unit.exe / build\manifest.json (产物清单)
param(
    [string]$MachineId = 'auto',
    [string]$Config = 'Release',
    [string]$VcVars = ''
)
$ErrorActionPreference = 'Stop'

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
        'C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
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
python tools\vmenc.py genserial --json demo\vm_build.json --machine-id "$MachineId"
if ($LASTEXITCODE -ne 0) { throw 'build FAILED: vmenc.py genserial' }

# 2.5. RSA 授权 (A1): 生成/复用私钥 (build\keys, gitignore, 不入库) 并导出公钥 blob;
#     对该 json 的 serial/machine_id 签发 -> build\license.txt (供下发与测试用)
python tools\vmenc.py keygen --key-out "build\keys\license_priv.json" --blob-out "demo\gen\license_pubkey.c"
if ($LASTEXITCODE -ne 0) { throw 'build FAILED: vmenc.py keygen' }
python tools\vmenc.py sign --key "build\keys\license_priv.json" --json demo\vm_build.json --out "build\license.txt" --print
if ($LASTEXITCODE -ne 0) { throw 'build FAILED: vmenc.py sign' }

# 3. 汇编 + 加密 VM 镜像 (ROADMAP Phase 2a: 一个校验逻辑拆成 3 个独立小 VM,
#    各自独立密钥/置换/窗口: FNV 哈希 -> GOLDEN 混合 -> 期望值校验)
python tools\vmenc.py assemble demo\license_hash.vasm demo\vm_build.json demo\gen\vm_hash_blob.c demo\gen\vm_hash_blob.h --name g_vm_hash_image
if ($LASTEXITCODE -ne 0) { throw 'build FAILED: vmenc.py assemble (hash)' }

python tools\vmenc.py assemble demo\license_mix.vasm demo\vm_build.json demo\gen\vm_mix_blob.c demo\gen\vm_mix_blob.h --name g_vm_mix_image
if ($LASTEXITCODE -ne 0) { throw 'build FAILED: vmenc.py assemble (mix)' }

python tools\vmenc.py assemble demo\license_verify.vasm demo\vm_build.json demo\gen\vm_verify_blob.c demo\gen\vm_verify_blob.h --name g_vm_verify_image
if ($LASTEXITCODE -ne 0) { throw 'build FAILED: vmenc.py assemble (verify)' }

python tools\vmenc.py assemble demo\license_gate.vasm demo\vm_build.json demo\gen\vm_gate_blob.c demo\gen\vm_gate_blob.h --name g_vm_gate_image
if ($LASTEXITCODE -ne 0) { throw 'build FAILED: vmenc.py assemble (gate)' }

# 3b. 汇编 VM 指令集单测镜像 (ROADMAP Phase 1d, 每个新指令都要有测试用例)
python tools\vmenc.py assemble tests\unit_vm.vasm demo\vm_build.json demo\gen\vm_unit_blob.c demo\gen\vm_unit_blob.h --name g_vm_unit_image
if ($LASTEXITCODE -ne 0) { throw 'build FAILED: vmenc.py assemble (unit_vm)' }

# 4. 字符串加密
python tools\strgen.py demo\strings.txt demo\gen\strings.c
if ($LASTEXITCODE -ne 0) { throw 'build FAILED: strgen.py' }

# 5. 编译 + 链接 (vcvars64 环境; cl 失败即中止)
cmd /c "`"$vcvars`" >nul 2>&1 && cl /nologo /O2 /W4 /WX /std:c11 /utf-8 /I include /I demo\gen /Fe:build\demo.exe src\vm.c src\crc32.c src\antidebug.c src\integrity.c src\strcrypt.c src\hostid.c src\license.c demo\main.c demo\gen\strings.c demo\gen\vm_hash_blob.c demo\gen\vm_mix_blob.c demo\gen\vm_verify_blob.c demo\gen\vm_gate_blob.c demo\gen\license_pubkey.c /link /SUBSYSTEM:CONSOLE bcrypt.lib"
if ($LASTEXITCODE -ne 0) { throw 'build FAILED: cl' }

# 5b. 编译并运行 VM 指令集单测
cmd /c "`"$vcvars`" >nul 2>&1 && cl /nologo /O2 /W4 /WX /std:c11 /utf-8 /I include /I demo\gen /Fe:build\vm_unit.exe src\vm.c src\crc32.c demo\gen\vm_unit_blob.c tests\vm_unit.c /link /SUBSYSTEM:CONSOLE"
if ($LASTEXITCODE -ne 0) { throw 'build FAILED: cl (vm_unit)' }

# 6. 烧录 .text CRC32 到二进制 (integrity 自检依赖)
python tools\hashpatch.py build\demo.exe
if ($LASTEXITCODE -ne 0) { throw 'build FAILED: hashpatch.py' }

# 6.5 清理 cl 留在仓库根目录的中间 .obj (cl 默认把 obj 输出到 cwd)
Get-ChildItem -LiteralPath . -Filter *.obj -File | Remove-Item -Force

# 7. 跑 VM 指令集单测 (失败即中止构建)
& .\build\vm_unit.exe
if ($LASTEXITCODE -ne 0) { throw 'build FAILED: vm_unit.exe (Phase 1D ops)' }

# 7.5. 产物清单 (基础设施: 每次构建可追溯 -- 机器标识/镜像指纹/时间/Git SHA)
$seeds = @()
Get-ChildItem -LiteralPath 'demo\gen' -Filter 'vm_*_blob.c' -File | ForEach-Object {
    $raw = Get-Content -LiteralPath $_.FullName -Raw
    $m = [regex]::Matches($raw, '0x([0-9a-fA-F]{16})')
    if ($m.Count -gt 0) { $seeds += $m[0].Groups[1].Value }
}
$jb = Get-Content -LiteralPath demo\vm_build.json -Raw | ConvertFrom-Json
$machineAuto = ($MachineId -in @('auto', '0'))
$manifest = [ordered]@{
    tool       = 'build.ps1'
    timestamp  = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    config     = $Config
    machine_id = $jb.machine_id
    machine_auto = $machineAuto
    sha        = (git rev-parse --short HEAD 2>$null)
    vm_seeds   = $seeds
    demo_exe_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath build\demo.exe).Hash
}
$manifest | ConvertTo-Json | Set-Content -LiteralPath build\manifest.json -Encoding utf8

# 8.
Write-Host 'DONE'
