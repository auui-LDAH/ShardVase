# build.ps1 — 一键构建 (Lane D)
# 按 docs/CONTRACT.md §10 管线执行:
#   genserial -> assemble -> strgen -> cl -> hashpatch
# 每步失败即中止并打印明确错误。
$ErrorActionPreference = 'Stop'

# 锚定到脚本所在目录 (仓库根), 保证相对路径可靠
Set-Location -LiteralPath (Split-Path -Parent $MyInvocation.MyCommand.Path)

$vcvars = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
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

# 2. 重算期望常量 (serial/machine_id 保留, expect1/expect2 每次构建重算)
python tools\vmenc.py genserial --json demo\vm_build.json
if ($LASTEXITCODE -ne 0) { throw 'build FAILED: vmenc.py genserial' }

# 3. 汇编 + 加密 VM 镜像 (ROADMAP Phase 2a: 一个校验逻辑拆成 3 个独立小 VM,
#    各自独立密钥/置换/窗口: FNV 哈希 -> GOLDEN 混合 -> 期望值校验)
python tools\vmenc.py assemble demo\license_hash.vasm demo\vm_build.json demo\gen\vm_hash_blob.c demo\gen\vm_hash_blob.h --name g_vm_hash_image
if ($LASTEXITCODE -ne 0) { throw 'build FAILED: vmenc.py assemble (hash)' }

python tools\vmenc.py assemble demo\license_mix.vasm demo\vm_build.json demo\gen\vm_mix_blob.c demo\gen\vm_mix_blob.h --name g_vm_mix_image
if ($LASTEXITCODE -ne 0) { throw 'build FAILED: vmenc.py assemble (mix)' }

python tools\vmenc.py assemble demo\license_verify.vasm demo\vm_build.json demo\gen\vm_verify_blob.c demo\gen\vm_verify_blob.h --name g_vm_verify_image
if ($LASTEXITCODE -ne 0) { throw 'build FAILED: vmenc.py assemble (verify)' }

# 3b. 汇编 VM 指令集单测镜像 (ROADMAP Phase 1d, 每个新指令都要有测试用例)
python tools\vmenc.py assemble tests\unit_vm.vasm demo\vm_build.json demo\gen\vm_unit_blob.c demo\gen\vm_unit_blob.h --name g_vm_unit_image
if ($LASTEXITCODE -ne 0) { throw 'build FAILED: vmenc.py assemble (unit_vm)' }

# 4. 字符串加密
python tools\strgen.py demo\strings.txt demo\gen\strings.c
if ($LASTEXITCODE -ne 0) { throw 'build FAILED: strgen.py' }

# 5. 编译 + 链接 (vcvars64 环境; cl 失败即中止)
cmd /c "`"$vcvars`" >nul 2>&1 && cl /nologo /O2 /W4 /WX /std:c11 /utf-8 /I include /I demo\gen /Fe:build\demo.exe src\vm.c src\crc32.c src\antidebug.c src\integrity.c src\strcrypt.c src\hostid.c demo\main.c demo\gen\strings.c demo\gen\vm_hash_blob.c demo\gen\vm_mix_blob.c demo\gen\vm_verify_blob.c /link /SUBSYSTEM:CONSOLE"
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

# 8.
Write-Host 'DONE'
