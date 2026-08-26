# tools/clean_build.ps1 — 清理构建/演练产物 (INFRA_PLAN I5)
#
# 删除 build/drill*, verify-artifacts, 测试临时物; **保留 build\keys** (私钥).
# 用法:
#   powershell -ExecutionPolicy Bypass -File tools\clean_build.ps1 [-AlsoBuild]
#     -AlsoBuild: 一并删除 build\demo.exe 等产物 (全清)
[cmdletbinding()]
param([switch]$AlsoBuild)

$ErrorActionPreference = 'Continue'
$MyDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath (Join-Path $MyDir '..')
$Root = (Get-Location).Path

$targets = @(
    'build\drill', 'build\drill2', 'build\drill3', 'build\drill4', 'build\drill5',
    'verify-artifacts'
)
foreach ($t in $targets) {
    if (Test-Path -LiteralPath $t) {
        Remove-Item -LiteralPath $t -Recurse -Force
        Write-Host "[clean] removed $t"
    }
}

# 根目录 .obj/.pyc 残留
Get-ChildItem -LiteralPath . -Filter '*.obj' -File -ErrorAction SilentlyContinue | Remove-Item -Force
Get-ChildItem -LiteralPath . -Recurse -Directory -Filter '__pycache__' -ErrorAction SilentlyContinue |
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

if ($AlsoBuild) {
    foreach ($f in @('build\demo.exe','build\vm_unit.exe','build\syscall_probe.exe',
                     'build\vm.blob','build\license.txt','build\manifest.json',
                     'build\seeds.json','build\revoke.blob','build\vm_blob_dl.tmp')) {
        if (Test-Path -LiteralPath $f) {
            Remove-Item -LiteralPath $f -Force
            Write-Host "[clean] removed $f"
        }
    }
}

Write-Host "[clean] done (build\keys 保留: 私钥不删) "
Write-Host '[clean] 注意: -AlsoBuild 会删产物, 随后需 build.ps1 重新构建'