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
#   -D2b              N1 调用级解密 (D2b) — PROT_SELFCRYPT_D2B
#   -Drill            演练钩子 (ATTACK framework) — PROT_DRILL_HOOK
#   -Help             打印本帮助 (INFRA_PLAN I4)
# 输出: build\demo.exe / build\vm_unit.exe / build\manifest.json (产物清单)
param(
    [string]$MachineId = 'auto',
    [string]$Config = 'Dev',
    [string]$VcVars = '',
    [string]$Python = '',
    [string]$SeedsFile = '',
    [switch]$RecordSeeds,
    [switch]$SkipSign,
    [switch]$SkipSmoke,
    [switch]$D2b,
    [switch]$Drill,
    [switch]$NoD2b,
    [string]$ExtraSelfCrypt = '',  # S1 排障: 追加加密函数名 (逗号分隔)
    [switch]$ScDebug,              # selfcrypt 解密期诊断日志 (默认关闭)
    [string]$Composition = '',     # 阶段2: 拼装图名 (compositions/<name>.json)
    [switch]$NoPad,                # 阶段2: 关闭节填充（默认开启）
    # W4(每用户唯一): 用户标识 —— 传入后**全部种子由该用户派生**,
    # 使同一策略的两个用户产出**互不相同**的二进制。
    # 未传时行为与改动前完全一致（每构建随机）。
    # 优先级: -SeedsFile > -UserId > 系统随机。
    [string]$UserId = '',
    [switch]$Help
)
# 阶段1/3: 节名与 magic 的随机种子。
#
# **两个方向都要满足**:
#   · 未提供 -SeedsFile -> **系统随机**（发布必须随机，否则攻击者只需破一次）
#   · 提供了 -SeedsFile -> **确定性派生**（满足 I3 可复现构建）
#
# 教训（2026-09-23 实测）: 初版把本变量恒置为 ''，导致传 -SeedsFile 时
# 节名仍每次不同，**破坏了项目的 I3 可复现属性**（repro_check 用的正是这条
# 路径，却没有比对节名，故一度漏检）。
$sectionsSeed = ''

# W1.6(序言噪声): 构建盐 —— 让保护函数的**机器码**随构建变化，
# 从而破坏攻击者的"字节特征跨构建匹配"（W5.6 实测 55.9% 可匹配）。
# 允许外部（-BuildSalt 或环境变量）覆盖，否则由种子派生。
$buildSalt = if ($env:PROT_BUILD_SALT) { $env:PROT_BUILD_SALT } else { '' }
if ($SeedsFile -and (Test-Path -LiteralPath $SeedsFile)) {
    # 由种子表内容派生一个稳定种子（同表 -> 同节名；不同表 -> 不同节名）
    $seedHash = (Get-FileHash -LiteralPath $SeedsFile -Algorithm SHA256).Hash
    $sectionsSeed = '0x' + $seedHash.Substring(0, 16).ToLower()
}

# W4: 用户种子派生（**优先于**系统随机，但**低于** -SeedsFile）
#
# 派生链（见 tools/identity.py）:
#   user_seed = HKDF(master, project, version, user_id)
#     [0:8]   -> sectionsSeed（节名/magic）
#     [8:12]  -> buildSalt（序言噪声）
#     [12:20] -> strgen seed（字符串加密）
#     [20:28] -> indirect seed（间接表置换）
#
# 用**分段**而非逐维再派生: 简单、确定性、各段独立（便于单独重派生）。
#
# 优先级: -SeedsFile > -UserId > 系统随机
#
# ⚠️ 注意: 本段的**用户种子派生**必须放在 `$py` 定义之后（见下方
# "identity 派生延后" 标记）—— 初版写在文件开头，而 `$py` 在
# "python 探测" 段才定义 -> 运行时 `$py` 为空（2026-09-23 实测修正）。
$userSeed = ''
$userStrgenSeed = ''
$userIndirectSeed = ''
$userIdPending = $UserId      # 延后到 $py 可用时再派生

# W1.6: 构建盐的派生（在种子确定之后）
#
# · 有确定性种子 -> 由它派生（保持 I3 可复现）
# · 无种子（发布构建）-> **系统随机**（每构建必须不同）
#
# 注: 用种子的**不同片段**派生，避免与节名种子撞用同一值。
if (-not $buildSalt) {
    if ($sectionsSeed -and $sectionsSeed.Length -ge 10) {
        $buildSalt = '0x' + $sectionsSeed.Substring(2, 8)
    } else {
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $buf = New-Object byte[] 4
        $rng.GetBytes($buf)
        $rng.Dispose()
        $buildSalt = '0x' + (($buf | ForEach-Object { $_.ToString('x2') }) -join '')
    }
}
Write-Host ("build: 构建盐 {0}（序言噪声用）" -f $buildSalt)


$ErrorActionPreference = 'Stop'

# I4: --help / 参数校验
if ($Help) {
    Write-Host @'
用法: powershell -ExecutionPolicy Bypass -File build.ps1 [选项]

选项:
  -MachineId <值>   machine_id (十进制/0x16进制/"0"/"auto"); 默认 auto=绑定本机
  -Config <Type>    Release|Dev (Release: 发行加固/签名/可复现)
  -VcVars <path>    vcvars64.bat 路径 (缺省自动探测)
  -Python <path>    python.exe 路径 (缺省自动探测)
  -SeedsFile <json> 确定性种子表 (I3 可复现)
  -RecordSeeds      记录本次种子到 build\seeds.json
  -SkipSign         跳过数字签名
  -SkipSmoke        跳过构建期冒烟测试 (跨机绑定构建用)
  -D2b              N1 调用级解密 (D2b) — Release 默认开启 (WIN_ENHANCE W1)
  -NoD2b            显式关闭 D2b (回退 D2a; 杀软敏感/调试环境用)
  -Drill            演练钩子 (PROT_DRILL_HOOK, 测试构建)
  -ScDebug          selfcrypt 解密期诊断日志 (默认关闭; 会泄漏 RVA/密钥/CRC)
  -Composition <名> 按拼装图构建 (compositions/<名>.json); 默认 full 全模块
                    可选: full / standard / hardened / minimal
  -Help             打印本帮助

输出: build\demo.exe / build\vm_unit.exe / build\syscall_probe.exe /
      build\manifest.json (产物清单)
'@
    exit 0
}
if ($Config -notin @('Dev', 'Release')) {
    Write-Host "build FAILED: -Config must be Dev or Release (got $Config)" -ForegroundColor Red
    exit 2
}
if ($SeedsFile -and -not (Test-Path -LiteralPath $SeedsFile)) {
    Write-Host "build FAILED: -SeedsFile not found: $SeedsFile" -ForegroundColor Red
    exit 2
}
if ($MachineId -and $MachineId -notmatch '^(auto|0|[0-9]+|0x[0-9a-fA-F]+)$') {
    Write-Host "build FAILED: -MachineId invalid: $MachineId (expect auto|0|decimal|0xhex)" -ForegroundColor Red
    exit 2
}
$isRelease = ($Config -eq 'Release')
# W1 (WIN_ENHANCE): Release 默认 D2b (运行期间隙密文, 缩明文窗口);
# Dev 默认 D2a (调试平坦). -NoD2b / -D2b 显式覆盖.
$scDef = if ($D2b -or (-not $NoD2b -and $isRelease)) { ' /DPROT_SELFCRYPT_D2B' } else { '' }
if ($Drill) { $scDef += ' /DPROT_DRILL_HOOK' }
# W4 (WIN_ENHANCE): Release 收敛内部错误输出 (隐藏 prot_status 码)
if ($isRelease) { $scDef += ' /DPROT_RELEASE_CONCEAL' }
# 2026-09-20: selfcrypt 解密期诊断日志 (RVA/密钥/明文CRC) 改为**显式 opt-in**。
# 默认不定义 -> 宏展开为空, 字符串不进入产物 (Dev/Release 皆然)。
# 排障时显式 -ScDebug 打开; 注意打开会改变布局, 需重建 mask/CRC (管线已自动)。
if ($ScDebug) { $scDef += ' /DPROT_SELFCRYPT_DEBUG' }

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
    # W4: 未提供 -SeedsFile 但有用户种子时，由**用户种子**为该镜像派生确定性
    # 密钥/置换 -> 同用户可复现、跨用户唯一。
    #
    # ⚠️ 修正（2026-09-23 实测）: 初版**完全没接** blob 的种子 ->
    #    `build/vm.blob` 每次都不同 -> 同 UserId 两次构建**不可复现**
    #    （实测: blob sha 不同，而 strings.c/sec.json 相同 —— 精确定位到此）。
    #
    # 派生方式: HMAC(user_seed, image_name) -> 32 字节 ->
    #   key0 = 前 16 hex, key1 = 后 16 hex
    # 用镜像名做 info -> 各镜像**独立**（一个泄露不影响其它）。
    if ($userSeed) {
        $hmac = [System.Security.Cryptography.HMACSHA256]::new(
            [System.Text.Encoding]::UTF8.GetBytes($userSeed))
        $h = $hmac.ComputeHash(
            [System.Text.Encoding]::UTF8.GetBytes("shardvase-image|$name"))
        $hmac.Dispose()
        $hx = ($h | ForEach-Object { $_.ToString('x2') }) -join ''
        return @('--seed', ('0x' + $hx.Substring(0, 16)),
                 '--perm-seed', ('0x' + $hx.Substring(16, 16)))
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

# W4: 用户种子派生（**在 $py 可用之后**执行）
#
# 为什么在此处而非文件开头: `$py` 由上面的 Find-Python 定义；
# 初版把它放在文件开头 -> `$py` 为空 -> 派生静默失败
# （实测: 两个用户的产物 SHA 完全相同，才暴露此问题）。
if ($userIdPending -and -not $SeedsFile) {
    $idOut = & $py tools\identity.py --project 'shardvase-demo' --version '1' --user $userIdPending 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "build FAILED: identity.py (UserId=$userIdPending) -> $idOut"
    }
    $userSeed = ($idOut | Where-Object { $_ -match '^0x[0-9a-f]{64}$' } |
                 Select-Object -First 1)
    if (-not $userSeed) {
        throw "build FAILED: identity.py 未返回种子 (输出: $idOut)"
    }
    $hex = $userSeed.Substring(2)
    $sectionsSeed = '0x' + $hex.Substring(0, 16)
    $buildSalt = '0x' + $hex.Substring(16, 8)
    $userStrgenSeed = '0x' + $hex.Substring(24, 16)
    $userIndirectSeed = '0x' + $hex.Substring(40, 16)
    Write-Host ("build: 用户 [{0}] 种子派生完成 (sections={1} salt={2})" -f `
                $userIdPending, $sectionsSeed, $buildSalt)
}


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
#     启动时由 launcher 装载 build\vm.blob (缺失/损坏 -> 0xB10B)。
#     BLOB_SIGN_PLAN: --sign 用 A1 私钥签 v1 blob (防伪造)
& $py tools\vmenc.py pack --sign "build\keys\license_priv.json" --out build\vm.blob demo\gen\vm_hash_blob.bin demo\gen\vm_mix_blob.bin demo\gen\vm_verify_blob.bin demo\gen\vm_gate_blob.bin
if ($LASTEXITCODE -ne 0) { throw 'build FAILED: vmenc.py pack' }

# 3b. 汇编 VM 指令集单测镜像 (ROADMAP Phase 1d, 每个新指令都要有测试用例)
& $py tools\vmenc.py assemble tests\unit_vm.vasm demo\vm_build.json demo\gen\vm_unit_blob.c demo\gen\vm_unit_blob.h --name g_vm_unit_image $(Get-SeedArgs 'g_vm_unit_image')
if ($LASTEXITCODE -ne 0) { throw 'build FAILED: vmenc.py assemble (unit_vm)' }

& $py tools\vmenc.py assemble tests\unit_vm_brk.vasm demo\vm_build.json demo\gen\vm_unit_brk_blob.c demo\gen\vm_unit_brk_blob.h --name g_vm_unit_brk_image $(Get-SeedArgs 'g_vm_unit_brk_image')
if ($LASTEXITCODE -ne 0) { throw 'build FAILED: vmenc.py assemble (unit_vm_brk)' }

# 4. 字符串加密 (I3: -SeedsFile 注入确定性密钥种子; -RecordSeeds 先定种子再构建)
if ($userStrgenSeed -and $strgenSeedArgs.Count -eq 0) {
    # W4: 用户种子优先（覆盖系统随机）
    $strgenSeedArgs = @('--seed', $userStrgenSeed)
}
if ($RecordSeeds -and $strgenSeedArgs.Count -eq 0) {
    $seedHex = -join (1..16 | ForEach-Object { '{0:x1}' -f (Get-Random -Max 16) })
    $strgenSeedArgs = @('--seed', ('0x' + $seedHex))
}
& $py tools\strgen.py demo\strings.txt demo\gen\strings.c $strgenSeedArgs
if ($LASTEXITCODE -ne 0) { throw 'build FAILED: strgen.py' }

# ---- 阶段1(第二支柱): 生成随机节名与 magic ----
# 目的: 消除产物中的自解释名字（.protcrc / PROTCRCP 等）——
#       攻击者看到节名即知"这里是完整性校验"，故每构建随机。
# 实测: PE 节名上限 8 字节（源码写 .protcrypt(10) 会被截断为 .protcry），
#       故生成器产 "." + 7 字符 = 8，正好合规。
# 注意: 必须在**编译之前**执行（src/*.c 会 #include "prot_sections.h"）。
# 注意: 本脚本**没有** $REPO 变量 —— 它假定从仓库根运行，全部用相对路径
# （与 strgen.py / indirect.py / compose.py 的调用写法一致）。
$sectionsJson = 'demo\gen\prot_sections.json'
$secArgs = @()
if ($sectionsSeed) { $secArgs = @('--seed', $sectionsSeed) }
& $py tools\gen_sections.py --out-dir demo\gen @secArgs
if ($LASTEXITCODE -ne 0) { throw 'build FAILED: gen_sections.py' }

# 4c. N4 函数级间接化: 生成槽位随机化函数指针表
#     (I3: -SeedsFile 注入确定性种子; -RecordSeeds 先定种子再构建)
#
# W4: 用户种子优先于系统随机（但低于 -SeedsFile）
# ⚠️ 修正（2026-09-23 实测）: 初版把用户种子分支错误地嵌进了
#    `if ($RecordSeeds ...)` 块内部 -> **未传 -RecordSeeds 时用户种子不生效**
#    -> 同 UserId 两次构建的 indirect_table.c **不同**（不可复现）。
if (-not $indirectSeed -and $userIndirectSeed) {
    $indirectSeed = @('--seed', $userIndirectSeed)   # W4 用户种子
}
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
#
#    阶段 2 (组合驱动): -Composition <名> 时由 tools/compose.py 决定
#      (a) 生成 demo\gen\prot_modconfig.h (宿主条件编译依据)
#      (b) 输出本次参与编译的 src/*.c 清单
#    未指定时 default = "full" (等价于改造前的全模块硬编码构建)。
$linkHard = if ($isRelease) { ' /DEBUG:NONE /OPT:REF /OPT:ICF /Brepro' } else { '' }
$resObj = if ($isRelease) { ' demo\gen\version.res' } else { '' }

$compName = if ($Composition) { $Composition } else { 'full' }
$compSrcList = 'build\_composition_srcs.txt'
& $py tools\compose.py $compName --header-out demo\gen\prot_modconfig.h --sources-out $compSrcList
if ($LASTEXITCODE -ne 0) { throw "build FAILED: compose.py ($compName)" }
$compSrcs = @(Get-Content -LiteralPath $compSrcList | Where-Object { $_.Trim() } |
              ForEach-Object { $_.Trim() -replace '/', '\' })
if ($compSrcs.Count -eq 0) { throw "build FAILED: composition '$compName' 无源文件" }
$compSrcJoined = ($compSrcs -join ' ')
Write-Host ("build: composition '{0}' — {1} 源文件" -f $compName, $compSrcs.Count)

# 阶段1(第二支柱): -DPROT_USE_GENERATED_SECTIONS 让 include/protect/
# prot_sections.h 采用 demo\gen 下的**随机节名**（覆盖其默认值）。
# 不定义该宏的独立构建（skeleton/examples/tests）沿用默认节名，不受影响。
cmd /c "`"$vcvars`" >nul 2>&1 && cl /nologo /O2 /W4 /WX /std:c11 /utf-8 /I include /I demo\gen /DPROT_USE_GENERATED_SECTIONS=1 /DPROT_BUILD_SALT=$buildSalt$scDef$resObj /Fe:build\demo.exe $compSrcJoined demo\main.c demo\gen\strings.c demo\gen\license_pubkey.c demo\gen\indirect_table.c demo\gen\expect_default.c /link /SUBSYSTEM:CONSOLE bcrypt.lib winhttp.lib advapi32.lib user32.lib /MAP:build\demo.map$linkHard"
if ($LASTEXITCODE -ne 0) { throw 'build FAILED: cl' }

# 5b. 编译并运行 VM 指令集单测
#
# ## L6b（2026-09-25）: 加入平台层源文件
#   L6b 把 `vm.c` 的平台相关部分改走平台层（`prot_plat_monotonic_ns`）
#   -> 本行**硬编码的源文件列表**缺平台层 ->
#     `LNK2019: 无法解析的外部符号 prot_plat_monotonic_ns`
#
#   **为什么 L3 没抓到**: L3 修了 `build_example.ps1`，
#   而 S1 检查只扫**独立 *.ps1 文件**，**没扫 build.ps1 内部的字符串**。
#
#   **注意**: 本文件里 vm_unit 的编译命令**出现两次**（L437 是本行，
#   另一处在 §7 附近，为 Invoke-Unit 版本）。两处都需同步。
# S1-ALLOW: 单元测试**刻意只链接被测模块**（vm.c + crc32 + 平台层）——用完整组合会让"单元测试"变成"整套构建测试"，丧失定位能力。
#   平台层为必需: vm.c 的熵源已改走 prot_plat_monotonic_ns（L6b）。
cmd /c "`"$vcvars`" >nul 2>&1 && cl /nologo /O2 /W4 /WX /std:c11 /utf-8 /I include /I demo\gen /Fe:build\vm_unit.exe src\vm.c src\crc32.c src\platform\prot_platform_win.c demo\gen\vm_unit_blob.c demo\gen\vm_unit_brk_blob.c tests\vm_unit.c /link /SUBSYSTEM:CONSOLE advapi32.lib"
if ($LASTEXITCODE -ne 0) { throw 'build FAILED: cl (vm_unit)' }

# 5c. 编译 A6 direct syscall 单测 (直调结果须与 API 路径一致)
cmd /c "`"$vcvars`" >nul 2>&1 && cl /nologo /O2 /W4 /WX /std:c11 /utf-8 /I include /Fe:build\syscall_probe.exe src\syscall.c tests\syscall_probe.c /link /SUBSYSTEM:CONSOLE"
if ($LASTEXITCODE -ne 0) { throw 'build FAILED: cl (syscall_probe)' }

# 5d. 阶段2(第二支柱): 节填充（统一节尺寸，消除"组合可推断"）
#
# **为什么需要**: 不同组合因编入模块多少而有不同节尺寸（实测 .text 差 8704
#   字节），攻击者可据此判断"开了哪些防护"。填到统一目标可消除该信号。
#
# **实现**: "先量测 -> 生成填充 -> 二次编译"。
#   目标尺寸来自 build/section_baseline.json（由 -RecordBaseline 生成，
#   或首次自动从当前组合推导）。
#
# **只填可安全填充的节**（实测边界）:
#   .text/.rdata/自定义节 -> 可用源码级填充（pragma section/segment + allocate）
#   .pdata/.reloc/.data/.rsrc -> **工具链管理**，填充会破坏节表（LNK4078 等），
#                               其尺寸是"代码的派生量"，另行处理。
#
# **不填充时为默认行为**（-NoPad 可显式关闭）。
if (-not $NoPad) {
    $baselineFile = 'build\section_baseline.json'
    $padSrc = 'demo\gen\prot_padding.c'
    # 本脚本用相对路径（无 $REPO 变量）

    # 量测当前产物（第一遍编译已完成）
    & $py tools\measure_sections.py build\demo.exe --out-json build\section_actual.json
    if ($LASTEXITCODE -ne 0) { throw 'build FAILED: measure_sections.py' }

    # 基线维护: **只增不减**（取"旧基线"与"本次实际"的较大值）
    #
    # 教训（2026-09-23）: 初版仅在"基线不存在"时建立一次。当源码变化使某
    # 组合变大（如 §15 把字符串表从 14 条增至 33 条，.rdata 从 0xDBE2 增至
    # 0xDDE2），旧基线成为**过期目标** -> 其它组合按旧目标填充 ->
    # 组合间尺寸不一致（实测 minimal 229376 vs full 229888，差 512 字节）。
    #
    # 改为每次合并取 max -> 基线自动跟进"最大组合"，无需人工干预。
    & $py tools\merge_baseline.py --baseline $baselineFile --actual build\section_actual.json
    if ($LASTEXITCODE -ne 0) { throw 'build FAILED: merge_baseline.py' }

    # 生成填充源（若无需填充则产出空文件）
    #
    # W1（差异扩散）: --spread-ratio 让**每个组合**（含最大的 full）都有
    # 随机填充区。旧逻辑是"补齐到基线即止"，而基线 = 各组合最大值 ->
    # full 无需填充 -> per-build 差异仅 0.54%（实测），远低于 >30% 目标。
    #
    # 默认 0.35（目标尺寸的 35% 作为随机增量）—— 可按需调整；
    # 设 0 可关闭（回退到"仅归一化"行为）。
    $spreadRatio = if ($null -ne $env:PROT_SPREAD_RATIO) {
        $env:PROT_SPREAD_RATIO } else { '0.35' }
    $padSeed = if ($sectionsSeed) { $sectionsSeed } else { '' }
    $padArgs = @('tools\gen_padding.py', '--baseline', $baselineFile,
                 '--actual', 'build\section_actual.json',
                 '--out', $padSrc,
                 '--spread-ratio', $spreadRatio,
                 '--min-spread', '512')
    if ($padSeed) { $padArgs += @('--seed', $padSeed) }
    & $py @padArgs
    if ($LASTEXITCODE -ne 0) { throw 'build FAILED: gen_padding.py' }

    # 二次编译（带填充）—— 仅当填充源非空
    $padBody = if (Test-Path -LiteralPath $padSrc) {
        (Get-Content -LiteralPath $padSrc -Raw) } else { '' }
    if ($padBody -match '__declspec\(allocate') {
        Write-Host 'build: 应用节填充（二次编译）'
        Set-Content -LiteralPath build\_d9026_cmd.txt -Value $clCmd2 -Encoding UTF8
        cmd /c "`"$vcvars`" >nul 2>&1 && cl /nologo /O2 /W4 /WX /std:c11 /utf-8 /I include /I demo\gen /DPROT_USE_GENERATED_SECTIONS=1 /DPROT_BUILD_SALT=$buildSalt$scDef$resObj /Fe:build\demo.exe $compSrcJoined demo\main.c demo\gen\strings.c demo\gen\license_pubkey.c demo\gen\indirect_table.c demo\gen\expect_default.c $padSrc /link /SUBSYSTEM:CONSOLE bcrypt.lib winhttp.lib advapi32.lib user32.lib /MAP:build\demo.map$linkHard"
        if ($LASTEXITCODE -ne 0) { throw 'build FAILED: cl (填充后重编译)' }
    } else {
        Write-Host 'build: 无需填充（当前组合已是最大尺寸）'
    }
}

# 6. N1 (阶段 0 原型): 引擎函数原位加密 (方案 B) —— 必须在 hashpatch 之前
#     (加密改 .text, hashpatch 对加密段掩码后烧录, 两侧一致)。
#     掩码 rva/len 由 selfcrypt_proto.py 写入 build/selfcrypt_mask.txt
#
#     阶段 2: 组合排除了 integrity/antidebug 等模块时, 其加密目标函数不在
#     .map 中 —— selfcrypt_proto.py 会跳过并报告 (f48ffbd)。
#     仅当组合为 full (全模块) 时用 --require-all 保持严格校验。
$scExtraArgs = @()
if ($ExtraSelfCrypt) {
    foreach ($n in ($ExtraSelfCrypt -split ',')) {
        $scExtraArgs += '--extra', $n.Trim()
    }
}
if ($compName -eq 'full') { $scExtraArgs += '--require-all' }
& $py tools\selfcrypt_proto.py build\demo.exe build\demo.map @scExtraArgs --sections-json "$sectionsJson"
if ($LASTEXITCODE -ne 0) { throw 'build FAILED: selfcrypt_proto.py' }
$maskArgs = @()
if (Test-Path -LiteralPath 'build\selfcrypt_mask.txt') {
    foreach ($ln in (Get-Content -LiteralPath 'build\selfcrypt_mask.txt')) {
        $maskArgs += '--mask', $ln.Trim()
    }
}

# 6. 烧录 .text CRC32 到二进制 (integrity 自检依赖; 带 selfcrypt 掩码)
#
#     阶段 2 (组合): .protcrc 段与三段 CRC 烧录表由 **src/integrity.c** 定义。
#     组合排除 integrity 时该段不存在 -> hashpatch 无目标可写 (实测
#     "no .protcrc section found")。此时**跳过烧录**并明确报告 ——
#     因为该组合本就不含完整性校验, 没有 CRC 需要烧录。
#     这是 integrity 与 hashpatch 的**构建级耦合**, 属预期而非缺陷。
$hasIntegrity = $compSrcs -match 'integrity\.c$'
if ($hasIntegrity) {
    & $py tools\hashpatch.py build\demo.exe @maskArgs --sections-json "$sectionsJson"
    if ($LASTEXITCODE -ne 0) { throw 'build FAILED: hashpatch.py' }
} else {
    Write-Host 'build: hashpatch SKIPPED (组合不含 integrity, 无 .protcrc 段可烧录)'
}

# 6.1 W1(差异扩散): 文件尾精确填充 —— 让所有组合**文件大小完全一致**
#
# **为什么需要**（实测 2026-09-23）: 节填充的预算按文件级算，但只能花在
# **节**上，而节被链接器对齐到 0x200 -> 各组合最终大小仍差 512~1024 字节
# （实测 minimal 305152 / standard 305664 / hardened 304640 / full 304640）
# -> "文件大小可推断组合"的信号未完全消除。
#
# **为什么安全**:
#   · PE 加载器只按 PE 头声明的长度映射，尾部多余字节被忽略
#     （阶段2 早期实测: 追加 4096 字节后 rc=0 正常输出）
#   · 完整性 CRC 只覆盖**节**（TARGET_NAMES = .text/.rdata/.pdata）
#     -> 尾部不参与校验（已核实 tools/hashpatch.py）
#
# **插入顺序**: 必须在 hashpatch **之后**（否则 CRC 与最终字节不符）、
#   在签名**之前**（否则签名失效）。
$tailTarget = if ($null -ne $env:PROT_TAIL_TARGET) {
    $env:PROT_TAIL_TARGET } else { '327680' }
& $py tools\normalize_tail.py build\demo.exe --target $tailTarget `
    $(if ($sectionsSeed) { @('--seed', $sectionsSeed) } else { @() }) --quiet
if ($LASTEXITCODE -ne 0) { throw 'build FAILED: normalize_tail.py' }

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
    # 时间戳: **默认不使用**（W5.7 实测修复 2026-09-23）
    #
    # **为什么默认关闭**:
    #   · `/t http://timestamp.digicert.com` 是**公网**服务 -> 网络抖动/
    #     服务不可达时 signtool 返回非 0 -> **整个构建失败**
    #     （实测: 门禁中间歇失败、手动跑却成功 —— 典型网络抖动特征）。
    #   · 本项目定位是**可复现构建** + 本地离线授权 —— 依赖公网时间戳自相矛盾。
    #   · RFC3161 时间戳会让签名**每次不同** -> 反而**破坏**字节级可复现。
    #   · 此处证书是**自签 demo 证书**，时间戳无实际信任价值。
    #
    # 若发版确需时间戳，设环境变量显式开启:
    #     $env:PROT_TIMESTAMP_URL = 'http://timestamp.digicert.com'
    $tsArg = ''
    if ($env:PROT_TIMESTAMP_URL) {
        $tsArg = "/t $($env:PROT_TIMESTAMP_URL)"
    }
    cmd /c "`"$($signtool.FullName)`" sign /fd SHA256 /f `"$pfx`" $pass $tsArg $exe"
    if ($LASTEXITCODE -ne 0) {
        # 明确诊断: 区分"证书问题"与"时间戳问题"（后者在网络不稳时常见）
        $hint = if ($tsArg) {
            '(已启用时间戳; 网络不可达是常见原因, 可 unset PROT_TIMESTAMP_URL 重试)'
        } else { '(签名失败: 请检查证书与私钥口令)' }
        throw "build FAILED: signtool sign $exe $hint"
    }
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

# ## L6b（2026-09-25）: 修正**硬编码源文件列表**（本项目第 5 处）
#
# **问题**: 这两条命令**硬编码**了源文件列表。L6b 把 `vm.c` 的
#   平台相关部分改走平台层（`prot_plat_monotonic_ns`）后:
#     `LNK2019: 无法解析的外部符号 prot_plat_monotonic_ns，
#              函数 prot_vm_run 中引用了该符号`
#   —— 因为列表里**没有** `src\platform\prot_platform_win.c`。
#
# **为什么 L3 没抓到**: L3 修了 `build_example.ps1`，
#   但 S1 检查只扫**独立的 *.ps1 文件**，**没扫 build.ps1 内部的字符串**
#   -> build.ps1 里的这两条硬编码列表**逃过了检查**。
#
# **修法**: 显式加入平台层（这两个探测程序只需**最小集**，
#   不适用组合驱动 —— 它们刻意保持"只链接被测模块"）。
#   S1 已同步增强（见 tools/modcheck.py）。
$platSrc = 'src\platform\prot_platform_win.c'
$unitCl = "cl /nologo /O2 /W4 /WX /std:c11 /utf-8 /I include /I demo\gen /Fe:build\vm_unit.exe src\vm.c src\crc32.c $platSrc demo\gen\vm_unit_blob.c demo\gen\vm_unit_brk_blob.c tests\vm_unit.c /link /SUBSYSTEM:CONSOLE advapi32.lib"
# syscall_probe 只用 syscall.c（无平台层依赖）—— 保持不变
$probeCl = 'cl /nologo /O2 /W4 /WX /std:c11 /utf-8 /I include /Fe:build\syscall_probe.exe src\syscall.c tests\syscall_probe.c /link /SUBSYSTEM:CONSOLE'
Invoke-Unit 'vm_unit.exe' $unitCl 'vm_unit.exe (Phase 1D ops)'
Invoke-Unit 'syscall_probe.exe' $probeCl 'syscall_probe.exe (A6 direct syscall)'

# 7.2. 冒烟自检 (P0): 正确序列号 + license + vm.blob 必须整体通过 ——
#      验证 hashpatch 烧录 CRC 与运行期掩码规则一致 (IAT/重定位), 以及
#      blob/授权链路; 失败即中止, 尽早暴露"两侧不一致"类缺陷。
#      -SkipSmoke: 绑定"他机" machine_id 构建时 (运行机 != 构建机) 冒烟
#      必然失败, 属预期 (机器绑定), 跳过之 (真机验证场景)。
#      WDAC 拦截时重试 (延迟重跑), 最多 3 轮。
#
#      实现注意 (2026-09-20): 这里**必须**用 cmd 管道, 不能用 PowerShell 管道。
#      两个已实证的坑:
#        1) $ErrorActionPreference='Stop' 下, 原生命令的 stderr 重定向
#           (2>&1 与 2>$null 均然) 会被包装成终止性 RemoteException ->
#           直接跳进 catch, exit code 永不参与判定。
#        2) PowerShell 管道向原生进程 stdin 写入时会带编码前缀 (BOM),
#           使 demo 读到的序列号多 3 字节 -> 校验失败 exit 1。
#      demo.exe 恒定向 stderr 输出 [SCDBG] 自解密日志, 故上述 1) 必然触发。
#      改用 cmd /c 后: stdin 为干净字节, stderr 不被 PS 包装, exit code 可靠。
$smokeSerial = (Get-Content -LiteralPath demo\vm_build.json -Raw | ConvertFrom-Json).serial
$smokeOk = $true
if (-not $SkipSmoke) {
    $smokeOk = $false
    $smokeOut = @()
    for ($try = 1; $try -le 3 -and -not $smokeOk; $try++) {
        try {
            # > 文件 收集 stdout; 2>nul 丢弃 SCDBG 噪声; < 输入序列号
            $smokeLog = Join-Path $env:TEMP 'prot_smoke_out.txt'
            $smokeIn = Join-Path $env:TEMP 'prot_smoke_in.txt'
            [System.IO.File]::WriteAllText($smokeIn, $smokeSerial)
            cmd /c ".\build\demo.exe --license-file build\license.txt --vm-blob build\vm.blob < `"$smokeIn`" > `"$smokeLog`" 2>nul"
            $rc = $LASTEXITCODE
            if (Test-Path -LiteralPath $smokeLog) {
                $smokeOut = @(Get-Content -LiteralPath $smokeLog -ErrorAction SilentlyContinue)
            }
            if ($rc -eq 0) { $smokeOk = $true }
            else {
                Write-Host "build: smoke try $try exit=$rc (WDAC 信誉瞬态? retry in 10s)"
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
    composition = $compName          # 阶段2: 本次构建所用拼装图
    comp_modules = (@(
        Select-String -LiteralPath 'demo\gen\prot_modconfig.h' `
            -Pattern '^#define PROT_MOD_(\w+)' |
        ForEach-Object { $_.Matches[0].Groups[1].Value }
    ) | Sort-Object)
    version    = $manifestVersion
    toolchain  = $toolchain
    os         = ((& $py tools\osinfo.py --json) | ConvertFrom-Json)
    machine_id = $jb.machine_id
    machine_auto = $machineAuto
    sha        = if (Get-Command git -ErrorAction SilentlyContinue) {
                     (git rev-parse --short HEAD 2>$null)
                 } else { 'no-git' }
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

