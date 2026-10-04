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
    # 缺陷 5c（2026-10-02）: Dev 配置下也强制链接器 /Brepro。
    # 为什么需要: `reproducible` job 的两步都用默认 Dev，而 /Brepro 原本
    # 只在 Release 分支注入（见下方 $linkHard）-> PE TimeDateStamp 每构建
    # 不同 -> 即使种子全部记录，字节比对仍 MISMATCH。实测见
    # build/_repro_5c_out.txt（6 字节差异，其中 0x108 即 TimeDateStamp）。
    [switch]$Brepro,
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
$seedTable = $null
if ($SeedsFile -and (Test-Path -LiteralPath $SeedsFile)) {
    # 由种子表内容派生一个稳定种子（同表 -> 同节名；不同表 -> 不同节名）
    $seedHash = (Get-FileHash -LiteralPath $SeedsFile -Algorithm SHA256).Hash
    $sectionsSeed = '0x' + $seedHash.Substring(0, 16).ToLower()

    # 缺陷 5（2026-10-02 实测）: 若种子表**自带** sectionsSeed/buildSalt 则优先采用。
    # 旧种子表无这两个键 -> 回退到上面的哈希派生（向后兼容）。
    #
    # **为什么必须有这两键**: `-RecordSeeds` 原本只记录 images/strgen/indirect，
    #   · `sectionsSeed`（节名/magic/gen_padding/normalize_tail）是 `SystemRandom`
    #   · `buildSalt`（/DPROT_BUILD_SALT，保护函数机器码）是 `RandomNumberGenerator`
    # 二者都不在表里 -> 同表重建只能碰巧一致。实测（build/_exact_ci_out.txt）:
    # 首次构建盐 0x2d0533f3 / sha E4C2F982…，带 -SeedsFile 重建盐 0xd5718f9f /
    # sha C2290CE5… -> CI `reproducible` job 的 `A -eq B` 恒为 False。
    # 环境变量 PROT_BUILD_SALT 仍**优先于**种子表（显式覆盖 > 表内记录）。
    $seedTable = Get-Content -LiteralPath $SeedsFile -Raw | ConvertFrom-Json
    if ($seedTable.sectionsSeed) { $sectionsSeed = [string]$seedTable.sectionsSeed }
    if ($seedTable.buildSalt -and -not $env:PROT_BUILD_SALT) {
        $buildSalt = [string]$seedTable.buildSalt
    }
}

# 缺陷 5b（2026-10-02 实测）: 无确定性种子时, **本脚本必须自己产生** sectionsSeed。
#
# ⚠️ 这是缺陷 5 的必要补充 —— 只把 `$sectionsSeed` 写进种子表还不够:
#   在「未传 -SeedsFile / 未传 -UserId」的发布构建路径上 `$sectionsSeed` 恒为 ''，
#   于是 `--seed` 根本不会传给子工具 —— `gen_sections.py` / `gen_padding.py` /
#   `normalize_tail.py` **各自在内部**用 `random.SystemRandom()` 取种子。那个值
#   build.ps1 从未见过, 自然也无从记录 -> 重建必然不同。
#
# 实测（build/_repro_fix_out.txt）: 记录出的 `sectionsSeed = `（空字符串）,
#   带 -SeedsFile 重建后 `demo.exe A -eq B = False`（而 `vm.blob` 已能一致 ——
#   它由 images 种子决定, 与本节无关）。
#
# 修法: 与下方 strgen（4.）/ indirect（4c.）**同一惯例** —— 只在 `-RecordSeeds`
#   时物化, 使「非 RecordSeeds 构建」的字节行为与改动前**完全一致**;
#   随机性语义不变（仍是每构建不同）, 只是那个随机值现在**可被记录**。
#   用密码学 RNG 而非 `Get-Random`: 本节名种子驱动节名/magic/填充/尾部,
#   与 buildSalt 同类（见下方 W1.6 派生段用的是同一个 RNG）。
if ($RecordSeeds -and -not $sectionsSeed) {
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $sbuf = New-Object byte[] 8
    $rng.GetBytes($sbuf)
    $rng.Dispose()
    $sectionsSeed = '0x' + (($sbuf | ForEach-Object { $_.ToString('x2') }) -join '')
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

# =============================================================================
# 生成物目录（A-c，2026-09-25）—— **单一来源**: tools/genpaths.py
#
# 与 build.sh（A-b）对称: 路径**只在一处决定**；
# `$env:PROT_GEN_LAYOUT = 'flat'` 可回退旧布局。
# =============================================================================
# ## 用**相对路径**（A-c 实测修正）
#   绝对路径含空格（`...\Reverse Engineering\...`）-> 会被 cmd/shell 拆词
#   （实测: `LNK1181: 无法打开输入文件 "D:\specifically.obj"`）。
#   本脚本在**仓库根**执行 -> 相对路径**无空格**，从根上消除引号问题。
$genDir = (& $py tools\genpaths.py --platform win --print-gen-rel 2>$null | Select-Object -First 1)
$vmJson = (& $py tools\genpaths.py --platform win --print-vm-json 2>$null | Select-Object -First 1)
if (-not $genDir -or -not $vmJson) {
    throw 'build FAILED: 无法取得生成物路径（tools/genpaths.py 异常）'
}
$genDir = $genDir.Trim()
# ## 平台专属 build 目录（A-d 补完，2026-09-25）
#   快照比对实测: `build/_composition_srcs.txt` 与
#   `build/section_baseline.json` 被**两平台都写** -> 泄漏
#   （前者会让 Windows 用错源清单；后者会互相抬高归一化基线）。
$buildDir = (& $py tools\genpaths.py --platform win --print-build-dir 2>$null | Select-Object -First 1)
if (-not $buildDir) { throw 'build FAILED: 无法取得 build 目录' }
$buildDir = $buildDir.Trim()
$vmJson = $vmJson.Trim()

# 状态文件路径（A-c）: 由 genpaths 决定（win: demo\vm_build.json；linux: build/linux/vm_build.json）
$jsonPath = $vmJson
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
    Write-Host 'build: creating default "${vmJson}"'
    Set-Content -LiteralPath $jsonPath -Value '{"serial":"DEMO-2026-ABCDEFGH","machine_id":0}' -Encoding ascii
}

# 输出目录
if (-not (Test-Path -LiteralPath $genDir)) {
    New-Item -ItemType Directory -Path $genDir | Out-Null
}
if (-not (Test-Path -LiteralPath 'build')) {
    New-Item -ItemType Directory -Path 'build' | Out-Null
}

# 2. 重算期望常量 (machine_id 默认 auto=绑定本机; 可 --MachineId 覆盖)
#
# 缺陷 5e（2026-10-02 实测）: `machine_id` 是决定 demo.exe 字节的第三个未记录输入。
#   `tools/vmenc.py:974-979` 对 'auto'/'0' 一律用 `hostid()` **重算**，并**丢弃**
#   `demo/vm_build.json` 里已有的 machine_id。而 CI 的 `build-and-verify` 与
#   `reproducible` 跑在**不同 runner** 上、两步都传 `-MachineId auto`
#   -> hostid 不同 -> expect2 不同 -> 该常量被编译进 demo.exe -> 恒 MISMATCH。
#
# 实测（build/_mid_out.txt）: 显式 MID=0x1122334455667788 构建得
#   sha FD689063F1C676CBF60C142B71E1F29DBCB485E8B8E9D32D1AF02CDD022B9FA8
#   （mid=1234605616436508552, expect2=0x51ba0eb085e11c04）;
#   同种子 + `-MachineId auto` 重建得 sha CF8D6F52…0513
#   （mid=12981648366597980211, expect2=0x2d270f40b2a15b10）-> A == B **False**;
#   再显式复述同一 MID 重建又得 FD689063…9FA8 -> A == C **True**。
#   （注意 expect1 两边相同 —— 它只由 serial 决定 —— 差异全在 expect2。）
#
# 修法: `-SeedsFile` 带来的**表内** machine_id 优先于 `auto`。
#   优先级: 显式 `-MachineId <值>` > 种子表 `machine_id` > 本机 hostid 绑定。
#   这样 CI 跨 runner 的重放才确定; 不带种子表的发布构建行为**不变**（仍绑本机）。
$effMachineId = $MachineId
if ($MachineId -in @('auto', '0') -and $seedTable -and $seedTable.machine_id) {
    $effMachineId = [string]$seedTable.machine_id
    Write-Host ("build: machine_id {0} -> 采用种子表记录值 {1}（缺陷 5e 跨机重放）" -f `
                $MachineId, $effMachineId)
}
& $py tools\vmenc.py genserial --json "${vmJson}" --machine-id "$effMachineId"
if ($LASTEXITCODE -ne 0) { throw 'build FAILED: vmenc.py genserial' }

# 2.2. N5: 从 vm_build.json 生成构建期默认期望值 C 文件 (VM#3 离线兜底值)
$jbExpect = Get-Content -LiteralPath "${vmJson}" -Raw | ConvertFrom-Json
$e1 = ($jbExpect.expect1 -replace '^0x', '')
$e2 = ($jbExpect.expect2 -replace '^0x', '')
$expLines = @(
    '/* generated by build.ps1 from "${vmJson}" - do not edit */',
    '#include <stdint.h>',
    '#include "protect/protdef.h"',
    '',
    '/* N5: VM#3 build-time default expects (overridden by server session values) */',
    ('const uint64_t g_prot_expect_default[2] = { 0x' + $e1 + 'ULL, 0x' + $e2 + 'ULL };')
)
$expC = $expLines -join [Environment]::NewLine
Set-Content -LiteralPath (Join-Path $genDir 'expect_default.c') -Value $expC -Encoding ascii

# 2.5. RSA 授权 (A1): 生成/复用私钥 (build\keys, gitignore, 不入库) 并导出公钥 blob;
#     对该 json 的 serial/machine_id 签发 -> build\license.txt (供下发与测试用)
& $py tools\vmenc.py keygen --key-out "build\keys\license_priv.json" --blob-out "${genDir}\license_pubkey.c"
if ($LASTEXITCODE -ne 0) { throw 'build FAILED: vmenc.py keygen' }
& $py tools\vmenc.py sign --key "build\keys\license_priv.json" --json "${vmJson}" --out "build\license.txt" --print
if ($LASTEXITCODE -ne 0) { throw 'build FAILED: vmenc.py sign' }

# 3. 汇编 + 加密 VM 镜像 (ROADMAP Phase 2a: 一个校验逻辑拆成 3 个独立小 VM,
#    各自独立密钥/置换/窗口: FNV 哈希 -> GOLDEN 混合 -> 期望值校验;
#    --bin-out/--bin-name: 写单镜像 .bin, 供 3c 打包 vm.blob 由 demo 装载;
#    -SeedsFile: 注入确定性种子 (I3 可复现构建))
& $py tools\vmenc.py assemble demo\license_hash.vasm "${vmJson}" "${genDir}\vm_hash_blob.c" "${genDir}\vm_hash_blob.h" --name g_vm_hash_image --bin-out "${genDir}\vm_hash_blob.bin" --bin-name hash $(Get-SeedArgs 'g_vm_hash_image')
if ($LASTEXITCODE -ne 0) { throw 'build FAILED: vmenc.py assemble (hash)' }

& $py tools\vmenc.py assemble demo\license_mix.vasm "${vmJson}" "${genDir}\vm_mix_blob.c" "${genDir}\vm_mix_blob.h" --name g_vm_mix_image --bin-out "${genDir}\vm_mix_blob.bin" --bin-name mix $(Get-SeedArgs 'g_vm_mix_image')
if ($LASTEXITCODE -ne 0) { throw 'build FAILED: vmenc.py assemble (mix)' }

& $py tools\vmenc.py assemble demo\license_verify.vasm "${vmJson}" "${genDir}\vm_verify_blob.c" "${genDir}\vm_verify_blob.h" --name g_vm_verify_image --bin-out "${genDir}\vm_verify_blob.bin" --bin-name verify $(Get-SeedArgs 'g_vm_verify_image')
if ($LASTEXITCODE -ne 0) { throw 'build FAILED: vmenc.py assemble (verify)' }

& $py tools\vmenc.py assemble demo\license_gate.vasm "${vmJson}" "${genDir}\vm_gate_blob.c" "${genDir}\vm_gate_blob.h" --name g_vm_gate_image --bin-out "${genDir}\vm_gate_blob.bin" --bin-name gate $(Get-SeedArgs 'g_vm_gate_image')
if ($LASTEXITCODE -ne 0) { throw 'build FAILED: vmenc.py assemble (gate)' }

# 3c. 打包 VM blob (DBI launcher, 技术债 #3): demo.exe 不再静态嵌入 VM 密文,
#     启动时由 launcher 装载 build\vm.blob (缺失/损坏 -> 0xB10B)。
#     BLOB_SIGN_PLAN: --sign 用 A1 私钥签 v1 blob (防伪造)
& $py tools\vmenc.py pack --sign "build\keys\license_priv.json" --out build\vm.blob "${genDir}\vm_hash_blob.bin" "${genDir}\vm_mix_blob.bin" "${genDir}\vm_verify_blob.bin" "${genDir}\vm_gate_blob.bin"
if ($LASTEXITCODE -ne 0) { throw 'build FAILED: vmenc.py pack' }

# 3b. 汇编 VM 指令集单测镜像 (ROADMAP Phase 1d, 每个新指令都要有测试用例)
& $py tools\vmenc.py assemble tests\unit_vm.vasm "${vmJson}" "${genDir}\vm_unit_blob.c" "${genDir}\vm_unit_blob.h" --name g_vm_unit_image $(Get-SeedArgs 'g_vm_unit_image')
if ($LASTEXITCODE -ne 0) { throw 'build FAILED: vmenc.py assemble (unit_vm)' }

& $py tools\vmenc.py assemble tests\unit_vm_brk.vasm "${vmJson}" "${genDir}\vm_unit_brk_blob.c" "${genDir}\vm_unit_brk_blob.h" --name g_vm_unit_brk_image $(Get-SeedArgs 'g_vm_unit_brk_image')
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
& $py tools\strgen.py demo\strings.txt "${genDir}\strings.c" $strgenSeedArgs
if ($LASTEXITCODE -ne 0) { throw 'build FAILED: strgen.py' }

# ---- 阶段1(第二支柱): 生成随机节名与 magic ----
# 目的: 消除产物中的自解释名字（.protcrc / PROTCRCP 等）——
#       攻击者看到节名即知"这里是完整性校验"，故每构建随机。
# 实测: PE 节名上限 8 字节（源码写 .protcrypt(10) 会被截断为 .protcry），
#       故生成器产 "." + 7 字符 = 8，正好合规。
# 注意: 必须在**编译之前**执行（src/*.c 会 #include "prot_sections.h"）。
# 注意: 本脚本**没有** $REPO 变量 —— 它假定从仓库根运行，全部用相对路径
# （与 strgen.py / indirect.py / compose.py 的调用写法一致）。
$sectionsJson = (Join-Path $genDir 'prot_sections.json')
$secArgs = @()
if ($sectionsSeed) { $secArgs = @('--seed', $sectionsSeed) }
& $py tools\gen_sections.py --out-dir ${genDir} @secArgs
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

    & $py tools\indirect.py --out "${genDir}\indirect_table.c" $indirectSeed
} else {
    & $py tools\indirect.py --out "${genDir}\indirect_table.c"
}
if ($LASTEXITCODE -ne 0) { throw 'build FAILED: indirect.py' }

# 4b. Release: 编译版本资源 (RELEASE §2.3, 值只来自 version.h)
if ($isRelease) {
    # ## ⚠️ `cmd /c "..."` 内的路径引号（A-c 实测）
    #   外层是 `cmd /c "..."`，内层再用 `"` 会被**外层消耗** ->
    #   含空格的路径被拆分（实测 RC1107 invalid usage）。
    #   => cmd 语义下需用 **`\"`**（PowerShell 里写作 `` `" ``）转义内层引号。
    cmd /c "`"$vcvars`" >nul 2>&1 && rc /nologo /I include /fo `"${genDir}\version.res`" demo\version.rc"
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
# 缺陷 5c（2026-10-02）: /Brepro 让链接器产出**确定性** PE 头（TimeDateStamp/
#   校验和）与调试目录时间戳，是"同种子两次构建字节一致"的必要条件（I3）。
#   Release 恒开（原有行为不变）。Dev **默认仍关**（保留 /INCREMENTAL 等开发
#   体验、也不改变既有 Dev 产物字节）；但 CI 的 reproducible job 用 Dev，
#   故新增显式 `-Brepro` 让调用方按需打开，而不去动 Dev 的默认语义。
$linkHard = if ($isRelease) { ' /DEBUG:NONE /OPT:REF /OPT:ICF /Brepro' }
            elseif ($Brepro) { ' /Brepro' }
            else { '' }
$resObj = if ($isRelease) {  ' ' + (Join-Path $genDir 'version.res')  } else { '' }

$compName = if ($Composition) { $Composition } else { 'full' }
$compSrcList = Join-Path $buildDir '_composition_srcs.txt'
# B 阶段（2026-09-25）: 用**构建盐**作为打乱种子 —— 源文件链接顺序按构建随机化。
#
# ## 为什么（两个防护目标兼得，实测验证）
#   · **节大小归一化**（防组合指纹）: 顺序**不改**节大小（实测两次顺序
#     .text 均 = 94880）-> 填充归一化的成果**保持**。
#   · **函数地址抖动**（防破解迁移）: 顺序**改**函数布局（实测 RVA
#     变化 42.7%）-> `migration_gate` 的 M1 恢复低值。
#
# ## 为什么用 $buildSalt
#   · 普通构建: 随机（每构建不同 -> 地址变化）
#   · `-SeedsFile` 可复现构建: 由种子派生（**同种子 -> 同顺序**）
#   · `repro_check` 因此仍通过（确定性）。
# ## --extra（2026-09-25）: 尾部文件**并入统一打乱**
#
# 原实现在 $compSrcJoined 后**固定追加**这些文件 -> 尾部前缀恒定
# -> 尾部符号（255 个字符串字面量 + main.c 等）**位置锁死**
# -> M1 实测 16.9%。并入打乱后应显著下降。
# ⚠️ 必须与**原 cl 尾部完全一致**（不含 prot_pubkey_der.c —— 那是
#   Linux 侧用的 DER 公钥，原 Windows cl 命令从未链接它）。
$compExtras = @('demo\main.c', (Join-Path $genDir 'strings.c'),
                (Join-Path $genDir 'license_pubkey.c'),
                (Join-Path $genDir 'indirect_table.c'), (Join-Path $genDir 'expect_default.c'))
$extraArgs = @()
foreach ($ex in $compExtras) { $extraArgs += @('--extra', $ex) }
# ## 顺序随机化: **默认关**（2026-09-25 实测教训）
#
# 实测: 开启后**多数布局让程序崩溃**（`--version` 成功但完整启动
#   崩 0xC0000005，发生在 license 校验之后的 selfcrypt 解密路径）。
#   根因: selfcrypt 的**页分离保证（S1）是布局相关的** ——
#   源码顺序变化会移动 `.text` 内各贡献的相对位置，可能让**启动路径**
#   与加密段同页 -> VirtualProtect(RW) 禁执行 -> 崩溃。
#
# => **默认不打乱**（恢复验证过的正确行为）；需要时显式设
#    `$env:PROT_SHUFFLE_SEED` 启用（供 selfcrypt 改造后使用）。
# ## 2026-09-25 更新: **默认开启**（selfcrypt 页自伤已修复）
#
# 修复内容（src/selfcrypt.c）:
#   ① 先恢复页为 RX **再** flush icache（消除"在 RW 页上执行"窗口）
#   ② 解密窗口内**恒用 EXECUTE_READWRITE** -> 与谁同页都不会取指失败
#   实测: 原崩溃盐修复；4 盐 × e2e + attacks = **0 失败**
#         （修复前 3/4 盐崩溃、78 项失败）
#
# 显式设 `PROT_SHUFFLE_SEED=0` 可**关闭**（回归诊断用）。
if ($env:PROT_SHUFFLE_SEED -eq '0') {
    $shuffleArgs = @()
    Write-Host 'build: 顺序随机化**已关闭**（PROT_SHUFFLE_SEED=0）'
} else {
    $seed = if ($env:PROT_SHUFFLE_SEED) { $env:PROT_SHUFFLE_SEED } else { $buildSalt }
    $shuffleArgs = @('--shuffle-seed', $seed)
}
& $py tools\compose.py $compName --header-out "${genDir}\prot_modconfig.h" --sources-out $compSrcList @shuffleArgs @extraArgs
if ($LASTEXITCODE -ne 0) { throw "build FAILED: compose.py ($compName)" }
$compSrcs = @(Get-Content -LiteralPath $compSrcList | Where-Object { $_.Trim() } |
              ForEach-Object { $_.Trim() -replace '/', '\' })
if ($compSrcs.Count -eq 0) { throw "build FAILED: composition '$compName' 无源文件" }
# ## ⚠️ 每个源路径必须**加引号**（A-c 实测）
#   本仓库路径含空格（`…\Reverse Engineering\…`）——
#   `-join ' '` 生成的裸串在 `cmd /c "cl ..."` 里会被**拆词**
#   -> `c1: 无法打开源文件: "Engineering\demo\gen\win\strings.c"`（实测）。
#   内层用**普通双引号**（实测 B_plain 形态有效），与外层 `cmd /c "..."` 兼容。
$compSrcJoined = (($compSrcs | ForEach-Object { '"' + $_ + '"' }) -join ' ')
Write-Host ("build: composition '{0}' — {1} 源文件" -f $compName, $compSrcs.Count)

# 阶段1(第二支柱): -DPROT_USE_GENERATED_SECTIONS 让 include/protect/
# prot_sections.h 采用 demo\gen 下的**随机节名**（覆盖其默认值）。
# 不定义该宏的独立构建（skeleton/examples/tests）沿用默认节名，不受影响。
cmd /c "`"$vcvars`" >nul 2>&1 && cl /nologo /O2 /W4 /WX /std:c11 /utf-8 /I include /I `"${genDir}`" /DPROT_USE_GENERATED_SECTIONS=1 /DPROT_BUILD_SALT=$buildSalt$scDef$resObj /Fe:build\demo.exe $compSrcJoined /link /SUBSYSTEM:CONSOLE bcrypt.lib winhttp.lib advapi32.lib user32.lib /MAP:build\demo.map$linkHard"
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
cmd /c "`"$vcvars`" >nul 2>&1 && cl /nologo /O2 /W4 /WX /std:c11 /utf-8 /I include /I `"${genDir}`" /Fe:build\vm_unit.exe src\vm.c src\crc32.c src\platform\prot_platform_win.c `"${genDir}\vm_unit_blob.c`" `"${genDir}\vm_unit_brk_blob.c`" tests\vm_unit.c /link /SUBSYSTEM:CONSOLE advapi32.lib winhttp.lib"
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
    $baselineFile = (Join-Path $buildDir 'section_baseline.json')
    $padSrc = (Join-Path $genDir 'prot_padding.c')
    # 本脚本用相对路径（无 $REPO 变量）

    # 量测当前产物（第一遍编译已完成）
    & $py tools\measure_sections.py build\demo.exe --out-json build\section_actual.json --sections-json (Join-Path $genDir 'prot_sections.json')
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
    $padArgs = @('tools\gen_padding.py', '--baseline', $baselineFile, '--sections-json', (Join-Path $genDir 'prot_sections.json'),
                 '--actual', (Join-Path $buildDir 'section_actual.json'),
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
        cmd /c "`"$vcvars`" >nul 2>&1 && cl /nologo /O2 /W4 /WX /std:c11 /utf-8 /I include /I `"${genDir}`" /DPROT_USE_GENERATED_SECTIONS=1 /DPROT_BUILD_SALT=$buildSalt$scDef$resObj /Fe:build\demo.exe $compSrcJoined $padSrc /link /SUBSYSTEM:CONSOLE bcrypt.lib winhttp.lib advapi32.lib user32.lib /MAP:build\demo.map$linkHard"
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

# 6. 烧录段 CRC32 到二进制 (integrity 自检依赖; 带 selfcrypt 掩码)
#
#     阶段 2 (组合): .protcrc 段与 CRC 烧录表由 **src/integrity.c** 定义。
#     组合排除 integrity 时该段不存在 -> hashpatch 无目标可写 (实测
#     "no .protcrc section found")。此时**跳过烧录**并明确报告 ——
#     因为该组合本就不含完整性校验, 没有 CRC 需要烧录。
#     这是 integrity 与 hashpatch 的**构建级耦合**, 属预期而非缺陷。
#
#     DRILL9 (2026-10-04): 目标由 3 个增至 **4 个**
#     (TARGET_NAMES = .text/.rdata/.pdata/**.protxec**)。
#     第 4 个 `.protxec` 承载守卫检查器自身 (check_iat/register_guard/
#     start_watchdog/iat_snapshot_init), 此前不在任何段 CRC 覆盖内 ->
#     运行期改写它可静默关掉检测。注意 `.protxec` 的节名也**每构建随机**
#     (gen_sections.py), 故 hashpatch.py 用 TARGET_LOGICAL 把它映射为实际名;
#     映射缺失会走 "section absent — skip" 而**静默不校验**, 必须由
#     tools/check_crc_targets.py 与判据守护。
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
#   · 完整性 CRC 只覆盖**节**（TARGET_NAMES = .text/.rdata/.pdata/.protxec）
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
# ## ⚠️ 内层路径用**单引号**（A-c 实测）
#   整串外层是双引号（PowerShell 会插值 `${genDir}`），
#   若内层也用双引号 -> **嵌套冲突** -> 解析错误。
#   PowerShell 允许 `"... '...' ..."`（内层单引号为字面量）。
$unitCl = "cl /nologo /O2 /W4 /WX /std:c11 /utf-8 /I include /I ${genDir} /Fe:build\vm_unit.exe src\vm.c src\crc32.c $platSrc '${genDir}\vm_unit_blob.c' '${genDir}\vm_unit_brk_blob.c' tests\vm_unit.c /link /SUBSYSTEM:CONSOLE advapi32.lib winhttp.lib"
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
#      demo.exe **不含** SCDBG 日志（`SC_DBG` 由 PROT_SELFCRYPT_DEBUG 控制；R1 复核 2026-09-29 实测产物无该串），下述 2>nul 仅作**保守冗余**。
#      改用 cmd /c 后: stdin 为干净字节, stderr 不被 PS 包装, exit code 可靠。
$smokeSerial = (Get-Content -LiteralPath "${vmJson}" -Raw | ConvertFrom-Json).serial
$smokeOk = $true
if (-not $SkipSmoke) {
    $smokeOk = $false
    $smokeOut = @()
    for ($try = 1; $try -le 3 -and -not $smokeOk; $try++) {
        try {
            # > 文件 收集 stdout; 2>nul 保守丢弃 stderr（含可能的调试输出）; < 输入序列号
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
Get-ChildItem -LiteralPath $genDir -Filter 'vm_*_blob.c' -File | ForEach-Object {
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
$jb = Get-Content -LiteralPath "${vmJson}" -Raw | ConvertFrom-Json
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
        Select-String -LiteralPath (Join-Path $genDir 'prot_modconfig.h') `
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

    # 缺陷 5（2026-10-02 实测）: **必须**把 sectionsSeed / buildSalt 一并记入。
    #
    # 旧版只记录 images/strgen/indirect，漏掉了两个各自由系统随机数产生、
    # 却**直接决定产物字节**的输入:
    #   · sectionsSeed -> 节名/magic（gen_sections.py）+ gen_padding --seed
    #                     + normalize_tail --seed
    #   · buildSalt    -> /DPROT_BUILD_SALT（保护函数的序言噪声机器码）
    # 后果: `-SeedsFile` 重建时二者重新随机（或由表哈希另派生）-> 与首次构建
    # 不同 -> `reproducible` job 的 SHA-256 比对**必然** MISMATCH。
    # 证据: build/_exact_ci_out.txt —— 首次盐 0x2d0533f3 / sha E4C2F982…，
    # 重建盐 0xd5718f9f / sha C2290CE5…，`A -eq B = False`。
    #
    # 读回侧见本文件上方 `-SeedsFile` 分支（优先采用表内这两键）。
    $seedOut['sectionsSeed'] = $sectionsSeed
    $seedOut['buildSalt'] = $buildSalt

    # 缺陷 5e（2026-10-02 实测）: machine_id 同样是决定字节的输入，必须记录。
    #
    # CI 的 `reproducible` job 与 `build-and-verify` 跑在**不同 runner** 上，
    # 而两侧都传 `-MachineId auto` -> `vmenc.py` 用 `hostid()` 重算 ->
    # 卷序列号/计算机名/MachineGuid/磁盘序列号任一变 -> expect2 变 ->
    # 该常量被编译进 demo.exe -> 字节比对 MISMATCH（与种子无关）。
    # 实测 build/_mid_out.txt: A(显式 MID) FD689063… != B(auto) CF8D6F52…,
    # 而 A == C(显式 MID 复述) -> 记下 machine_id 即可跨机复现。
    $seedOut['machine_id'] = $jb.machine_id

    if ($strgenSeed) { $seedOut['strgen'] = $strgenSeed }
    if ($indirectSeed -and $indirectSeed.Count -ge 2) {
        $seedOut['indirect'] = $indirectSeed[1] -replace '^0x', ''
    }
    $seedOut | ConvertTo-Json -Depth 4 |
        Set-Content -LiteralPath build\seeds.json -Encoding utf8
    Write-Host "build: recorded seeds -> build\seeds.json (strgen=$strgenSeed indirect=$($seedOut.indirect) sections=$sectionsSeed salt=$buildSalt mid=$($seedOut.machine_id))"
}

# 8.
Write-Host 'DONE'

