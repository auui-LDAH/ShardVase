# tools/gen_changelog.ps1 — 从 git log 生成 CHANGELOG 草稿 (INFRA_PLAN I6)
#
# 按 commit 前缀分类 (feat/fix/docs/test/chore), 生成 CHANGELOG 新增段草稿。
# 用法:
#   powershell -ExecutionPolicy Bypass -File tools\gen_changelog.ps1 [-Since <ref>]
param([string]$Since = '')

$ErrorActionPreference = 'Continue'
$MyDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath (Join-Path $MyDir '..')

$args = @('log', '--pretty=format:%h|%s')
if ($Since) { $args += "$Since..HEAD" }
$log = git @args 2>$null

$sections = @{ feat = @(); fix = @(); docs = @(); test = @(); chore = @(); other = @() }
foreach ($line in $log) {
    if (-not $line -or -not $line.Contains('|')) { continue }
    $parts = $line.Split('|', 2)
    $hash = $parts[0]
    $msg = $parts[1]
    $p = $msg.Split('(', 2)
    if ($p.Count -ge 2) {
        $tag = $p[0].Trim()
        if ($sections.ContainsKey($tag)) { $sections[$tag] += ("* $hash $msg") }
        else { $sections['other'] += ("* $hash $msg") }
    } else {
        $sections['other'] += ("* $hash $msg")
    }
}

$now = Get-Date -Format 'yyyy-MM-dd'
Write-Host "## [$now]"
$order = @('feat', 'fix', 'docs', 'test', 'chore', 'other')
$labels = @{ feat = 'Features'; fix = 'Fixes'; docs = 'Docs'; test = 'Tests'; chore = 'Chore'; other = 'Other' }
foreach ($k in $order) {
    if ($sections[$k].Count -gt 0) {
        Write-Host ""
        Write-Host "### $($labels[$k])"
        $sections[$k] | ForEach-Object { Write-Host "  $_" }
    }
}