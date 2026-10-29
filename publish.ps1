# 建独立仓库并推送（GitHub 二次限流期间可随时重跑，幂等）
#   pwsh -File publish.ps1
$ErrorActionPreference = 'Stop'
$repo = 'Umagic-v1.12-Hardstone-APP-2api'
$desc = 'Umagic v1.12.0 (Hardstone/dailyjoypro) APK reverse + 2API gateway. Protocol fully recovered; upstream ai/art/* gated by Play Integrity (status 114).'

Set-Location $PSScriptRoot

$exists = gh api "repos/lza6/$repo" --jq '.full_name' 2>$null
if (-not $exists) {
    Write-Host "创建仓库 lza6/$repo ..."
    gh api -X POST user/repos -f name="$repo" -f description="$desc" -F private=false --jq '.full_name'
    if (-not $?) { Write-Host "创建被限流/失败，稍后重跑本脚本即可"; exit 1 }
} else {
    Write-Host "仓库已存在：$exists"
}

if (-not (git remote | Select-String -Quiet '^dedicated$')) {
    git remote add dedicated "https://github.com/lza6/$repo.git"
}
git push -u dedicated master:master
gh api -X PATCH "repos/lza6/$repo" -f default_branch=master --jq '.default_branch'

Write-Host "完成：https://github.com/lza6/$repo"
