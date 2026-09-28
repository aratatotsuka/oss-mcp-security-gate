param(
    [Parameter(ParameterSetName='Local', Mandatory=$true)][string]$Target,
    [Parameter(ParameterSetName='Git', Mandatory=$true)][string]$RepositoryUrl,
    [Parameter(ParameterSetName='Git')][string]$Commit,
    [string]$Output
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$gate = & (Join-Path $PSScriptRoot 'ensure-gate.ps1') -Root $root

if ($PSCmdlet.ParameterSetName -eq 'Git') {
    if ($RepositoryUrl -notmatch '^https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$') {
        throw 'RepositoryUrl must be a GitHub HTTPS repository URL'
    }
    $owner = $Matches[1]
    $name = $Matches[2]
    $targetPath = Join-Path $root ("var/targets/$owner/$name")
    if (Test-Path -LiteralPath $targetPath) {
        throw "Target already exists. Inspect it and pass -Target to scan it: $targetPath"
    }
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $targetPath) | Out-Null
    & git clone --no-checkout -- $RepositoryUrl $targetPath
    if ($LASTEXITCODE -ne 0) { exit 4 }
    if ($Commit) {
        if ($Commit -notmatch '^[0-9a-fA-F]{40}$') { throw 'Commit must be a full 40-character Git commit ID' }
        & git -C $targetPath checkout --detach -- $Commit
    } else {
        & git -C $targetPath checkout --detach
    }
    if ($LASTEXITCODE -ne 0) { exit 4 }
    & git -C $targetPath rev-parse HEAD
    if ($LASTEXITCODE -ne 0) { exit 4 }
} else {
    $targetPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Target)
    if (-not (Test-Path -LiteralPath $targetPath -PathType Container)) {
        throw "Target directory does not exist: $targetPath"
    }
}

$outputPath = if ($Output) {
    $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Output)
} else {
    & (Join-Path $PSScriptRoot 'report-output.ps1') -Root $root -Kind 'oss' -TargetPath $targetPath
}
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $outputPath) | Out-Null
& $gate scan --root $root --target $targetPath --type oss --output $outputPath
exit $LASTEXITCODE
