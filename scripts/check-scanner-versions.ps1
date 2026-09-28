param(
    [string]$Root = (Split-Path -Parent $PSScriptRoot),
    [string[]]$Scanner
)

$ErrorActionPreference = 'Stop'
$manifestPath = Join-Path $Root 'config/scanners.yaml'
$manifest = Get-Content -Raw -Encoding utf8 -LiteralPath $manifestPath | ConvertFrom-Json
$entries = @($manifest.scanners)
if ($Scanner) {
    $unknown = @($Scanner | Where-Object { $_ -notin @($entries | ForEach-Object name) })
    if ($unknown.Count -gt 0) { throw "Scanner is not in the approved manifest: $($unknown -join ', ')" }
    $entries = @($entries | Where-Object { $_.name -in $Scanner })
}

function ConvertTo-ReleaseVersion([string]$Value) {
    $number = $Value -replace '^[vV]', ''
    if ($number -notmatch '^\d+\.\d+\.\d+(?:\.\d+)?$') {
        throw "Version is not a numeric release: $Value"
    }
    [version]::Parse($number)
}

$results = @()
foreach ($entry in $entries) {
    $source = ''
    $latest = ''
    $status = 'CHECK_FAILED'
    $errorMessage = ''
    try {
        $artifactUri = [uri]$entry.artifact_uri
        $headers = @{ 'User-Agent' = 'security-gate-version-check'; Accept = 'application/json' }
        if ($artifactUri.Host -eq 'github.com' -and
            $artifactUri.AbsolutePath -match '^/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/releases/download/') {
            $owner = $Matches[1]
            $repo = $Matches[2]
            $source = "https://github.com/$owner/$repo/releases/latest"
            $headers.Accept = 'application/vnd.github+json'
            $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$owner/$repo/releases/latest" -Headers $headers -TimeoutSec 20
            $latest = [string]$release.tag_name
        } elseif ($entry.name -eq 'mcp-scanner' -and $artifactUri.Host -eq 'files.pythonhosted.org') {
            $source = 'https://pypi.org/project/cisco-ai-mcp-scanner/'
            $release = Invoke-RestMethod -Uri 'https://pypi.org/pypi/cisco-ai-mcp-scanner/json' -Headers $headers -TimeoutSec 20
            $latest = [string]$release.info.version
        } else {
            throw "No trusted release lookup for $($entry.artifact_uri)"
        }
        $configuredVersion = ConvertTo-ReleaseVersion ([string]$entry.approved_version)
        $latestVersion = ConvertTo-ReleaseVersion $latest
        if ($configuredVersion -eq $latestVersion) {
            $status = 'CURRENT'
        } elseif ($configuredVersion -lt $latestVersion) {
            $status = 'UPDATE_AVAILABLE'
        } else {
            $status = 'AHEAD_OF_LATEST'
        }
    } catch {
        $errorMessage = $_.Exception.Message
    }
    $results += [pscustomobject][ordered]@{
        scanner = [string]$entry.name
        configured_version = [string]$entry.approved_version
        latest_version = $latest
        status = $status
        source = $source
        error = $errorMessage
    }
}

$results
if (@($results | Where-Object { $_.status -in @('CHECK_FAILED', 'AHEAD_OF_LATEST') }).Count -gt 0) { exit 1 }
if (@($results | Where-Object { $_.status -eq 'UPDATE_AVAILABLE' }).Count -gt 0) { exit 2 }
exit 0
