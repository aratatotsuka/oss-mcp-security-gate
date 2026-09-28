param(
    [Parameter(Mandatory=$true)][string]$Root
)

$suffix = if ($env:OS -eq 'Windows_NT') { '.exe' } else { '' }
$gate = Join-Path $Root "bin/security-gate$suffix"
$sourceFiles = @(Get-ChildItem -LiteralPath (Join-Path $Root 'cmd'), (Join-Path $Root 'internal') -Recurse -File -Filter '*.go')
$sourceFiles += Get-Item -LiteralPath (Join-Path $Root 'go.mod')
$newestSource = $sourceFiles | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1

if (-not (Test-Path -LiteralPath $gate -PathType Leaf) -or
    (Get-Item -LiteralPath $gate).LastWriteTimeUtc -lt $newestSource.LastWriteTimeUtc) {
    Write-Host 'Building Security Gate CLI from current source...'
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $gate) | Out-Null
    Push-Location $Root
    try {
        & go build -o $gate ./cmd/security-gate
        if ($LASTEXITCODE -ne 0) { throw 'Security Gate CLI build failed' }
    } finally {
        Pop-Location
    }
}

$gate
