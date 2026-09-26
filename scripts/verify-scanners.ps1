param([string]$Root = (Split-Path -Parent $PSScriptRoot))
$ErrorActionPreference = 'Stop'
$manifestPath = Join-Path $Root 'config/scanners.yaml'
$manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
$failed = $false
foreach ($scanner in $manifest.scanners) {
    $artifact = Join-Path $Root $scanner.runtime_path
    if (-not (Test-Path -LiteralPath $artifact -PathType Leaf)) {
        Write-Error "$($scanner.name): artifact is absent: $artifact" -ErrorAction Continue
        $failed = $true
        continue
    }
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $artifact).Hash.ToLowerInvariant()
    if ($actual -ne $scanner.artifact_sha256) {
        Write-Error "$($scanner.name): SHA-256 mismatch" -ErrorAction Continue
        $failed = $true
        continue
    }
    if ($scanner.name -ne 'opa' -and $scanner.worker_image -match '@sha256:0{64}$') {
        Write-Error "$($scanner.name): verified internal worker image is not provisioned" -ErrorAction Continue
        $failed = $true
        continue
    }
    Write-Output "$($scanner.name) $($scanner.approved_version): verified"
}
if ($failed) { exit 1 }
