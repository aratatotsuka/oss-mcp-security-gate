param(
    [Parameter(Mandatory=$true)][string]$Scanner,
    [switch]$Execute,
    [string]$Root = (Split-Path -Parent $PSScriptRoot)
)
$ErrorActionPreference = 'Stop'
$manifest = Get-Content -Raw -LiteralPath (Join-Path $Root 'config/scanners.yaml') | ConvertFrom-Json
$entry = $manifest.scanners | Where-Object { $_.name -eq $Scanner }
if ($null -eq $entry) { throw "Scanner is not approved: $Scanner" }
if (-not $Execute) {
    [pscustomobject]@{ scanner=$entry.name; version=$entry.approved_version; uri=$entry.artifact_uri; expected_sha256=$entry.artifact_sha256; action='PLAN_ONLY' } | ConvertTo-Json
    exit 0
}

$stamp = Get-Date -Format 'yyyyMMddTHHmmssZ'
$quarantine = Join-Path $Root "var/update-quarantine/$stamp/$Scanner"
New-Item -ItemType Directory -Force -Path $quarantine | Out-Null
$download = Join-Path $quarantine ([IO.Path]::GetFileName(([Uri]$entry.artifact_uri).AbsolutePath))
Invoke-WebRequest -UseBasicParsing -Uri $entry.artifact_uri -OutFile $download
$actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $download).Hash.ToLowerInvariant()
if ($actual -ne $entry.artifact_sha256) {
    throw "SCANNER_HASH_MISMATCH scanner=$($entry.name) expected=$($entry.artifact_sha256) actual=$actual quarantined_path=$download"
}

# Admission deliberately stops here. Signature/provenance verification commands
# are scanner-specific and documented in docs/detailed-design.md. After those
# checks and advisory review, an approver copies the verified artifact to the
# exact runtime_path and replaces the zero worker digest with the signed internal
# image digest. Scan workers never call this script.
[pscustomobject]@{
    scanner=$entry.name
    version=$entry.approved_version
    quarantined_path=$download
    sha256=$actual
    signature_verification=$entry.signature_verification
    provenance_verification=$entry.provenance_verification
    status='AWAITING_SIGNATURE_PROVENANCE_AND_ADVISORY_APPROVAL'
} | ConvertTo-Json -Depth 4
