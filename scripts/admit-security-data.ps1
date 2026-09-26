param(
    [Parameter(Mandatory=$true)][ValidateSet('osv-scanner','trivy')][string]$Scanner,
    [Parameter(Mandatory=$true)][string]$Artifact,
    [Parameter(Mandatory=$true)][string]$Version,
    [Parameter(Mandatory=$true)][datetime]$UpdatedAt,
    [Parameter(Mandatory=$true)][string]$ExpectedSha256,
    [Parameter(Mandatory=$true)][string]$ApprovalRecord,
    [string]$Root = (Split-Path -Parent $PSScriptRoot)
)
$ErrorActionPreference = 'Stop'
$rootPath = [IO.Path]::GetFullPath($Root)
$quarantineRoot = [IO.Path]::GetFullPath((Join-Path $rootPath 'var/update-quarantine'))
$artifactPath = [IO.Path]::GetFullPath($Artifact)
if (-not $artifactPath.StartsWith($quarantineRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Artifact must remain inside the update quarantine until admission'
}
if (-not (Test-Path -LiteralPath $artifactPath -PathType Leaf)) { throw 'Artifact not found' }
$approvalPath = [IO.Path]::GetFullPath($ApprovalRecord)
if (-not $approvalPath.StartsWith($quarantineRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Approval record must be inside update quarantine'
}
$approval = Get-Content -Raw -LiteralPath $approvalPath | ConvertFrom-Json
if ($approval.scanner -ne $Scanner -or $approval.version -ne $Version -or
    $approval.signature_verified -ne $true -or $approval.provenance_verified -ne $true -or
    [string]::IsNullOrWhiteSpace($approval.approver) -or [string]::IsNullOrWhiteSpace($approval.evidence)) {
    throw 'Approval record is incomplete or does not match the artifact'
}
$expected = $ExpectedSha256.ToLowerInvariant()
if ($expected -notmatch '^[0-9a-f]{64}$') { throw 'ExpectedSha256 is malformed' }
$actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $artifactPath).Hash.ToLowerInvariant()
if ($actual -ne $expected) { throw 'SECURITY_DATA_HASH_MISMATCH' }

$cache = [IO.Path]::GetFullPath((Join-Path $rootPath "var/cache/$Scanner"))
if (-not $cache.StartsWith($rootPath + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'Invalid cache path' }
New-Item -ItemType Directory -Force -Path $cache | Out-Null
$name = [IO.Path]::GetFileName($artifactPath)
$destination = Join-Path $cache $name
Copy-Item -LiteralPath $artifactPath -Destination $destination
$metadata = [ordered]@{
    version = $Version
    updated_at = $UpdatedAt.ToUniversalTime().ToString('o')
    artifact = $name
    sha256 = $actual
    approver = $approval.approver
    approval_evidence = $approval.evidence
}
$metadata | ConvertTo-Json | Set-Content -Encoding utf8 -LiteralPath (Join-Path $cache 'metadata.json')
Write-Output "Admitted $Scanner security data $Version with SHA-256 $actual"
