param(
    [ValidateSet('Prepare', 'Apply', 'Auto')][string]$Mode = 'Prepare',
    [string[]]$Scanner,
    [string]$Candidate,
    [string]$ApprovalRecord,
    [string]$Root = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'scanner-update-common.ps1')
$rootPath = Resolve-SecurityPath $Root
$manifestPath = Join-Path $rootPath 'config/scanners.yaml'
$manifest = Read-ScannerUpdateJSON $manifestPath
$shaPattern = '^[0-9a-f]{64}$'

function Assert-WithinRoot([string]$Path) {
    $full = Resolve-SecurityPath $Path
    $prefix = $rootPath.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    if (-not $full.StartsWith($prefix, (Get-SecurityPathComparison))) {
        throw "Path is outside repository: $full"
    }
    return $full
}

function Get-Sha256([string]$Path) {
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

function Assert-Version([string]$Value) {
    $number = $Value -replace '^[vV]', ''
    if ($number -notmatch '^\d+\.\d+\.\d+(?:\.\d+)?$') { throw "Unsupported release version: $Value" }
    return [version]::Parse($number)
}

function Get-LatestArtifact($Entry) {
    $oldUri = [uri]$Entry.artifact_uri
    $headers = @{ 'User-Agent' = 'security-gate-version-update'; Accept = 'application/json' }
    if ($oldUri.Host -eq 'github.com' -and $oldUri.AbsolutePath -match '^/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/releases/download/') {
        $owner = $Matches[1]; $repo = $Matches[2]
        $headers.Accept = 'application/vnd.github+json'
        $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$owner/$repo/releases/latest" -Headers $headers -TimeoutSec 30
        $version = ([string]$release.tag_name) -replace '^[vV]', ''
        $null = Assert-Version $version
        if ($release.draft -or $release.prerelease) { throw "Latest release is not stable: $($Entry.name)" }
        $oldFile = [IO.Path]::GetFileName($oldUri.AbsolutePath)
        $newFile = $oldFile.Replace([string]$Entry.approved_version, $version)
        $assets = @($release.assets | Where-Object { $_.name -ceq $newFile })
        if ($assets.Count -ne 1) { throw "Expected one release asset named $newFile; found $($assets.Count)" }
        $asset = $assets[0]
        $uri = [uri]$asset.browser_download_url
        $expectedPrefix = "/$owner/$repo/releases/download/"
        if ($uri.Scheme -ne 'https' -or $uri.Host -ne 'github.com' -or
            -not $uri.AbsolutePath.StartsWith($expectedPrefix, [StringComparison]::Ordinal) -or
            [IO.Path]::GetFileName($uri.AbsolutePath) -cne $newFile) {
            throw "Unexpected release asset URL: $uri"
        }
        $sha = ([string]$asset.digest) -replace '^sha256:', ''
        $source = "https://api.github.com/repos/$owner/$repo/releases/latest"
    } elseif ($Entry.name -eq 'mcp-scanner' -and $oldUri.Host -eq 'files.pythonhosted.org') {
        $release = Invoke-RestMethod -Uri 'https://pypi.org/pypi/cisco-ai-mcp-scanner/json' -Headers $headers -TimeoutSec 30
        $version = [string]$release.info.version
        $null = Assert-Version $version
        $newFile = "cisco_ai_mcp_scanner-$version-py3-none-any.whl"
        $assets = @($release.urls | Where-Object { $_.filename -ceq $newFile })
        if ($assets.Count -ne 1) { throw "Expected one PyPI wheel named $newFile; found $($assets.Count)" }
        $asset = $assets[0]
        $uri = [uri]$asset.url
        if ($uri.Scheme -ne 'https' -or $uri.Host -ne 'files.pythonhosted.org' -or
            [IO.Path]::GetFileName($uri.AbsolutePath) -cne $newFile) { throw "Unexpected PyPI asset URL: $uri" }
        $sha = [string]$asset.digests.sha256
        $source = 'https://pypi.org/pypi/cisco-ai-mcp-scanner/json'
    } else {
        throw "No trusted release source for $($Entry.name)"
    }
    if ($sha -cnotmatch $shaPattern) { throw "Release SHA-256 is missing or malformed for $($Entry.name)" }
    return [pscustomobject]@{ version = $version; uri = $uri.AbsoluteUri; filename = $newFile; sha256 = $sha; source = $source }
}

if ($Mode -eq 'Prepare') {
    if ($Candidate -or $ApprovalRecord) { throw 'Candidate and ApprovalRecord are only used with -Mode Apply' }
    $entries = @($manifest.scanners)
    if ($Scanner) {
        $unknown = @($Scanner | Where-Object { $_ -notin @($entries | ForEach-Object name) })
        if ($unknown.Count) { throw "Unknown scanner: $($unknown -join ', ')" }
        $entries = @($entries | Where-Object { $_.name -in $Scanner })
    }
    $baseSha = Get-Sha256 $manifestPath
    foreach ($entry in $entries) {
        $latest = Get-LatestArtifact $entry
        $currentVersion = Assert-Version ([string]$entry.approved_version)
        $latestVersion = Assert-Version $latest.version
        if ($latestVersion -lt $currentVersion) { throw "Latest release is older than approved version: $($entry.name)" }
        if ($latestVersion -eq $currentVersion) {
            [pscustomobject]@{ scanner = $entry.name; version = $entry.approved_version; status = 'CURRENT' }
            continue
        }
        $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
        $bundle = Assert-WithinRoot (Join-Path $rootPath "var/update-candidates/$($entry.name)/$($latest.version)/$stamp-$([guid]::NewGuid().ToString('N').Substring(0, 8))")
        New-Item -ItemType Directory -Path $bundle -Force | Out-Null
        $artifact = Assert-WithinRoot (Join-Path $bundle $latest.filename)
        Invoke-WebRequest -UseBasicParsing -Uri $latest.uri -OutFile $artifact -TimeoutSec 300
        $actualSha = Get-Sha256 $artifact
        if ($actualSha -cne $latest.sha256) { throw "Artifact SHA-256 mismatch; file remains quarantined: $artifact" }
        $metadata = [ordered]@{
            scanner = [string]$entry.name
            from_version = [string]$entry.approved_version
            version = $latest.version
            artifact_uri = $latest.uri
            artifact_filename = $latest.filename
            artifact_sha256 = $latest.sha256
            source = $latest.source
            base_manifest_sha256 = $baseSha
            status = 'PENDING_APPROVAL'
        }
        $metadataPath = Join-Path $bundle 'candidate.json'
        $metadata | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 -LiteralPath $metadataPath
        $approvalTemplate = [ordered]@{
            scanner = [string]$entry.name
            version = $latest.version
            artifact_sha256 = $latest.sha256
            candidate_sha256 = Get-Sha256 $metadataPath
            signature_verified = $false
            provenance_verified = $false
            advisory_checked = $false
            advisory_checked_at = ''
            compatibility_tests_passed = $false
            signature_method = ''
            provenance_method = ''
            worker_image = ''
            approver = ''
            evidence = ''
        }
        $approvalTemplate | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 -LiteralPath (Join-Path $bundle 'approval.template.json')
        [pscustomobject]@{ scanner = $entry.name; version = $latest.version; status = 'PENDING_APPROVAL'; candidate = $metadataPath; approval_template = (Join-Path $bundle 'approval.template.json') }
    }
    return
}

if ($Mode -eq 'Auto' -and -not $Candidate) {
    if ($ApprovalRecord) { throw '-ApprovalRecord is not used with -Mode Auto' }
    if ($Scanner -and (@($Scanner | Where-Object { $_ -ne 'opa' }).Count -gt 0)) {
        throw 'AUTO_UPDATE_UNSUPPORTED: only OPA has an automated production verification path'
    }
    $prepared = @(& $PSCommandPath -Mode Prepare -Scanner opa -Root $rootPath)
    foreach ($result in $prepared) {
        if ($result.status -eq 'CURRENT') { $result; continue }
        & $PSCommandPath -Mode Auto -Candidate $result.candidate -Root $rootPath
    }
    return
}
if ($Scanner) { throw '-Scanner is only used with -Mode Prepare or automatic discovery' }
if (-not $Candidate -or ($Mode -eq 'Apply' -and -not $ApprovalRecord)) { throw 'A candidate is required; -Mode Apply also requires -ApprovalRecord' }
if ($Mode -eq 'Auto' -and $ApprovalRecord) { throw '-ApprovalRecord is not used with -Mode Auto' }
$candidatePath = Assert-WithinRoot $Candidate
$candidateData = Read-ScannerUpdateJSON $candidatePath
if ($Mode -eq 'Apply') {
    $approvalPath = Assert-WithinRoot $ApprovalRecord
    $approval = Read-ScannerUpdateJSON $approvalPath
}
$candidateDir = Split-Path -Parent $candidatePath
$expectedCandidateRoot = Assert-WithinRoot (Join-Path $rootPath 'var/update-candidates')
if (-not $candidateDir.StartsWith(($expectedCandidateRoot + [IO.Path]::DirectorySeparatorChar), (Get-SecurityPathComparison))) {
    throw 'Candidate must be under var/update-candidates'
}
if ([IO.Path]::GetFileName($candidatePath) -cne 'candidate.json') { throw 'Expected candidate.json' }
if ([string]$candidateData.artifact_filename -notmatch '^[A-Za-z0-9_.-]+$') { throw 'Invalid artifact filename' }
$artifact = Assert-WithinRoot (Join-Path $candidateDir ([string]$candidateData.artifact_filename))
if ([string]$candidateData.artifact_sha256 -cnotmatch $shaPattern -or
    (Get-Sha256 $artifact) -cne [string]$candidateData.artifact_sha256) { throw 'Candidate artifact SHA-256 mismatch' }
if ((Get-Sha256 $manifestPath) -cne [string]$candidateData.base_manifest_sha256) {
    throw 'Approved manifest changed since candidate preparation; prepare again'
}
$entries = @($manifest.scanners | Where-Object { $_.name -ceq $candidateData.scanner })
if ($entries.Count -ne 1) { throw 'Candidate scanner is not in manifest' }
$entry = $entries[0]
if ([string]$entry.approved_version -cne [string]$candidateData.from_version) { throw 'Candidate base version changed' }
if ((Assert-Version ([string]$candidateData.version)) -le (Assert-Version ([string]$entry.approved_version))) { throw 'Candidate is not newer' }

if ($Mode -eq 'Auto') {
    if ($entry.name -ne 'opa') { throw 'AUTO_UPDATE_UNSUPPORTED: worker image and scanner-specific verification are not automated' }
    if ($IsLinux -ne $true) { throw 'AUTO_UPDATE_UNSUPPORTED: run OPA promotion with PowerShell 7 on a Linux update worker' }
    $version = [string]$candidateData.version
    $expectedUri = "https://github.com/open-policy-agent/opa/releases/download/v$version/opa_linux_amd64_static"
    if ([string]$candidateData.artifact_uri -cne $expectedUri -or
        [string]$candidateData.artifact_filename -cne 'opa_linux_amd64_static') {
        throw 'OPA candidate is not the expected official Linux release artifact'
    }
    foreach ($command in @('gh', 'go', 'chmod')) {
        if (-not (Get-Command $command -ErrorAction SilentlyContinue)) { throw "AUTO_UPDATE_UNSUPPORTED: $command is required" }
    }
    $tag = "v$version"
    $attestation = & gh release verify-asset $tag $artifact --repo open-policy-agent/opa --format json 2>&1
    if ($LASTEXITCODE -ne 0) { throw "GitHub release asset attestation verification failed: $attestation" }
    $verifiedRelease = $attestation | Out-String | ConvertFrom-Json
    if ($null -eq $verifiedRelease) { throw 'GitHub release asset attestation was empty' }
    $attestationPath = Join-Path $candidateDir 'release-attestation.json'
    [IO.File]::WriteAllText($attestationPath, (($attestation | Out-String).Trim() + [Environment]::NewLine), [Text.UTF8Encoding]::new($false))

    $headers = @{ 'User-Agent' = 'security-gate-auto-update'; Accept = 'application/vnd.github+json' }
    # Capture before the request; advisories published while tests run must be
    # discovered on the next update rather than counted as already reviewed.
    $advisoryCheckedAt = [datetimeoffset]::UtcNow
    $advisoryResponse = Invoke-RestMethod -Uri 'https://api.github.com/repos/open-policy-agent/opa/security-advisories?state=published&per_page=100' -Headers $headers -TimeoutSec 30
    $advisories = @($advisoryResponse)
    if ($advisories.Count -ge 100) { throw 'Advisory list may be incomplete; automatic promotion stopped' }
    $reviewedThrough = Get-AdvisoryReviewTime $entry
    foreach ($advisory in $advisories) {
        if ((ConvertTo-AdvisoryTimestamp $advisory.updated_at) -gt $reviewedThrough) {
            throw "New or revised advisory $($advisory.ghsa_id) needs review"
        }
    }

    Test-NativeOPAUpdate $artifact $version (Join-Path $rootPath 'policies')
    $previousOpaTest = $env:OPA_TEST_BIN
    try {
        $env:OPA_TEST_BIN = $artifact
        Push-Location $rootPath
        try {
            $goOutput = & go test ./... 2>&1
            if ($LASTEXITCODE -ne 0) { throw "Go tests failed: $goOutput" }
        } finally { Pop-Location }
    } finally { $env:OPA_TEST_BIN = $previousOpaTest }
    $verificationRecord = [ordered]@{
        scanner = 'opa'; version = $version; artifact_sha256 = [string]$candidateData.artifact_sha256
        candidate_sha256 = Get-Sha256 $candidatePath
        release_attestation = 'gh release verify-asset'
        release_attestation_sha256 = Get-Sha256 $attestationPath
        advisory_source = 'https://api.github.com/repos/open-policy-agent/opa/security-advisories'
        advisory_count = $advisories.Count
        advisory_checked_at = $advisoryCheckedAt.UtcDateTime.ToString('o')
        policy_tests = 'PASS'; go_tests = 'PASS'; checked_at = (Get-Date).ToUniversalTime().ToString('o')
    }
    $verificationRecord | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 -LiteralPath (Join-Path $candidateDir 'automatic-verification.json')
    $entry.signature_verification = 'GitHub cryptographically signed release asset attestation'
    $entry.provenance_verification = 'GitHub signed release identity and asset digest'
} else {
    # Manual approval remains available for products whose verification cannot yet be automated.
    if ([string]$approval.scanner -cne [string]$candidateData.scanner -or
        [string]$approval.version -cne [string]$candidateData.version -or
        [string]$approval.artifact_sha256 -cne [string]$candidateData.artifact_sha256 -or
        [string]$approval.candidate_sha256 -cne (Get-Sha256 $candidatePath) -or
        [string]::IsNullOrWhiteSpace([string]$approval.approver) -or
        [string]::IsNullOrWhiteSpace([string]$approval.evidence) -or
        $approval.signature_verified -cne $true -or
        $approval.provenance_verified -cne $true -or
        $approval.advisory_checked -cne $true -or
        $approval.compatibility_tests_passed -cne $true) {
        throw 'Approval record is incomplete or does not match the candidate'
    }
    if ($entry.name -ne 'opa') {
        $image = [string]$approval.worker_image
        if ($image -cnotmatch '^\S+@sha256:[0-9a-f]{64}$' -or $image -match '@sha256:0{64}$' -or
            $image -match 'registry\.example\.invalid') { throw 'Approval requires a real immutable worker image digest' }
        $entry.worker_image = $image
    }
    $advisoryCheckedAt = ConvertTo-AdvisoryTimestamp $approval.advisory_checked_at
    $entry.signature_verification = [string]$approval.signature_method
    $entry.provenance_verification = [string]$approval.provenance_method
}
if ($entry.name -eq 'opa') {
    if ([string]::IsNullOrWhiteSpace([string]$entry.worker_image)) {
        if ($Mode -eq 'Apply') { Test-NativeOPAUpdate $artifact ([string]$candidateData.version) (Join-Path $rootPath 'policies') }
    } else {
        # Preserve Docker execution and bind it to this exact candidate.
        $entry.worker_image = New-OPAUpdateImage $artifact ([string]$candidateData.version) (Join-Path $rootPath 'policies') $candidateDir
    }
}
$newRuntime = ([string]$entry.runtime_path).Replace([string]$entry.approved_version, [string]$candidateData.version)
if ($newRuntime -ceq [string]$entry.runtime_path -or [IO.Path]::GetFileName($newRuntime) -cne $candidateData.artifact_filename) {
    throw 'Candidate runtime path could not be derived safely'
}
$runtimePath = Assert-WithinRoot (Join-Path $rootPath $newRuntime)
if (Test-Path -LiteralPath $runtimePath) { throw "Runtime artifact already exists: $runtimePath" }
$entry.approved_version = [string]$candidateData.version
$entry.artifact_uri = [string]$candidateData.artifact_uri
$entry.artifact_sha256 = [string]$candidateData.artifact_sha256
$entry.runtime_path = $newRuntime.Replace('\', '/')
$entry.approved_date = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd')
$entry.security_advisory_checked_date = $advisoryCheckedAt.UtcDateTime.ToString('yyyy-MM-dd')
$entry | Add-Member -NotePropertyName security_advisory_checked_at -NotePropertyValue $advisoryCheckedAt.UtcDateTime.ToString('o') -Force
if ([string]::IsNullOrWhiteSpace($entry.signature_verification) -or [string]::IsNullOrWhiteSpace($entry.provenance_verification)) {
    throw 'Approval must document signature_method and provenance_method'
}
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $runtimePath) | Out-Null
Copy-Item -LiteralPath $artifact -Destination $runtimePath
if ((Get-Sha256 $runtimePath) -cne [string]$candidateData.artifact_sha256) { throw 'Copied runtime artifact SHA-256 mismatch' }
if ($entry.name -eq 'opa' -and [string]::IsNullOrWhiteSpace([string]$entry.worker_image)) {
    Test-NativeOPAUpdate $runtimePath ([string]$candidateData.version) (Join-Path $rootPath 'policies')
}
$newManifest = $manifest | ConvertTo-Json -Depth 20
$tempManifest = Join-Path (Split-Path -Parent $manifestPath) ('.scanners-' + [guid]::NewGuid().ToString('N') + '.tmp')
$backupManifest = Join-Path $candidateDir 'scanners.before.yaml'
if (Test-Path -LiteralPath $backupManifest) { throw 'Candidate already has a manifest backup' }
try {
    [IO.File]::WriteAllText($tempManifest, $newManifest + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
    $null = Read-ScannerUpdateJSON $tempManifest
    if ((Get-Sha256 $manifestPath) -cne [string]$candidateData.base_manifest_sha256) { throw 'Manifest changed during promotion' }
    [IO.File]::Replace($tempManifest, $manifestPath, $backupManifest)
} finally {
    if (Test-Path -LiteralPath $tempManifest) { Remove-Item -LiteralPath $tempManifest }
}
[pscustomobject]@{ scanner = $entry.name; version = $entry.approved_version; status = 'MANIFEST_UPDATED'; runtime_path = $runtimePath; manifest = $manifestPath }
