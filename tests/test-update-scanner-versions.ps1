$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$fixture = Join-Path $repo ('var/update-script-test-' + [guid]::NewGuid().ToString('N'))
if (-not ([IO.Path]::GetFullPath($fixture)).StartsWith(([IO.Path]::GetFullPath((Join-Path $repo 'var')) + [IO.Path]::DirectorySeparatorChar), [StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe fixture path' }
$updateScript = Join-Path $repo 'scripts/update-scanner-versions.ps1'
. (Join-Path $repo 'scripts/scanner-update-common.ps1')
$global:SecurityUpdateTestState = @{}
function docker {
    $a = @($args)
    $global:LASTEXITCODE = 0
    $global:SecurityUpdateTestState.calls += ,$a
    if ($a[0] -eq 'build') {
        if ($global:SecurityUpdateTestState.fail -eq 'build') { $global:LASTEXITCODE = 1; return 'build failed' }
        $copied = Join-Path $a[-1] 'opa'
        if ((Get-FileHash -LiteralPath $copied -Algorithm SHA256).Hash -ne $global:SecurityUpdateTestState.artifactHash) { throw 'Image did not contain the candidate artifact' }
        return ('sha256:' + ('c' * 64))
    }
    if ($a[-1] -eq 'version') {
        if ($global:SecurityUpdateTestState.fail -eq 'version') { return 'Version: 1.0.0' }
        return 'Version: 2.0.0'
    }
    if ($a -contains 'test') {
        if ($global:SecurityUpdateTestState.fail -eq 'policy') { $global:LASTEXITCODE = 1; return 'policy failed' }
        return 'PASS: 1/1'
    }
    throw "Unexpected Docker call: $a"
}
function gh { $global:LASTEXITCODE = 0; '{"verification":"fixture"}' }
function go {
    $global:LASTEXITCODE = 0
    if (-not $env:OPA_TEST_BIN) { throw 'Automatic tests did not use the candidate OPA' }
    $global:SecurityUpdateTestState.goTestAt = [datetimeoffset]::UtcNow
    'PASS: fixture Go tests'
}
function Invoke-RestMethod {
    param([string]$Uri, $Headers, $TimeoutSec)
    if ($Uri -cne 'https://api.github.com/repos/open-policy-agent/opa/security-advisories?state=published&per_page=100') { throw "Unexpected network request: $Uri" }
    $global:SecurityUpdateTestState.advisoryRequestAt = [datetimeoffset]::UtcNow
    return ,@($global:SecurityUpdateTestState.advisories)
}

function New-Fixture([string]$Name, [bool]$Container) {
    $root = Join-Path $fixture $Name
    $bundle = Join-Path $root 'var/update-candidates/opa/2.0.0/test'
    New-Item -ItemType Directory -Force -Path (Join-Path $root 'config'), (Join-Path $root 'policies'), $bundle | Out-Null
    $entry = [ordered]@{
        name = 'opa'; approved_version = '1.0.0'
        artifact_uri = 'https://github.com/open-policy-agent/opa/releases/download/v1.0.0/opa_linux_amd64_static'
        artifact_sha256 = 'a' * 64; runtime_path = 'var/scanners/opa/1.0.0/opa_linux_amd64_static'
        worker_image = $(if ($Container) { 'sha256:' + ('b' * 64) } else { '' })
        signature_verification = 'old'; provenance_verification = 'old'
        approved_date = '2026-01-01'; security_advisory_checked_date = '2026-01-01'
    }
    $manifestPath = Join-Path $root 'config/scanners.yaml'
    @{ schema_version = '1.0'; scanners = @($entry) } | ConvertTo-Json -Depth 10 | Set-Content -Encoding UTF8 -LiteralPath $manifestPath
    $artifactPath = Join-Path $bundle 'opa_linux_amd64_static'
    $payload = "#!/bin/sh`nif [ `"`$1`" = version ]; then echo 'Version: 2.0.0'; else echo 'PASS: 1/1'; fi`n"
    [IO.File]::WriteAllText($artifactPath, $payload, [Text.UTF8Encoding]::new($false))
    if ($IsLinux -eq $true) { & chmod 644 $artifactPath; if ($LASTEXITCODE -ne 0) { throw 'Fixture chmod failed' } }
    $artifactSha = (Get-FileHash -Algorithm SHA256 -LiteralPath $artifactPath).Hash.ToLowerInvariant()
    $manifestSha = (Get-FileHash -Algorithm SHA256 -LiteralPath $manifestPath).Hash.ToLowerInvariant()
    $candidatePath = Join-Path $bundle 'candidate.json'
    [ordered]@{
        scanner = 'opa'; from_version = '1.0.0'; version = '2.0.0'
        artifact_uri = 'https://github.com/open-policy-agent/opa/releases/download/v2.0.0/opa_linux_amd64_static'
        artifact_filename = 'opa_linux_amd64_static'; artifact_sha256 = $artifactSha
        source = 'fixture'; base_manifest_sha256 = $manifestSha; status = 'PENDING_APPROVAL'
    } | ConvertTo-Json | Set-Content -Encoding UTF8 -LiteralPath $candidatePath
    $approvalPath = Join-Path $bundle 'approval.json'
    $approval = [ordered]@{
        scanner = 'opa'; version = '2.0.0'; artifact_sha256 = $artifactSha
        candidate_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $candidatePath).Hash.ToLowerInvariant()
        signature_verified = $true; provenance_verified = $true; advisory_checked = $true
        advisory_checked_at = '2026-01-01T01:00:00Z'
        compatibility_tests_passed = $true; signature_method = 'fixture'; provenance_method = 'fixture'
        approver = 'fixture'; evidence = 'fixture'
    }
    $approval | ConvertTo-Json | Set-Content -Encoding UTF8 -LiteralPath $approvalPath
    return @{ root=$root; manifest=$manifestPath; manifestHash=$manifestSha; candidate=$candidatePath; approval=$approvalPath; approvalData=$approval; artifactHash=$artifactSha }
}

function Invoke-Fixture($Case) {
    Push-Location $Case.root
    try { & $updateScript -Root '.' -Mode Apply -Candidate 'var/update-candidates/opa/2.0.0/test/candidate.json' -ApprovalRecord 'var/update-candidates/opa/2.0.0/test/approval.json' | Out-Null }
    finally { Pop-Location }
}

try {
    foreach ($failure in @('approval', 'timestamp', 'future', 'build', 'version', 'policy')) {
        $case = New-Fixture $failure $true
        $global:SecurityUpdateTestState = @{ calls=@(); fail=$failure; artifactHash=$case.artifactHash }
        if ($failure -eq 'approval') { $case.approvalData.signature_verified = $false }
        if ($failure -eq 'timestamp') { $case.approvalData.advisory_checked_at = '' }
        if ($failure -eq 'future') { $case.approvalData.advisory_checked_at = '2999-01-01T00:00:00Z' }
        $case.approvalData | ConvertTo-Json | Set-Content -Encoding UTF8 -LiteralPath $case.approval
        $rejected = $false
        $expected = @{ approval='*Approval record is incomplete*'; timestamp='*RFC3339 timestamp*'; future='*timestamp is in the future*'; build='*Docker verification failed*'; version='*candidate version check failed*'; policy='*Docker verification failed*' }
        try { Invoke-Fixture $case } catch { $rejected = $_.Exception.Message -like $expected[$failure]; if (-not $rejected) { throw } }
        if (-not $rejected) { throw "Failure was accepted: $failure" }
        if ((Get-FileHash -Algorithm SHA256 -LiteralPath $case.manifest).Hash.ToLowerInvariant() -ne $case.manifestHash) { throw "Failure changed manifest: $failure" }
    }
    $case = New-Fixture 'container-success' $true
    $global:SecurityUpdateTestState = @{ calls=@(); fail=''; artifactHash=$case.artifactHash }
    Invoke-Fixture $case
    $updated = (Read-ScannerUpdateJSON $case.manifest).scanners[0]
    if ($updated.approved_version -ne '2.0.0' -or $updated.worker_image -cne ('sha256:' + ('c' * 64))) { throw 'OPA image remained on the old version' }
    if ($updated.security_advisory_checked_at -ne '2026-01-01T01:00:00.0000000Z' -or $updated.security_advisory_checked_date -ne '2026-01-01') { throw 'Review time was replaced by promotion time' }
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $case.root $updated.runtime_path)).Hash.ToLowerInvariant() -ne $case.artifactHash) { throw 'Promoted runtime hash changed' }
    foreach ($call in $global:SecurityUpdateTestState.calls | Where-Object { $_[0] -eq 'run' }) {
        if ($call -notcontains 'none' -or $call -notcontains '--read-only' -or $call -contains ('sha256:' + ('b' * 64))) { throw 'OPA verification used an unsafe or stale image' }
    }
    $case = New-Fixture 'native' $false
    if ($IsLinux -eq $true) {
        Invoke-Fixture $case
        $updated = (Read-ScannerUpdateJSON $case.manifest).scanners[0]
        $runtime = Join-Path $case.root $updated.runtime_path
        $versionOutput = & $runtime version
        if ($LASTEXITCODE -ne 0 -or $versionOutput -ne 'Version: 2.0.0' -or $updated.worker_image -ne '') { throw 'Native runtime was not made executable' }
    } else {
        $rejected = $false
        try { Invoke-Fixture $case } catch { $rejected = $_.Exception.Message -like '*requires PowerShell 7 on Linux*' }
        if (-not $rejected) { throw 'Unsupported native host was accepted' }
        $rejected = $false
        try { & $updateScript -Root $case.root -Mode Auto -Candidate $case.candidate | Out-Null } catch { $rejected = $_.Exception.Message -like '*PowerShell 7 on a Linux*' }
        if (-not $rejected) { throw 'Unsupported automatic host was accepted' }
        if ((Get-FileHash -Algorithm SHA256 -LiteralPath $case.manifest).Hash.ToLowerInvariant() -ne $case.manifestHash) { throw 'Unsupported host changed manifest' }
    }
    $legacy = [pscustomobject]@{security_advisory_checked_date='2026-01-01'}
    $baseline = Get-AdvisoryReviewTime $legacy
    if ($baseline.UtcDateTime.Hour -ne 0 -or [datetimeoffset]::Parse('2026-01-01T10:00:00Z') -le $baseline) { throw 'Same-day advisory was missed' }
    $exact = [pscustomobject]@{security_advisory_checked_date='2026-01-01'; security_advisory_checked_at='2026-01-01T01:00:00Z'}
    if ([datetimeoffset]::Parse('2026-01-01T10:00:00Z') -le (Get-AdvisoryReviewTime $exact)) { throw 'Exact review instant was lost' }
    if ($IsLinux -eq $true) {
        foreach ($withExactTime in @($false, $true)) {
            $case = New-Fixture ('auto-advisory-' + $withExactTime) $true
            if ($withExactTime) {
                $m = Read-ScannerUpdateJSON $case.manifest
                $m.scanners[0] | Add-Member -NotePropertyName security_advisory_checked_at -NotePropertyValue '2026-01-01T01:00:00Z'
                $m | ConvertTo-Json -Depth 10 | Set-Content -Encoding UTF8 -LiteralPath $case.manifest
                $case.manifestHash = (Get-FileHash -LiteralPath $case.manifest -Algorithm SHA256).Hash.ToLowerInvariant()
                $c = Read-ScannerUpdateJSON $case.candidate
                $c.base_manifest_sha256 = $case.manifestHash
                $c | ConvertTo-Json | Set-Content -Encoding UTF8 -LiteralPath $case.candidate
            }
            $global:SecurityUpdateTestState = @{calls=@(); artifactHash=$case.artifactHash; advisories=@([pscustomobject]@{updated_at='2026-01-01T10:00:00Z'; ghsa_id='GHSA-fixture'})}
            $rejected = $false
            try { & $updateScript -Root $case.root -Mode Auto -Candidate $case.candidate | Out-Null }
            catch { $rejected = $_.Exception.Message -like '*New or revised advisory*'; if (-not $rejected) { throw } }
            if (-not $rejected -or $global:SecurityUpdateTestState.calls.Count -ne 0) { throw 'Same-day advisory did not stop automatic promotion' }
            if ((Get-FileHash -LiteralPath $case.manifest -Algorithm SHA256).Hash.ToLowerInvariant() -ne $case.manifestHash) { throw 'Advisory rejection changed manifest' }
        }
        foreach ($container in @($false, $true)) {
            $case = New-Fixture ('auto-success-' + $container) $container
            $global:SecurityUpdateTestState = @{calls=@(); fail=''; artifactHash=$case.artifactHash; advisories=@()}
            & $updateScript -Root $case.root -Mode Auto -Candidate $case.candidate | Out-Null
            $updated = (Read-ScannerUpdateJSON $case.manifest).scanners[0]
            $checked = [datetimeoffset]::Parse($updated.security_advisory_checked_at)
            if ($checked -gt $global:SecurityUpdateTestState.advisoryRequestAt -or $checked -ge $global:SecurityUpdateTestState.goTestAt) { throw 'Automatic advisory baseline used the end of verification' }
            if ($container -and $updated.worker_image -cne ('sha256:' + ('c' * 64))) { throw 'Automatic promotion retained old OPA image' }
            if (-not $container -and $updated.worker_image -ne '') { throw 'Automatic native promotion changed execution mode' }
        }
    }
    'PASS: update promotion, rejection, relative paths, advisory timestamps and OPA runtime'
} finally {
    Remove-Variable -Name SecurityUpdateTestState -Scope Global -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $fixture) { Remove-Item -LiteralPath $fixture -Recurse -Force }
}
