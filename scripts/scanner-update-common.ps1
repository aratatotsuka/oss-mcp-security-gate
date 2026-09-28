# Shared path, advisory and OPA runtime checks used before manifest activation.
function Resolve-SecurityPath([string]$Path) {
    return $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
}

function Get-SecurityPathComparison {
    if ([IO.Path]::DirectorySeparatorChar -eq '\') { return [StringComparison]::OrdinalIgnoreCase }
    return [StringComparison]::Ordinal
}

function Read-ScannerUpdateJSON([string]$Path) {
    $parameters = @{ InputObject = (Get-Content -Raw -Encoding UTF8 -LiteralPath $Path) }
    # PowerShell 7.5+ otherwise converts RFC3339 strings into DateTime objects.
    if ((Get-Command ConvertFrom-Json).Parameters.ContainsKey('DateKind')) { $parameters.DateKind = 'String' }
    return ConvertFrom-Json @parameters
}

function ConvertTo-AdvisoryTimestamp($Value) {
    if ($Value -is [datetimeoffset]) { $time = $Value }
    elseif ($Value -is [datetime] -and $Value.Kind -ne [DateTimeKind]::Unspecified) { $time = [datetimeoffset]$Value }
    else {
        if ([string]$Value -cnotmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?(?:Z|[+-]\d{2}:\d{2})$') {
            throw 'Advisory review requires an RFC3339 timestamp with a timezone'
        }
        $time = [datetimeoffset]::Parse([string]$Value, [Globalization.CultureInfo]::InvariantCulture)
    }
    if ($time -gt [datetimeoffset]::UtcNow) { throw 'Advisory review timestamp is in the future' }
    return $time.ToUniversalTime()
}

function Get-AdvisoryReviewTime($Entry) {
    $date = [datetimeoffset]::ParseExact(([string]$Entry.security_advisory_checked_date + 'T00:00:00Z'), 'yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
    if ([string]::IsNullOrWhiteSpace([string]$Entry.security_advisory_checked_at)) { return $date }
    $time = ConvertTo-AdvisoryTimestamp $Entry.security_advisory_checked_at
    if ($time.UtcDateTime.ToString('yyyy-MM-dd') -cne [string]$Entry.security_advisory_checked_date) {
        throw 'Advisory review timestamp and date disagree'
    }
    return $time
}

function Invoke-UpdateDocker([string[]]$Arguments) {
    & docker @Arguments
    if ($LASTEXITCODE -ne 0) { throw "OPA Docker verification failed ($LASTEXITCODE): $($Arguments -join ' ')" }
}

function Assert-OPAVersion([string]$Output, [string]$Version) {
    if ($Output -notmatch ('(?m)^Version:\s+' + [regex]::Escape($Version) + '\s*$')) {
        throw "OPA candidate version check failed: $Output"
    }
}

function Test-NativeOPAUpdate([string]$Artifact, [string]$Version, [string]$Policies) {
    if ($IsLinux -ne $true) { throw 'Native OPA promotion requires PowerShell 7 on Linux; use Docker deployment on Windows' }
    & chmod 755 $Artifact
    if ($LASTEXITCODE -ne 0) { throw 'Could not make OPA runtime executable' }
    $output = & $Artifact version 2>&1
    if ($LASTEXITCODE -ne 0) { throw "OPA candidate execution failed: $output" }
    Assert-OPAVersion ($output | Out-String) $Version
    $output = & $Artifact test $Policies --fail-on-empty 2>&1
    if ($LASTEXITCODE -ne 0) { throw "OPA policy tests failed: $output" }
}

function Test-OPAUpdateImage([string]$Image, [string]$Version, [string]$Policies) {
    $run = @('run', '--rm', '--pull', 'never', '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true', '--user', '65532:65532', '--pids-limit', '128', '--memory', '512m', '--cpus', '1', '--tmpfs', '/tmp:rw,nosuid,nodev,size=64m', '--entrypoint', '/scanner')
    $output = Invoke-UpdateDocker ($run + @($Image, 'version'))
    Assert-OPAVersion ($output | Out-String) $Version
    Invoke-UpdateDocker ($run + @('--mount', "type=bind,src=$Policies,dst=/policies,readonly", $Image, 'test', '/policies', '--fail-on-empty')) | Out-Host
}

function Test-OPARegistryUpdateImage([string]$Image, [string]$Artifact, [string]$Version, [string]$Policies, [string]$Directory) {
    # The admitted registry image must already be loaded on this update worker.
    # Copy from a stopped container before executing any code from the image.
    $inspection = Join-Path $Directory ('opa-registry-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $inspection | Out-Null
    $container = (Invoke-UpdateDocker @('create', '--pull', 'never', '--network', 'none', '--entrypoint', '/scanner', $Image, 'version') | Out-String).Trim()
    if ($container -cnotmatch '^[0-9a-f]{64}$') { throw 'Docker returned an invalid OPA inspection container ID' }
    try {
        $binary = Join-Path $inspection 'scanner'
        Invoke-UpdateDocker @('cp', ($container + ':/scanner'), $binary) | Out-Host
        $file = Get-Item -Force -LiteralPath $binary
        if ($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            (Get-FileHash -Algorithm SHA256 -LiteralPath $binary).Hash -cne (Get-FileHash -Algorithm SHA256 -LiteralPath $Artifact).Hash) {
            throw 'OPA registry image does not contain the candidate artifact at /scanner'
        }
    } finally {
        Invoke-UpdateDocker @('rm', $container) | Out-Host
    }
    Test-OPAUpdateImage $Image $Version $Policies
}

function New-OPAUpdateImage([string]$Artifact, [string]$Version, [string]$Policies, [string]$Directory) {
    $context = Join-Path $Directory ('opa-image-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $context | Out-Null
    Copy-Item -LiteralPath $Artifact -Destination (Join-Path $context 'opa')
    # OPA evaluates local policy without network access or a CA bundle.
    $dockerfile = "FROM scratch`nCOPY --chmod=755 opa /scanner`nENV HOME=/tmp`nUSER 65532:65532`nENTRYPOINT [`"/scanner`"]`n"
    [IO.File]::WriteAllText((Join-Path $context 'Dockerfile'), $dockerfile, [Text.UTF8Encoding]::new($false))
    $image = (Invoke-UpdateDocker @('build', '--network', 'none', '--pull=false', '--quiet', $context) | Out-String).Trim()
    if ($image -cnotmatch '^sha256:[0-9a-f]{64}$' -or $image -cmatch '^sha256:0{64}$') { throw 'Docker returned an invalid OPA image ID' }
    Test-OPAUpdateImage $image $Version $Policies
    return $image
}
