param(
    [Parameter(Mandatory = $false)]
    [string]$Image = $env:SECURITY_GATE_TEST_IMAGE
)

$ErrorActionPreference = 'Stop'

if ($Image -notmatch '^\S+@sha256:[0-9a-f]{64}$') {
    throw 'Set SECURITY_GATE_TEST_IMAGE (or -Image) to a reviewed image@sha256 digest.'
}

$tempRoot = [System.IO.Path]::GetTempPath()
$probe = Join-Path $tempRoot ("security-gate-runtime-" + [guid]::NewGuid().ToString('N'))
[System.IO.Directory]::CreateDirectory($probe) | Out-Null
$sentinel = Join-Path $probe 'sentinel'
[System.IO.File]::WriteAllText($sentinel, 'unchanged')
$before = (Get-FileHash -LiteralPath $sentinel -Algorithm SHA256).Hash

try {
    docker image inspect $Image | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'The digest-pinned test image is not available locally.' }

    docker run --rm --pull never --network none --read-only --user 65532:65532 `
        --cap-drop ALL --security-opt no-new-privileges:true --pids-limit 32 `
        --cpus 0.25 --memory 64m --memory-swap 64m `
        --tmpfs /tmp:rw,nosuid,nodev,noexec,size=16m `
        --mount "type=bind,src=$probe,dst=/target,readonly" `
        $Image sh -ec '
          test ! -e /var/run/docker.sock
          test ! -e /run/containerd/containerd.sock
          ! printf changed > /target/sentinel
          ! wget -q -T 2 -O /dev/null http://169.254.169.254/latest/meta-data/
          ! wget -q -T 2 -O /dev/null https://example.com/
        '
    if ($LASTEXITCODE -ne 0) { throw "Runtime isolation probe failed with exit $LASTEXITCODE." }

    $after = (Get-FileHash -LiteralPath $sentinel -Algorithm SHA256).Hash
    if ($before -ne $after) { throw 'Read-only target changed during the probe.' }
    Write-Output 'RUNTIME_ISOLATION_EXIT=0'
    Write-Output 'TARGET_UNCHANGED=True'
}
finally {
    $resolvedProbe = [System.IO.Path]::GetFullPath($probe)
    $resolvedTemp = [System.IO.Path]::GetFullPath($tempRoot)
    if ($resolvedProbe.StartsWith($resolvedTemp, [System.StringComparison]::OrdinalIgnoreCase) -and
        $resolvedProbe -ne $resolvedTemp -and (Test-Path -LiteralPath $resolvedProbe)) {
        Remove-Item -LiteralPath $resolvedProbe -Recurse -Force
    }
}
