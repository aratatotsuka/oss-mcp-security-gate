$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$fixture = Join-Path $repo ('var/version-check-test-' + [guid]::NewGuid().ToString('N'))
$fixture = [IO.Path]::GetFullPath($fixture)
$allowed = [IO.Path]::GetFullPath((Join-Path $repo 'var')) + [IO.Path]::DirectorySeparatorChar
if (-not $fixture.StartsWith($allowed, [StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe fixture path' }
try {
    New-Item -ItemType Directory -Path (Join-Path $fixture 'config') -Force | Out-Null
    @{ scanners = @(
        @{ name='opa'; approved_version='1.0.0'; artifact_uri='https://github.com/open-policy-agent/opa/releases/download/v1.0.0/opa_linux_amd64_static' },
        @{ name='mcp-scanner'; approved_version='1.0.0'; artifact_uri='https://files.pythonhosted.org/cisco_ai_mcp_scanner-1.0.0-py3-none-any.whl' }
    ) } | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 -LiteralPath (Join-Path $fixture 'config/scanners.yaml')
    $script = Join-Path $repo 'scripts/check-scanner-versions.ps1'
    $engine = (Get-Process -Id $PID).Path
    # Run in a child process so the script's exit codes are tested as well.
    $runner = @'
param($Script, $Root, $Latest, $ExpectedStatus)
$ErrorActionPreference = 'Stop'
$global:SecurityVersionCheckRequests = @()
$global:SecurityVersionCheckLatest = $Latest
function Invoke-RestMethod {
    param($Uri, [Parameter(Mandatory=$true)][string]$UserAgent, $Headers, $TimeoutSec)
    if ($UserAgent -cne 'security-gate-version-check' -or $Headers.ContainsKey('User-Agent')) { throw 'Invalid User-Agent binding' }
    if ($Uri -eq 'https://api.github.com/repos/open-policy-agent/opa/releases/latest') {
        if ($Headers.Accept -cne 'application/vnd.github+json') { throw 'Incorrect GitHub Accept header' }
        $global:SecurityVersionCheckRequests += 'github'
        return @{tag_name=('v' + $global:SecurityVersionCheckLatest)}
    }
    if ($Uri -eq 'https://pypi.org/pypi/cisco-ai-mcp-scanner/json') {
        if ($Headers.Accept -cne 'application/json') { throw 'Incorrect PyPI Accept header' }
        $global:SecurityVersionCheckRequests += 'pypi'
        return @{info=@{version=$global:SecurityVersionCheckLatest}}
    }
    throw "Unexpected request: $Uri"
}
$result = @(& $Script -Root $Root)
$code = $LASTEXITCODE
if ($global:SecurityVersionCheckRequests.Count -ne 2 -or @($result | Where-Object { $_.status -cne $ExpectedStatus }).Count -ne 0) { Write-Error ($result | ConvertTo-Json) -ErrorAction Continue; exit 90 }
exit $code
'@
    $runnerPath = Join-Path $fixture 'runner.ps1'
    [IO.File]::WriteAllText($runnerPath, $runner, [Text.UTF8Encoding]::new($false))
    foreach ($case in @(@('1.0.0','CURRENT',0), @('2.0.0','UPDATE_AVAILABLE',2), @('0.9.0','AHEAD_OF_LATEST',1))) {
        & $engine -NoLogo -NoProfile -File $runnerPath $script $fixture $case[0] $case[1]
        if ($LASTEXITCODE -ne $case[2]) { throw "Version check failed: $($case[1]), exit $LASTEXITCODE" }
    }
    'PASS: GitHub/PyPI User-Agent binding and version-check exit codes'
} finally {
    if (Test-Path -LiteralPath $fixture) { Remove-Item -LiteralPath $fixture -Recurse -Force }
}
