$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$fixture = Join-Path $repo ('var/mcp-script-test-' + [guid]::NewGuid().ToString('N'))
if (-not ([IO.Path]::GetFullPath($fixture)).StartsWith(([IO.Path]::GetFullPath((Join-Path $repo 'var')) + [IO.Path]::DirectorySeparatorChar), [StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe fixture path' }
try {
    $scripts = Join-Path $fixture 'scripts'
    New-Item -ItemType Directory -Force -Path $scripts | Out-Null
    Copy-Item -LiteralPath (Join-Path $repo 'scripts/scan-mcp-snapshot.ps1') -Destination $scripts
    [IO.File]::WriteAllText((Join-Path $scripts 'ensure-gate.ps1'), "param([string]`$Root)`nJoin-Path `$PSScriptRoot 'gate.ps1'`n")
    [IO.File]::WriteAllText((Join-Path $scripts 'gate.ps1'), "`$global:LASTEXITCODE = 0`n'CLI_STUB_REACHED'`n")
    $japanese = ([string][char]0x65e5) + [char]0x672c + [char]0x8a9e
    $source = Join-Path $fixture 'source.json'
    $json = '{"tools":[{"name":"sample","description":"' + $japanese + '"}]}'
    [IO.File]::WriteAllText($source, $json, [Text.UTF8Encoding]::new($false))
    $wrapper = Join-Path $scripts 'scan-mcp-snapshot.ps1'
    $snapshot = Join-Path $fixture 'snapshot'
    $output = & $wrapper -SnapshotDir $snapshot -ToolsSource $source -Output (Join-Path $fixture 'report.json')
    if ($output -notcontains 'CLI_STUB_REACHED') { throw 'UTF-8 JSON was rejected before scanning' }
    $copied = Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $snapshot 'tools.json') | ConvertFrom-Json
    if ($copied.tools[0].description -cne $japanese) { throw 'Japanese snapshot content changed' }
    $output = & $wrapper -SnapshotDir $snapshot -Output (Join-Path $fixture 'report2.json')
    if ($output -notcontains 'CLI_STUB_REACHED') { throw 'Existing UTF-8 snapshot was rejected' }
    [IO.File]::WriteAllText((Join-Path $snapshot 'tools.json'), '{invalid', [Text.UTF8Encoding]::new($false))
    $rejected = $false
    try { & $wrapper -SnapshotDir $snapshot -Output (Join-Path $fixture 'bad.json') | Out-Null } catch { $rejected = $_.Exception.Message -like 'Invalid JSON:*' }
    if (-not $rejected) { throw 'Invalid snapshot JSON was accepted' }
    'PASS: BOM-less Japanese UTF-8 source and existing MCP snapshot'
} finally {
    if (Test-Path -LiteralPath $fixture) { Remove-Item -LiteralPath $fixture -Recurse -Force }
}
