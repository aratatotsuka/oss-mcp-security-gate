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
    foreach ($name in @('../copied.json', (Join-Path $fixture 'absolute.json'))) {
        $safeSnapshot = Join-Path $fixture 'contained-snapshot'
        $destination = [IO.Path]::GetFullPath([IO.Path]::Combine($safeSnapshot, $name))
        $rejected = $false
        try { & $wrapper -SnapshotDir $safeSnapshot -ToolsSource $source -Tools $name -Output (Join-Path $fixture 'rejected.json') | Out-Null }
        catch { $rejected = $_.Exception.Message -like 'Snapshot file must be inside SnapshotDir:*'; if (-not $rejected) { throw } }
        if (-not $rejected -or (Test-Path -LiteralPath $destination)) { throw "Rejected tools destination was written: $destination" }
        [IO.File]::WriteAllText($destination, 'preserve')
        $rejected = $false
        try { & $wrapper -SnapshotDir $safeSnapshot -ToolsSource $source -Tools $name -Output (Join-Path $fixture 'rejected.json') | Out-Null }
        catch { $rejected = $_.Exception.Message -like 'Snapshot file must be inside SnapshotDir:*'; if (-not $rejected) { throw } }
        if (-not $rejected -or [IO.File]::ReadAllText($destination) -cne 'preserve') { throw 'Rejected tools destination was overwritten' }
    }
    $safeSnapshot = Join-Path $fixture 'bad-prompts'
    $rejected = $false
    try { & $wrapper -SnapshotDir $safeSnapshot -ToolsSource $source -Prompts '../source.json' -Output (Join-Path $fixture 'rejected.json') | Out-Null }
    catch { $rejected = $_.Exception.Message -like 'Snapshot file must be inside SnapshotDir:*'; if (-not $rejected) { throw } }
    if (-not $rejected -or (Test-Path -LiteralPath (Join-Path $safeSnapshot 'tools.json'))) { throw 'Input validation happened after tools copy' }
    $safeSnapshot = Join-Path $fixture 'nested-snapshot'
    New-Item -ItemType Directory -Path (Join-Path $safeSnapshot 'nested') -Force | Out-Null
    $output = & $wrapper -SnapshotDir ($safeSnapshot + [IO.Path]::DirectorySeparatorChar) -ToolsSource $source -Tools 'nested/tools.json' -Output (Join-Path $fixture 'nested-report.json')
    if ($output -notcontains 'CLI_STUB_REACHED' -or [IO.File]::ReadAllText((Join-Path $safeSnapshot 'nested/tools.json')) -cne $json) { throw 'Contained nested snapshot was rejected or changed' }
    if ($IsLinux -eq $true) {
        $outside = Join-Path $fixture 'NESTED-SNAPSHOT'
        New-Item -ItemType Directory -Path $outside | Out-Null
        foreach ($name in @('../NESTED-SNAPSHOT/case.json', 'linked/link.json')) {
            if ($name -eq 'linked/link.json') { New-Item -ItemType SymbolicLink -Path (Join-Path $safeSnapshot 'linked') -Target $outside | Out-Null }
            $rejected = $false
            try { & $wrapper -SnapshotDir $safeSnapshot -ToolsSource $source -Tools $name -Output (Join-Path $fixture 'rejected.json') | Out-Null }
            catch { $rejected = $_.Exception.Message -like 'Snapshot file must be inside SnapshotDir:*' -or $_.Exception.Message -like 'Snapshot file parent must not be a link:*'; if (-not $rejected) { throw } }
            if (-not $rejected -or (Test-Path -LiteralPath (Join-Path $outside ([IO.Path]::GetFileName($name))))) { throw 'Case or link traversal wrote outside snapshot' }
        }
    }
    'PASS: UTF-8 MCP snapshot, contained copies and rejection before writes'
} finally {
    if (Test-Path -LiteralPath $fixture) { Remove-Item -LiteralPath $fixture -Recurse -Force }
}
