param(
    [Parameter(Mandatory=$true)][string]$SnapshotDir,
    [string]$ToolsSource,
    [string]$Tools = 'tools.json',
    [string]$Prompts,
    [string]$Resources,
    [string]$Output
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$gate = & (Join-Path $PSScriptRoot 'ensure-gate.ps1') -Root $root
$snapshotPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($SnapshotDir)
if ($ToolsSource) {
    $sourcePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ToolsSource)
    if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
        throw "ToolsSource file does not exist: $sourcePath"
    }
    try { $null = Get-Content -Raw -Encoding UTF8 -LiteralPath $sourcePath | ConvertFrom-Json } catch { throw "Invalid JSON: $sourcePath" }
}
$null = New-Item -ItemType Directory -Force -Path $snapshotPath
$snapshotPath = (Resolve-Path -LiteralPath $snapshotPath).ProviderPath
if ($ToolsSource) {
    $toolsPath = Join-Path $snapshotPath $Tools
    if (Test-Path -LiteralPath $toolsPath) {
        throw "Snapshot file already exists and was not overwritten: $toolsPath. Use the existing snapshot or specify a new SnapshotDir."
    }
    Copy-Item -LiteralPath $sourcePath -Destination $toolsPath
}

$arguments = @('scan', '--root', $root, '--target', $snapshotPath, '--type', 'mcp-static')
foreach ($item in @(@('tools', $Tools), @('prompts', $Prompts), @('resources', $Resources))) {
    $file = $item[1]
    if (-not $file) { continue }
    $path = Join-Path $snapshotPath $file
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Snapshot file does not exist: $path`nPass -ToolsSource <actual-tools.json> to copy a captured MCP tools/list response. This script does not connect to the MCP server or generate snapshot JSON." }
    $path = (Resolve-Path -LiteralPath $path).ProviderPath
    if (-not $path.StartsWith($snapshotPath.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Snapshot file must be inside SnapshotDir: $path"
    }
    try { $null = Get-Content -Raw -Encoding UTF8 -LiteralPath $path | ConvertFrom-Json } catch { throw "Invalid JSON: $path" }
    $arguments += @("--$($item[0])", $path)
}

$outputPath = if ($Output) {
    $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Output)
} else {
    & (Join-Path $PSScriptRoot 'report-output.ps1') -Root $root -Kind 'mcp-static' -TargetPath $snapshotPath
}
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $outputPath) | Out-Null
$arguments += @('--output', $outputPath)
& $gate @arguments
exit $LASTEXITCODE
