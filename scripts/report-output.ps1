param(
    [Parameter(Mandatory=$true)][string]$Root,
    [Parameter(Mandatory=$true)][ValidateSet('oss', 'mcp-static')][string]$Kind,
    [Parameter(Mandatory=$true)][string]$TargetPath
)

$leaf = [IO.Path]::GetFileName($TargetPath.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar))
$parent = [IO.Path]::GetFileName([IO.Path]::GetDirectoryName($TargetPath.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)))
$label = "$parent--$leaf" -replace '[^\p{L}\p{N}_.-]', '_'
$reportRoot = Join-Path $Root "var/reports/$Kind/$label"
New-Item -ItemType Directory -Force -Path $reportRoot | Out-Null
$runId = (Get-Date -Format 'yyyyMMdd-HHmmss-fff') + '-' + [guid]::NewGuid().ToString('N').Substring(0, 6)
$runDir = Join-Path $reportRoot $runId
New-Item -ItemType Directory -Path $runDir | Out-Null
Join-Path $runDir 'report.json'
