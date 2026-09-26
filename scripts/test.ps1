param([string]$Go = 'go', [string]$Opa = 'opa')
$ErrorActionPreference = 'Stop'
$env:GOTOOLCHAIN = 'local'
& $Go test ./...
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $Opa test policies --fail-on-empty
exit $LASTEXITCODE
