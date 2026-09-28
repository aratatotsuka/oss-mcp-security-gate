param(
    [string[]]$Ecosystem = @('Go'),
    [switch]$IncludeJavaDB,
    [switch]$SkipDataUpdate,
    [switch]$PrepareOnly,
    [switch]$AcceptOfficialDigestPolicy,
    [string]$Root = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
. (Join-Path $PSScriptRoot 'scanner-update-common.ps1')
$rootPath = Resolve-SecurityPath $Root
$manifestPath = Join-Path $rootPath 'config/scanners.yaml'
$baseSha = (Get-FileHash -Algorithm SHA256 -LiteralPath $manifestPath).Hash
$manifest = Read-ScannerUpdateJSON $manifestPath
$runId = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ') + '-' + [guid]::NewGuid().ToString('N').Substring(0,8)
$stage = Join-Path $rootPath "var/deploy/$runId"
$destinationRoot = if($PrepareOnly){Join-Path $stage 'prepared-root'}else{$rootPath}
$receipts = @()
$repos = @{ 'osv-scanner'='google/osv-scanner'; trivy='aquasecurity/trivy'; gitleaks='gitleaks/gitleaks'; opa='open-policy-agent/opa' }
$images = @{}

function CheckedPath([string]$Path) {
    $full=Resolve-SecurityPath $Path
    if (-not $full.StartsWith(($rootPath.TrimEnd([IO.Path]::DirectorySeparatorChar)+[IO.Path]::DirectorySeparatorChar),(Get-SecurityPathComparison))) { throw "Path escapes repository: $full" }
    return $full
}
function Run-Docker([string[]]$Arguments) {
    & docker @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Docker failed ($LASTEXITCODE): $($Arguments -join ' ')" }
}
function Hash([string]$Path) { return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant() }
function Update-Container([string]$Image,[string[]]$Command,[string]$Cache,[string]$Empty='') {
    $a=@('run','--rm','--pull','never','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges:true','--pids-limit','128','--memory','2g','--cpus','2','--tmpfs','/tmp:rw,nosuid,nodev,size=256m','--user','0:0','--mount',"type=bind,src=$Cache,dst=/cache")
    if($Empty){$a+=@('--mount',"type=bind,src=$Empty,dst=/empty,readonly")}
    Run-Docker ($a+@($Image)+$Command)
}

if (@($Ecosystem | Where-Object { $_ -notmatch '^[A-Za-z0-9._-]+$' }).Count) { throw 'Invalid ecosystem name' }
if($PrepareOnly -and $SkipDataUpdate){throw 'PrepareOnly cannot reuse data outside the prepared root'}
if(-not $PrepareOnly -and -not $AcceptOfficialDigestPolicy){throw 'Activation requires -AcceptOfficialDigestPolicy. This policy verifies official HTTPS digests, not release signatures or build provenance. Use -PrepareOnly to inspect it first.'}
$engine = Run-Docker @('info','--format','{{.OSType}}')
if (($engine | Out-String).Trim() -ne 'linux') { throw 'Docker Desktop must use Linux containers' }
New-Item -ItemType Directory -Force -Path $stage,(Join-Path $rootPath 'bin') | Out-Null
$suffix=if($env:OS -eq 'Windows_NT'){'.exe'}else{''}
$helper=Join-Path $rootPath "bin/security-gate-deploy$suffix"
Push-Location $rootPath
try { & go build -o $helper ./cmd/security-gate-deploy; if($LASTEXITCODE -ne 0){throw 'Deployment helper build failed'} } finally { Pop-Location }
$headers=@{'User-Agent'='security-gate-deploy';Accept='application/vnd.github+json'}
$ca=Join-Path $stage 'ca-certificates.crt'
Invoke-WebRequest -UseBasicParsing -Uri 'https://curl.se/ca/cacert.pem' -OutFile $ca
$caSum=Invoke-WebRequest -UseBasicParsing -Uri 'https://curl.se/ca/cacert.pem.sha256'
$caText=if($caSum.Content -is [byte[]]){[Text.Encoding]::UTF8.GetString($caSum.Content)}else{[string]$caSum.Content}
$expectedCA=($caText.Trim() -split '\s+')[0]
if($expectedCA -notmatch '^[0-9a-f]{64}$' -or (Hash $ca) -cne $expectedCA){throw 'CA bundle hash mismatch'}

foreach($name in @('osv-scanner','trivy','gitleaks','opa')) {
    Write-Host "Preparing $name..."
    $entry=$manifest.scanners | Where-Object name -eq $name
    $repo=$repos[$name]
    $release=Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases/tags/v$($entry.approved_version)" -Headers $headers -TimeoutSec 30
    $fileName=[IO.Path]::GetFileName(([uri]$entry.artifact_uri).AbsolutePath)
    $assets=@($release.assets | Where-Object { $_.name -ceq $fileName })
    if($assets.Count -ne 1 -or $assets[0].browser_download_url -cne $entry.artifact_uri -or $assets[0].digest -cne "sha256:$($entry.artifact_sha256)") { throw "Official release identity/digest differs from manifest: $name" }
    # Existing advisory review is the baseline. New or revised advisories stop admission.
    $advisoryCheckedAt=[datetimeoffset]::UtcNow
    $advisoryResponse=Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/security-advisories?state=published&per_page=100" -Headers $headers -TimeoutSec 30
    $advisories=@($advisoryResponse)
    if($advisories.Count -ge 100){throw "Incomplete advisory listing: $name"}
    $baseline=Get-AdvisoryReviewTime $entry
    foreach($advisory in $advisories){if((ConvertTo-AdvisoryTimestamp $advisory.updated_at) -gt $baseline){throw "New/revised advisory for $name`: $($advisory.ghsa_id)"}}
    $entry.security_advisory_checked_date=$advisoryCheckedAt.UtcDateTime.ToString('yyyy-MM-dd')
    $entry | Add-Member -NotePropertyName security_advisory_checked_at -NotePropertyValue $advisoryCheckedAt.UtcDateTime.ToString('o') -Force
    $artifact=$null
    $quarantine=Join-Path $rootPath 'var/update-quarantine'
    foreach($f in @(Get-ChildItem -LiteralPath $quarantine -Recurse -File -ErrorAction SilentlyContinue | Where-Object Name -eq $fileName | Sort-Object LastWriteTime -Descending)) {
        if((Hash $f.FullName) -ceq $entry.artifact_sha256){$artifact=$f.FullName;break}
    }
    if(-not $artifact){$downloadDir=Join-Path $stage "downloads/$name";New-Item -ItemType Directory -Force -Path $downloadDir | Out-Null;$artifact=Join-Path $downloadDir $fileName;Invoke-WebRequest -UseBasicParsing -Uri $entry.artifact_uri -OutFile $artifact}
    if((Hash $artifact) -cne $entry.artifact_sha256){throw "Artifact hash mismatch: $name"}
    $context=Join-Path $stage "images/$name"
    New-Item -ItemType Directory -Force -Path $context | Out-Null
    $binary=Join-Path $context 'scanner'
    & $helper extract --artifact $artifact --name $name --output $binary
    if($LASTEXITCODE -ne 0){throw "Safe extraction failed: $name"}
    Copy-Item -LiteralPath $ca -Destination (Join-Path $context 'ca-certificates.crt')
    Copy-Item -LiteralPath (Join-Path $rootPath 'workers/static/Dockerfile') -Destination (Join-Path $context 'Dockerfile')
    $tag="security-gate-local/$name`:$($entry.approved_version)-$runId"
    Run-Docker @('build','--network','none','--pull=false','--tag',$tag,$context) | Out-Host
    $image=(Run-Docker @('image','inspect',$tag,'--format','{{.Id}}') | Out-String).Trim()
    if($image -notmatch '^sha256:[0-9a-f]{64}$'){throw 'Docker returned an invalid image ID'}
    $versionArgs=if($name -in @('gitleaks','opa')){@('version')}else{@('--version')}
    $versionText=Run-Docker (@('run','--rm','--pull','never','--network','none','--read-only','--cap-drop','ALL',$image)+$versionArgs)
    if(($versionText | Out-String) -notmatch ([regex]::Escape($entry.approved_version))){throw "Unexpected scanner version: $name"}
    $images[$name]=$image
    $entry.worker_image=$image
    $receipts+=[pscustomobject]@{scanner=$name;version=$entry.approved_version;official_uri=$entry.artifact_uri;artifact_sha256=$entry.artifact_sha256;binary_sha256=(Hash $binary);image_id=$image;verification='OFFICIAL_HTTPS_RELEASE_DIGEST';immutable_release=[bool]$release.immutable;advisory_count=$advisories.Count;advisory_checked_at=$entry.security_advisory_checked_at;runtime_source=$artifact}
}

Run-Docker @('run','--rm','--pull','never','--network','none','--read-only','--cap-drop','ALL','--mount',"type=bind,src=$(Join-Path $rootPath 'policies'),dst=/policies,readonly",$images.opa,'test','/policies','--fail-on-empty') | Out-Host

foreach($name in @('osv-scanner','trivy')) {
    $entry=$manifest.scanners | Where-Object name -eq $name
    if($SkipDataUpdate){
        if(-not $entry.cache_generation){throw "No existing cache generation: $name"}
        $existing=CheckedPath (Join-Path $rootPath "var/cache/$name/$($entry.cache_generation)")
        & $helper verify --path $existing
        if($LASTEXITCODE -ne 0){throw "Existing cache failed verification: $name"}
        continue
    }
    $cache=Join-Path $stage "cache/$name"
    New-Item -ItemType Directory -Force -Path $cache | Out-Null
    if($name -eq 'osv-scanner'){
        $sourceTimes=@()
        foreach($eco in $Ecosystem){
            Write-Host "Downloading OSV database: $eco"
            # OSV 2.6 uses the pinned SCALIBR matcher (older docs still say osv-scanner).
            $dir=Join-Path $cache "osv-scalibr/$eco";New-Item -ItemType Directory -Force -Path $dir | Out-Null
            $url="https://osv-vulnerabilities.storage.googleapis.com/$eco/all.zip"
            $response=Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile (Join-Path $dir 'all.zip') -PassThru
            $sourceTimes+=[datetimeoffset]::Parse([string]$response.Headers['Last-Modified']).UtcDateTime
        }
        $updated=($sourceTimes | Sort-Object | Select-Object -First 1).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    }else{
        Write-Host 'Downloading Trivy vulnerability DB...'
        Update-Container $images.trivy @('fs','--download-db-only','--cache-dir=/cache','--no-progress') $cache | Out-Host
        if($IncludeJavaDB){Update-Container $images.trivy @('fs','--download-java-db-only','--cache-dir=/cache','--no-progress') $cache | Out-Host}
        $empty=Join-Path $stage 'empty';New-Item -ItemType Directory -Force -Path $empty | Out-Null
        Update-Container $images.trivy @('fs','--scanners=misconfig','--cache-dir=/cache','--no-progress','--format=json','/empty') $cache $empty | Out-Host
        $db=Read-ScannerUpdateJSON (Join-Path $cache 'db/metadata.json')
        $updated=([datetimeoffset]::Parse($db.UpdatedAt)).UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
    }
    & $helper snapshot --path $cache --version $runId --updated-at $updated
    if($LASTEXITCODE -ne 0){throw "Cache inventory failed: $name"}
    $destination=CheckedPath (Join-Path $destinationRoot "var/cache/$name/$runId")
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $destination) | Out-Null
    Copy-Item -LiteralPath $cache -Destination $destination -Recurse
    & $helper verify --path $destination
    if($LASTEXITCODE -ne 0){throw "Copied cache failed verification: $name"}
    $entry | Add-Member -NotePropertyName cache_generation -NotePropertyValue $runId -Force
}

foreach($receipt in $receipts){
    $entry=$manifest.scanners | Where-Object name -eq $receipt.scanner
    $runtime=CheckedPath (Join-Path $destinationRoot $entry.runtime_path)
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $runtime) | Out-Null
    if(Test-Path -LiteralPath $runtime){if((Hash $runtime) -cne $entry.artifact_sha256){throw "Existing runtime artifact differs: $runtime"}}
    else{Copy-Item -LiteralPath $receipt.runtime_source -Destination $runtime}
    $entry.signature_verification='Official HTTPS release asset digest (not signature verification)'
    $entry.provenance_verification='Official release identity; build provenance is not verified'
    $entry.approved_date=(Get-Date).ToUniversalTime().ToString('yyyy-MM-dd')
}
$receipts | ConvertTo-Json -Depth 12 | Set-Content -Encoding UTF8 -LiteralPath (Join-Path $stage 'deployment-receipt.json')
$gate=& (Join-Path $PSScriptRoot 'ensure-gate.ps1') -Root $rootPath
if((Get-FileHash -Algorithm SHA256 -LiteralPath $manifestPath).Hash -cne $baseSha){throw 'Manifest changed during deployment'}
if($PrepareOnly){
    if($SkipDataUpdate){throw 'PrepareOnly cannot reuse data outside the prepared root'}
    New-Item -ItemType Directory -Force -Path (Join-Path $destinationRoot 'config') | Out-Null
    Copy-Item -LiteralPath (Join-Path $rootPath 'config/policy.yaml') -Destination (Join-Path $destinationRoot 'config/policy.yaml')
    Copy-Item -LiteralPath (Join-Path $rootPath 'config/scanner-config') -Destination (Join-Path $destinationRoot 'config/scanner-config') -Recurse
    Copy-Item -LiteralPath (Join-Path $rootPath 'policies') -Destination (Join-Path $destinationRoot 'policies') -Recurse
    [IO.File]::WriteAllText((Join-Path $destinationRoot 'config/scanners.yaml'),(($manifest | ConvertTo-Json -Depth 20)+[Environment]::NewLine),[Text.UTF8Encoding]::new($false))
}else{
    $temp=Join-Path $rootPath "config/scanners-$runId.tmp"
    try{
        [IO.File]::WriteAllText($temp,(($manifest | ConvertTo-Json -Depth 20)+[Environment]::NewLine),[Text.UTF8Encoding]::new($false))
        & $gate verify-scanners --root $destinationRoot --manifest $temp --type oss
        if($LASTEXITCODE -ne 0){throw 'Candidate deployment verification failed; active manifest was not changed'}
        if((Get-FileHash -Algorithm SHA256 -LiteralPath $manifestPath).Hash -cne $baseSha){throw 'Manifest changed during verification'}
        [IO.File]::Replace($temp,$manifestPath,(Join-Path $stage 'scanners.before.yaml'))
    }finally{if(Test-Path -LiteralPath $temp){Remove-Item -LiteralPath $temp}}
}
Write-Host "OSS preparation completed. Root: $destinationRoot Receipt: $stage/deployment-receipt.json"
& $gate verify-scanners --root $destinationRoot --type oss
if($LASTEXITCODE -ne 0){throw 'Deployment verification failed'}
