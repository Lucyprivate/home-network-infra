$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
foreach ($name in @('review-coexist-offline.ps1','review-tablet-rdp-offline.ps1')) {
    $script=Join-Path $root ('windows/'+$name)
    & $script
    if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {throw 'Offline Windows checks failed.'}
}
