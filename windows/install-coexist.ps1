# SPDX-License-Identifier: MIT
# Copyright Home Network Infra Contributors
# Default is read-only. Run -Apply from a real Administrator PowerShell after exiting v2rayN.
# Undo: & "$env:ProgramData\HomeNetworkInfraVPNCoexist\install-coexist.ps1" -Undo -Apply
[CmdletBinding()]
param(
    [switch]$Apply,
    [switch]$Undo,
    [string]$ConfigPath = 'C:\Program Files (x86)\V2RayN\guiConfigs\guiNConfig.json',
    [string]$ExpectedSubnetRoutes = '10.10.10.0/24,10.10.20.0/24'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$marker = 'HomeNetworkInfraVPNCoexist-v1'
$taskName = 'HomeNetworkInfra-VPN-Coexist-RouteGuard'
$root = Join-Path $env:ProgramData 'HomeNetworkInfraVPNCoexist'
$private = Join-Path $root 'private'
$manifestPath = Join-Path $private 'manifest.json'
$metricPath = Join-Path $private 'metric-state.json'
$guardPath = Join-Path $root 'coexist-route-guard.ps1'
$installerPath = Join-Path $root 'install-coexist.ps1'
$psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$utf8 = New-Object Text.UTF8Encoding($false)

function Get-ExpectedSubnetPrefixes([string]$Csv) {
    $prefixes=@()
    foreach ($value in $Csv.Split(',')) {
        if ($value -notmatch '^([0-9.]+)/([0-9]{1,2})$') { throw 'ExpectedSubnetRoutes must be a comma-separated IPv4 CIDR list.' }
        $address=[Net.IPAddress]::Parse($matches[1]); $length=[int]$matches[2]
        if ($address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or $address.ToString() -ne $matches[1] -or $length -gt 32) { throw 'ExpectedSubnetRoutes contains an invalid IPv4 CIDR.' }
        $prefixes+=($address.ToString()+'/'+$length)
    }
    if ($prefixes.Count -eq 0) { throw 'ExpectedSubnetRoutes cannot be empty.' }
    return @($prefixes | Sort-Object -Unique)
}
function Get-GuardArguments([string]$Csv) {
    $canonical=@(Get-ExpectedSubnetPrefixes $Csv) -join ','
    return '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $guardPath + '" -ExpectedSubnetRoutes "' + $canonical + '"'
}
function Assert-NoReparse([string]$Path) {
    $itemPath = [IO.Path]::GetFullPath($Path)
    while (-not [string]::IsNullOrWhiteSpace($itemPath)) {
        if (Test-Path -LiteralPath $itemPath) {
            if ((Get-Item -LiteralPath $itemPath -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw 'A managed path contains a junction or symbolic link; refusing changes.'
            }
        }
        $parent = [IO.Path]::GetDirectoryName($itemPath)
        if ($parent -eq $itemPath) { break }
        $itemPath = $parent
    }
}
function Set-ManagedAcl([string]$Path, [bool]$PrivateOnly) {
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $admins = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $system = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    $acl.SetOwner($admins)
    foreach ($sid in @($admins,$system)) {
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))
    }
    if (-not $PrivateOnly) {
        $users = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-545')
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($users,'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow')))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}
function Save-Json([string]$Path, $Value) {
    $temp = $Path + '.new'
    $existingAcl = if (Test-Path -LiteralPath $Path) { Get-Acl -LiteralPath $Path } else { $null }
    [IO.File]::WriteAllText($temp, ($Value | ConvertTo-Json -Depth 100), $utf8)
    if ($existingAcl) { Set-Acl -LiteralPath $temp -AclObject $existingAcl }
    Move-Item -LiteralPath $temp -Destination $Path -Force
}
function Get-ByteHash([byte[]]$Bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-','') } finally { $sha.Dispose() }
}
function Read-ConfigSnapshot([string]$Path) {
    $bytes = [IO.File]::ReadAllBytes($Path)
    return [pscustomobject]@{Hash=(Get-ByteHash $bytes);Content=([Text.Encoding]::UTF8.GetString($bytes).TrimStart([char]0xFEFF) | ConvertFrom-Json)}
}
function Write-ConfigDelta([string]$Path, $Before, [string]$ExpectedHash, $NewValues) {
    $beforeText = $Before | ConvertTo-Json -Depth 100 -Compress
    $after = $beforeText | ConvertFrom-Json
    foreach ($name in @('StrictRoute','EnableTun')) { $after.TunModeItem.$name = $NewValues.$name }
    $comparison = ($after | ConvertTo-Json -Depth 100 -Compress) | ConvertFrom-Json
    foreach ($name in @('StrictRoute','EnableTun')) { $comparison.TunModeItem.$name = $Before.TunModeItem.$name }
    if (($comparison | ConvertTo-Json -Depth 100 -Compress) -cne $beforeText) { throw 'Configuration semantic validation failed before writing.' }
    if ((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ne $ExpectedHash) { throw 'Configuration changed concurrently; refusing replacement.' }
    Save-Json $Path $after
    $written = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    foreach ($name in @('StrictRoute','EnableTun')) {
        if ($written.TunModeItem.$name -isnot [bool] -or $written.TunModeItem.$name -ne $NewValues.$name) { throw 'Configuration delta verification failed after writing.' }
        $written.TunModeItem.$name = $Before.TunModeItem.$name
    }
    if (($written | ConvertTo-Json -Depth 100 -Compress) -cne $beforeText) { throw 'Unrelated configuration changed during replacement; preserve recovery state.' }
}
function Assert-InstallationOwned($Manifest, $Task) {
    if (-not $Manifest -or $Manifest.Marker -ne $marker) { throw 'Unknown installation identity.' }
    Assert-TaskOwned $Task $Manifest
    foreach ($item in @(@{Path=$guardPath;Hash=$Manifest.GuardSHA256},@{Path=$installerPath;Hash=$Manifest.InstallerSHA256},@{Path=(Join-Path $private 'guiNConfig.before.json');Hash=$Manifest.OriginalConfigSHA256})) {
        Assert-NoReparse $item.Path
        if (-not (Test-Path -LiteralPath $item.Path -PathType Leaf) -or
            (Get-FileHash -LiteralPath $item.Path -Algorithm SHA256).Hash -ne $item.Hash) {
            throw 'Managed source or private backup was modified or is missing; preserve all files for review.'
        }
    }
}
function Get-ManagedTask {
    $tasks = @(Get-ScheduledTask -TaskPath '\' -TaskName $taskName -ErrorAction SilentlyContinue)
    if ($tasks.Count -gt 1) { throw 'Ambiguous scheduled task identity.' }
    if ($tasks.Count -eq 0) { return $null }
    return $tasks[0]
}
function Assert-TaskOwned($Task, $Manifest) {
    if (-not $Task) { return }
    if (-not $Manifest -or $Manifest.Marker -ne $marker) { throw 'Unknown same-name scheduled task; refusing changes.' }
    $actions = @($Task.Actions)
    $expected = Get-GuardArguments $Manifest.ExpectedSubnetRoutes
    if ($Task.Description -ne ($marker + ' ' + $Manifest.InstallationId) -or $actions.Count -ne 1 -or
        $actions[0].Execute -ne $psExe -or $actions[0].Arguments -ne $expected -or
        [string]$Task.Principal.UserId -notin @('SYSTEM','S-1-5-18')) {
        throw 'Same-name scheduled task differs from this installation; refusing changes.'
    }
}
function Assert-ClientStopped([string]$Path) {
    $running = @(Get-Process -Name v2rayN -ErrorAction SilentlyContinue)
    if ($running.Count -gt 0) { throw 'Exit v2rayN completely, including its notification-area process, before applying or undoing.' }
    $clientRoot = Split-Path -Parent (Split-Path -Parent $Path)
    $cores = @(Get-Process -Name sing-box -ErrorAction SilentlyContinue | Where-Object {
        $_.Path -and [IO.Path]::GetFullPath($_.Path).StartsWith($clientRoot + '\',[StringComparison]::OrdinalIgnoreCase)
    })
    if ($cores.Count -gt 0) { throw 'The v2rayN sing-box process is still running; refusing configuration changes.' }
}
function Undo-ConfigDelta($Manifest) {
    $path = [string]$Manifest.ConfigPath
    Assert-NoReparse $path
    $snapshot = Read-ConfigSnapshot $path
    $currentHash = $snapshot.Hash
    $current = $snapshot.Content
    if (-not $current.TunModeItem) { throw 'Current configuration has no TunModeItem; preserve it for manual review.' }
    $changed = $false
    $newValues = [pscustomobject]@{StrictRoute=$current.TunModeItem.StrictRoute;EnableTun=$current.TunModeItem.EnableTun}
    foreach ($name in @('StrictRoute','EnableTun')) {
        $installed = [bool]$Manifest.Applied.$name
        $original = [bool]$Manifest.Original.$name
        if ([bool]$current.TunModeItem.$name -eq $installed -and $installed -ne $original) {
            $newValues.$name = $original
            $changed = $true
        }
    }
    if ($changed) { Write-ConfigDelta $path $current $currentHash $newValues }
}
function Restore-Metrics {
    if (-not (Test-Path -LiteralPath $metricPath)) { return }
    $state = Get-Content -LiteralPath $metricPath -Raw | ConvertFrom-Json
    if ($state.Marker -ne $marker) { throw 'Unknown metric restoration state; refusing restoration.' }
    $adapters = @(Get-NetAdapter -IncludeHidden)
    foreach ($entry in @($state.Entries)) {
        $adapter = @($adapters | Where-Object { [string]$_.InterfaceGuid -eq [string]$entry.InterfaceGuid -and $_.Name -eq 'singbox_tun' })
        if ($adapter.Count -ne 1) { continue }
        $current = @(Get-NetIPInterface -InterfaceIndex $adapter[0].ifIndex -AddressFamily $entry.AddressFamily -PolicyStore ActiveStore -ErrorAction SilentlyContinue)
        if ($current.Count -ne 1) { continue }
        if ([long]$current[0].InterfaceMetric -eq [long]$entry.LastApplied -and [string]$current[0].AutomaticMetric -eq 'Disabled') {
            Set-NetIPInterface -InterfaceIndex $adapter[0].ifIndex -AddressFamily $entry.AddressFamily -AutomaticMetric $entry.OriginalAutomatic -InterfaceMetric $entry.OriginalMetric -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
        }
    }
}
function Remove-OwnedFiles($Manifest) {
    if ($Manifest) { Assert-InstallationOwned $Manifest (Get-ManagedTask) }
    $knownFiles = @($manifestPath, $metricPath, (Join-Path $private 'guiNConfig.before.json'),
        (Join-Path $private 'metric-state.json.new'), (Join-Path $private 'manifest.json.new'),
        $guardPath, $installerPath, (Join-Path $root 'guard.log'))
    foreach ($path in $knownFiles) {
        Assert-NoReparse $path
        if (Test-Path -LiteralPath $path -PathType Leaf) { Remove-Item -LiteralPath $path -Force }
    }
    foreach ($directory in @($private,$root)) {
        if ((Test-Path -LiteralPath $directory) -and @(Get-ChildItem -LiteralPath $directory -Force).Count -eq 0) {
            Remove-Item -LiteralPath $directory -Force
        }
    }
}

$ExpectedSubnetRoutes=@(Get-ExpectedSubnetPrefixes $ExpectedSubnetRoutes) -join ','
Assert-NoReparse $root
Assert-NoReparse $ConfigPath
$existingTask = Get-ManagedTask
$manifest = if (Test-Path -LiteralPath $manifestPath) { Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json } else { $null }
if ($manifest -and $manifest.Marker -ne $marker) { throw 'Unknown installation manifest; refusing changes.' }
Assert-TaskOwned $existingTask $manifest
if ($manifest) { Assert-InstallationOwned $manifest $existingTask }

if ($Undo) {
    if (-not $manifest) { throw 'No recognized installation to undo.' }
    if ($Apply) { Assert-ClientStopped $manifest.ConfigPath }
    if (-not $Apply) {
        [pscustomobject]@{ Mode='DryRunUndo'; Task=$taskName; Config='Restore only unchanged StrictRoute/EnableTun deltas'; Metrics='Restore only unchanged owned metrics'; PrivateBackup='Retained until successful undo' } | ConvertTo-Json
        exit 0
    }
} else {
    if ($manifest) { throw 'Already installed. Do not overwrite restoration state; use the installed undo command first.' }
    if (Test-Path -LiteralPath $root) { throw 'Unrecognized pre-existing installation directory; refusing changes.' }
    if ($Apply) { Assert-ClientStopped $ConfigPath }
    $sourceGuard = Join-Path $PSScriptRoot 'coexist-route-guard.ps1'
    if (-not (Test-Path -LiteralPath $sourceGuard -PathType Leaf)) { throw 'The route guard must be beside this installer.' }
    $config = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if (-not $config.TunModeItem -or $null -eq $config.TunModeItem.StrictRoute -or $null -eq $config.TunModeItem.EnableTun) { throw 'Unexpected v2rayN TunModeItem schema.' }
    if (-not $Apply) {
        [pscustomobject]@{ Mode='DryRunInstall'; Task=$taskName; ConfigPath=$ConfigPath; StrictRouteBefore=[bool]$config.TunModeItem.StrictRoute; StrictRouteAfter=$false; EnableTunBefore=[bool]$config.TunModeItem.EnableTun; EnableTunAfter=$true; InstallRoot=$root; Requires='Administrator and v2rayN fully exited' } | ConvertTo-Json
        exit 0
    }
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Apply requires a real elevated Administrator process. No changes were made.' }
$installLock = New-Object Threading.Mutex($false, 'Global\HomeNetworkInfraVPNCoexistInstaller')
if (-not $installLock.WaitOne(0)) { throw 'Another coexist installation is in progress.' }
$createdRoot = $false
$taskCreated = $false
$configWritten = $false
try {
    if ($Undo) {
        if ($existingTask) {
            Stop-ScheduledTask -InputObject $existingTask -ErrorAction SilentlyContinue
            Start-Sleep -Milliseconds 500
        }
        $guardLock = New-Object Threading.Mutex($false, 'Global\HomeNetworkInfraVPNCoexistRouteGuard')
        $guardLocked = $false
        try {
            try { $guardLocked = $guardLock.WaitOne(10000) } catch [Threading.AbandonedMutexException] { $guardLocked = $true }
            if (-not $guardLocked) { throw 'The route guard did not stop; refusing restoration.' }
            Restore-Metrics
            Undo-ConfigDelta $manifest
            if ($existingTask) { Unregister-ScheduledTask -TaskPath '\' -TaskName $taskName -Confirm:$false }
            Remove-OwnedFiles $manifest
        } finally {
            if ($guardLocked) { $guardLock.ReleaseMutex() }
            $guardLock.Dispose()
        }
        [pscustomobject]@{ Result='Undone'; Task=$taskName; FutureConfigurationPreserved=$true } | ConvertTo-Json
        exit 0
    }

    # Recheck after acquiring the installer lock.
    Assert-ClientStopped $ConfigPath
    if ((Get-ManagedTask) -or (Test-Path -LiteralPath $root)) { throw 'Installation state changed during preflight.' }
    New-Item -ItemType Directory -Path $root | Out-Null
    $createdRoot = $true
    Set-ManagedAcl $root $false
    New-Item -ItemType Directory -Path $private | Out-Null
    Set-ManagedAcl $private $true
    # The unredacted original never leaves the ACL-protected private directory.
    $originalBytes = [IO.File]::ReadAllBytes($ConfigPath)
    $originalHash = Get-ByteHash $originalBytes
    [IO.File]::WriteAllBytes((Join-Path $private 'guiNConfig.before.json'), $originalBytes)
    Copy-Item -LiteralPath $sourceGuard -Destination $guardPath
    Copy-Item -LiteralPath $PSCommandPath -Destination $installerPath
    $config = [Text.Encoding]::UTF8.GetString($originalBytes).TrimStart([char]0xFEFF) | ConvertFrom-Json
    $manifest = [pscustomobject]@{
        Marker=$marker; InstallationId=[guid]::NewGuid().ToString(); CreatedUtc=[DateTime]::UtcNow.ToString('o');
        ConfigPath=[IO.Path]::GetFullPath($ConfigPath); ExpectedSubnetRoutes=$ExpectedSubnetRoutes;
        Original=[pscustomobject]@{ StrictRoute=[bool]$config.TunModeItem.StrictRoute; EnableTun=[bool]$config.TunModeItem.EnableTun };
        Applied=[pscustomobject]@{ StrictRoute=$false; EnableTun=$true };
        GuardSHA256=(Get-FileHash -LiteralPath $guardPath -Algorithm SHA256).Hash;
        InstallerSHA256=(Get-FileHash -LiteralPath $installerPath -Algorithm SHA256).Hash;
        OriginalConfigSHA256=$originalHash
    }
    Save-Json $manifestPath $manifest
    # Set before writing so a post-write verification error still invokes delta rollback.
    $configWritten = $true
    Write-ConfigDelta $ConfigPath $config $originalHash $manifest.Applied
    $arguments = Get-GuardArguments $ExpectedSubnetRoutes
    $action = New-ScheduledTaskAction -Execute $psExe -Argument $arguments -WorkingDirectory $root
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $taskPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
    Register-ScheduledTask -TaskName $taskName -TaskPath '\' -Action $action -Trigger $trigger -Principal $taskPrincipal -Settings $settings -Description ($marker + ' ' + $manifest.InstallationId) | Out-Null
    $taskCreated = $true
    Start-ScheduledTask -TaskPath '\' -TaskName $taskName
    Start-Sleep -Seconds 2
    $checkTask = Get-ManagedTask
    Assert-TaskOwned $checkTask $manifest
    if ([string]$checkTask.State -ne 'Running') { throw 'Installed route guard did not remain running.' }
    [pscustomobject]@{ Result='Installed'; Task=$taskName; StrictRoute=$false; EnableTun=$true; PrivateBackupProtected=$true; ClientMustBeReopened=$true } | ConvertTo-Json
} catch {
    $failure = $_
    if (-not $Undo -and $createdRoot) {
        try {
            if ($taskCreated) {
                $rollbackTask = Get-ManagedTask
                Assert-TaskOwned $rollbackTask $manifest
                if ($rollbackTask) { Stop-ScheduledTask -InputObject $rollbackTask -ErrorAction SilentlyContinue }
                Start-Sleep -Milliseconds 500
            }
            $rollbackLock = New-Object Threading.Mutex($false, 'Global\HomeNetworkInfraVPNCoexistRouteGuard')
            $rollbackLocked = $false
            try {
                try { $rollbackLocked = $rollbackLock.WaitOne(10000) } catch [Threading.AbandonedMutexException] { $rollbackLocked = $true }
                if (-not $rollbackLocked) { throw 'The route guard did not stop during rollback.' }
                Restore-Metrics
                if ($configWritten) { Undo-ConfigDelta $manifest }
                if ($taskCreated) { Unregister-ScheduledTask -TaskPath '\' -TaskName $taskName -Confirm:$false }
                # Keep all protected backups and manifest after any failed installation.
                # A later explicit -Undo can inspect and remove this recognized state.
            } finally {
                if ($rollbackLocked) { $rollbackLock.ReleaseMutex() }
                $rollbackLock.Dispose()
            }
        } catch {
            throw ('Installation failed and automatic rollback is incomplete. Keep protected state for recovery. Cause: ' + $failure.Exception.Message + '; rollback: ' + $_.Exception.Message)
        }
    }
    throw $failure
} finally {
    $installLock.ReleaseMutex()
    $installLock.Dispose()
}
