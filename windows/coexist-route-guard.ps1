# SPDX-License-Identifier: MIT
# Copyright Home Network Infra Contributors
# Local route-priority guard. Does not change Tailscale preferences, routes, or DNS.
[CmdletBinding()]
param(
    [string]$InstallRoot = (Join-Path $env:ProgramData 'HomeNetworkInfraVPNCoexist'),
    [string]$ExpectedSubnetRoutes = '10.10.10.0/24,10.10.20.0/24',
    [ValidateRange(15,300)][int]$PollSeconds = 30,
    [switch]$Once,
    [switch]$DryRun
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$marker = 'HomeNetworkInfraVPNCoexist-v1'
$private = Join-Path $InstallRoot 'private'
$statePath = Join-Path $private 'metric-state.json'
$logPath = Join-Path $InstallRoot 'guard.log'
$mutex = New-Object Threading.Mutex($false, 'Global\HomeNetworkInfraVPNCoexistRouteGuard')
if (-not $mutex.WaitOne(0)) { exit 0 }
$lastMessage = ''

function Write-Metadata([string]$Message) {
    if ($Message -eq $script:lastMessage) { return }
    $script:lastMessage = $Message
    $line = [DateTime]::UtcNow.ToString('o') + ' ' + $Message
    if ($DryRun) { if (-not $Once) { Write-Output $line }; return }
    if ((Test-Path -LiteralPath $logPath) -and (Get-Item -LiteralPath $logPath).Length -gt 1048576) {
        [IO.File]::WriteAllText($logPath, '', (New-Object Text.UTF8Encoding($false)))
    }
    [IO.File]::AppendAllText($logPath, $line + [Environment]::NewLine, (New-Object Text.UTF8Encoding($false)))
}
function Save-State($State) {
    if ($DryRun) { return }
    $temp = $statePath + '.new'
    [IO.File]::WriteAllText($temp, ($State | ConvertTo-Json -Depth 10), (New-Object Text.UTF8Encoding($false)))
    Move-Item -LiteralPath $temp -Destination $statePath -Force
}
function Get-Cost($Route, $Interfaces) {
    $item = @($Interfaces | Where-Object { $_.InterfaceIndex -eq $Route.InterfaceIndex -and [string]$_.AddressFamily -eq [string]$Route.AddressFamily })
    if ($item.Count -ne 1) { throw 'Interface identity is ambiguous.' }
    return [long]$Route.RouteMetric + [long]$item[0].InterfaceMetric
}
function Get-TailscaleExitSelection {
    $tsExe = Join-Path $env:ProgramFiles 'Tailscale\tailscale.exe'
    if (-not (Test-Path -LiteralPath $tsExe -PathType Leaf)) { throw 'Tailscale CLI is unavailable.' }
    $raw = & $tsExe debug prefs 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect Tailscale exit-node preference.' }
    $prefs = ($raw -join "`n") | ConvertFrom-Json
    return (-not [string]::IsNullOrWhiteSpace([string]$prefs.ExitNodeID) -or -not [string]::IsNullOrWhiteSpace([string]$prefs.ExitNodeIP))
}
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
function Invoke-Reconcile {
    $expectedSubnetPrefixes=@(Get-ExpectedSubnetPrefixes $ExpectedSubnetRoutes)
    $adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop)
    $tun = @($adapters | Where-Object { $_.Name -eq 'singbox_tun' -and $_.Status -eq 'Up' })
    $ts = @($adapters | Where-Object { $_.Name -eq 'Tailscale' -and $_.Status -eq 'Up' })
    if ($tun.Count -eq 0) { Write-Metadata 'idle: TUN is absent'; return }
    if ($tun.Count -ne 1 -or $ts.Count -ne 1) { throw 'Expected one active singbox_tun and one active Tailscale adapter.' }
    $interfaces = @(Get-NetIPInterface -PolicyStore ActiveStore -ErrorAction Stop)
    $routes = @(Get-NetRoute -PolicyStore ActiveStore -ErrorAction Stop)
    $tsRoutes = @($routes | Where-Object { $_.InterfaceIndex -eq $ts[0].ifIndex })
    $scope = @($tsRoutes | Where-Object { $_.DestinationPrefix -eq '0.0.0.0/0' -or $_.DestinationPrefix -in $expectedSubnetPrefixes })
    if ($scope.Count -eq 0) { throw 'No expected Tailscale default or family subnet route; refusing changes.' }
    $selectedExit = Get-TailscaleExitSelection
    $physical = @($adapters | Where-Object { $_.HardwareInterface -and $_.Status -eq 'Up' } | ForEach-Object { $_.ifIndex })
    if ($physical.Count -eq 0) { throw 'No active hardware uplink; refusing changes.' }
    $physical6 = @($routes | Where-Object { $_.InterfaceIndex -in $physical -and $_.DestinationPrefix -eq '::/0' })
    $ts6 = @($tsRoutes | Where-Object { $_.DestinationPrefix -eq '::/0' })
    if ($selectedExit -and $physical6.Count -gt 0 -and $ts6.Count -eq 0) {
        throw 'IPv6 uplink has a default route but selected Tailscale exit has none; refusing changes.'
    }
    $plans = @()
    foreach ($family in @('IPv4','IPv6')) {
        $prefix = if ($family -eq 'IPv4') { '0.0.0.0/0' } else { '::/0' }
        $tunInterface = @($interfaces | Where-Object { $_.InterfaceIndex -eq $tun[0].ifIndex -and [string]$_.AddressFamily -eq $family })
        $tunDefaults = @($routes | Where-Object { $_.InterfaceIndex -eq $tun[0].ifIndex -and $_.DestinationPrefix -eq $prefix })
        if ($tunDefaults.Count -eq 0) { continue }
        if ($tunInterface.Count -ne 1 -or $tunDefaults.Count -ne 1) { throw 'Ambiguous TUN default route.' }
        $extra = @($routes | Where-Object {
            $_.InterfaceIndex -eq $tun[0].ifIndex -and [string]$_.AddressFamily -eq $family -and
            $_.DestinationPrefix -ne $prefix -and $_.DestinationPrefix -notmatch '^(172\.18\.0\.|172\.19\.0\.|127\.|224\.|255\.|ff00:|fe80:|fdfe:dcba:9876:)'
        })
        if ($extra.Count -gt 0) { throw 'Unexpected more-specific TUN routes; default metric alone is insufficient.' }
        $tsDefaults = @($tsRoutes | Where-Object { $_.DestinationPrefix -eq $prefix })
        if ($selectedExit -and $family -eq 'IPv4' -and $tsDefaults.Count -ne 1) { throw 'Selected exit has no unique Tailscale IPv4 default.' }
        foreach ($route in $tsDefaults) {
            if ((Get-Cost $route $interfaces) -ne 0) { throw 'Tailscale default total metric is not zero; refusing changes.' }
        }
        $uplinks = @($routes | Where-Object { $_.InterfaceIndex -in $physical -and $_.DestinationPrefix -eq $prefix })
        if ($uplinks.Count -eq 0) { throw 'No matching physical default route; refusing changes.' }
        $minimum = ($uplinks | ForEach-Object { Get-Cost $_ $interfaces } | Measure-Object -Minimum).Minimum
        $routeMetric = [long]$tunDefaults[0].RouteMetric
        if ($selectedExit) {
            # Tailscale excludes only its own adapter when selecting its underlay.
            # Keep another TUN below the physical uplink in that separate lookup.
            $desired = [long][Math]::Max(1, ($minimum + 5 - $routeMetric))
            if (($routeMetric + $desired) -le $minimum) { throw 'TUN priority would capture the Tailscale underlay.' }
        } else {
            $desired = if ($minimum -gt ($routeMetric + 5)) { 5 } elseif ($minimum -gt ($routeMetric + 1)) { 1 } else { throw 'No safe metric between Tailscale and the physical uplink.' }
            if (($routeMetric + $desired) -ge $minimum) { throw 'TUN fallback would not precede the physical uplink.' }
        }
        if ($desired -lt 1 -or $desired -gt 9999) { throw 'Required TUN interface metric is outside the supported safe range 1..9999.' }
        if (($routeMetric + $desired) -le 0) { throw 'TUN priority would tie Tailscale.' }
        $plans += [pscustomobject]@{ Family=$family; Interface=$tunInterface[0]; Desired=$desired; Guid=[string]$tun[0].InterfaceGuid }
    }
    if ($plans.Count -eq 0) { throw 'Active TUN has no supported default route.' }
    $state = if (Test-Path -LiteralPath $statePath) { Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json } else { [pscustomobject]@{ Marker=$marker; Entries=@() } }
    if ($state.Marker -ne $marker) { throw 'Unknown metric state owner.' }
    foreach ($plan in $plans) {
        $current = $plan.Interface
        if ([long]$current.InterfaceMetric -eq $plan.Desired -and [string]$current.AutomaticMetric -eq 'Disabled') { continue }
        $entry = @($state.Entries | Where-Object { $_.InterfaceGuid -eq $plan.Guid -and $_.AddressFamily -eq $plan.Family })
        if ($entry.Count -gt 1) { throw 'Duplicate metric restoration record.' }
        if ($entry.Count -eq 0) {
            $record = [pscustomobject]@{ InterfaceGuid=$plan.Guid; AddressFamily=$plan.Family; OriginalMetric=[long]$current.InterfaceMetric; OriginalAutomatic=[string]$current.AutomaticMetric; LastApplied=$plan.Desired }
            $state.Entries = @($state.Entries) + @($record)
        } else { $entry[0].LastApplied = $plan.Desired }
        Save-State $state
        if (-not $DryRun) {
            Set-NetIPInterface -InterfaceIndex $current.InterfaceIndex -AddressFamily $plan.Family -AutomaticMetric Disabled -InterfaceMetric $plan.Desired -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
        }
        Write-Metadata ('metric: family=' + $plan.Family + ' index=' + $current.InterfaceIndex + ' value=' + $plan.Desired + ' exitSelected=' + $selectedExit)
    }
    Write-Metadata ('healthy: TUN priority checked; exitSelected=' + $selectedExit)
}
try {
    if (-not $DryRun) {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run the installed guard elevated.' }
        if (-not (Test-Path -LiteralPath $private -PathType Container)) { throw 'Private installation state is absent.' }
    }
    if (-not $Once) {
        Add-Type -TypeDefinition @'
using System;
using System.Net.NetworkInformation;
using System.Threading;
public static class HomeNetworkInfraVpnNetworkSignal {
    public static readonly AutoResetEvent Changed = new AutoResetEvent(false);
    private static readonly NetworkAddressChangedEventHandler AddressHandler = (s, e) => Changed.Set();
    private static readonly NetworkAvailabilityChangedEventHandler AvailableHandler = (s, e) => Changed.Set();
    public static void Start() { NetworkChange.NetworkAddressChanged += AddressHandler; NetworkChange.NetworkAvailabilityChanged += AvailableHandler; }
    public static void Stop() { NetworkChange.NetworkAddressChanged -= AddressHandler; NetworkChange.NetworkAvailabilityChanged -= AvailableHandler; }
}
'@
        [HomeNetworkInfraVpnNetworkSignal]::Start()
    }
    do {
        $reconcileFailed = $false
        try { Invoke-Reconcile } catch { $reconcileFailed = $true; Write-Metadata ('refused: ' + $_.Exception.Message) }
        if ($Once) {
            [pscustomobject]@{ Success=(-not $reconcileFailed); DryRun=[bool]$DryRun; Status=$script:lastMessage } | ConvertTo-Json -Compress
            if ($reconcileFailed) { exit 2 }
            break
        }
        [void][HomeNetworkInfraVpnNetworkSignal]::Changed.WaitOne($PollSeconds * 1000)
    } while ($true)
} catch {
    try { Write-Metadata ('fatal: ' + $_.Exception.Message) } catch { }
    throw
} finally {
    if (-not $Once -and ('HomeNetworkInfraVpnNetworkSignal' -as [type])) { [HomeNetworkInfraVpnNetworkSignal]::Stop() }
    $mutex.ReleaseMutex()
    $mutex.Dispose()
}
