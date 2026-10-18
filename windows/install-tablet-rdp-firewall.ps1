# SPDX-License-Identifier: MIT
# Copyright Home Network Infra Contributors
# Scope: allow this tablet to reach this Windows Tailscale RDP listener only.
# Read-only by default. Apply/undo require a real Administrator PowerShell.
[CmdletBinding()]
param(
    [switch]$Apply,
    [switch]$Undo,
    [string]$TabletTailIP='100.100.10.3',
    [string]$WindowsTailIP='100.100.10.5'
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2.0
$marker='HomeNetworkInfraTabletRDP-v1'
$root=Join-Path $env:ProgramData 'HomeNetworkInfraTabletRDP'
$manifestPath=Join-Path $root 'manifest.json'
$installedScript=Join-Path $root 'install-tablet-rdp-firewall.ps1'
$utf8=New-Object Text.UTF8Encoding($false)
$builtinNames=@('RemoteDesktop-UserMode-In-TCP','RemoteDesktop-UserMode-In-UDP','RemoteDesktop-Shadow-In-TCP')
$ownedNames=@('HomeNetworkInfra-TabletRDP-Allow-TCP','HomeNetworkInfra-TabletRDP-Allow-UDP','HomeNetworkInfra-TabletRDP-Block-Others-TCP','HomeNetworkInfra-TabletRDP-Block-Others-UDP')

function Get-IPv4Number([string]$Address) {
    $bytes=[Net.IPAddress]::Parse($Address).GetAddressBytes()
    if ($bytes.Count -ne 4) { throw 'An IPv4 address is required.' }
    return [uint64]$bytes[0]*16777216+[uint64]$bytes[1]*65536+[uint64]$bytes[2]*256+[uint64]$bytes[3]
}
function Get-IPv4Text([uint64]$Number) {
    if ($Number -gt 4294967295) { throw 'IPv4 number is out of range.' }
    return '{0}.{1}.{2}.{3}' -f (($Number -shr 24) -band 255),(($Number -shr 16) -band 255),(($Number -shr 8) -band 255),($Number -band 255)
}
function Assert-TailAddress([string]$Address) {
    $parsed=[Net.IPAddress]::Parse($Address)
    $number=Get-IPv4Number $Address
    if ($parsed.ToString() -ne $Address -or $number -lt 1681915904 -or $number -gt 1686110207) { throw 'Use a canonical IPv4 tailnet address within 100.64.0.0/10.' }
    return $Address
}
function Get-OtherSourceRanges([string]$AllowedAddress) {
    [void](Assert-TailAddress $AllowedAddress)
    $allowed=Get-IPv4Number $AllowedAddress
    # Native Windows firewall accepts these two IPv6 halves; ::/0 is not used.
    $before='0.0.0.0-'+(Get-IPv4Text ($allowed-1))
    $after=(Get-IPv4Text ($allowed+1))+'-255.255.255.255'
    return @($before,$after,'::/1','8000::/1')
}
function Get-TextHash([string]$Text) {
    $sha=[Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)))).Replace('-','') } finally {$sha.Dispose()}
}
function Save-Manifest($Value) {
    $temp=$manifestPath+'.new'
    [IO.File]::WriteAllText($temp,($Value | ConvertTo-Json -Depth 30),$utf8)
    Move-Item -LiteralPath $temp -Destination $manifestPath -Force
}
function Assert-NoReparse([string]$Path) {
    $part=[IO.Path]::GetFullPath($Path)
    while ($part) {
        if ((Test-Path -LiteralPath $part) -and ((Get-Item -LiteralPath $part -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {throw 'Managed path contains a link or junction; refusing changes.'}
        $parent=[IO.Path]::GetDirectoryName($part)
        if ($parent -eq $part) {break}
        $part=$parent
    }
}
function Protect-Directory {
    $acl=New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true,$false)
    $admins=New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $system=New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    $acl.SetOwner($admins)
    foreach ($sid in @($admins,$system)) {$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))}
    Set-Acl -LiteralPath $root -AclObject $acl
}
function Normalize-Addresses($Values) {
    $result=@()
    foreach ($value in @($Values)) {
        $v=([string]$value).Trim().ToLowerInvariant()
        if ($v -match '^(.+)/32$' -and $matches[1] -notmatch ':') {$v=$matches[1]}
        if ($v -match '^(.+)/128$' -and $matches[1] -match ':') {$v=([Net.IPAddress]::Parse($matches[1])).ToString().ToLowerInvariant()}
        if ($v -eq '0:0:0:0:0:0:0:0/0' -or $v -eq '::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff') {$v='::/0'}
        $result+=$v
    }
    return @($result | Sort-Object -Unique)
}
function Normalize-Values($Values) {return @(@($Values) | ForEach-Object {([string]$_).Trim().ToLowerInvariant()} | Sort-Object -Unique)}
function Get-OneRule([string]$Name,[string]$Store='PersistentStore') {
    $items=@(Get-NetFirewallRule -PolicyStore $Store -Name $Name -ErrorAction SilentlyContinue)
    if ($items.Count -gt 1) {throw 'Firewall rule identity is ambiguous.'}
    if ($items.Count -eq 0) {return $null}
    return $items[0]
}
function Get-OneFilter($Rule,[string]$Kind) {
    $items=@(switch ($Kind) {
        'Port' {Get-NetFirewallPortFilter -AssociatedNetFirewallRule $Rule}
        'Address' {Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $Rule}
        'Application' {Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $Rule}
        'Service' {Get-NetFirewallServiceFilter -AssociatedNetFirewallRule $Rule}
        'Interface' {Get-NetFirewallInterfaceFilter -AssociatedNetFirewallRule $Rule}
        'InterfaceType' {Get-NetFirewallInterfaceTypeFilter -AssociatedNetFirewallRule $Rule}
        'Security' {Get-NetFirewallSecurityFilter -AssociatedNetFirewallRule $Rule}
    })
    if ($items.Count -ne 1) {throw 'Firewall rule filter identity is ambiguous.'}
    return $items[0]
}
function Get-PropertyValue($Object,[string]$Name) {
    $p=$Object.PSObject.Properties[$Name]
    if ($null -eq $p) {return '<absent>'}
    return $p.Value
}
function Get-RuleDocument($Rule,[switch]$IgnoreEnabled) {
    $doc=[ordered]@{}
    foreach ($name in @('Name','DisplayName','Description','Group','Profile','Direction','Action','EdgeTraversalPolicy','LooseSourceMapping','LocalOnlyMapping','Owner')) {$doc[$name]=@(Normalize-Values (Get-PropertyValue $Rule $name))}
    if (-not $IgnoreEnabled) {$doc['Enabled']=@(Normalize-Values $Rule.Enabled)}
    foreach ($filter in @(
        @{Kind='Port';Properties=@('Protocol','LocalPort','RemotePort','IcmpType','DynamicTarget')},
        @{Kind='Address';Properties=@('LocalAddress','RemoteAddress')},
        @{Kind='Application';Properties=@('Program','Package')},
        @{Kind='Service';Properties=@('Service')},
        @{Kind='Interface';Properties=@('InterfaceAlias')},
        @{Kind='InterfaceType';Properties=@('InterfaceType')},
        @{Kind='Security';Properties=@('Authentication','Encryption','OverrideBlockRules','LocalUser','RemoteUser','RemoteMachine')}
    )) {
        $object=Get-OneFilter $Rule $filter.Kind
        foreach ($name in $filter.Properties) {
            $value=Get-PropertyValue $object $name
            $doc[$filter.Kind+'.'+$name]=if ($filter.Kind -eq 'Address') {@(Normalize-Addresses $value)} else {@(Normalize-Values $value)}
        }
    }
    return [pscustomobject]$doc
}
function Get-Fingerprint($Rule,[switch]$IgnoreEnabled) {return Get-TextHash ((Get-RuleDocument $Rule -IgnoreEnabled:$IgnoreEnabled) | ConvertTo-Json -Depth 10 -Compress)}
function Assert-EffectiveProfiles {
    $profiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore)
    if ($profiles.Count -ne 3) {throw 'Expected three effective firewall profiles.'}
    foreach ($profile in $profiles) {
        if ([string]$profile.Enabled -ne 'True') {throw 'An effective firewall profile is disabled.'}
        if ([string]$profile.AllowLocalFirewallRules -eq 'False') {throw 'Effective policy rejects local firewall rules.'}
        if ([string]$profile.AllowInboundRules -eq 'False') {throw 'Effective policy rejects inbound allow rules.'}
        if ([string]$profile.DefaultInboundAction -notin @('Block','NotConfigured')) {throw 'An effective inbound firewall policy is not blocking by default.'}
    }
}
function Get-RuleSpecifications([string]$Id) {
    $specs=@()
    foreach ($protocol in @('TCP','UDP')) {
        $specs+=[pscustomobject]@{Name=('HomeNetworkInfra-TabletRDP-Allow-'+$protocol);Protocol=$protocol;Action='Allow';RemoteAddress=@($TabletTailIP);LocalAddress=@($WindowsTailIP);InterfaceAlias=@('Tailscale');Service='TermService';Description=($marker+' '+$Id)}
    }
    foreach ($protocol in @('TCP','UDP')) {
        $specs+=[pscustomobject]@{Name=('HomeNetworkInfra-TabletRDP-Block-Others-'+$protocol);Protocol=$protocol;Action='Block';RemoteAddress=@(Get-OtherSourceRanges $TabletTailIP);LocalAddress=@('Any');InterfaceAlias=@('Any');Service='Any';Description=($marker+' '+$Id)}
    }
    return $specs
}
function Assert-Specification($Rule,$Spec) {
    $port=Get-OneFilter $Rule 'Port';$address=Get-OneFilter $Rule 'Address';$service=Get-OneFilter $Rule 'Service';$iface=Get-OneFilter $Rule 'Interface'
    $protocol=if ([string]$port.Protocol -in @('TCP','6')) {'TCP'} elseif ([string]$port.Protocol -in @('UDP','17')) {'UDP'} else {'Other'}
    if ($Rule.Name -ne $Spec.Name -or $Rule.DisplayName -ne $Spec.Name -or $Rule.Description -ne $Spec.Description -or
        [string]$Rule.Enabled -ne 'True' -or [string]$Rule.Direction -ne 'Inbound' -or [string]$Rule.Action -ne $Spec.Action -or
        [string]$Rule.Profile -ne 'Any' -or $protocol -ne $Spec.Protocol -or
        (@(Normalize-Values $port.LocalPort) -join ',') -ne '3389' -or (@(Normalize-Values $port.RemotePort) -join ',') -ne 'any' -or
        (@(Normalize-Addresses $address.LocalAddress) -join ',') -ne (@(Normalize-Addresses $Spec.LocalAddress) -join ',') -or
        (@(Normalize-Addresses $address.RemoteAddress) -join ',') -ne (@(Normalize-Addresses $Spec.RemoteAddress) -join ',') -or
        (@(Normalize-Values $iface.InterfaceAlias) -join ',') -ne (@(Normalize-Values $Spec.InterfaceAlias) -join ',') -or
        [string]$service.Service -ne $Spec.Service) {throw 'Firewall rule differs from the intended tablet-only specification.'}
    if ($Spec.Action -eq 'Block' -and 'any' -in @(Normalize-Addresses $address.RemoteAddress)) {throw 'IPv6 complement expanded to all addresses; refusing to block the tablet.'}
}
function Assert-InstallationOwned($Manifest) {
    if ($Manifest.Marker -ne $marker) {throw 'Unknown installation identity.'}
    [void](Assert-TailAddress $Manifest.TabletTailIP)
    [void](Assert-TailAddress $Manifest.WindowsTailIP)
    if ($Manifest.TabletTailIP -eq $Manifest.WindowsTailIP) {throw 'Stored tablet and Windows addresses must differ.'}
    Assert-NoReparse $installedScript
    if (-not (Test-Path -LiteralPath $installedScript -PathType Leaf) -or (Get-FileHash -LiteralPath $installedScript -Algorithm SHA256).Hash -ne $Manifest.InstallerSHA256) {throw 'Installed source was modified or is missing; preserve protected state for review.'}
    if ((@($Manifest.BuiltinRules | ForEach-Object Name | Sort-Object) -join ',') -ne (@($builtinNames | Sort-Object) -join ',')) {throw 'Installation metadata has unexpected builtin rules.'}
    if (@($Manifest.OwnedRules | ForEach-Object Name | Sort-Object -Unique).Count -ne @($Manifest.OwnedRules).Count) {throw 'Duplicate owned rule in restoration state.'}
    foreach ($entry in @($Manifest.OwnedRules)) {if ($entry.Name -notin $ownedNames) {throw 'Unknown owned rule in restoration state.'}}
}
function Undo-Deltas($Manifest,[switch]$Rollback) {
    $warnings=@()
    foreach ($entry in @($Manifest.OwnedRules)) {
        $rule=Get-OneRule $entry.Name
        if (-not $rule) {continue}
        if ((Get-Fingerprint $rule) -ne $entry.Fingerprint) {$warnings+=('Preserved modified owned rule: '+$entry.Name);continue}
        Remove-NetFirewallRule -PolicyStore PersistentStore -Name $entry.Name
    }
    foreach ($entry in @($Manifest.BuiltinRules)) {
        if (-not $entry.Changed) {continue}
        $rule=Get-OneRule $entry.Name
        if (-not $rule) {$warnings+=('Preserved missing builtin rule: '+$entry.Name);continue}
        if ((Get-Fingerprint $rule -IgnoreEnabled) -ne $entry.WithoutEnabledFingerprint) {$warnings+=('Preserved modified builtin rule: '+$entry.Name);continue}
        if ([string]$rule.Enabled -eq 'False') {Set-NetFirewallRule -PolicyStore PersistentStore -Name $entry.Name -Enabled $entry.OriginalEnabled | Out-Null}
        elseif ([string]$rule.Enabled -ne $entry.OriginalEnabled) {$warnings+=('Preserved later builtin Enabled value: '+$entry.Name)}
    }
    return @($warnings)
}
function Remove-OwnedInstallation($Manifest) {
    Assert-InstallationOwned $Manifest
    foreach ($path in @($installedScript,$manifestPath,($manifestPath+'.new'))) {Assert-NoReparse $path;if (Test-Path -LiteralPath $path -PathType Leaf) {Remove-Item -LiteralPath $path -Force}}
    if (@(Get-ChildItem -LiteralPath $root -Force).Count -eq 0) {Remove-Item -LiteralPath $root -Force}
}

$TabletTailIP=Assert-TailAddress $TabletTailIP
$WindowsTailIP=Assert-TailAddress $WindowsTailIP
if ($TabletTailIP -eq $WindowsTailIP) {throw 'Tablet and Windows addresses must differ.'}
Assert-NoReparse $root
$manifest=if (Test-Path -LiteralPath $manifestPath -PathType Leaf) {Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json} else {$null}
if ($manifest) {
    Assert-InstallationOwned $manifest
    if ($Undo) {$TabletTailIP=[string]$manifest.TabletTailIP;$WindowsTailIP=[string]$manifest.WindowsTailIP}
}
if ($Undo) {
    if (-not $manifest) {throw 'No recognized tablet RDP firewall installation exists.'}
} else {
    if ($manifest -or (Test-Path -LiteralPath $root)) {throw 'Installation state already exists; inspect or undo it before installing.'}
    Assert-EffectiveProfiles
    foreach ($name in $ownedNames) {if ((Get-OneRule $name) -or (Get-OneRule $name 'ActiveStore')) {throw 'Unknown same-name firewall rule; refusing changes.'}}
    foreach ($name in $builtinNames) {if (-not (Get-OneRule $name) -or -not (Get-OneRule $name 'ActiveStore')) {throw 'An expected builtin RDP rule is missing.'}}
}
if (-not $Apply) {
    [pscustomobject]@{Mode=$(if ($Undo) {'ReadOnlyUndo'} else {'ReadOnlyInstall'});Marker=$marker;TabletTailIP=$TabletTailIP;WindowsTailIP=$WindowsTailIP;Allow='TCP/UDP 3389 on Tailscale, TermService';Block='All other IPv4 and all IPv6 sources on TCP/UDP 3389';DisableBuiltinRules=$builtinNames;ChangedSystem=$false} | ConvertTo-Json -Depth 5
    exit 0
}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {throw 'Apply requires a real elevated Administrator process. No changes were made.'}
$mutex=New-Object Threading.Mutex($false,'Global\HomeNetworkInfraTabletRDPInstaller')
if (-not $mutex.WaitOne(0)) {throw 'Another tablet RDP firewall installation is running.'}
$createdRoot=$false
try {
    if ($Undo) {
        Assert-InstallationOwned $manifest
        $warnings=@(Undo-Deltas $manifest)
        if ($warnings.Count -eq 0) {Remove-OwnedInstallation $manifest} else {Save-Manifest $manifest}
        [pscustomobject]@{Result=$(if ($warnings.Count) {'UndoneWithPreservedEdits'} else {'Undone'});Warnings=$warnings;ProtectedStateRetained=($warnings.Count -gt 0)} | ConvertTo-Json -Depth 5
        exit 0
    }
    Assert-EffectiveProfiles
    if (Test-Path -LiteralPath $root) {throw 'Installation directory appeared during preflight.'}
    foreach ($name in $ownedNames) {if ((Get-OneRule $name) -or (Get-OneRule $name 'ActiveStore')) {throw 'Firewall rule appeared during preflight.'}}
    $records=@()
    foreach ($name in $builtinNames) {
        $rule=Get-OneRule $name
        if (-not $rule) {throw 'Builtin rule disappeared during preflight.'}
        $records+=[pscustomobject]@{Name=$name;OriginalEnabled=[string]$rule.Enabled;WillDisable=([string]$rule.Enabled -eq 'True');Changed=$false;OriginalFingerprint=(Get-Fingerprint $rule);WithoutEnabledFingerprint=(Get-Fingerprint $rule -IgnoreEnabled)}
    }
    New-Item -ItemType Directory -Path $root | Out-Null
    $createdRoot=$true
    Protect-Directory
    Copy-Item -LiteralPath $PSCommandPath -Destination $installedScript
    $manifest=[pscustomobject]@{Marker=$marker;InstallationId=[guid]::NewGuid().ToString();CreatedUtc=[DateTime]::UtcNow.ToString('o');InstallerSHA256=(Get-FileHash -LiteralPath $installedScript -Algorithm SHA256).Hash;TabletTailIP=$TabletTailIP;WindowsTailIP=$WindowsTailIP;BuiltinRules=$records;OwnedRules=@();State='Installing'}
    Save-Manifest $manifest
    # Install explicit blocks first, then the narrow allows. No profile or service setting changes.
    $specs=@(Get-RuleSpecifications $manifest.InstallationId)
    foreach ($spec in @($specs | Sort-Object @{Expression={if ($_.Action -eq 'Block') {0} else {1}}},Name)) {
        New-NetFirewallRule -PolicyStore PersistentStore -Name $spec.Name -DisplayName $spec.Name -Description $spec.Description -Group $marker -Enabled True -Direction Inbound -Action $spec.Action -Profile Any -Protocol $spec.Protocol -LocalPort 3389 -RemotePort Any -LocalAddress $spec.LocalAddress -RemoteAddress $spec.RemoteAddress -InterfaceAlias $spec.InterfaceAlias -Service $spec.Service -EdgeTraversalPolicy Block | Out-Null
        $rule=Get-OneRule $spec.Name
        if (-not $rule) {throw 'Created firewall rule cannot be read back.'}
        $manifest.OwnedRules=@($manifest.OwnedRules)+@([pscustomobject]@{Name=$spec.Name;Fingerprint=(Get-Fingerprint $rule)})
        Save-Manifest $manifest
        Assert-Specification $rule $spec
    }
    foreach ($entry in $manifest.BuiltinRules) {
        $rule=Get-OneRule $entry.Name
        if ((Get-Fingerprint $rule) -ne $entry.OriginalFingerprint) {throw 'Builtin rule changed concurrently; refusing to overwrite it.'}
        if ($entry.WillDisable) {$entry.Changed=$true;Save-Manifest $manifest;Set-NetFirewallRule -PolicyStore PersistentStore -Name $entry.Name -Enabled False | Out-Null}
    }
    Assert-EffectiveProfiles
    foreach ($spec in $specs) {$effective=Get-OneRule $spec.Name 'ActiveStore';if (-not $effective) {throw 'Owned rule is absent from effective firewall policy.'};Assert-Specification $effective $spec}
    foreach ($entry in $manifest.BuiltinRules) {$effective=Get-OneRule $entry.Name 'ActiveStore';if (-not $effective -or [string]$effective.Enabled -ne 'False') {throw 'A broad builtin RDP rule remains enabled in effective policy.'}}
    $manifest.State='Installed'
    Save-Manifest $manifest
    [pscustomobject]@{Result='Installed';Marker=$marker;AllowSources=@($TabletTailIP);Destination=($WindowsTailIP+':3389');Interface='Tailscale';Protocols=@('TCP','UDP');OwnedRules=4;DisabledBuiltinRules=@($records | Where-Object Changed | ForEach-Object Name);ServiceOrUserChanges=$false} | ConvertTo-Json -Depth 5
} catch {
    $failure=$_
    if (-not $Undo -and $createdRoot -and $manifest) {
        try {$warnings=@(Undo-Deltas $manifest -Rollback);$manifest.State='RolledBackAfterInstallFailure';Save-Manifest $manifest;if ($warnings.Count) {throw ($warnings -join '; ')}}
        catch {throw ('Installation failed and rollback needs review. Protected metadata retained. Cause: '+$failure.Exception.Message+'; rollback: '+$_.Exception.Message)}
    }
    throw $failure
} finally {$mutex.ReleaseMutex();$mutex.Dispose()}
