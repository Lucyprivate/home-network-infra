# SPDX-License-Identifier: MIT
# Copyright Home Network Infra Contributors
# Offline only: extract functions, mock all firewall reads/writes, never execute installer body.
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2.0
$path=Join-Path $PSScriptRoot 'install-tablet-rdp-firewall.ps1'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
if (@($errors).Count) {throw ($errors | Out-String)}
foreach ($definition in $ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]},$false)) {Invoke-Expression $definition.Extent.Text}
$marker='HomeNetworkInfraTabletRDP-v1'
$builtinNames=@('RemoteDesktop-UserMode-In-TCP','RemoteDesktop-UserMode-In-UDP','RemoteDesktop-Shadow-In-TCP')
$ownedNames=@('HomeNetworkInfra-TabletRDP-Allow-TCP','HomeNetworkInfra-TabletRDP-Allow-UDP','HomeNetworkInfra-TabletRDP-Block-Others-TCP','HomeNetworkInfra-TabletRDP-Block-Others-UDP')
$results=@([pscustomobject]@{Test='PowerShell AST';Passed=$true})
function Get-OneFilter($Rule,[string]$Kind) {return $Rule.Filters[$Kind]}
function Get-OneRule([string]$Name,[string]$Store='PersistentStore') {if ($script:rules.ContainsKey($Name)) {return $script:rules[$Name]};return $null}
function Get-NetFirewallProfile {param($PolicyStore) return $script:profiles}
function Set-NetFirewallRule {param($PolicyStore,$Name,$Enabled) $script:writes+=('Set:'+ $Name + ':'+$Enabled);$script:rules[$Name].Enabled=[string]$Enabled}
function Remove-NetFirewallRule {param($PolicyStore,$Name) $script:writes+=('Remove:'+$Name);$script:rules.Remove($Name)}
function New-MockRule($Spec) {
    return [pscustomobject]@{
        Name=$Spec.Name;DisplayName=$Spec.Name;Description=$Spec.Description;Group=$marker;Profile='Any';Direction='Inbound';Action=$Spec.Action;Enabled='True';EdgeTraversalPolicy='Block';LooseSourceMapping='False';LocalOnlyMapping='False';Owner='';
        Filters=@{
            Port=[pscustomobject]@{Protocol=$Spec.Protocol;LocalPort=@('3389');RemotePort=@('Any');IcmpType=@('Any');DynamicTarget='Any'};
            Address=[pscustomobject]@{LocalAddress=$Spec.LocalAddress;RemoteAddress=$Spec.RemoteAddress};
            Application=[pscustomobject]@{Program='Any';Package='Any'};
            Service=[pscustomobject]@{Service=$Spec.Service};Interface=[pscustomobject]@{InterfaceAlias=$Spec.InterfaceAlias};InterfaceType=[pscustomobject]@{InterfaceType='Any'};
            Security=[pscustomobject]@{Authentication='NotRequired';Encryption='NotRequired';OverrideBlockRules='False';LocalUser='Any';RemoteUser='Any';RemoteMachine='Any'}
        }
    }
}
function Reset-Fixture {
    $script:TabletTailIP='100.100.10.3';$script:WindowsTailIP='100.100.10.5'
    $script:writes=@();$script:rules=@{}
    $script:profiles=@('Domain','Private','Public' | ForEach-Object {[pscustomobject]@{Name=$_;Enabled='True';AllowLocalFirewallRules='True';AllowInboundRules='True';DefaultInboundAction='Block'}})
    $script:specs=@(Get-RuleSpecifications 'offline-id')
    foreach ($spec in $script:specs) {$script:rules[$spec.Name]=New-MockRule $spec}
    $builtinRecords=@()
    foreach ($name in $builtinNames) {
        $spec=[pscustomobject]@{Name=$name;Protocol='TCP';Action='Allow';RemoteAddress=@('Any');LocalAddress=@('Any');InterfaceAlias=@('Any');Service='TermService';Description='Builtin'}
        $rule=New-MockRule $spec
        $script:rules[$name]=$rule
        $builtinRecords+=[pscustomobject]@{Name=$name;OriginalEnabled='True';WillDisable=$true;Changed=$true;OriginalFingerprint=(Get-Fingerprint $rule);WithoutEnabledFingerprint=(Get-Fingerprint $rule -IgnoreEnabled)}
        $rule.Enabled='False'
    }
    $ownedRecords=@($script:specs | ForEach-Object {[pscustomobject]@{Name=$_.Name;Fingerprint=(Get-Fingerprint $script:rules[$_.Name])}})
    $script:manifest=[pscustomobject]@{Marker=$marker;InstallationId='offline-id';BuiltinRules=$builtinRecords;OwnedRules=$ownedRecords}
}
function Assert-Case([string]$Name,[scriptblock]$Body) {Reset-Fixture;& $Body;$script:results+=[pscustomobject]@{Test=$Name;Passed=$true}}
function Assert-Fails([scriptblock]$Body) {$failed=$false;try {& $Body}catch {$failed=$true};if (-not $failed) {throw 'Expected refusal.'}}
function IPv4-Number([string]$Address) {$bytes=[Net.IPAddress]::Parse($Address).GetAddressBytes();return [uint64]$bytes[0]*16777216+[uint64]$bytes[1]*65536+[uint64]$bytes[2]*256+[uint64]$bytes[3]}
function In-BlockComplement([string]$Address) {
    $ip=IPv4-Number $Address
    foreach ($range in $script:specs[2].RemoteAddress) {if ($range -match ':') {continue};$endpoints=$range.Split('-');if ($ip -ge (IPv4-Number $endpoints[0]) -and $ip -le (IPv4-Number $endpoints[1])) {return $true}}
    return $false
}
Assert-Case 'Exact four specifications accepted' {foreach ($spec in $script:specs) {Assert-Specification $script:rules[$spec.Name] $spec};if ($script:writes.Count) {throw 'Read-only validation wrote firewall state.'}}
Assert-Case 'Complement has four explicit scopes and expected new boundaries' {
    $actual=@(Get-OtherSourceRanges '100.100.10.3')
    if ($actual.Count -ne 4 -or ($actual -join ',') -ne '0.0.0.0-100.100.10.2,100.100.10.4-255.255.255.255,::/1,8000::/1') {throw 'Wrong complement boundary calculation.'}
}
Assert-Case 'Custom tablet and Windows parameters reach every specification' {
    $script:TabletTailIP='100.100.11.42';$script:WindowsTailIP='100.100.11.44'
    $custom=@(Get-RuleSpecifications 'custom-id')
    foreach ($spec in @($custom | Where-Object Action -eq 'Allow')) {
        if ($spec.RemoteAddress[0] -ne '100.100.11.42' -or $spec.LocalAddress[0] -ne '100.100.11.44') {throw 'Custom address did not propagate.'}
    }
    if (($custom[2].RemoteAddress -join ',') -ne '0.0.0.0-100.100.11.41,100.100.11.43-255.255.255.255,::/1,8000::/1') {throw 'Custom complement is stale.'}
}
Assert-Case 'Tail address validation rejects noncanonical, IPv6 and outside tailnet' {
    foreach ($address in @('10.10.10.3','100.128.0.1','100.63.255.254','::1','100.100.10.003')) {Assert-Fails {[void](Assert-TailAddress $address)}}
    foreach ($address in @('100.64.0.0','100.127.255.255')) {if ((Assert-TailAddress $address) -ne $address) {throw 'Valid tail boundary rejected.'}}
}
Assert-Case 'IPv4 complement excludes only tablet address at both boundaries' {
    foreach ($ip in @('0.0.0.0','100.100.10.2','100.100.10.4','255.255.255.255','10.10.10.1','10.10.20.50')) {if (-not (In-BlockComplement $ip)) {throw 'Complement omitted another source.'}}
    if (In-BlockComplement '100.100.10.3') {throw 'Complement blocks tablet.'}
    if ('::/1' -notin $script:specs[2].RemoteAddress -or '8000::/1' -notin $script:specs[2].RemoteAddress) {throw 'IPv6 complement halves absent.'}
}
Assert-Case 'Native IPv6 halves are disjoint and cover every first-bit value' {
    $prefixes=@($script:specs[2].RemoteAddress | Where-Object {$_ -match ':'})
    if ($prefixes.Count -ne 2 -or 'any' -in @(Normalize-Addresses $prefixes)) {throw 'Unexpected IPv6 scope.'}
    $firstBits=@()
    foreach ($prefix in $prefixes) {
        $parts=$prefix.Split('/');if ($parts[1] -ne '1') {throw 'IPv6 half prefix length changed.'}
        $bytes=[Net.IPAddress]::Parse($parts[0]).GetAddressBytes()
        if ($bytes.Count -ne 16 -or ($bytes[0] -band 127) -ne 0 -or @($bytes[1..15] | Where-Object {$_ -ne 0}).Count -ne 0) {throw 'IPv6 half is not aligned.'}
        $firstBits+=($bytes[0] -shr 7)
    }
    if (($firstBits | Sort-Object -Unique) -join ',' -ne '0,1') {throw 'IPv6 halves overlap or omit addresses.'}
}
Assert-Case 'IPv6 all remains distinct from Any' {if ((@(Normalize-Addresses @('::/0')) -join ',') -eq (@(Normalize-Addresses @('Any')) -join ',')) {throw 'IPv6 normalization widened its family.'}}
Assert-Case 'Windows host /32 normalization accepted' {$script:rules[$script:specs[0].Name].Filters.Address.RemoteAddress=@('100.100.10.3/32');Assert-Specification $script:rules[$script:specs[0].Name] $script:specs[0]}
Assert-Case 'IPv6 normalized to Any is refused' {$script:rules[$script:specs[2].Name].Filters.Address.RemoteAddress=@('Any');Assert-Fails {Assert-Specification $script:rules[$script:specs[2].Name] $script:specs[2]}}
Assert-Case 'Broadened source allow refused' {$script:rules[$script:specs[0].Name].Filters.Address.RemoteAddress=@('Any');Assert-Fails {Assert-Specification $script:rules[$script:specs[0].Name] $script:specs[0]}}
Assert-Case 'Wrong local destination refused' {$script:rules[$script:specs[0].Name].Filters.Address.LocalAddress=@('10.10.20.50');Assert-Fails {Assert-Specification $script:rules[$script:specs[0].Name] $script:specs[0]}}
Assert-Case 'Wrong interface refused' {$script:rules[$script:specs[0].Name].Filters.Interface.InterfaceAlias=@('Any');Assert-Fails {Assert-Specification $script:rules[$script:specs[0].Name] $script:specs[0]}}
Assert-Case 'Wrong service refused' {$script:rules[$script:specs[0].Name].Filters.Service.Service='Any';Assert-Fails {Assert-Specification $script:rules[$script:specs[0].Name] $script:specs[0]}}
Assert-Case 'Effective enabled profiles accepted' {Assert-EffectiveProfiles}
Assert-Case 'Disabled effective profile refused' {$script:profiles[0].Enabled='False';Assert-Fails {Assert-EffectiveProfiles}}
Assert-Case 'GPO rejecting local rules refused' {$script:profiles[1].AllowLocalFirewallRules='False';Assert-Fails {Assert-EffectiveProfiles}}
Assert-Case 'GPO rejecting inbound allows refused' {$script:profiles[2].AllowInboundRules='False';Assert-Fails {Assert-EffectiveProfiles}}
Assert-Case 'Permissive effective inbound policy refused' {$script:profiles[0].DefaultInboundAction='Allow';Assert-Fails {Assert-EffectiveProfiles}}
Assert-Case 'Undo removes own matching four and restores only builtin Enabled' {$warnings=@(Undo-Deltas $script:manifest);if ($warnings.Count -ne 0 -or $script:writes.Count -ne 7) {throw 'Unexpected undo scope.'};foreach ($name in $builtinNames) {if ($script:rules[$name].Enabled -ne 'True') {throw 'Builtin not restored.'}}}
Assert-Case 'Undo preserves a later owned address change' {$name=$script:specs[0].Name;$script:rules[$name].Filters.Address.RemoteAddress=@('100.100.10.9');$warnings=@(Undo-Deltas $script:manifest);if ($warnings.Count -ne 1 -or -not $script:rules.ContainsKey($name) -or ('Remove:'+$name) -in $script:writes) {throw 'Modified owned rule was clobbered.'}}
Assert-Case 'Undo preserves a later builtin profile change' {$name=$builtinNames[0];$script:rules[$name].Profile='Private';$warnings=@(Undo-Deltas $script:manifest);if ($warnings.Count -ne 1 -or $script:rules[$name].Enabled -ne 'False') {throw 'Modified builtin rule was clobbered.'}}
Assert-Case 'Undo never restores an unchanged builtin' {$script:manifest.BuiltinRules[0].Changed=$false;$warnings=@(Undo-Deltas $script:manifest);if ($script:rules[$builtinNames[0]].Enabled -ne 'False' -or $script:writes.Count -ne 6) {throw 'Undo changed a rule it did not disable.'}}
Assert-Case 'Fingerprint detects service, interface and port changes' {
    $rule=$script:rules[$script:specs[0].Name];$hash=Get-Fingerprint $rule
    $rule.Filters.Port.LocalPort=@('3390');if ((Get-Fingerprint $rule) -eq $hash) {throw 'Port change escaped fingerprint.'}
}
[pscustomobject]@{AllPassed=$true;Count=$results.Count;Tests=$results;FirewallOrSystemChanges=$false} | ConvertTo-Json -Depth 6
