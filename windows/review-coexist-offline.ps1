# SPDX-License-Identifier: MIT
# Copyright Home Network Infra Contributors
# Offline harness: extracts functions only; mocks every network read/write and CLI query.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$guard = Join-Path $PSScriptRoot 'coexist-route-guard.ps1'
$installer = Join-Path $PSScriptRoot 'install-coexist.ps1'
$results = @()
foreach ($path in @($guard,$installer)) {
    $tokens=$null; $errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
    if (@($errors).Count -gt 0) { throw ($errors | Out-String) }
    $results += [pscustomobject]@{ Test=('AST ' + [IO.Path]::GetFileName($path)); Passed=$true }
    if ($path -eq $guard) {
        $compileCommands = @($ast.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq 'Add-Type'},$true))
        if ($compileCommands.Count -ne 1) { throw 'Expected exactly one real Add-Type block.' }
        Invoke-Expression $compileCommands[0].Extent.Text
        [HomeNetworkInfraVpnNetworkSignal]::Start()
        [HomeNetworkInfraVpnNetworkSignal]::Stop()
        $results += [pscustomobject]@{ Test='Real network-event C# compiles, subscribes, and unsubscribes'; Passed=$true }
        foreach ($definition in $ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst]},$false)) {
            Invoke-Expression $definition.Extent.Text
        }
    }
}
$DryRun=$false; $Once=$true; $marker='HomeNetworkInfraVPNCoexist-v1'
$ExpectedSubnetRoutes='10.10.10.0/24,10.10.20.0/24'
$statePath=Join-Path $PSScriptRoot '__offline_missing_state__.json'
function Write-Metadata([string]$Message) { $script:lastStatus=$Message }
function Save-State($State) { $script:savedState=$State }
function Test-Path { param($LiteralPath,$PathType) return ($LiteralPath -eq $statePath -and $null -ne $script:savedState) }
function Get-Content { param($LiteralPath,[switch]$Raw,$Encoding) if ($LiteralPath -eq $statePath) { return $script:savedState | ConvertTo-Json -Depth 10 }; throw 'Unexpected offline content read.' }
function Get-TailscaleExitSelection { return $script:selected }
function Get-NetAdapter { param([switch]$IncludeHidden,$ErrorAction) return $script:adapters }
function Get-NetIPInterface { param($PolicyStore,$ErrorAction,$InterfaceIndex,$AddressFamily) return @($script:interfaces | Where-Object { (-not $InterfaceIndex -or $_.InterfaceIndex -eq $InterfaceIndex) -and (-not $AddressFamily -or $_.AddressFamily -eq $AddressFamily) }) }
function Get-NetRoute { param($PolicyStore,$ErrorAction) return $script:routes }
function Set-NetIPInterface { param($InterfaceIndex,$AddressFamily,$AutomaticMetric,$InterfaceMetric,$PolicyStore,$ErrorAction) $script:writes += [pscustomobject]@{ Index=$InterfaceIndex; Family=$AddressFamily; Metric=$InterfaceMetric; Automatic=$AutomaticMetric } }
function Reset-Fixture {
    $script:selected=$true; $script:writes=@(); $script:lastStatus=''; $script:savedState=$null
    $script:adapters=@(
        [pscustomobject]@{Name='Tailscale';Status='Up';ifIndex=43;HardwareInterface=$false;InterfaceGuid='ts-guid'},
        [pscustomobject]@{Name='singbox_tun';Status='Up';ifIndex=16;HardwareInterface=$false;InterfaceGuid='tun-guid'},
        [pscustomobject]@{Name='Wi-Fi';Status='Up';ifIndex=5;HardwareInterface=$true;InterfaceGuid='wifi-guid'}
    )
    $script:interfaces=@(
        [pscustomobject]@{InterfaceIndex=43;AddressFamily='IPv4';InterfaceMetric=0;AutomaticMetric='Disabled'},
        [pscustomobject]@{InterfaceIndex=16;AddressFamily='IPv4';InterfaceMetric=0;AutomaticMetric='Disabled'},
        [pscustomobject]@{InterfaceIndex=5;AddressFamily='IPv4';InterfaceMetric=35;AutomaticMetric='Enabled'}
    )
    $script:routes=@(
        [pscustomobject]@{InterfaceIndex=43;AddressFamily='IPv4';DestinationPrefix='0.0.0.0/0';RouteMetric=0},
        [pscustomobject]@{InterfaceIndex=43;AddressFamily='IPv4';DestinationPrefix='10.10.10.0/24';RouteMetric=0},
        [pscustomobject]@{InterfaceIndex=16;AddressFamily='IPv4';DestinationPrefix='0.0.0.0/0';RouteMetric=0},
        [pscustomobject]@{InterfaceIndex=5;AddressFamily='IPv4';DestinationPrefix='0.0.0.0/0';RouteMetric=0}
    )
}
function Assert-Case([string]$Name,[scriptblock]$Case) {
    Reset-Fixture
    & $Case
    $script:results += [pscustomobject]@{Test=$Name;Passed=$true}
}
function Assert-Refusal {
    $refused=$false
    try { Invoke-Reconcile } catch { $refused=$true }
    if (-not $refused -or $script:writes.Count -ne 0) { throw 'Expected fail-closed refusal before any metric write.' }
}
Assert-Case 'Exit on selects metric 40 above physical 35 and records original' {
    Invoke-Reconcile
    if ($script:writes.Count -ne 1 -or $script:writes[0].Metric -ne 40 -or $script:savedState.Entries[0].OriginalMetric -ne 0) { throw 'Wrong plan or restoration record.' }
}
Assert-Case 'Exit on physical 45 selects metric 50' {
    $script:interfaces[2].InterfaceMetric=45
    Invoke-Reconcile
    if ($script:writes.Count -ne 1 -or $script:writes[0].Metric -ne 50) { throw 'Wrong on-state underlay protection.' }
}
Assert-Case 'Exit off retains family route and uses TUN fallback' {
    $script:selected=$false
    $script:routes=@($script:routes | Where-Object {-not ($_.InterfaceIndex -eq 43 -and $_.DestinationPrefix -eq '0.0.0.0/0')})
    Invoke-Reconcile
    if ($script:writes.Count -ne 1 -or $script:writes[0].Metric -ne 5) { throw 'Wrong fallback plan.' }
}
Assert-Case 'Custom subnet scope supports another installation' {
    $previous=$ExpectedSubnetRoutes
    try {
        $ExpectedSubnetRoutes='10.44.0.0/16'
        $script:selected=$false
        $script:routes=@($script:routes | Where-Object {$_.InterfaceIndex -ne 43})
        $script:routes+=[pscustomobject]@{InterfaceIndex=43;AddressFamily='IPv4';DestinationPrefix='10.44.0.0/16';RouteMetric=0}
        Invoke-Reconcile
        if ($script:writes.Count -ne 1 -or $script:writes[0].Metric -ne 5) {throw 'Custom scope not accepted.'}
    } finally {$ExpectedSubnetRoutes=$previous}
}
Assert-Case 'Physical cost 4 selects metric 1' {
    $script:selected=$false
    $script:interfaces[2].InterfaceMetric=4
    Invoke-Reconcile
    if ($script:writes[0].Metric -ne 1) { throw 'Wrong narrow-cost plan.' }
}
Assert-Case 'Already correct metric avoids writes' {
    $script:interfaces[1].InterfaceMetric=40
    Invoke-Reconcile
    if ($script:writes.Count -ne 0) { throw 'Unnecessary mutation.' }
}
Assert-Case 'Exit off physical cost 1 refuses without writes' { $script:selected=$false; $script:interfaces[2].InterfaceMetric=1; Assert-Refusal }
Assert-Case 'Exit on metric above 9999 refuses without writes' { $script:interfaces[2].InterfaceMetric=9999; Assert-Refusal }
Assert-Case 'Exit on metric at safe ceiling 9999 is accepted' {
    $script:interfaces[2].InterfaceMetric=9994
    Invoke-Reconcile
    if ($script:writes.Count -ne 1 -or $script:writes[0].Metric -ne 9999) { throw 'Wrong safe-ceiling calculation.' }
}
Assert-Case 'Exit state transition rewrites current TUN priority without changing restoration original' {
    Invoke-Reconcile
    $script:interfaces[1].InterfaceMetric=40
    $script:selected=$false
    Invoke-Reconcile
    if ($script:writes.Count -ne 2 -or $script:writes[1].Metric -ne 5 -or $script:savedState.Entries[0].OriginalMetric -ne 0 -or $script:savedState.Entries[0].LastApplied -ne 5) { throw 'TUN transition did not preserve exact restoration state.' }
}
Assert-Case 'Unknown Tailscale scope refuses without writes' { $script:routes=@($script:routes | Where-Object {$_.InterfaceIndex -ne 43}); Assert-Refusal }
Assert-Case 'Nonzero Tailscale cost refuses without writes' { $script:interfaces[0].InterfaceMetric=1; Assert-Refusal }
Assert-Case 'Specific TUN public route refuses without writes' {
    $script:routes += [pscustomobject]@{InterfaceIndex=16;AddressFamily='IPv4';DestinationPrefix='128.0.0.0/1';RouteMetric=0}
    Assert-Refusal
}
Assert-Case 'Uncovered IPv6 exit risk refuses without writes' {
    $script:routes += [pscustomobject]@{InterfaceIndex=5;AddressFamily='IPv6';DestinationPrefix='::/0';RouteMetric=0}
    Assert-Refusal
}
Assert-Case 'Late IPv6 plan failure prevents earlier IPv4 write' {
    $script:interfaces += @(
        [pscustomobject]@{InterfaceIndex=43;AddressFamily='IPv6';InterfaceMetric=0;AutomaticMetric='Disabled'},
        [pscustomobject]@{InterfaceIndex=16;AddressFamily='IPv6';InterfaceMetric=0;AutomaticMetric='Disabled'},
        [pscustomobject]@{InterfaceIndex=5;AddressFamily='IPv6';InterfaceMetric=9999;AutomaticMetric='Enabled'}
    )
    $script:routes += @(
        [pscustomobject]@{InterfaceIndex=43;AddressFamily='IPv6';DestinationPrefix='::/0';RouteMetric=0},
        [pscustomobject]@{InterfaceIndex=16;AddressFamily='IPv6';DestinationPrefix='::/0';RouteMetric=0},
        [pscustomobject]@{InterfaceIndex=5;AddressFamily='IPv6';DestinationPrefix='::/0';RouteMetric=0}
    )
    Assert-Refusal
}
# Installer functions only; all filesystem and task operations below are mocked.
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($installer,[ref]$tokens,[ref]$errors)
foreach ($definition in $ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst]},$false)) { Invoke-Expression $definition.Extent.Text }
function Assert-NoReparse([string]$Path) {}
function Get-Content { param($LiteralPath,[switch]$Raw,$Encoding) if ($LiteralPath -eq 'mock-metrics') { return $script:metricJson }; return $script:configJson }
function Save-Json([string]$Path,$Value) { $script:savedConfig=$Value; $script:configJson=$Value | ConvertTo-Json -Depth 100 -Compress }
function Read-ConfigSnapshot([string]$Path) { return [pscustomobject]@{Hash='expected';Content=($script:configJson | ConvertFrom-Json)} }
function Get-FileHash { param($LiteralPath,$Algorithm) return [pscustomobject]@{Hash=$script:fakeHash} }
function Test-Path { param($LiteralPath) return ($LiteralPath -eq 'mock-metrics') }
$metricPath='mock-metrics'
$manifest=[pscustomobject]@{ConfigPath='mock-config';Original=[pscustomobject]@{StrictRoute=$true;EnableTun=$false};Applied=[pscustomobject]@{StrictRoute=$false;EnableTun=$true}}
$script:fakeHash='expected'
Assert-Case 'Subnet scope rejects task argument injection' {
    $refused=$false
    try {Get-ExpectedSubnetPrefixes '10.10.10.0/24" -File other.ps1' | Out-Null} catch {$refused=$true}
    if (-not $refused) {throw 'Unsafe task argument accepted.'}
    $scope=@(Get-ExpectedSubnetPrefixes '10.10.20.0/24,10.10.10.0/24,10.10.10.0/24')
    if (($scope -join ',') -ne '10.10.10.0/24,10.10.20.0/24') {throw 'Scope normalization differs.'}
}
Assert-Case 'Undo restores only own two GUI fields and preserves future settings' {
    $script:configJson='{"TunModeItem":{"StrictRoute":false,"EnableTun":true,"Mtu":1400},"FutureSetting":"keep"}'
    $script:savedConfig=$null
    Undo-ConfigDelta $manifest
    if ($null -eq $script:savedConfig -or -not $script:savedConfig.TunModeItem.StrictRoute -or $script:savedConfig.TunModeItem.EnableTun -or $script:savedConfig.TunModeItem.Mtu -ne 1400 -or $script:savedConfig.FutureSetting -ne 'keep') { throw 'Undo overwrote unrelated current configuration.' }
}
Assert-Case 'Undo leaves a later GUI change alone' {
    $script:configJson='{"TunModeItem":{"StrictRoute":true,"EnableTun":false,"Mtu":1400}}'
    $script:savedConfig=$null
    Undo-ConfigDelta $manifest
    if ($null -ne $script:savedConfig) { throw 'Undo unnecessarily rewrote a changed configuration.' }
}
Assert-Case 'Undo restores matching owned metric' {
    $script:interfaces[1].InterfaceMetric=5
    $script:metricJson='{"Marker":"HomeNetworkInfraVPNCoexist-v1","Entries":[{"InterfaceGuid":"tun-guid","AddressFamily":"IPv4","OriginalMetric":0,"OriginalAutomatic":"Disabled","LastApplied":5}]}'
    Restore-Metrics
    if ($script:writes.Count -ne 1 -or $script:writes[0].Metric -ne 0) { throw 'Owned metric was not restored.' }
}
Assert-Case 'Undo preserves a later metric change' {
    $script:interfaces[1].InterfaceMetric=7
    $script:metricJson='{"Marker":"HomeNetworkInfraVPNCoexist-v1","Entries":[{"InterfaceGuid":"tun-guid","AddressFamily":"IPv4","OriginalMetric":0,"OriginalAutomatic":"Disabled","LastApplied":5}]}'
    Restore-Metrics
    if ($script:writes.Count -ne 0) { throw 'Undo overwrote a future metric change.' }
}
Assert-Case 'Unknown same-name task is refused' {
    $refused=$false
    try { Assert-TaskOwned ([pscustomobject]@{Description='foreign'}) $null } catch { $refused=$true }
    if (-not $refused) { throw 'Unknown task accepted.' }
}
Assert-Case 'Owned task accepts canonical custom subnet argument' {
    $guardPath='C:\ProgramData\HomeNetworkInfraVPNCoexist\coexist-route-guard.ps1'
    $psExe='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
    $owned=[pscustomobject]@{Marker=$marker;InstallationId='offline-installation';ExpectedSubnetRoutes='10.44.0.0/16'}
    $task=[pscustomobject]@{Description=($marker+' '+$owned.InstallationId);Actions=@([pscustomobject]@{Execute=$psExe;Arguments=(Get-GuardArguments $owned.ExpectedSubnetRoutes)});Principal=[pscustomobject]@{UserId='SYSTEM'}}
    Assert-TaskOwned $task $owned
}
Assert-Case 'Owned task refuses later subnet action changes' {
    $guardPath='C:\ProgramData\HomeNetworkInfraVPNCoexist\coexist-route-guard.ps1'
    $psExe='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
    $owned=[pscustomobject]@{Marker=$marker;InstallationId='offline-installation';ExpectedSubnetRoutes='10.44.0.0/16'}
    $task=[pscustomobject]@{Description=($marker+' '+$owned.InstallationId);Actions=@([pscustomobject]@{Execute=$psExe;Arguments=(Get-GuardArguments '10.45.0.0/16')});Principal=[pscustomobject]@{UserId='SYSTEM'}}
    $refused=$false
    try {Assert-TaskOwned $task $owned} catch {$refused=$true}
    if (-not $refused) {throw 'Modified task arguments accepted.'}
}
Assert-Case 'Concurrent GUI edit refuses before save' {
    $script:configJson='{"TunModeItem":{"StrictRoute":true,"EnableTun":false,"Mtu":1400}}'
    $script:savedConfig=$null; $script:fakeHash='changed'
    $refused=$false
    try { Write-ConfigDelta 'mock-config' ($script:configJson | ConvertFrom-Json) 'expected' $manifest.Applied } catch { $refused=$true }
    $script:fakeHash='expected'
    if (-not $refused -or $null -ne $script:savedConfig) { throw 'Concurrent edit was overwritten.' }
}
[pscustomobject]@{AllPassed=$true;Count=$results.Count;Tests=$results;SystemOrNetworkChanges=$false} | ConvertTo-Json -Depth 8
