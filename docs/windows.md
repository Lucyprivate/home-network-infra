# Windows, dual TUN operation, and tablet-only remote desktop

The Windows client uses Tailscale for home services, an optional VPS exit, and remote desktop from one enrolled tablet.
The sing-box TUN in v2rayN can run at the same time.
All addresses and names below are examples.
Use the private site values and the addresses that Headscale assigns.

| Role | Example |
| --- | --- |
| Windows node | `windows-client`, `100.100.10.5` |
| Designated tablet | `tablet`, `100.100.10.3` |
| Home subnets | `10.10.10.0/24`, `10.10.20.0/24` |
| MagicDNS name | `windows-client.tail.example.test` |
| Control endpoint | `https://hs.example.com` |

## Enroll the client

Install Tailscale and v2rayN from their official distributions.
The reference uses Tailscale 1.104.1, v2rayN 7.25.6, and sing-box 1.14.3.
Review route and configuration changes before a version upgrade.
The repository contains no binaries, subscriptions, node keys, or GUI backups.

Enroll the Windows node through the site's Headscale process.
Use the registered name `windows-client`.
Accept the approved home subnet routes and Tailscale DNS.
For a new client, these options request that configuration:

```powershell
& "$env:ProgramFiles\Tailscale\tailscale.exe" up `
  --login-server=https://hs.example.com `
  --hostname=windows-client --accept-routes=true --accept-dns=true
```

Complete enrollment locally.
Keep existing enrollments and approved routes.
A new client does not require replacement of other devices.
Check the assigned Windows address before running the RDP installer.
Neither installer changes Tailscale preferences, exit selection, service accounts, or the Headscale database.

## TUN route behavior

The guard reads the selected Tailscale exit and effective routes.
It does not depend on adapter names alone.
With an exit selected, the guard keeps the total sing-box default-route metric above the cheapest physical default by at least five.
The physical interface then carries the encrypted Tailscale underlay.
Without an exit, the guard uses TUN interface metric 5, or 1 when necessary.

The proxy TUN then precedes the physical uplink.
Specific Tailscale routes still take precedence.

The guard checks both address families before a write.
It refuses these conditions:

- Ambiguous adapters or an unexpected Tailscale route scope
- A nonzero Tailscale default cost
- Unsupported TUN routes more specific than the default
- An IPv6 exit path without coverage
- A metric outside the safe range

A refusal leaves the metric unchanged and records the reason.
The guard does not force traffic through an uncertain interface.

## Install TUN coexistence

1. Exit v2rayN completely, including its tray process.
2. Open Administrator Windows PowerShell in the repository's `windows` directory.
3. Preview the installation with the local GUI path and home subnets.

   ```powershell
   .\install-coexist.ps1 `
     -ConfigPath 'C:\Program Files (x86)\V2RayN\guiConfigs\guiNConfig.json' `
     -ExpectedSubnetRoutes '10.10.10.0/24,10.10.20.0/24'
   ```

4. Review the preview.
5. Repeat the command with `-Apply`.
6. Start v2rayN.

The installer changes only `TunModeItem.StrictRoute` to `false` and `EnableTun` to `true`.
Check the selected core and generated TUN configuration against the installed version.

The installer creates `HomeNetworkInfra-VPN-Coexist-RouteGuard` as a SYSTEM startup task with the highest privilege.
The guard responds to network-change events. It also checks every 30 seconds.
Its scripts and metadata reside in `%ProgramData%\HomeNetworkInfraVPNCoexist`.

The private subdirectory holds the original GUI bytes without redaction.
Only Administrators and SYSTEM can read that backup.
Do not publish it.

The installation record contains source hashes, backup hashes, a unique owner marker, the exact task action, and original adapter metrics.
The installer rejects a foreign task with the same name.
It also rejects reparse-point paths.
Before a configuration write, it checks the original hash.
It preserves settings outside its two owned fields.

Undo restores only owned fields and metrics that still match the installed values.
Later edits remain intact.
If installation fails, protected recovery metadata remains.

## Remove TUN coexistence

Exit v2rayN completely before a removal preview or removal.

```powershell
& "$env:ProgramData\HomeNetworkInfraVPNCoexist\install-coexist.ps1" -Undo
& "$env:ProgramData\HomeNetworkInfraVPNCoexist\install-coexist.ps1" -Undo -Apply
```

Do not delete the protected state to bypass an ownership refusal.
Review the changed source, task, or private backup before recovery.

## Remote Desktop requirements

Use a Windows edition that can host Remote Desktop.
Enable the Remote Desktop listener in Windows settings.
Keep Network Level Authentication (NLA) enabled.
Require Transport Layer Security (TLS).
The reference listener uses `UserAuthentication=1` and `SecurityLayer=2`.
The firewall installer does not reduce these requirements.

It does not create users, set passwords, or change group membership.
Read [Microsoft's Remote Desktop setup guide](https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/remotepc/remote-desktop-allow-access).

Two independent access checks protect the standard TCP/UDP 3389 listener:

| Layer | Required behavior |
| --- | --- |
| Headscale policy | Permit `100.100.10.3/32` to `100.100.10.5/32` for `tcp:3389` and `udp:3389` only. Deny other tailnet sources. Retain other service grants. |
| Windows narrow allows | Permit only the tablet source to the Windows tailnet address on interface `Tailscale`, service `TermService`, TCP/UDP 3389, all profiles. |
| Windows explicit blocks | Block every other IPv4 source and every IPv6 source to TCP/UDP 3389 on all interfaces. |

The installer calculates the IPv4 complement from `-TabletTailIP`.
For the example, it uses `0.0.0.0-100.100.10.2` and `100.100.10.4-255.255.255.255`.
IPv6 blocks use `::/1` and `8000::/1`.
The native firewall does not accept the all-IPv6 `/0` form that some tools use.
The designated tablet uses its IPv4 tailnet path.

## Install the tablet RDP boundary

1. Apply the server policy through the Headscale procedure.
2. Test the policy before a client firewall change.
3. Preview the local firewall installation.

```powershell
.\install-tablet-rdp-firewall.ps1 `
  -TabletTailIP '100.100.10.3' -WindowsTailIP '100.100.10.5'
```

4. Review the preview.
5. Repeat the command with `-Apply` in Administrator Windows PowerShell.

Active firewall profiles must accept local inbound rules and block inbound traffic by default.
The installer creates explicit blocks before narrow allows.
It disables the three broad built-in RDP rules.
Then it checks the effective policy.
This restriction covers the standard 3389 listener.
Do not add an alternate listener, gateway, public port forward, or relay service that bypasses it.

The installed script and recovery manifest reside in `%ProgramData%\HomeNetworkInfraTabletRDP`.
Only Administrators and SYSTEM can access them.
The manifest records the selected addresses and fingerprints for all owned and affected rules.
Replace a tablet or change its tailnet address through the controlled enrollment process.
Then update both policy layers.

## Remove the tablet RDP boundary

Undo uses the addresses in the manifest.
It removes only unchanged owned rules.
It restores only the built-in `Enabled` values that the installation changed.
Later edits remain, with warnings.
Undo removes the tablet-only restriction.

```powershell
& "$env:ProgramData\HomeNetworkInfraTabletRDP\install-tablet-rdp-firewall.ps1" -Undo
& "$env:ProgramData\HomeNetworkInfraTabletRDP\install-tablet-rdp-firewall.ps1" -Undo -Apply
```

## Configure MagicDNS

Enable MagicDNS in the Headscale configuration.
Use a reserved internal domain such as `tail.example.test`.
Keep the existing upstream and split-DNS settings.
These fields control the example:

```yaml
dns:
  magic_dns: true
  base_domain: tail.example.test
```

1. Save a private backup of the server configuration.
2. Test the complete candidate with the deployment's Headscale binary, service user, database, and existing key files.
3. Replace the configuration only after that test passes.
4. Restart Headscale to apply changed DNS fields.
5. Check service health, node identities, approved routes, and policy integrity.

In Headscale 0.29.5, SIGHUP reloads policy only.
DNS field changes need a service restart.
Do not restart home routers, application containers, or Tailscale to apply those server fields.

Route availability can change briefly during client reconnection.
Compare persistent approvals separately from transient primary-route state.

## Connect Windows App Mobile

1. Connect the tablet to Tailscale.
2. Keep **Use Tailscale DNS** enabled.
3. After a server DNS change, disconnect the tablet's Tailscale session.
4. Reconnect Tailscale to refresh its DNS configuration.
5. Add a PC in Windows App Mobile with these settings.

| Setting | Value |
| --- | --- |
| PC Name | `windows-client` |
| Full name for diagnosis | `windows-client.tail.example.test` |
| IP fallback | `100.100.10.5` |
| Gateway | Empty |
| User account | An existing account with Windows access. A Microsoft account uses its full email and account password. The Windows Hello PIN does not replace that password. Enter credentials only in the app. |

Inspect the current Windows listener certificate locally.
Compare it with the certificate in the tablet prompt.
The repository contains no original certificate subject or fingerprint.
Name resolution does not grant access.
Headscale policy and the Windows firewall still limit the listener to the designated tablet.
Do not open NetBIOS, mDNS, or discovery ports for this connection.

See [Headscale DNS](https://headscale.net/stable/ref/dns/) and [Tailscale MagicDNS](https://tailscale.com/docs/features/magicdns).

If local policy permits access after Windows sign-out, enable unattended Tailscale operation from an Administrator terminal:

```powershell
& "$env:ProgramFiles\Tailscale\tailscale.exe" set --unattended=true
```

Check the Tailscale service startup policy.
Test a real sign-out or restart separately.
Review AC power, battery sleep, lid, and hibernation settings for the hardware.
The installers do not change power policy.
They cannot keep a sleeping computer reachable.

## Live acceptance

The source design had device tests for dual-TUN access and external-network tablet RDP.
The public sources replace addresses, names, parameters, and owner markers.
Their automated checks run offline.
A new installation needs its own live tests.

| Scenario | Required result |
| --- | --- |
| Both TUNs enabled | Public DNS, public HTTPS, home services, and the selected VPS public exit work. |
| Exit and network changes | Access survives exit deselection/reselection, proxy TUN recreation, and uplink reconnection. A selected Tailscale exit retains a physical underlay. |
| Tablet outside the home network | Tailscale connects. The short PC name opens Windows App Mobile. The tablet can control the desktop. |
| Another tailnet device or LAN client | A TCP connection to Windows port 3389 fails. No Windows credentials are necessary for this negative test. |
| Effective access boundary | Positive and negative policy assertions pass. All four firewall rule scopes match. Only the tablet appears as an established remote RDP source. |
| Existing controls | NLA, TLS, account permissions, and existing home service grants remain correct. |

DERP relay can carry a valid connection.
It does not prove an access failure or guarantee a direct connection.
For DNS diagnosis, test the full name and IPv4 fallback.
Do not broaden RDP rules to solve a name-resolution error.
Keep live evidence and private backups outside the repository.

## Recovery and offline tests

If the guard refuses a topology, read its recorded reason.
Restore the last working TUN and exit selection before further diagnosis.
Use the installed preview and undo commands for owned changes.

If the MagicDNS candidate fails:

1. Restore the saved server configuration.
2. Test the restored configuration.
3. Restart Headscale.
4. Reconnect the client DNS session.

The IP RDP fallback retains its separate access checks.

Offline tests cover refusal before route writes, exit transitions, concurrent configuration edits, safe undo, and custom site addresses.
They also cover exact IPv4 complement limits, both IPv6 halves, refusal of broad allows, and later administrator edits.
Run them after script changes or dependency upgrades.
