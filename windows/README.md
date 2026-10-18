# Windows client maintenance

Read [the deployment and acceptance guide](../docs/windows.md) before running an installer.
This directory contains the reusable PowerShell sources from the reference design.

| File | Purpose |
| --- | --- |
| `coexist-route-guard.ps1` | Adjust the sing-box TUN interface metric and retain the physical Tailscale underlay. |
| `install-coexist.ps1` | Preview, install, or undo the guard and its two v2rayN GUI changes. |
| `install-tablet-rdp-firewall.ps1` | Preview, install, or undo the firewall rules for one designated tablet. |
| `review-coexist-offline.ps1` | Test routing, configuration changes, ownership, and undo with mocks. |
| `review-tablet-rdp-offline.ps1` | Test RDP scopes, address complements, effective policy, and undo with mocks. |
| `site-commands.ps1.tmpl` | Render site-specific calls to either installer. Preview is the default. |

Both installers preview changes by default.
`-Apply` requires an elevated Windows PowerShell process.
`-Undo -Apply` restores only matching owned changes.
Neither installer supplies subscriptions, proxy accounts, Windows accounts, pre-authentication keys, or production configuration.

The scripts target Windows PowerShell 5.1.
Their offline harnesses also run under PowerShell 7.
The harnesses parse the installers and extract functions.
They do not run installer main programs.
Mocks replace network, firewall, configuration, and task writes.

The routing harness compiles a small event type in memory.
It subscribes to network events and removes the subscription without a network change.

Run these tests from this directory:

```powershell
powershell.exe -NoProfile -File .\review-coexist-offline.ps1
powershell.exe -NoProfile -File .\review-tablet-rdp-offline.ps1
pwsh.exe -NoProfile -File .\review-coexist-offline.ps1
pwsh.exe -NoProfile -File .\review-tablet-rdp-offline.ps1
```

These tests use anonymous examples.
They do not certify connectivity or a new deployment.

The site renderer fills `site-commands.ps1.tmpl` from the shared configuration.
Run the rendered wrapper from the repository root.
Select `-Component Coexist` or `-Component TabletRdp`.
Review the preview before adding `-Apply`.
Use `-WindowsSourceDirectory` to select a source directory when running the wrapper elsewhere.
The renderer and CI do not run the wrapper automatically.
