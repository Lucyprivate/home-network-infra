# Router maintenance components

These components use consistent example defaults.
They do not install a router unattended.
Render a private site before preparing installation files.
Review the target versions, paths, dependencies, and ownership boundaries before installation.
Use the chosen OpenWrt distribution for ucode, nftables/fw4, rpcd, LuCI, iproute2, WireGuard, and named shell tools.
This directory includes no system binaries.

## Suggested placement

| Source | Target |
| --- | --- |
| `wireguard/controller/vpn-egress` | `/usr/sbin/vpn-egress` |
| `wireguard/controller/vpn-egress.init` | `/etc/init.d/vpn-egress` |
| `wireguard/luci/backend/vpn-egress-webctl` | `/usr/sbin/vpn-egress-webctl` |
| `wireguard/luci/backend/luci.vpn-egress` | `/usr/share/rpcd/ucode/luci.vpn-egress` |
| `wireguard/luci/ui/acl/*`, `ui/menu/*` | `/usr/share/rpcd/acl.d/`, `/usr/share/luci/menu.d/` |
| `wireguard/luci/ui/view/egress.js` | `/www/luci-static/resources/view/vpn/egress.js` |
| `bandwidth-monitor/backend/{model,nft,collector}.uc` | `/usr/share/proxy-usage/` |
| `bandwidth-monitor/backend/proxy-usage-run` | `/usr/libexec/proxy-usage-run` |
| `bandwidth-monitor/backend/proxy-usage.init` | `/etc/init.d/proxy-usage` |
| `bandwidth-monitor/ui/rpcd/luci.proxy-usage` | `/usr/share/rpcd/ucode/luci.proxy-usage` |
| `bandwidth-monitor/ui/acl/*`, `ui/menu/*` | `/usr/share/rpcd/acl.d/`, `/usr/share/luci/menu.d/` |
| `bandwidth-monitor/ui/view/proxy.js` | `/www/luci-static/resources/view/nlbw/proxy.js` |

Check the exact menu and script paths before installation.
Keep private state root-owned with restricted permissions.
Give controllers and init scripts executable modes.
Give RPC, ACL, menu, and view files only the permissions that rpcd and the web server need.
Before enabling a daemon, run its explicit status or preflight command.
Keep the independent management path reachable.

## Egress control

`templates/wireguard-network.uci` uses netifd without automatic allowed-IP routes.
The controller owns table 200 and its policy priorities.
Enter peer keys privately.
Keep direct endpoint routing.
Test the candidate path before `resume`.

The separate VPS link, service, and forwarding helpers target legacy Linux.
They are not OpenWrt init scripts.
Review the VPS uplink device and existing firewall backend before porting them.
Do not clear whole route tables, firewall rulesets, or connection tracking for recovery.

The controller samples every 30 seconds.
Repeated health failures latch direct mode.
Only explicit `resume` returns it to WireGuard.
The interfaces remain `status`, `direct`, `resume`, and `watch`.
Health probes contact public HTTPS services.
These are deliberate outbound requests, not local tests.

Keep the legacy HomeProxy watcher disabled while this controller owns public egress.
Keep saved proxy configuration private.
Do not use a second automatic owner for the same routes.

## Accounting and backups

Accounting saves persistent state about once per hour.
Power loss can lose the unsaved interval.
The view reports coverage gaps.
`nlbw-persist` is a guarded, one-time storage migration with receipt-aware rollback.
Test it on the actual filesystem.
Do not repeat migration to query counters.

Accounting examples and schedules use UTC.
The migration rejects timezone differences that could silently shift imported period boundaries.

The VM backup hook and pull service are optional.
The private pull configuration supplies a dedicated SSH key and pinned known-hosts file.
The tool rejects failed or changing backups as incomplete.
It removes only its manifest-owned local copies.
It never removes backups from the source hypervisor.
Review storage capacity and test isolated restore separately.

The legacy `.service.in` needs three private installation paths in its `@...@` markers.
It cannot run unchanged.
Keep real key paths and backup destinations out of the public site example.

## Test limits

Node view tests run without OpenWrt.
Shell, ucode, and permission tests need Linux.
The ucode suites also need a compatible ucode runtime.
The tests use fixtures and do not modify a router.
Test hardware and cold starts separately.
