# Infrastructure sources

This directory contains anonymous infrastructure examples and maintenance source.
Offline checks cover the public templates.
They do not prove a new live deployment.
Run the root renderer before preparing deployment files.
It copies text files and replaces static examples with matching `.tmpl` files.
It keeps relative paths for the component tests.

| Area | Purpose | Protection |
| --- | --- | --- |
| `headscale/server` | Fresh staging, official artifacts, templates, manual DERP refresh | Rejects existing paths. Separates file installation from TLS and firewall activation. Binds refresh to root-owned receipts and current hashes. |
| `headscale/client` | Fixed-version Ubuntu client installation | Separates enrollment. Rejects registered or unmanaged clients and foreign package configuration. |
| `headscale/reference` | Legacy static exit installer | Reference for one old OS and firewall layout. Needs review and porting. |
| `openwrt/wireguard` | Egress controller, procd, LuCI, forwarding helpers, tests | Owns complete rule selectors and one table. Refuses conflicts. Latches direct mode until explicit resume. |
| `openwrt/bandwidth-monitor` | ucode/nft collector and LuCI view | Accepts only its exact owned nft table. Keeps lifetime and period counters separate. |
| `openwrt/daily-care` | Persistence checks and pinned-SSH backup pull | Protects private backup output. Removes only manifest-owned local copies. Never removes PVE backups. |
| `pve/reference` | Four-port handoff, uplink change, cable test, readiness checks | Hardware-specific migration reference. Keeps MAC, wiring, bridge, and fresh-session checks. |
| `ubuntu-service-host` | Docker installation, checks, guest audit, limited Intel VAAPI test | Rejects conflicting packages and workloads. Keeps receipt-bound recovery. Produces private audit output. |
| `pve/templates`, `openwrt/templates`, `ubuntu-service-host/templates` | Desired-state examples | Do not apply themselves or change a host. |

Sample MAC addresses are locally administered values.
Match the physical labels to locally observed devices before changing the private site values.
Do not remove MAC or ownership checks to make a migration pass.
Keep a console and independent rescue path before changing bridges or routes.

The examples use VM100 for the router and VM150 for the service host.
These are layout constants, not discovered identities.
Reference tests and rollback code depend on them.
To change VM IDs, change the protected-file list and tests together.

The renderer does not supply secrets.
Enter WireGuard peer keys privately in the empty credential templates.
Do not commit those keys.
Keep live receipts, SSH host keys, node state, databases, subscriptions, channel sources, and backups outside Git.

See [Infrastructure](../docs/infrastructure.md) for the deployment order, trust boundaries, and checks.
See [Third-party sources](THIRD_PARTY.md) for upstream provenance.
