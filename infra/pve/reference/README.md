# Layout-specific migration reference

These sources retain the original design's transaction and rollback logic with synthetic networks and MAC addresses.
They are not general installers.
The renderer and CI do not run them against a host.

| Source | Purpose and protection |
| --- | --- |
| `ports/pve-port-reorder` | Temporary dual-port rescue handoff, fresh SSH confirmation, timed rollback, final management/rescue split. |
| `uplink/pve-uplink-switch` | Staged management move, duplicate-IP ARP probes, exact bridge/MAC checks, immutable guest/boot checks, timed restoration of owned files and network state. |
| `router-ready/openwrt-admin-switch` | Named upstream-only firewall exception, persistent transaction snapshot, independent watchdog. No unrestricted WAN administration. |
| `router-ready/pve-downstream-test.py` | Namespace-bound cable test, device identity checks, owned network/DNS rollback. |
| `router-ready/router-readiness-check.py` | Selected read-only inventory through caller-supplied pinned SSH configuration. |

The cable test sends a public NTP request to Cloudflare's `162.159.200.1`.
It does not change the system clock.
Cloudflare documents this address in its [official time service](https://developers.cloudflare.com/time-services/ntp/usage/).
The readiness collector's old package-relative default SSH configuration is absent.
Supply a reviewed private configuration with `--ssh-config`.

1. Review constants, VM IDs, aliases, the initial layout, and protected files.
2. Prepare the adapted source with observed local hardware facts and a private site file.
3. Keep refusal paths, rollback markers, and snapshots from the same adapted source version.
4. Run the adjacent fixture tests against the adaptation.
5. Keep a physical console and separate rescue path for live changes.

Do not adopt old or foreign transactions.
The fixtures use artificial dates and devices.
Base64 calls frame runtime messages and serialize private backups.
They do not contain stored production payloads.
The repository includes no original backups, snapshots, receipts, remote SSH configuration, or identity files.
