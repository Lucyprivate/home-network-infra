# Control server and clients

## New server

Use the rendered server directory for a new installation only.
The fetch tools create local files that Git excludes.
The installer creates a stopped, disabled Headscale installation and a receipt for map maintenance.
It rejects existing destinations and a nonempty data directory.
It does not merge Caddy or activate firewall rules.

1. Run `fetch-artifact.sh` to download and check the pinned official artifact in `vendor/`.
2. Run `fetch-derp-map.py derp-public.yaml` to create a checked public relay map in a new staging file.
3. Review `install-files.sh` before installing the files.
4. Merge the Caddy fragment into a private HTTPS site with a trusted certificate.
5. Check the complete Caddyfile.

Keep the loopback listener and private Unix administrative socket.
The sample domain and address are reserved documentation values.
Check the real firewall zone and interface before opening HTTPS, UDP STUN, or the Tailscale UDP listener.
Do not expose metrics or gRPC publicly.

## Client enrollment and routes

The Ubuntu installer supports only its documented Ubuntu release and amd64 package.
It checks the version and official signing key.
It rejects registered client state and separates package installation from enrollment.
After installation, use interactive `tailscale up --login-server=YOUR_PRIVATE_URL`.
Approve that individual node on the server.
Do not put auth keys in scripts.

1. Enroll `linux-client`, `service-host`, `tablet`, `vps-exit`, and `windows-client` as separate nodes.
2. Read the actual assigned addresses into the private role configuration.
3. Render the individual `/32` policy grants.
4. Advertise the two household CIDRs on the service host.
5. Advertise the separate exit node on the VPS.

Inspect each route before approval.
Approve only the intended routes.
Shared user membership does not replace individual grants.
The repository contains no original node IDs or machine keys.

## Routine use

Select or clear the exit node with `tailscale set`.
Do not reset registration to change an exit choice.
Keep `--accept-dns=true` for MagicDNS.
Accept household subnet routes only on clients that need them.
On Windows, use the separate TUN coexistence and tablet-only RDP procedure.

On Linux with another TUN, check the marked transport path through the physical uplink.
Check that the expected Tailscale policy rules precede the other TUN rules.
This repository has no general automatic Linux TUN rewriter.

## Legacy reference limits

`reference/install-legacy-vps-exit.sh` retains receipt-bound installation and rollback for one legacy CentOS/firewalld profile.
It is review source, not a general VPS installer.
It rejects other operating systems, changed firewall zone membership, existing client state, foreign files, and changed ownership hashes.
Use official packages on a maintained distribution for a new server.
Do equivalent preflight, backup, and rollback tests.
Do not remove compatibility checks to force installation.

The [architecture document](../../docs/infrastructure.md) describes the procedures that replace one-time live migration helpers.
These include Caddy changes, node reconnection or enrollment, and policy appenders bound to historical node hashes.
The repository excludes their production inventory, receipts, and hashes.
It does not replace those checks with broad permission.
