# Operations and recovery

## Boundaries

This repository retains the design and reusable maintenance logic from a working private deployment.
Public addresses and identities are synthetic.
The repository excludes historical live receipts.
Those receipts do not certify this changed public source tree.
Root continuous integration (CI) runs offline.
Do not give it production credentials.

## Check changes by layer

### Host and applications

1. Check the rescue path before a bridge or management change.
   Identify ports from the local hardware inventory.
   Do not trust example MAC addresses.
2. Check router routes and VM routes separately.
   Media policy routes must not use a different exit when their uplink fails.
3. Start application guards before exposing listeners.
   Test the allowed LAN and explicit tailnet sources.
   Test rejected sources and IPv6 boundaries.

### Remote access

1. Track Headscale identity and approved routes separately from online status and primary route choice.
   A control restart can interrupt access without changing permission.
   Wait for the actual family routes to return.
2. Test exit traffic, DNS, and family access separately.
   A public IP result does not prove which VPN path carried it.
   Record the TUN state and selected exit node.
3. Test RDP from the authorized tablet on an external network.
   Check that Windows sees the expected tailnet source.
   Test an unauthorized source.
   Record a timeout as an observed result, not proof of the filter layer.

## Ownership and rollback

Keep private backups of the previous state with restricted permissions.
Apply a change only when the current configuration, owner, source hash, and target identity match the expected values.
Use atomic replacement within the same directory for configuration files.
Check ownership again before replacement or undo.
Do not overwrite another administrator's change because an old backup exists.

Windows installers keep ownership markers, protected manifests, and exact rule scopes.
Undo removes only the owned installation.
It restores the recorded prior state only when that state still matches.
Removing a host restriction can restore broad previous rules.
Treat that removal as an explicit access change.

Headscale DNS changes need a control-service restart.
A policy reload cannot replace that restart.
Keep the ACL and client identities unchanged during a DNS change.
Do not restart the reverse proxy or exit daemon without a cause.

Restore only the layer that changed.
Do not restore an old network policy to undo one DNS setting.
Before restoring an old OCR snapshot over a later firewall extension, obey its ownership checks.

## Unattended access

Keep Windows powered, awake, and connected.
Tailscale unattended mode and an automatic service can maintain access across user sessions.
They do not wake a sleeping computer.
Test restart and logout separately on the target installation.
The tailnet path does not need public RDP port forwarding.
