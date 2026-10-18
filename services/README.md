# Household services

This directory reconstructs the service layer with anonymous examples.
It contains source code and fixed examples, not a backup of a live system.
It excludes databases, credentials, media choices, backups, models, generated web assets, and old acceptance output.

| Component | Included behavior | Limit |
| --- | --- | --- |
| `home-tools` | Portainer, FileBrowser Quantum, Homepage, ingress guard, and unprivileged status timer | Only Portainer has the Docker socket. Homepage has no socket access. |
| `jellyfin` | Caddy gateway, one ordinary playback-device lease, direct-uplink policy routing, firewall that closes on failure, and bounded playlist/EPG updates | The lease coordinates cooperative devices. It cannot stop shared credentials or deliberate reuse of device identities. |
| `stirling-pdf` | Offline ingress/egress guard, Paddle CPU bridge, reading-order/quad geometry, and resource helper | Download models during staging only. The public Compose and units form a new reference integration. |

The site renderer processes files with the `.tmpl` suffix.
Adjacent sources without that suffix serve as executable synthetic fixtures.
If a subnet, interface, directory, or service name changes, update the site configuration first.
Then update the generated sources, guards, and tests together.
Do not combine a new Compose file with an old firewall fixture.

Read [the service operations guide](../docs/services.md) for deployment order, local secrets, recovery, and source coverage.
No script in this directory contacts the original system.
