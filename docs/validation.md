# Validation status

The public sources receive separate checks after anonymization.
These offline results do not certify a new live deployment.

| Test group | Coverage |
| --- | --- |
| Portable Python | Publication and rendering, device-specific policy, DERP maps, ingress guards, playback leases, route ownership, offline PDF limits, and source integrity. |
| Node.js fixtures | Router egress UI and bandwidth UI behavior. |
| Windows PowerShell 5.1 and PowerShell 7 | TUN coexistence and tablet-only RDP. Each harness extracts pure logic or mocks operating-system state. |
| Source and rendered examples | Python, JSON, YAML, JavaScript, shell syntax, and relative document links. |
| Publication privacy | Text, filenames, supported encoded text, all reachable Git objects, and generic author/committer metadata. |

The Windows tests do not apply firewall rules or install tasks.
The source-specific private identifier scan runs locally only.
CI fetches the complete Git history and runs the generic scan with `--git-blobs`.

Linux/POSIX fixtures run in the Ubuntu CI job.
They test ownership, recovery, temporary process control, and mocked router and backup behavior.
Tests on a Windows host do not establish POSIX permission behavior or ucode runtime behavior.
OpenWrt ucode tests need their target dependencies.
Upstream web patch tests need the separately generated payloads.
The repository retains those tests where applicable.

The offline checks do not enroll production devices or apply firewalls.
They do not change bridges, download live models, restart hosts, or sign users out.
They do not test an external tablet session.
Each new deployment needs those live checks separately.
