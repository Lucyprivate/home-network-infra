# Publication and privacy

## Source coverage

The public tree contains maintained infrastructure, application, and client sources.
It also contains text code from the service archives.
Each component README identifies runtime tools, hardware-specific references, and source gaps.
An architecture guide does not make an old one-time migration a portable installer.

The repository excludes runtime inventories, before/after receipts, SSH access files, identity digests, certificates, and secret unlock helpers.
It also excludes proxy subscriptions and media credentials.
Other excluded materials include model weights, generated upstream web payloads, system backups, and third-party build archives.

## Example data

The upstream, downstream, rescue, overlay, container, and WireGuard examples form one synthetic network.
Operator and device names describe roles.
Paths, DNS names, SSH settings, and hardware addresses are examples.
Upstream versions, public source URLs, and artifact checksums retain their source information.
These references do not describe private deployment state.

The publication review decodes embedded configuration before inspection.
Readable templates or reference procedures replace one-time programs that contained a full deployment configuration and its digest.
The public sources retain safety checks.
They do not bypass a check to make a converted migration run.

## Privacy checks

`scripts/check_publication.py` scans text, filenames, and supported encoded text.
With `--git-blobs`, it also scans staged and reachable Git blobs, commit metadata, and historical paths.
A local `--denylist` adds source-specific identifiers.
The scanner reports a rule and a safe path instead of the matched private value.
Keep the private list and source mapping outside the repository.

CI fetches the complete history and runs generic checks with `--git-blobs`.
CI does not receive production credentials or the private identifier list.
The publication review also checks file selection and third-party sources.
A text scan cannot identify every personal fact in arbitrary code.
The repository permits text files only. It excludes photographs, PDFs, and backups instead of claiming that text scans can sanitize them.

## Commit identity and limits

The publication commit uses a generic author and committer identity.
The GitHub repository owner remains visible.
Configure the local Git identity before contributing.
Do not commit populated local configuration.

Checks of current files and reachable history do not prove removal from platform backups or third-party clones.
After a history replacement, inspect the known old public object URLs separately.
If an old object still exposes private data, request removal through the platform's support process.
