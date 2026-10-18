# Third-party materials

The root MIT license covers original project code and documentation. It does
not replace upstream copyrights, licenses, or trademark rights.

This repository describes Proxmox VE, OpenWrt, WireGuard, Ubuntu, Docker,
Headscale, Tailscale, v2rayN/sing-box, Jellyfin, Caddy, Stirling-PDF, PaddleOCR,
ONNX Runtime, Homepage, FileBrowser Quantum and Portainer. They remain separate
upstream projects under their respective licenses. Describing a deployment does
not redistribute their container images or operating systems.

| Material | Source and distribution conditions |
| --- | --- |
| Retained vendor code | Component-local notices and LICENSE files identify the source and license. |
| Model assets | Manifests record upstream URLs, revisions, checksums, and license notes. Git excludes weights, Python wheels, container layers, and compiled network tools. Get these assets from the documented upstream sources. |
| WireGuard build inputs | These include MIT and GPL-2.0 components. Obey the component notices when building or distributing them. The root MIT license does not cover these inputs. |
| Upstream web assets | Git excludes generated bundles and HTML payloads. Patch builders require a separate upstream image at the pinned version. |

Product names and any retained upstream marks belong to their respective
owners. No affiliation or endorsement is implied.
