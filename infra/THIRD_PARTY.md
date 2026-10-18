# Third-party software sources

No third-party executable, model, distribution archive, static libc, or copied
framework source is shipped in this directory. The maintenance programs and
LuCI modules are original integration code. Dependencies retain their own
licenses; the repository MIT license does not relicense those dependencies.

| Dependency | Pinned reference | Official source | License |
| --- | --- | --- | --- |
| Headscale | 0.29.5 Linux amd64, SHA-256 `e979d27fe17d924d33bb6ab7504f6338d0635989a0cfdcfbc0ceb637dbcbe980` | [release](https://github.com/juanfont/headscale/releases/tag/v0.29.5) | [BSD-3-Clause](https://github.com/juanfont/headscale/blob/v0.29.5/LICENSE) |
| Tailscale Ubuntu client | 1.104.1 amd64 package, SHA-256 `509753a4ff223efc70234e7f539afc51f743b3af043d9e55313960bd7327700f` | [official packages](https://pkgs.tailscale.com/stable/) | [BSD-3-Clause and bundled notices](https://github.com/tailscale/tailscale/blob/v1.104.1/LICENSE) |
| Tailscale static client | 1.104.1 amd64 archive, SHA-256 `108d1d96ecf410d305571e173516f27038f870919a9b89c914a167c6d33a4528` | [official archive](https://pkgs.tailscale.com/stable/tailscale_1.104.1_amd64.tgz) | Same upstream license/notices |
| wireguard-go | commit `2631ce99a06f27120d581611cf125d68bc6aa565`, source archive SHA-256 `cbc516fea851a6cda039f95a9e323c91df5081ef21aee8218ca3a1bf1242b10a` | [official repository](https://git.zx2c4.com/wireguard-go/) | [MIT](https://git.zx2c4.com/wireguard-go/tree/LICENSE) |
| wireguard-tools | v1.0.20260223, source archive SHA-256 `af459827b80bfd31b83b08077f4b5843acb7d18ad9a33a2ef532d3090f291fbf` | [official repository](https://git.zx2c4.com/wireguard-tools/) | [GPL-2.0](https://git.zx2c4.com/wireguard-tools/tree/COPYING) |
| OpenWrt / LuCI / ucode | Use versions compatible with the chosen OpenWrt image | [OpenWrt source](https://git.openwrt.org/), [LuCI](https://github.com/openwrt/luci), [ucode](https://github.com/jow-/ucode) | See each package's license |
| Proxmox VE | Distribution packages, installed separately | [official download](https://www.proxmox.com/en/downloads) | See distribution and package licenses |
| Ubuntu / Docker Engine / Intel media driver | Distribution-supported packages, installed separately | [Ubuntu](https://ubuntu.com/download/server), [Docker](https://docs.docker.com/engine/install/ubuntu/), [Intel driver](https://github.com/intel/media-driver) | See respective package licenses |

These hashes identify public upstream artifacts, not a private installation.
The repository excludes private build output and machine-specific test reports.
Get official releases for the target platform.
Check each artifact against its listed hash before use.
Legacy WireGuard builds need a compatible toolchain and separate target runtime tests.
This directory includes no binary with a compatibility claim.
