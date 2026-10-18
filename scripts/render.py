#!/usr/bin/env python3
"""Render text reference infrastructure; never contact or deploy to a host."""
import argparse
import hashlib
import ipaddress
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
TOKEN = re.compile(r"\{\{([A-Z][A-Z0-9_]*)\}\}")
GROUPS = ("infra", "services", "windows")


def validate_site(site):
    if not isinstance(site, dict) or not site:
        raise ValueError("Site must be a nonempty JSON object")
    expected = set(json.loads((ROOT / 'config/site.example.json').read_text(encoding='utf-8')))
    if set(site) != expected:
        raise ValueError('Site keys must match the complete example schema')
    domain_pattern = r'(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?'
    for key, value in site.items():
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key) or not isinstance(value, str):
            raise ValueError("Site keys and scalar values must be strings")
        if any(c in value for c in "\r\n\x00") or "{{" in value:
            raise ValueError("Multiline or recursive template value: " + key)
        if key.endswith("_CIDR"):
            network = ipaddress.IPv4Network(value, strict=True)
            if key in ('UPLINK_CIDR', 'LAN_CIDR', 'RESCUE_CIDR') and network.prefixlen != 24:
                raise ValueError('This reference uses /24 family and rescue networks')
            if key == 'WG_SUBNET_CIDR' and network.prefixlen != 30:
                raise ValueError('This reference uses a /30 WireGuard pair')
            fixed = {'JF_NETWORK_CIDR': '172.28.40.0/28', 'PDF_NETWORK_CIDR': '172.28.50.0/28', 'HOME_TOOLS_NETWORK_CIDR': '172.28.60.0/28'}
            if key in fixed and value != fixed[key]:
                raise ValueError('Internal container networks are fixed by the component guards and tests')
        elif key.endswith("_IP") or key.endswith('_GATEWAY'):
            ipaddress.IPv4Address(value)
        elif key.endswith("_PORT"):
            if not value.isdigit() or not 1 <= int(value) <= 65535:
                raise ValueError("Invalid port: " + key)
        elif key.endswith("_MAC"):
            if not re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", value):
                raise ValueError("Invalid MAC: " + key)
            if int(value[:2], 16) & 1:
                raise ValueError('Multicast MAC is not a host identity')
        elif key == 'MAGICDNS_DOMAIN':
            if not re.fullmatch(domain_pattern, value) or len(value) > 253:
                raise ValueError('Invalid DNS domain')
        elif key == 'HEADSCALE_URL':
            url = urlsplit(value)
            if (url.scheme != 'https' or url.username is not None or url.password is not None
                    or url.query or url.fragment or url.path not in ('', '/')
                    or not url.hostname or any(c.isspace() for c in value)):
                raise ValueError('HEADSCALE_URL must be an HTTPS origin without credentials')
            try:
                ipaddress.IPv4Address(url.hostname)
            except ValueError:
                if not re.fullmatch(domain_pattern, url.hostname):
                    raise ValueError('Invalid control hostname')
            if url.port is not None and not 1 <= url.port <= 65535:
                raise ValueError('Invalid control port')
        elif key == 'SSH_USER':
            if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', value):
                raise ValueError('Invalid Linux login user')
        else:
            raise ValueError('Unclassified site key: ' + key)
    if site.get("PVE_IP") != site.get("PVE_UPLINK_IP"):
        raise ValueError("PVE_IP alias must equal PVE_UPLINK_IP")
    for prefix, member in (("UPLINK", "APP_UPLINK_IP"), ("LAN", "APP_LAN_IP"),
                           ("RESCUE", "PVE_RESCUE_IP")):
        if ipaddress.ip_address(site[member]) not in ipaddress.ip_network(site[prefix + "_CIDR"]):
            raise ValueError("Address is outside its configured network: " + member)
    for key in ("LINUX_TAIL_IP", "APP_TAIL_IP", "TABLET_TAIL_IP", "EXIT_TAIL_IP", "WINDOWS_TAIL_IP"):
        if ipaddress.ip_address(site[key]) not in ipaddress.ip_network(site["TAILNET_CIDR"]):
            raise ValueError("Tail address is outside TAILNET_CIDR: " + key)
    tail_addresses = [site[key] for key in ('LINUX_TAIL_IP', 'APP_TAIL_IP', 'TABLET_TAIL_IP', 'EXIT_TAIL_IP', 'WINDOWS_TAIL_IP')]
    if len(set(tail_addresses)) != len(tail_addresses):
        raise ValueError('Tailnet role addresses must be distinct')
    if not ipaddress.IPv4Network(site['TAILNET_CIDR']).subnet_of(ipaddress.IPv4Network('100.64.0.0/10')):
        raise ValueError('Tailnet addresses must use the Tailscale CGNAT range')
    networks = [ipaddress.IPv4Network(site[key]) for key in ('UPLINK_CIDR', 'LAN_CIDR', 'RESCUE_CIDR')]
    if any(a.overlaps(b) for n, a in enumerate(networks) for b in networks[n + 1:]):
        raise ValueError('Family and rescue networks must not overlap')
    wg = ipaddress.IPv4Network(site['WG_SUBNET_CIDR'])
    peers = [ipaddress.IPv4Address(site[k]) for k in ('WG_CLIENT_IP', 'WG_SERVER_IP')]
    if len(set(peers)) != 2 or any(ip not in wg or ip in (wg.network_address, wg.broadcast_address) for ip in peers):
        raise ValueError('WireGuard peers must be distinct usable hosts of the /30 pair')
    for network_key, gateway_key in (('UPLINK_CIDR', 'UPLINK_GATEWAY'), ('LAN_CIDR', 'LAN_GATEWAY'), ('PDF_NETWORK_CIDR', 'PDF_NETWORK_GATEWAY')):
        network = ipaddress.IPv4Network(site[network_key])
        gateway = ipaddress.IPv4Address(site[gateway_key])
        if gateway not in network or gateway in (network.network_address, network.broadcast_address):
            raise ValueError('Gateway must be a usable host of its network')


def render_text(text, site):
    def replace(match):
        key = match.group(1)
        if key not in site:
            raise ValueError("Unknown template key: " + key)
        return site[key]
    return TOKEN.sub(replace, text)


def render(site_path, output):
    site = json.loads(Path(site_path).read_text(encoding="utf-8"))
    validate_site(site)
    output = Path(output).resolve()
    source_roots = [(ROOT / group).resolve() for group in GROUPS]
    if output == ROOT or any(output == p or p in output.parents or output in p.parents for p in source_roots):
        raise ValueError("Output must not overlap the source tree")
    if output.exists() and any(output.iterdir()):
        raise ValueError('Use a new or empty output directory; existing results are never merged')
    selected = {}
    for group in GROUPS:
        for path in sorted((ROOT / group).rglob("*")):
            if not path.is_file() or "__pycache__" in path.parts or path.suffix == ".pyc":
                continue
            if path.is_symlink():
                raise ValueError("Symlinks are not supported")
            relative = path.relative_to(ROOT)
            target = Path(str(relative)[:-5]) if path.name.endswith(".tmpl") else relative
            # Templates intentionally replace static example variants in a rendered tree.
            if target not in selected or path.name.endswith(".tmpl"):
                selected[target] = path
    manifest = []
    # Validate every template before writing any result.
    prepared = []
    for relative, path in selected.items():
        text = path.read_text(encoding="utf-8-sig")
        if path.name.endswith(".tmpl"):
            text = render_text(text, site)
        raw = text.replace("\r\n", "\n").encode("utf-8")
        prepared.append((relative, raw))
        manifest.append({"path": relative.as_posix(), "sha256": hashlib.sha256(raw).hexdigest()})
    for relative, raw in prepared:
        target = output / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    output.mkdir(parents=True, exist_ok=True)
    (output / "render-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return len(prepared)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--site", type=Path, default=ROOT / "config/site.example.json")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps({"rendered_files": render(args.site, args.output), "deployment_performed": False}))
