#!/usr/bin/env python3
"""Independent ServiceHost home-tools ingress guard; leaves other tables/routes alone."""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

TABLE = 'home_tools_guard'
CREATOR = 'ServiceHostHomeToolsGuardV1'
BRIDGE = 'br-home-tools'
DIRECTORY = Path('/var/lib/home-tools-guard')
OWNER = DIRECTORY / 'owner.json'
CONTAINERS = ('portainer', 'filebrowser', 'homepage')
INGRESS = (('ens18', '10.10.20.0/24'),
           ('jf-uplink', '10.10.10.0/24'),
           ('tailscale0', '100.100.10.1/32'),
           ('tailscale0', '100.100.10.3/32'),
           ('tailscale0', '100.100.10.5/32'))
SERVICES = (('172.28.60.3', 9443), ('172.28.60.4', 80), ('172.28.60.5', 3000))


class Refused(RuntimeError):
    pass


def call(args, input=None):
    result = subprocess.run(args, input=input, text=True, capture_output=True, timeout=30)
    if result.returncode:
        raise Refused('Command failed: ' + ' '.join(args[:5]) + ': ' + result.stderr.strip()[:300])
    return result.stdout


def render():
    lines = [f'create table inet {TABLE} {{', f'  comment "{CREATOR}"',
             '  chain input {', '    type filter hook input priority -30; policy accept;',
             '    meta nfproto ipv6 tcp dport { 9443, 8081, 3000 } counter drop',
             '    iifname "lo" ip saddr 127.0.0.0/8 tcp dport { 9443, 8081, 3000 } counter accept']
    for interface, source in INGRESS:
        lines.append(f'    iifname "{interface}" ip saddr {source} tcp dport {{ 9443, 8081, 3000 }} counter accept')
    lines += ['    tcp dport { 9443, 8081, 3000 } counter drop', '  }', '  chain forward {',
              '    type filter hook forward priority -30; policy accept;',
              f'    meta nfproto ipv6 iifname "{BRIDGE}" counter drop',
              f'    meta nfproto ipv6 oifname "{BRIDGE}" counter drop',
              f'    oifname "{BRIDGE}" ct state {{ established, related }} counter accept']
    for interface, source in INGRESS:
        for address, port in SERVICES:
            lines.append(f'    iifname "{interface}" oifname "{BRIDGE}" ip saddr {source} ip daddr {address} tcp dport {port} ct status dnat ct state {{ new, established }} counter accept')
    lines += [f'    oifname "{BRIDGE}" counter drop', '  }', '}']
    return '\n'.join(lines) + '\n'


def identity(document):
    """Preserve per-chain rule order, ignoring nft handles and counter values."""
    def normal(value):
        if isinstance(value, list):
            return [normal(item) for item in value]
        if not isinstance(value, dict):
            return value
        value = {key: normal(item) for key, item in value.items() if key not in ('handle', 'index')}
        if isinstance(value.get('counter'), dict):
            value['counter'] = {key: item for key, item in value['counter'].items() if key not in ('packets', 'bytes')}
        if 'set' in value:
            value['set'] = sorted(value['set'], key=lambda item: json.dumps(item, sort_keys=True))
        return value
    declarations, chains = [], {}
    for item in document['nftables']:
        if 'metainfo' in item:
            continue
        item = normal(item)
        if 'rule' in item:
            rule = item['rule']
            key = (rule.get('family'), rule.get('table'), rule.get('chain'))
            chains.setdefault(key, []).append(item)
        else:
            declarations.append(item)
    canonical = sorted(declarations, key=lambda item: json.dumps(item, sort_keys=True))
    for key in sorted(chains):
        canonical.extend(chains[key])
    return hashlib.sha256(json.dumps(canonical, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def source_sha():
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def read_table():
    tables = json.loads(call(['nft', '-j', 'list', 'tables']))
    if not any(item.get('table', {}).get('family') == 'inet' and
               item.get('table', {}).get('name') == TABLE for item in tables['nftables']):
        return None
    return json.loads(call(['nft', '-j', 'list', 'table', 'inet', TABLE]))


def check_directory(create=False):
    if create:
        DIRECTORY.mkdir(mode=0o700, exist_ok=True)
    info = DIRECTORY.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
        raise Refused('Guard state must be a root-owned mode-700 directory')


def read_owner():
    try:
        info = OWNER.lstat()
    except FileNotFoundError:
        return None
    check_directory()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600 or
            info.st_nlink != 1 or info.st_size > 65536):
        raise Refused('Owner must be root-owned mode-600 regular data')
    owner = json.loads(OWNER.read_text())
    if (not isinstance(owner, dict) or
            set(owner) != {'schema', 'creator', 'source_sha256', 'table_identity', 'created_utc'} or
            owner['schema'] != 1 or owner['creator'] != CREATOR or owner['source_sha256'] != source_sha() or
            not isinstance(owner['table_identity'], str) or len(owner['table_identity']) != 64 or
            any(char not in '0123456789abcdef' for char in owner['table_identity']) or
            not isinstance(owner['created_utc'], str)):
        raise Refused('Owner schema/source identity differs; refusing mutation')
    return owner


def write_owner(table):
    owner = {'schema': 1, 'creator': CREATOR, 'source_sha256': source_sha(),
             'table_identity': identity(table), 'created_utc': datetime.now(timezone.utc).isoformat()}
    fd = os.open(OWNER, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(owner, stream, sort_keys=True, indent=2)
        stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
    return owner


@contextmanager
def mutation_lock():
    check_directory(create=True)
    fd = os.open(DIRECTORY / 'lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'a') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1:
            raise Refused('Guard lock must be owned regular data')
        os.fchmod(stream.fileno(), 0o600)
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def assert_table(owner, table):
    if owner is None:
        raise Refused('Table exists without an ownership receipt')
    if table is None or identity(table) != owner['table_identity']:
        raise Refused('Owned firewall table missing or modified')


def stopped_containers():
    rows = [json.loads(row) for row in call(['docker', 'container', 'ls', '-a', '--format', '{{json .}}']).splitlines() if row]
    for row in rows:
        if row.get('Names') in CONTAINERS and row.get('State') not in ('created', 'exited', 'dead'):
            raise Refused('All home-tools containers must be absent or stopped before guard removal')


def apply():
    owner, table = read_owner(), read_table()
    if table is not None:
        assert_table(owner, table)
        return {'state': 'ACTIVE', 'changed': False, 'table_identity': identity(table)}
    call(['nft', '-c', '-f', '-'], render())
    call(['nft', '-f', '-'], render())
    table = read_table()
    if table is None:
        raise Refused('New table missing after installation')
    if owner is None:
        owner = write_owner(table)
    else:
        assert_table(owner, table)
    return {'state': 'ACTIVE', 'changed': True, 'table_identity': owner['table_identity']}


def check():
    owner, table = read_owner(), read_table()
    assert_table(owner, table)
    return {'state': 'ACTIVE', 'changed': False, 'table_identity': owner['table_identity']}


def remove():
    owner, table = read_owner(), read_table()
    if owner is None:
        raise Refused('No owned guard to remove')
    stopped_containers()
    if table is None:
        return {'state': 'REMOVED', 'changed': False}
    assert_table(owner, table)
    call(['nft', 'delete', 'table', 'inet', TABLE])
    if read_table() is not None:
        raise Refused('Owned table still present after removal')
    return {'state': 'REMOVED', 'changed': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_mutually_exclusive_group(required=True)
    for action in ('apply', 'check', 'remove', 'render'):
        actions.add_argument('--' + action, action='store_true')
    args = parser.parse_args()
    if args.render:
        print(render(), end=''); return
    if os.geteuid() != 0:
        raise Refused('Root is required for firewall inspection/mutation')
    if args.check:
        result = check()
    else:
        with mutation_lock():
            result = apply() if args.apply else remove()
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (Refused, OSError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
        print(json.dumps({'state': 'REFUSED', 'reason': str(error)}, sort_keys=True))
        raise SystemExit(2)
