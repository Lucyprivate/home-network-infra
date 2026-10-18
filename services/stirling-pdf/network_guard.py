#!/usr/bin/env python3
"""Owned Stirling-PDF LAN/offline firewall; no route or Docker-daemon edits.

--apply atomically creates the missing owned table. --check is strictly
read-only. --check-stack additionally checks the fixed Compose scope before
systemd starts it. --remove is dry-run unless --execute is supplied, and only
removes the exact owned table after both units and all project containers stop.
Stopping stirling-guard.service deliberately leaves these rules installed.
"""
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
import uuid

TABLE = 'stirling_guard'
PROJECT = 'stirling-pdf'
SERVICE = 'stirling'
ROOT = Path('/srv/stirling-pdf')
COMPOSE = ROOT / 'compose.yaml'
RUNTIME = ROOT / 'runtime'
OWNER = RUNTIME / 'network-guard-owner.json'
LOCK = '/run/stirling-pdf-guard/network-guard.lock'
BRIDGE = 'br-stirling'
ADDRESS = '172.28.50.3'
SUBNET = '172.28.50.0/28'
CREATOR = 'ServiceHostStirlingPDFNetworkGuardV1'
TAILSCALE_CLIENT = {'set': ['100.100.10.1', '100.100.10.3', '100.100.10.5']}  # Individually authorized Tailscale /32 clients.


class Refused(RuntimeError):
    pass


def call(args, input=None, check=True):
    result = subprocess.run(args, input=input, capture_output=True, text=True, timeout=20)
    if check and result.returncode:
        raise Refused('Guard command failed: ' + ' '.join(args[:4]))
    return result


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def private_read(path):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600 or
            info.st_size > 1024 * 1024 or info.st_nlink != 1):
        raise Refused('Guard owner must be root-owned mode-600 regular data')
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise Refused('Invalid owner schema')
    return value


def private_write(path, value, replace=False):
    temporary = path.with_name(path.name + '.new-' + uuid.uuid4().hex) if replace else path
    fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as output:
        json.dump(value, output, sort_keys=True, indent=2)
        output.write('\n'); output.flush(); os.fsync(output.fileno())
    if replace:
        os.replace(temporary, path)


def ensure_directory():
    RUNTIME.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = RUNTIME.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
        raise Refused('Guard runtime directory must be root-owned mode 700')


@contextmanager
def mutation_lock():
    directory = Path(LOCK).parent
    directory.mkdir(mode=0o700, exist_ok=True)
    metadata = directory.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise Refused('Guard lock directory must be root-owned mode 700')
    fd = os.open(LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'a') as lock:
        info = os.fstat(lock.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1:
            raise Refused('Guard lock is not owned regular data')
        os.fchmod(lock.fileno(), 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def match(left, right, op='=='):
    return {'match': {'op': op, 'left': left, 'right': right}}


def meta(key):
    return {'meta': {'key': key}}


def payload(field, protocol='ip'):
    return {'payload': {'protocol': protocol, 'field': field}}


def prefix(address, length):
    return {'prefix': {'addr': address, 'len': length}}


def rules():
    lan = {'set': [prefix('10.10.10.0', 24), prefix('10.10.20.0', 24)]}
    physical = {'set': ['ens18', 'jf-uplink']}
    port = match(payload('dport', 'tcp'), 8080)
    ipv6 = match(meta('nfproto'), 'ipv6')
    reply = [match({'ct': {'key': 'state'}}, 'established'),
             match({'ct': {'key': 'direction'}}, 'reply')]
    def rule(chain, expressions, counter, verdict):
        return {'rule': {'family': 'inet', 'table': TABLE, 'chain': chain,
                         'expr': expressions + [{'counter': counter}, {verdict: None}]}}
    return [
        rule('input', [ipv6, port], 'ipv6_denied', 'drop'),
        rule('input', [match(meta('iifname'), 'lo'), match(payload('saddr'), prefix('127.0.0.0', 8)), port], 'lan_allowed', 'accept'),
        rule('input', [match(meta('iifname'), physical), match(payload('saddr'), lan), port], 'lan_allowed', 'accept'),
        rule('input', [match(meta('iifname'), 'tailscale0'), match(payload('saddr'), TAILSCALE_CLIENT), port], 'lan_allowed', 'accept'),
        rule('input', [port], 'ingress_denied', 'drop'),
        rule('input', [match(meta('iifname'), BRIDGE), ipv6], 'ipv6_denied', 'drop'),
        rule('input', [match(meta('iifname'), BRIDGE), match(payload('saddr'), ADDRESS),
                       match(payload('sport', 'tcp'), 8080), *reply], 'host_replies_allowed', 'accept'),
        rule('input', [match(meta('iifname'), BRIDGE)], 'host_access_denied', 'drop'),
        rule('input', [match(payload('saddr'), prefix('172.28.50.0', 28))], 'host_access_denied', 'drop'),
        rule('forward', [match(meta('iifname'), BRIDGE), ipv6], 'ipv6_denied', 'drop'),
        rule('forward', [match(meta('oifname'), BRIDGE), ipv6], 'ipv6_denied', 'drop'),
        rule('forward', [match(meta('iifname'), 'tailscale0'), match(meta('oifname'), BRIDGE),
                         match(payload('saddr'), TAILSCALE_CLIENT), match(payload('daddr'), ADDRESS), port,
                         match({'ct': {'key': 'state'}}, {'set': ['new', 'established']})], 'lan_allowed', 'accept'),
        rule('forward', [match(meta('iifname'), physical), match(meta('oifname'), BRIDGE),
                         match(payload('saddr'), lan), match(payload('daddr'), ADDRESS), port,
                         match({'ct': {'key': 'state'}}, {'set': ['new', 'established']})], 'lan_allowed', 'accept'),
        rule('forward', [match(meta('iifname'), BRIDGE), match(meta('oifname'), physical),
                         match(payload('saddr'), ADDRESS), match(payload('daddr'), lan),
                         match(payload('sport', 'tcp'), 8080), *reply], 'lan_replies_allowed', 'accept'),
        rule('forward', [match(meta('iifname'), BRIDGE), match(meta('oifname'), 'tailscale0'),
                         match(payload('saddr'), ADDRESS), match(payload('daddr'), TAILSCALE_CLIENT),
                         match(payload('sport', 'tcp'), 8080), *reply], 'lan_replies_allowed', 'accept'),
        rule('forward', [match(meta('iifname'), BRIDGE)], 'egress_denied', 'drop'),
        rule('forward', [match(meta('oifname'), BRIDGE)], 'ingress_denied', 'drop'),
        rule('forward', [match(payload('saddr'), prefix('172.28.50.0', 28))], 'egress_denied', 'drop'),
        rule('forward', [match(payload('daddr'), prefix('172.28.50.0', 28))], 'ingress_denied', 'drop')]


def expected_document():
    objects = [{'table': {'family': 'inet', 'name': TABLE}}]
    for name in ('input', 'forward'):
        objects.append({'chain': {'family': 'inet', 'table': TABLE, 'name': name, 'type': 'filter',
                                  'hook': name, 'prio': -20, 'policy': 'accept'}})
    for name in ('ipv6_denied', 'lan_allowed', 'ingress_denied', 'host_replies_allowed',
                 'host_access_denied', 'lan_replies_allowed', 'egress_denied'):
        objects.append({'counter': {'family': 'inet', 'table': TABLE, 'name': name, 'bytes': 0, 'packets': 0}})
    return {'nftables': objects + rules()}


def identity(document):
    def normal(value):
        if isinstance(value, list):
            return [normal(x) for x in value]
        if not isinstance(value, dict):
            return value
        value = {k: normal(v) for k, v in value.items() if k not in ('handle', 'index')}
        if 'counter' in value and isinstance(value['counter'], dict):
            value['counter'] = {k: v for k, v in value['counter'].items() if k not in ('packets', 'bytes')}
        if 'set' in value:
            value['set'] = sorted(value['set'], key=lambda x: json.dumps(x, sort_keys=True))
        entry = value.get('match', {})
        if entry.get('left') == {'ct': {'key': 'direction'}} and entry.get('right') in (0, 1):
            entry['right'] = ('original', 'reply')[entry['right']]
        return value
    objects, ordered_rules = [], {}
    for item in document['nftables']:
        if 'metainfo' in item:
            continue
        row = normal(item)
        if 'rule' in row:
            rule = row['rule']
            key = (rule.get('family'), rule.get('table'), rule.get('chain'))
            ordered_rules.setdefault(key, []).append(row)
        else:
            objects.append(row)
    canonical = sorted(objects, key=lambda x: json.dumps(x, sort_keys=True))
    for key in sorted(ordered_rules):
        canonical.extend(ordered_rules[key])
    return hashlib.sha256(json.dumps(canonical, sort_keys=True).encode()).hexdigest()


def expected_identity():
    return identity(expected_document())


def transaction():
    # `create` refuses EEXIST, including a foreign table racing installation.
    commands = [{'create': {'table': {'family': 'inet', 'name': TABLE}}}]
    commands.extend({'add': item} for item in expected_document()['nftables'][1:])
    return json.dumps({'nftables': commands})


def read_table():
    result = call(['nft', '-j', 'list', 'table', 'inet', TABLE], check=False)
    if result.returncode:
        if 'no such file or directory' in result.stderr.lower():
            return None
        raise Refused('Cannot safely inspect the Stirling firewall')
    return json.loads(result.stdout)


def owner():
    value = private_read(OWNER)
    if (value.get('schema') != 1 or value.get('created_by') != CREATOR or value.get('table') != TABLE or
            value.get('identity') != expected_identity() or value.get('state') not in ('PREPARED', 'ACTIVE', 'REMOVED')):
        raise Refused('Guard ownership receipt does not match this fixed deployment')
    return value


def validate(table, receipt):
    if receipt.get('state') not in ('PREPARED', 'ACTIVE') or identity(table) != expected_identity():
        raise Refused('Guard table is foreign or edited; nothing will be overwritten/deleted')
    return expected_identity()


def check():
    table = read_table()
    if table is None:
        raise Refused('Owned Stirling firewall is absent')
    digest = validate(table, owner())
    return {'result': 'GUARD_READY', 'read_only': True, 'table': TABLE, 'identity': digest,
            'route_changes': False, 'docker_daemon_changes': False}


def apply():
    table = read_table()
    receipt = owner() if OWNER.exists() or OWNER.is_symlink() else None
    if table is not None:
        if receipt is None:
            raise Refused('Existing firewall has no private owner; leave it untouched')
        validate(table, receipt)
        if receipt['state'] == 'PREPARED':
            receipt.update(state='ACTIVE', verified_utc=timestamp())
            private_write(OWNER, receipt, replace=True)
        return check()
    if receipt and receipt['state'] == 'REMOVED':
        raise Refused('This firewall was explicitly removed; review ownership before re-enabling it')
    ensure_directory()
    payload = transaction()
    call(['nft', '-j', '-c', '-f', '-'], payload)
    if receipt is None:
        receipt = {'schema': 1, 'created_by': CREATOR, 'table': TABLE, 'identity': expected_identity(),
                   'state': 'PREPARED', 'created_utc': timestamp()}
        private_write(OWNER, receipt)
    call(['nft', '-j', '-f', '-'], payload)
    table = read_table()
    if table is None:
        raise Refused('Firewall creation did not produce the owned table')
    validate(table, receipt)
    receipt.update(state='ACTIVE', verified_utc=timestamp())
    private_write(OWNER, receipt, replace=True)
    return {**check(), 'result': 'GUARD_APPLIED', 'read_only': False}


def project_containers():
    result = call(['docker', 'ps', '-aq', '--filter', 'label=com.docker.compose.project=' + PROJECT])
    ids = result.stdout.split()
    if not ids:
        return []
    template = '{"Id":{{json .Id}},"Labels":{{json .Config.Labels}},"Running":{{json .State.Running}},"RestartPolicy":{{json .HostConfig.RestartPolicy.Name}}}'
    output = []
    for identifier in ids:
        if not identifier.isalnum() or not 12 <= len(identifier) <= 64:
            raise Refused('Unsupported container identity')
        item = json.loads(call(['docker', 'inspect', '--format', template, identifier]).stdout)
        labels = item.get('Labels') or {}
        if (labels.get('com.docker.compose.project') != PROJECT or labels.get('com.docker.compose.service') != SERVICE or
                labels.get('com.docker.compose.project.config_files') != str(COMPOSE) or
                labels.get('com.docker.compose.project.working_dir') != str(ROOT)):
            raise Refused('Compose project namespace contains a foreign container')
        output.append(item)
    return output


def check_stack():
    result = check()
    config = json.loads(call(['docker', 'compose', '-p', PROJECT, '-f', str(COMPOSE), 'config', '--format', 'json']).stdout)
    if config.get('name') != PROJECT or set(config.get('services', {})) != {SERVICE}:
        raise Refused('Unexpected Compose project/service scope')
    service = config['services'][SERVICE]
    ports = service.get('ports') or []
    if (service.get('restart', 'no') != 'no' or service.get('network_mode') is not None or len(ports) != 1 or
            ports[0].get('host_ip') != '0.0.0.0' or str(ports[0].get('published')) != '8080' or
            ports[0].get('target') != 8080 or ports[0].get('protocol', 'tcp') != 'tcp'):
        raise Refused('Stirling must use restart=no, one IPv4 8080 port and its private bridge')
    # Docker's default embedded DNS can proxy host-loopback resolvers outside
    # FORWARD. Pin upstream DNS to this container's loopback; OCR is offline.
    if service.get('dns') != ['127.0.0.1']:
        raise Refused('Offline Stirling DNS must be explicitly confined to container loopback')
    networks = service.get('networks') or {}
    if not isinstance(networks, dict) or len(networks) != 1:
        raise Refused('Stirling must attach only to its dedicated bridge')
    name, attachment = next(iter(networks.items()))
    network = config.get('networks', {}).get(name, {})
    ipam = network.get('ipam', {}).get('config', [])
    if (attachment.get('ipv4_address') != ADDRESS or network.get('driver', 'bridge') != 'bridge' or
            network.get('enable_ipv6', False) or network.get('internal', False) or network.get('external', False) or
            network.get('driver_opts', {}).get('com.docker.network.bridge.name') != BRIDGE or
            len(ipam) != 1 or ipam[0].get('subnet') != SUBNET):
        raise Refused('Unexpected Stirling bridge/address/IPv6 configuration')
    for container in project_containers():
        if container.get('RestartPolicy') != 'no':
            raise Refused('An existing Stirling container has a Docker automatic restart policy')
    return {**result, 'result': 'STACK_PREFLIGHT_READY', 'compose_project': PROJECT,
            'docker_restart_policy': 'no', 'published_ipv4_port': 8080}


def stopped():
    for name in ('stirling-pdf.service', 'stirling-guard.service'):
        result = call(['systemctl', 'show', name, '-p', 'LoadState', '-p', 'ActiveState', '-p', 'Job'], check=False)
        if result.returncode and not result.stdout:
            raise Refused('Cannot verify stopped Stirling units')
        state = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
        job = state.get('Job', '').strip()
        if state.get('ActiveState') not in ('inactive', 'failed') or job and job.split()[0] != '0':
            raise Refused('Stop the Stirling service and guard before removing its firewall')
    containers = project_containers()
    if any(container.get('Running') is not False for container in containers):
        raise Refused('All exact-owned Stirling project containers must be stopped')
    return {'units_stopped': True, 'project_containers_stopped': len(containers)}


def stop_stack():
    """Safe ExecStopPost even when startup refused a foreign namespace."""
    containers = project_containers()
    if any(container.get('Running') is True for container in containers):
        call(['docker', 'compose', '-p', PROJECT, '-f', str(COMPOSE), 'stop', '--timeout', '15', SERVICE])
    if any(container.get('Running') is not False for container in project_containers()):
        raise Refused('Exact-owned Stirling containers have not stopped')
    return {'result': 'OWNED_STACK_STOPPED', 'project': PROJECT, 'firewall_kept': True}


def remove(execute=False):
    table = read_table()
    receipt = owner()
    if table is None:
        if receipt['state'] != 'REMOVED':
            raise Refused('Firewall unexpectedly absent; no deletion attempted')
        return {'result': 'ALREADY_REMOVED', 'read_only': not execute}
    validate(table, receipt)
    state = stopped()
    if not execute:
        return {'result': 'REMOVE_READY', 'read_only': True, 'table': TABLE, **state}
    # Repeat immediately before deletion; do not stop any unit or container here.
    stopped(); validate(read_table(), owner())
    call(['nft', '-c', 'delete', 'table', 'inet', TABLE])
    call(['nft', 'delete', 'table', 'inet', TABLE])
    if read_table() is not None:
        raise Refused('The owned table did not disappear')
    receipt.update(state='REMOVED', removed_utc=timestamp())
    private_write(OWNER, receipt, replace=True)
    return {'result': 'GUARD_REMOVED', 'read_only': False, 'table': TABLE, **state,
            'other_firewall_tables_untouched': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument('--apply', action='store_true')
    actions.add_argument('--check', action='store_true')
    actions.add_argument('--check-stack', action='store_true')
    actions.add_argument('--remove', action='store_true')
    actions.add_argument('--stop-stack', action='store_true', help='Stop only exact-owned project containers; retain firewall')
    parser.add_argument('--execute', action='store_true', help='Confirm exact-owned removal')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Run on ServiceHost as root')
    if args.execute and not args.remove:
        parser.error('--execute applies only to --remove')
    try:
        if args.stop_stack:
            result = stop_stack()
        elif args.apply or args.remove and args.execute:
            with mutation_lock():
                result = apply() if args.apply else remove(True)
        else:
            result = remove(False) if args.remove else check_stack() if args.check_stack else check()
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception as error:
        print(json.dumps({'result': 'REFUSED', 'reason': str(error) if isinstance(error, Refused) else type(error).__name__}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
