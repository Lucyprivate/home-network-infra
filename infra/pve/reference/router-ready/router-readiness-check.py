#!/usr/bin/env python3
"""Read-only PVE/OpenWrt readiness checks; stdout JSON, no configuration actions."""
import argparse
import base64
import binascii
import ipaddress
import json
import re
import shlex
import subprocess
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parents[2]
PORTS = {'vmbr0': ('enp2s0', '02:00:00:00:10:00'),
         'vmbr1': ('enp3s0', '02:00:00:00:10:01'),
         'vmbr2': ('enp4s0', '02:00:00:00:10:02'),
         'vmbr3': ('enp5s0', '02:00:00:00:10:03')}
SCHEMA = 'router-readiness-v1'
MAX_OUTPUT = 4 * 1024 * 1024

# Only selected network/configuration fields leave PVE. In particular this does
# not run the uplink CLI, whose status command creates a lock/state directory.
PVE_SCRIPT = r'''
import json, os, pathlib, re, subprocess
def read(path):
    try: return pathlib.Path(path).read_text().strip()
    except OSError: return None
def command(argv):
    try:
        p=subprocess.run(argv, text=True, capture_output=True, timeout=15)
        return p.returncode, p.stdout
    except (OSError, subprocess.TimeoutExpired): return 255, ''
def ipjson(argv):
    rc,out=command(argv)
    try: return json.loads(out) if rc == 0 else None
    except ValueError: return None
facts={'ssh_session':os.environ.get('SSH_CONNECTION',''),
       'addresses':ipjson(['ip','-j','-4','addr','show']),
       'defaults':ipjson(['ip','-j','-4','route','show','default']),
       'ipv6_defaults':ipjson(['ip','-j','-6','route','show','default']),
       'nameservers':[], 'host_aliases':{}, 'links':{}, 'vms':{}}
resolver=read('/etc/resolv.conf')
facts['nameservers']=re.findall(r'^\s*nameserver\s+(\S+)', resolver, re.M) if resolver is not None else None
for name in ['enp2s0','enp3s0','enp4s0','enp5s0','vmbr0','vmbr1','vmbr2','vmbr3']:
    p=pathlib.Path('/sys/class/net')/name
    try: master=(p/'master').resolve(strict=True).name
    except OSError: master=None
    carrier=read(p/'carrier')
    facts['links'][name]={'mac':read(p/'address'), 'carrier':carrier,
                         'flags':read(p/'flags'), 'master':master}
for vmid in ['100','150','199']:
    rc,out=command(['qm','status',vmid])
    config=pathlib.Path('/etc/pve/qemu-server')/(vmid+'.conf')
    selected={}
    try:
        with config.open() as f:
            for line in f:
                key,sep,value=line.partition(':')
                if sep and key in ['onboot','startup']: selected[key]=value.strip()
    except OSError: pass
    match=re.fullmatch(r'\s*status:\s*(running|stopped)\s*',out)
    facts['vms'][vmid]={'exists':config.exists(), 'status':match[1] if rc==0 and match else None, **selected}
hosts=read('/etc/hosts')
if hosts is not None:
    for line in hosts.splitlines():
        words=line.split('#',1)[0].split()
        if len(words)>1:
            for name in ['pve','hypervisor.example.test']:
                if name in words[1:]: facts['host_aliases'].setdefault(name,[]).append(words[0])
else: facts['host_aliases']=None
facts['pve_guests_enabled']=command(['systemctl','is-enabled','pve-guests.service'])[0]==0
state=read('/var/lib/codex-pve-uplink/state.json')
try:
    raw=json.loads(state) if state is not None else {}
    facts['uplink_state']={k:raw[k] for k in ['layout','phase'] if k in raw}
except ValueError: facts['uplink_state']={'phase':'invalid'}
print(json.dumps(facts))
'''

UCI_FIELDS = {
    'network.lan': ['device', 'ipaddr', 'delegate', 'ip6assign'],
    'network.wan': ['device', 'proto', 'peerdns'],
    'network.wan6': ['disabled'],
    'network.@device[0]': ['name', 'type', 'ports', 'macaddr'],
    'dhcp.lan': ['start', 'limit', 'leasetime', 'ignore', 'dhcpv4', 'dhcpv6', 'ra', 'ndp'],
    'dhcp.wan': ['ignore'],
    'dhcp.codex_servicevm': ['name', 'mac', 'ip'],
    'firewall.codex_upstream_admin': ['name', 'src', 'src_ip', 'family', 'proto', 'dest_port', 'target', 'dest', 'enabled'],
    'firewall.codex_lan_ipv6_block': ['src', 'dest', 'family', 'proto', 'target', 'enabled'],
    'homeproxy.config': ['main_node'],
    'homeproxy.server': ['enabled'],
}


def openwrt_queries():
    queries = {
        'lan': ['ubus', 'call', 'network.interface.lan', 'status'],
        'wan': ['ubus', 'call', 'network.interface.wan', 'status'],
        'wan6': ['ubus', 'call', 'network.interface.wan6', 'status'],
        'ssh_session': ['sh', '-c', 'printf "%s\\n" "$SSH_CONNECTION"'],
        'routes': ['ip', '-4', 'route', 'show', 'default'],
        'resolver': ['cat', '/tmp/resolv.conf.d/resolv.conf.auto'],
        'leases': ['cat', '/tmp/dhcp.leases'],
        'guard': ['/usr/sbin/homeproxy-guard', 'status'],
        'input_wan': ['nft', '-j', 'list', 'chain', 'inet', 'fw4', 'input_wan'],
        'guard_enabled': ['/etc/init.d/homeproxy-guard', 'enabled'],
    }
    for service in ('dnsmasq', 'uhttpd', 'dropbear', 'homeproxy-guard'):
        queries['service.' + service] = ['ubus', 'call', 'service', 'list', json.dumps({'name': service}, separators=(',', ':'))]
    for prefix, keys in UCI_FIELDS.items():
        queries['uci.' + prefix] = ['uci', '-q', 'get', prefix]
        for key in keys:
            queries['uci.' + prefix + '.' + key] = ['uci', '-q', 'get', prefix + '.' + key]
    # Inspect named zones by selected fields, independent of anonymous ordering.
    for index in range(8):
        for key in ('name', 'network', 'input', 'forward', 'masq'):
            label = f'uci.firewall.@zone[{index}].{key}'
            queries[label] = ['uci', '-q', 'get', f'firewall.@zone[{index}].{key}']
        for key in ('src', 'dest', 'enabled'):
            label = f'uci.firewall.@forwarding[{index}].{key}'
            queries[label] = ['uci', '-q', 'get', f'firewall.@forwarding[{index}].{key}']
    for section, keys in (('uhttpd.main', ('listen_http', 'listen_https')),
                          ('dropbear.@dropbear[0]', ('Port', 'Interface'))):
        for key in keys:
            queries['uci.' + section + '.' + key] = ['uci', '-q', 'get', section + '.' + key]
    return queries


def openwrt_script(queries):
    # Base64 framing avoids trusting arbitrary DHCP names or UCI line breaks.
    # This guest has ucode but no base64 utility. An encoder failure must abort
    # the whole SSH collection instead of quietly turning every value empty.
    prelude = '''command -v ucode >/dev/null 2>&1 || exit 95
rrc_emit() {
    rrc_label=$1; shift
    rrc_data="$("$@" 2>/dev/null)"; rrc_code=$?
    rrc_encoded="$(printf '%s' "$rrc_data" | ucode -e 'import { readfile } from "fs"; let value=readfile("/dev/stdin"); if (value === null) die("stdin_read_failed"); print(b64enc(value));' 2>/dev/null)"; rrc_encode_code=$?
    if [ "$rrc_encode_code" -ne 0 ] || { [ -n "$rrc_data" ] && [ -z "$rrc_encoded" ]; }; then
        printf '%s\\n' 'RRC_ENCODER_FAILED' >&2
        return 95
    fi
    printf 'RRC1 %s %s %s\\n' "$rrc_label" "$rrc_code" "$rrc_encoded" || return 95
}
'''
    return prelude + ''.join('rrc_emit ' + shlex.quote(label) + ' ' + shlex.join(argv) + ' || exit 95\n'
                             for label, argv in queries.items())


class CollectionError(Exception):
    pass


def ssh_run(alias, command, script, ssh_config, timeout):
    if alias not in ('pve', 'openwrt100', 'pve-uplink', 'openwrt-wan'):
        raise CollectionError('unsupported SSH alias')
    argv = ['ssh', '-F', str(ssh_config), '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8',
            '-o', 'ConnectionAttempts=1', '-o', 'ControlMaster=no', '-o', 'ControlPath=none',
            alias, command]
    try:
        result = subprocess.run(argv, input=script, text=True, encoding='utf-8', errors='replace', capture_output=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        raise CollectionError('SSH unavailable or timed out') from None
    # Never put arbitrary SSH/proxy stderr or full remote output in the report.
    if result.returncode or len(result.stdout) > MAX_OUTPUT:
        raise CollectionError('SSH collection failed or exceeded output limit')
    return result.stdout


def parse_records(text, expected):
    records = {}
    for line in text.splitlines():
        parts = line.split(' ', 3)
        if len(parts) != 4 or parts[0] != 'RRC1' or parts[1] not in expected or parts[1] in records:
            raise CollectionError('invalid or duplicate OpenWrt record')
        try:
            code = int(parts[2])
            if not 0 <= code <= 255:
                raise ValueError()
            value = base64.b64decode(parts[3], validate=True).decode('utf-8')
        except (ValueError, UnicodeError, binascii.Error):
            raise CollectionError('invalid OpenWrt record encoding') from None
        records[parts[1]] = {'rc': code, 'value': value}
    if set(records) != set(expected):
        raise CollectionError('incomplete OpenWrt collection')
    return records


def decode_json(record):
    if record.get('rc') != 0:
        return None
    try:
        return json.loads(record['value'])
    except (ValueError, KeyError):
        return None


def parse_kv(text):
    result = {}
    allowed = {'main_node', 'homeproxy_autostart', 'mode', 'reason', 'internet', 'updated', 'probe_cache'}
    for line in text.splitlines():
        key, separator, value = line.partition('=')
        if separator and key in allowed:
            if key in result:
                raise CollectionError('duplicate guard status field')
            result[key] = value
    return result


def sanitize_service(data, name):
    if not isinstance(data, dict) or not isinstance(data.get(name), dict):
        return {'registered': False, 'running': False, 'listeners': []}
    instances = data[name].get('instances', {})
    if not isinstance(instances, dict):
        return {'registered': False, 'running': False, 'listeners': []}
    running = False
    listeners = []
    for instance in instances.values():
        if not isinstance(instance, dict):
            continue
        running |= instance.get('running') is True
        command = instance.get('command', [])
        if name == 'uhttpd' and instance.get('running') is True and isinstance(command, list):
            for index, arg in enumerate(command[:-1]):
                if arg in ('-p', '-s') and isinstance(command[index + 1], str):
                    listeners.append({'kind': 'http' if arg == '-p' else 'https', 'bind': command[index + 1]})
        if name == 'dropbear' and instance.get('running') is True and isinstance(command, list):
            for index, arg in enumerate(command[:-1]):
                if arg == '-p' and isinstance(command[index + 1], str):
                    listeners.append({'kind': 'ssh', 'bind': command[index + 1]})
    return {'registered': True, 'running': running, 'listeners': listeners}


def summarize_openwrt(records):
    def value(label):
        item = records.get(label, {})
        return item.get('value') if item.get('rc') == 0 else None
    uci = {label.removeprefix('uci.'): value(label) for label in records if label.startswith('uci.')}
    leases = []
    for line in (value('leases') or '').splitlines():
        words = line.split()
        if len(words) >= 4 and words[1].lower() == '02:00:00:00:30:01':
            leases.append({'mac': words[1].lower(), 'address': words[2], 'hostname': words[3]})
    guard = parse_kv(value('guard') or '')
    services = {name: sanitize_service(decode_json(records.get('service.' + name, {})), name)
                for name in ('dnsmasq', 'uhttpd', 'dropbear', 'homeproxy-guard')}
    status = {name: decode_json(records.get(name, {})) for name in ('lan', 'wan', 'wan6')}
    status = {name: value if isinstance(value, dict) else None for name, value in status.items()}
    return {'ssh_session': value('ssh_session'),
            **status,
            'default_routes': parse_routes(value('routes') or ''),
            'wan_dns': re.findall(r'^\s*nameserver\s+(\S+)', value('resolver') or '', re.M),
            'leases_servicevm': leases, 'guard': guard, 'guard_enabled': records.get('guard_enabled', {}).get('rc') == 0,
            'services': services, 'uci': uci, 'input_wan': decode_json(records.get('input_wan', {})),
            'collection_available': {key: records.get(key, {}).get('rc') == 0 for key in ('lan', 'wan', 'wan6', 'routes', 'resolver', 'leases', 'guard', 'input_wan')}}


def parse_routes(text):
    routes = []
    for line in text.splitlines():
        words = line.split()
        if not words or words[0] != 'default':
            continue
        row = {}
        for key in ('via', 'dev'):
            if key in words and words.index(key) + 1 < len(words):
                row['gateway' if key == 'via' else 'dev'] = words[words.index(key) + 1]
        routes.append(row)
    return routes


def addresses(pve, name):
    links = pve.get('addresses')
    if not isinstance(links, list):
        return []
    return [(item.get('local'), item.get('prefixlen'))
            for link in links if isinstance(link, dict) and link.get('ifname') == name
            for item in link.get('addr_info', []) if isinstance(item, dict) and item.get('family', 'inet') == 'inet']


def startup(value):
    result = {}
    if not value:
        return result
    for item in value.split(','):
        key, separator, raw = item.partition('=')
        if not separator or key not in ('order', 'up', 'down') or key in result or not raw.isdigit():
            return None
        result[key] = int(raw)
    return result


def ipv4_in_subnet(address, subnet):
    try:
        return ipaddress.ip_address(address) in ipaddress.ip_network(subnet)
    except (TypeError, ValueError):
        return False


def runtime_admin_rule(data):
    if not isinstance(data, dict) or not isinstance(data.get('nftables'), list):
        return False
    matched = []
    for entry in data['nftables']:
        rule = entry.get('rule', {}) if isinstance(entry, dict) else {}
        if not isinstance(rule, dict):
            continue
        if rule.get('comment') == '!fw4: Allow upstream HTTPS and SSH':
            matched.append(rule)
    if len(matched) != 1:
        return False
    rule = matched[0]
    expressions = rule.get('expr')
    if rule.get('chain') != 'input_wan' or rule.get('table') != 'fw4' or rule.get('family') != 'inet' or not isinstance(expressions, list):
        return False
    source_ok = ports_ok = accept = False
    for expr in expressions:
        if not isinstance(expr, dict):
            continue
        accept |= 'accept' in expr
        match = expr.get('match', {})
        if not isinstance(match, dict) or match.get('op') != '==':
            continue
        left, right = match.get('left'), match.get('right')
        if left == {'payload': {'protocol': 'ip', 'field': 'saddr'}}:
            source_ok = right == {'prefix': {'addr': '10.10.10.0', 'len': 24}}
        if left == {'payload': {'protocol': 'tcp', 'field': 'dport'}} and isinstance(right, dict):
            values = right.get('set')
            ports_ok = isinstance(values, list) and len(values) == 2 and set(map(str, values)) == {'22', '443'}
    return source_ok and ports_ok and accept


def session_destination(value):
    fields = (value or '').split()
    try:
        if len(fields) != 4 or not all(0 < int(fields[index]) <= 65535 for index in (1, 3)):
            return None
        ipaddress.ip_address(fields[0])
        return str(ipaddress.ip_address(fields[2]))
    except (ValueError, TypeError):
        return None


def assess(pve, ow, mode):
    groups = {'common': [], 'offline': [], 'upstream': []}
    def check(group, name, condition=None, detail='', skip=False):
        groups[group].append({'name': name, 'status': 'SKIP' if skip else 'PASS' if condition else 'FAIL', 'detail': detail})
    links = pve.get('links', {})
    uci = ow.get('uci', {})
    vm = pve.get('vms', {})
    services = ow.get('services', {})
    wan = ow.get('wan') or {}
    wan6 = ow.get('wan6') or {}
    lan = ow.get('lan') or {}
    guard = ow.get('guard', {})
    wan_carrier = links.get('enp2s0', {}).get('carrier') == '1'
    management_carrier = links.get('enp4s0', {}).get('carrier') == '1'
    expected_pve = '10.10.99.10' if mode == 'offline' else '10.10.10.10'
    check('common', 'pve_ssh_destination', session_destination(pve.get('ssh_session')) == expected_pve, 'SSH must terminate on the requested management path')
    if mode == 'upstream':
        check('common', 'openwrt_ssh_destination', session_destination(ow.get('ssh_session')) == '10.10.10.2', 'New direct OpenWrt WAN management connection required')
    for bridge, (port, mac) in PORTS.items():
        check('common', bridge + '_physical_port', links.get(port, {}).get('master') == bridge and links.get(port, {}).get('mac') == mac,
              port + ' belongs to ' + bridge)
    check('common', 'management_rescue_bridge_macs', links.get('vmbr2', {}).get('mac') == PORTS['vmbr2'][1] and links.get('vmbr3', {}).get('mac') == PORTS['vmbr3'][1])
    check('common', 'rescue_address', addresses(pve, 'vmbr3') == [('10.10.99.10', 24)])
    check('common', 'wan_lan_host_unaddressed', not addresses(pve, 'vmbr0') and not addresses(pve, 'vmbr1') and isinstance(pve.get('addresses'), list))
    check('common', 'no_pve_ipv6_default_route', pve.get('ipv6_defaults') == [])
    check('common', 'pve_guests_autostart', pve.get('pve_guests_enabled') is True)
    for vmid, order in (('100', 1), ('150', 2)):
        record = vm.get(vmid, {})
        boot = startup(record.get('startup'))
        check('common', 'vm' + vmid + '_running_autostart_order', record.get('status') == 'running' and record.get('onboot') == '1' and boot is not None and boot.get('order') == order)
    check('common', 'vm100_start_delay', startup(vm.get('100', {}).get('startup')) is not None and (startup(vm.get('100', {}).get('startup')) or {}).get('up') == 30)
    temp = vm.get('199', {})
    check('common', 'diagnostic_vm_not_autostarted', not temp.get('exists') or temp.get('status') == 'stopped' and temp.get('onboot', '0') == '0')
    check('common', 'openwrt_lan', lan.get('up') is True and lan.get('device') == 'br-lan' and
          lan.get('l3_device') == 'br-lan' and lan.get('ipv4-address') == [{'address': '10.10.20.1', 'mask': 24}] and
          uci.get('network.lan.device') == 'br-lan' and uci.get('network.@device[0].ports') == 'eth1')
    check('common', 'openwrt_wan_dhcp', uci.get('network.wan.device') == 'eth0' and uci.get('network.wan.proto') == 'dhcp' and uci.get('network.wan.peerdns') == '1')
    check('common', 'lan_dhcp_pool', uci.get('dhcp.lan.start') == '100' and uci.get('dhcp.lan.limit') == '150' and uci.get('dhcp.lan.leasetime') == '12h' and uci.get('dhcp.lan.dhcpv4') in (None, 'server') and uci.get('dhcp.lan.ignore', '0') in (None, '0') and uci.get('dhcp.wan.ignore') == '1' and services.get('dnsmasq', {}).get('running') is True)
    check('common', 'servicehost_dhcp_reservation', (uci.get('dhcp.codex_servicevm.mac') or '').lower() == '02:00:00:00:30:01' and uci.get('dhcp.codex_servicevm.ip') == '10.10.20.112')
    leases = ow.get('leases_servicevm', [])
    check('common', 'servicehost_observed_lease', len(leases) == 1 and leases[0].get('address') == '10.10.20.112', 'DHCP lease evidence only; no ping or SSH performed', skip=not leases)
    check('common', 'initial_ipv4_only', uci.get('network.wan6.disabled') == '1' and uci.get('network.lan.delegate') == '0' and
          uci.get('network.lan.ip6assign') is None and wan6.get('up') is not True and all(uci.get('dhcp.lan.' + key) == 'disabled' for key in ('dhcpv6', 'ra', 'ndp')))
    prefix = 'firewall.codex_lan_ipv6_block'
    check('common', 'lan_ipv6_forward_block', uci.get(prefix) == 'rule' and uci.get(prefix + '.src') == 'lan' and uci.get(prefix + '.dest') == 'wan' and uci.get(prefix + '.family') == 'ipv6' and uci.get(prefix + '.proto') == 'all' and uci.get(prefix + '.target') == 'REJECT' and uci.get(prefix + '.enabled') in (None, '1'))
    zones = []
    forwardings = []
    for index in range(8):
        prefix = f'firewall.@zone[{index}].'
        zones.append({key: uci.get(prefix + key) for key in ('name', 'network', 'input', 'forward', 'masq')})
        prefix = f'firewall.@forwarding[{index}].'
        forwardings.append({key: uci.get(prefix + key) for key in ('src', 'dest', 'enabled')})
    wan_zones = [zone for zone in zones if zone['name'] == 'wan']
    check('common', 'wan_nat_and_default_input', len(wan_zones) == 1 and wan_zones[0]['masq'] == '1' and wan_zones[0]['input'] == 'REJECT' and wan_zones[0]['forward'] in ('DROP', 'REJECT'))
    check('common', 'lan_to_wan_forwarding', any(rule['src'] == 'lan' and rule['dest'] == 'wan' and rule['enabled'] in (None, '1') for rule in forwardings))
    prefix = 'firewall.codex_upstream_admin'
    rule_ok = (uci.get(prefix) == 'rule' and uci.get(prefix + '.name') == 'Allow upstream HTTPS and SSH' and
               uci.get(prefix + '.src') == 'wan' and uci.get(prefix + '.src_ip') == '10.10.10.0/24' and
               uci.get(prefix + '.family') == 'ipv4' and uci.get(prefix + '.proto') == 'tcp' and
               set((uci.get(prefix + '.dest_port') or '').split()) == {'22', '443'} and
               uci.get(prefix + '.target') == 'ACCEPT' and uci.get(prefix + '.dest') is None and
               uci.get(prefix + '.enabled') in (None, '1'))
    check('common', 'restricted_upstream_router_admin_input', rule_ok, 'Only the named input exception is checked; factory IPSec forwarding exceptions are unchanged')
    check('common', 'upstream_admin_runtime_rule', runtime_admin_rule(ow.get('input_wan')))
    for name in ('uhttpd', 'dropbear', 'homeproxy-guard'):
        check('common', name + '_running', services.get(name, {}).get('running') is True)
    check('common', 'router_https_listener', bool(services.get('uhttpd', {}).get('listeners')) and
          any(item.get('kind') == 'https' and item.get('bind') == '0.0.0.0:443' for item in services.get('uhttpd', {}).get('listeners', [])))
    check('common', 'router_ssh_listener', bool(services.get('dropbear', {}).get('listeners')) and
          any(item.get('bind') in ('22', '0.0.0.0:22') for item in services.get('dropbear', {}).get('listeners', [])))
    check('common', 'guard_autostart', ow.get('guard_enabled') is True)
    check('common', 'guard_consistent_mode', (guard.get('mode') == 'DIRECT_LATCHED' and guard.get('main_node') == 'nil') or
          (guard.get('mode') == 'PROXY' and guard.get('main_node') == 'urltest'), 'Stored guard status only; internet is not tested')
    check('common', 'homeproxy_server_disabled', uci.get('homeproxy.server.enabled') in (None, '0'))
    if mode == 'offline':
        state = pve.get('uplink_state', {})
        check('offline', 'uplink_not_pending', not state or state.get('layout') == 'router-first-v2-management-vmbr2-rescue-vmbr3' and state.get('phase') == 'initial')
        check('offline', 'management_not_activated', addresses(pve, 'vmbr2') == [])
        check('offline', 'no_pve_default_route', pve.get('defaults') == [])
        check('offline', 'no_pve_nameservers', pve.get('nameservers') == [])
        check('offline', 'pve_hosts_on_rescue', pve.get('host_aliases') == {'pve': ['10.10.99.10'], 'hypervisor.example.test': ['10.10.99.10']})
        check('offline', 'proxy_remains_direct', guard.get('mode') == 'DIRECT_LATCHED' and guard.get('main_node') == 'nil' and guard.get('homeproxy_autostart') == 'disabled')
        check('offline', 'wan_not_connected', not wan_carrier and wan.get('up') is False and not wan.get('ipv4-address'), 'Uses physical ETH0 carrier and DHCP status, not virtual eth0 carrier')
        check('upstream', 'management_and_wan_acceptance', skip=True, detail='Upstream not requested; no external DNS, internet or client access test performed')
    else:
        state = pve.get('uplink_state', {})
        check('upstream', 'uplink_committed', state.get('layout') == 'router-first-v2-management-vmbr2-rescue-vmbr3' and state.get('phase') == 'committed')
        check('offline', 'offline_only_checks', skip=True, detail='Upstream mode requested')
        check('upstream', 'management_connected', management_carrier, 'No ETH2 carrier; connect the management cable' if not management_carrier else '')
        for name, condition in (
            ('management_address', addresses(pve, 'vmbr2') == [('10.10.10.10', 24)]),
            ('management_default_route', isinstance(pve.get('defaults'), list) and len(pve['defaults']) == 1 and pve['defaults'][0].get('dev') == 'vmbr2' and pve['defaults'][0].get('gateway') == '10.10.10.1'),
            ('management_nameservers', pve.get('nameservers') == ['10.10.10.1']),
            ('pve_hosts_on_management', pve.get('host_aliases') == {'pve': ['10.10.10.10'], 'hypervisor.example.test': ['10.10.10.10']})):
            check('upstream', name, condition, skip=not management_carrier, detail='SKIP until ETH2 has physical carrier' if not management_carrier else '')
        check('upstream', 'wan_connected', wan_carrier, 'No ETH0 carrier; WAN DHCP and internet checks skipped' if not wan_carrier else '')
        wan_addresses = wan.get('ipv4-address') or []
        valid_address = wan_addresses == [{'address': '10.10.10.2', 'mask': 24}]
        check('upstream', 'wan_dhcp_address', wan.get('up') is True and wan.get('device') == 'eth0' and wan.get('l3_device') == 'eth0' and valid_address, skip=not wan_carrier)
        routes = ow.get('default_routes')
        check('upstream', 'wan_default_route', isinstance(routes, list) and len(routes) == 1 and routes[0].get('dev') == 'eth0' and routes[0].get('gateway') == '10.10.10.1', skip=not wan_carrier)
        check('upstream', 'wan_received_dns', bool(ow.get('wan_dns')), 'DHCP DNS present only; no DNS query performed', skip=not wan_carrier)
        check('upstream', 'internet_and_client_services', skip=True, detail='Not tested by this read-only inventory: DNS responses, internet, client DHCP/HTTPS/SSH/UDP and VM100 shutdown independence require separate acceptance')
    sections = {group: {'status': 'FAIL' if any(row['status'] == 'FAIL' for row in rows) else 'PASS' if any(row['status'] == 'PASS' for row in rows) else 'SKIP', 'checks': rows}
                for group, rows in groups.items()}
    overall = 'FAIL' if any(section['status'] == 'FAIL' for section in sections.values()) else 'PASS'
    if mode == 'upstream' and (not management_carrier or not wan_carrier):
        overall = 'INCOMPLETE' if sections['common']['status'] != 'FAIL' else 'FAIL'
    # Deliberately report selected facts only, never command lines/raw nft/UCI.
    public_uci = {key: value for key, value in uci.items() if key.startswith(('network.', 'dhcp.')) or key.startswith('firewall.codex_upstream_admin')}
    evidence = {'pve': pve, 'openwrt': {key: ow.get(key) for key in ('ssh_session', 'lan', 'wan', 'wan6', 'default_routes', 'wan_dns', 'leases_servicevm', 'guard', 'guard_enabled', 'services', 'collection_available')}}
    # ubus status may grow new data fields. Preserve only known network facts.
    for key in ('lan', 'wan', 'wan6'):
        status = evidence['openwrt'][key]
        evidence['openwrt'][key] = {field: status[field] for field in ('up', 'pending', 'device', 'l3_device', 'ipv4-address', 'route', 'dns-server') if isinstance(status, dict) and field in status}
    evidence['openwrt']['selected_config'] = public_uci
    return {'schema': SCHEMA, 'mode': mode, 'read_only': True, 'external_network_probes': False,
            'overall': overall, 'internet_status': 'NOT_TESTED', 'sections': sections, 'evidence': evidence,
            'limitations': ['PASS means configuration/status checks passed; it does not claim internet connectivity or application access.']}


def collect(ssh_config, timeout, mode='offline'):
    pve_alias, ow_alias = ('pve', 'openwrt100') if mode == 'offline' else ('pve-uplink', 'openwrt-wan')
    try:
        pve = json.loads(ssh_run(pve_alias, 'python3 -', PVE_SCRIPT, ssh_config, timeout))
    except ValueError:
        raise CollectionError('invalid PVE inventory JSON') from None
    if not isinstance(pve, dict) or any(not isinstance(pve.get(key), dict) for key in ('links', 'vms', 'uplink_state')) or any(not isinstance(value, dict) for value in pve.get('links', {}).values()) or any(not isinstance(value, dict) for value in pve.get('vms', {}).values()):
        raise CollectionError('invalid PVE inventory schema')
    queries = openwrt_queries()
    raw = ssh_run(ow_alias, 'sh -s', openwrt_script(queries), ssh_config, timeout)
    return pve, summarize_openwrt(parse_records(raw, queries))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=('offline', 'upstream'), default='offline')
    parser.add_argument('--ssh-config', type=Path, default=BASE / 'outputs/pve-access.conf')
    parser.add_argument('--timeout', type=int, default=60)
    args = parser.parse_args()
    if not 10 <= args.timeout <= 180:
        parser.error('--timeout must be between 10 and 180 seconds')
    try:
        pve, ow = collect(args.ssh_config, args.timeout, args.mode)
        report = assess(pve, ow, args.mode)
    except CollectionError as error:
        report = {'schema': SCHEMA, 'mode': args.mode, 'read_only': True, 'external_network_probes': False,
                  'overall': 'COLLECTION_FAILED', 'internet_status': 'NOT_TESTED', 'error': str(error)}
    report['checked_utc'] = datetime.now(timezone.utc).isoformat()
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report['overall'] == 'PASS' else 2


if __name__ == '__main__':
    raise SystemExit(main())
