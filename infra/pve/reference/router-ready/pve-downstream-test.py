#!/usr/bin/env python3
"""Ubuntu ETH1 test, isolated from the host Wi-Fi route and resolver.

Only eth-test0 is moved. No PVE/guest configuration or system clock is changed.
Dry-run is read-only. SIGKILL/power loss require --recover using the saved receipt.
"""
import argparse
import base64
import errno
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import shlex
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

INTERFACE = 'eth-test0'
MANAGEMENT = '10.10.10.10'
EXPECTED_MAC = '02:00:00:00:20:01'
GATEWAY = '10.10.20.1'
NETWORK = ipaddress.ip_network('10.10.20.0/24')
RUNROOT = Path('/run')
NM_SERVICE = 'org.freedesktop.NetworkManager'
NM_DEVICE = 'org.freedesktop.NetworkManager.Device'
NM_SETTINGS_CONNECTION = 'org.freedesktop.NetworkManager.Settings.Connection'
GENERATED_PROFILE_FIELDS = ('connection.id', 'connection.uuid', 'connection.type', 'connection.interface-name',
                            'ipv4.method', 'ipv4.addresses', 'ipv4.routes', 'ipv4.gateway', 'ipv4.dns',
                            'ipv4.routing-rules', 'ipv6.method', 'ipv6.addresses', 'ipv6.routes',
                            'ipv6.gateway', 'ipv6.dns', 'ipv6.routing-rules')
SYSCTLS = ('disable_ipv6', 'accept_ra', 'autoconf')
PHASES = ('baseline', 'vless', 'anytls', 'hysteria2', 'group', 'fault-wait', 'direct', 'recovered')
REQUEST_LIMIT = 512
RESPONSE_LIMIT = 65536
NTP_CODE = r'''import json,socket,struct,time
peer=('162.159.200.1',123)
started=time.time(); now=started+2208988800
stamp=struct.pack('!II',int(now),int((now%1)*(1<<32)))
packet=bytes([0x23])+bytes(39)+stamp
with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
 s.settimeout(4); s.connect(peer); local=s.getsockname(); s.send(packet); reply=s.recv(512)
if len(reply)<48 or reply[0]&7!=4 or reply[0]>>6==3 or not 1<=reply[1]<=15 or reply[24:32]!=stamp:
 raise SystemExit('invalid NTP response')
print(json.dumps({'endpoint':'162.159.200.1:123','source_address':local[0],'source_port':local[1],'sent_unix':started,'received_unix':time.time(),'transmit_nonce':stamp.hex(),'response_bytes':len(reply),'stratum':reply[1],'clock_changed':False}))
'''
TCP_CODE = r'''import json,socket,sys,time
peer=(sys.argv[1],int(sys.argv[2])); started=time.time()
with socket.create_connection(peer,timeout=3) as s:
 local=s.getsockname()
print(json.dumps({'target':peer[0],'port':peer[1],'source_address':local[0],'source_port':local[1],'connected':True,'unix':started,'latency_seconds':time.time()-started}))
'''


class Refusal(Exception):
    pass


class Interrupted(Refusal):
    pass


def request_decode(data):
    if len(data) > REQUEST_LIMIT or not data.endswith(b'\n') or b'\n' in data[:-1]:
        raise Refusal('One newline-terminated request of at most 512 bytes is required.')
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Duplicate request field.')
            result[key] = value
        return result
    try:
        value = json.loads(data, object_pairs_hook=unique_pairs)
    except (ValueError, UnicodeError) as error:
        raise Refusal('Invalid control JSON.') from error
    if not isinstance(value, dict):
        raise Refusal('Control request must be an object.')
    if value == {'action': 'finish'}:
        return value
    if (set(value) == {'action', 'phase'} and value['action'] == 'probe'
        and isinstance(value['phase'], str) and value['phase'] in PHASES):
        return value
    raise Refusal('Only finish or a probe with a fixed phase is allowed.')


def receive_line(connection, limit):
    data = b''
    while not data.endswith(b'\n'):
        part = connection.recv(min(4096, limit + 1 - len(data)))
        if not part:
            raise Refusal('Control peer closed before a complete message.')
        data += part
        if len(data) > limit or b'\n' in data[:-1]:
            raise Refusal('Oversized or multiple control messages.')
    return data


class ControlServer:
    """Filesystem permissions plus kernel peer credentials; no executable payloads."""
    def __init__(self, directory, uid):
        self.directory, self.uid = Path(directory), uid
        self.path = self.directory / 'control.sock'
        self.socket = None
        try:
            self.directory.chmod(0o711)  # root owns it; callers may traverse, never write/list
            self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.socket.bind(str(self.path))
            os.chmod(self.path, 0o600)
            os.chown(self.path, uid, -1)
            self.socket.listen(4)
            self.socket.settimeout(1)
        except BaseException:
            self.close()
            raise

    @staticmethod
    def reply(connection, result):
        try:
            connection.sendall(json.dumps(result, separators=(',', ':')).encode() + b'\n')
        except OSError:
            pass  # A disconnected requester cannot discard the saved probe evidence.
        finally:
            connection.close()

    def accept(self):
        try:
            connection, _ = self.socket.accept()
        except socket.timeout:
            return None
        connection.settimeout(1)
        try:
            _, uid, _ = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')))
            if uid not in (0, self.uid):
                raise Refusal('Control peer UID is not authorized.')
            request = request_decode(receive_line(connection, REQUEST_LIMIT))
        except (Refusal, OSError, struct.error) as error:
            self.reply(connection, {'accepted': False, 'error': str(error)[:300]})
            return None
        return connection, request

    def close(self):
        if self.socket:
            self.socket.close()
            self.socket = None


def control_cleanup(record):
    if not record:
        return
    directory, path = Path(record['directory']), Path(record['socket'])
    if (directory.parent != RUNROOT or not re.fullmatch(r'pve-downstream-control-[A-Za-z0-9_-]+', directory.name)
        or path != directory / 'control.sock'):
        raise Refusal('Control cleanup path identity differs.')
    if not directory.exists():
        return
    metadata = directory.lstat()
    if stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o711:
        raise Refusal('Control directory identity differs; kept for inspection.')
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        pass
    else:
        if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid != record['uid'] or stat.S_IMODE(metadata.st_mode) != 0o600:
            raise Refusal('Control socket identity differs; kept for inspection.')
        path.unlink()
    directory.rmdir()


def control_request(path, request):
    path = Path(path).absolute()
    directory = path.parent
    if (directory.parent != RUNROOT or not re.fullmatch(r'pve-downstream-control-[A-Za-z0-9_-]+', directory.name)
        or path.name != 'control.sock'):
        raise Refusal('Use the printed /run control socket path.')
    parent, metadata = directory.lstat(), path.lstat()
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or stat.S_IMODE(parent.st_mode) != 0o711
        or not stat.S_ISSOCK(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600
        or os.geteuid() not in (0, metadata.st_uid)):
        raise Refusal('Control socket ownership/permissions differ.')
    encoded = json.dumps(request, separators=(',', ':')).encode() + b'\n'
    request_decode(encoded)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(90)
        connection.connect(str(path))
        _, uid, _ = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')))
        if uid != 0:
            raise Refusal('Control server is not root.')
        connection.sendall(encoded)
        return json.loads(receive_line(connection, RESPONSE_LIMIT))


class IO:
    def lstat(self, path):
        return Path(path).lstat()

    def run(self, argv, check=True, timeout=15):
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                                env={**os.environ, 'LC_ALL': 'C'})
        if check and result.returncode:
            raise Refusal('Command failed: ' + shlex.join(argv) + ': ' + result.stderr[:400])
        return result

    def text(self, path):
        return Path(path).read_text()

    def dns(self):
        path = Path('/etc/resolv.conf')
        target = os.readlink(path) if path.is_symlink() else None
        data = path.read_bytes()
        if len(data) > 65536:
            raise Refusal('Unexpectedly large host resolver file.')
        return {'target': target, 'mode': stat.S_IMODE(path.stat().st_mode),
                'data': base64.b64encode(data).decode()}

    def which(self, name):
        return shutil.which(name)

    def namespace_inode(self, path):
        return Path(path).stat().st_ino

    def connect(self, target, source):
        with socket.create_connection(target, timeout=3, source_address=(source, 0)):
            pass

    def popen(self, argv, log):
        return subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT,
                                start_new_session=True, env={**os.environ, 'LC_ALL': 'C'})

    def process(self, pid):
        try:
            tail = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
            command = Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')
            return {'start': tail[19], 'argv': [word.decode() for word in command if word],
                    'netns': self.namespace_inode(f'/proc/{pid}/ns/net')}
        except FileNotFoundError:
            return None

    def signal_process(self, pid, identity, signum):
        # pidfd closes the PID-reuse race between identity checking and signal.
        with_fd = os.pidfd_open(pid)
        try:
            current = self.process(pid)
            if not current or current['start'] != identity['start']:
                raise Refusal('DHCP PID identity changed; no signal sent.')
            signal.pidfd_send_signal(with_fd, signum)
        finally:
            os.close(with_fd)

    def sleep(self, seconds):
        time.sleep(seconds)

    def now(self):
        return time.monotonic()


def route_key(row):
    return {key: value for key, value in row.items() if key not in ('expires', 'cache', 'age', 'used')}


def routes_key(rows):
    return sorted(json.dumps(route_key(row), sort_keys=True) for row in rows)


def address_key(rows):
    return sorted((item['family'], item['local'], item['prefixlen'], item.get('scope'))
                  for row in rows for item in row.get('addr_info', []))


def lease_values(text):
    result = {}
    for line in text.splitlines():
        match = re.fullmatch(r'(?:new_)?([a-z_]+)=(.*)', line)
        if not match:
            continue
        key, raw = match.groups()
        if key not in ('ip_address', 'subnet_mask', 'routers', 'domain_name_servers', 'dhcp_server_identifier'):
            continue
        if key in result:
            raise Refusal('Duplicate DHCP lease field: ' + key)
        try:
            result[key] = shlex.split(raw)
        except ValueError as error:
            raise Refusal('Malformed DHCP lease value.') from error
    return {key: ' '.join(words).split() for key, words in result.items()}


def route_command(family, row, device):
    supported = {'dst', 'gateway', 'dev', 'table', 'protocol', 'scope', 'prefsrc',
                 'metric', 'flags', 'type', 'pref', 'mtu', 'advmss'}
    if set(row) - supported or row.get('dev') != device or row.get('flags', []) not in ([], ['onlink'], ['linkdown']):
        raise Refusal('Wired route cannot be restored safely: ' + json.dumps(row, sort_keys=True))
    command = ['ip', '-' + str(family), 'route', 'replace']
    if row.get('type') not in (None, 'unicast'):
        command.append(row['type'])
    command.append(row.get('dst', 'default'))
    for field, keyword in (('table', 'table'), ('gateway', 'via'), ('dev', 'dev'),
                           ('protocol', 'proto'), ('scope', 'scope'), ('prefsrc', 'src'),
                           ('metric', 'metric'), ('pref', 'pref'), ('mtu', 'mtu'), ('advmss', 'advmss')):
        if field in row:
            command.extend([keyword, str(row[field])])
    if 'onlink' in row.get('flags', []):
        command.append('onlink')
    return command


class Tester:
    def __init__(self, args, io=None):
        self.args, self.io = args, io or IO()
        self.saved = None
        self.directory = None
        self.client = None
        self.log = None
        self.control = None
        self.finish_peer = None
        self.probe_count = 0
        self.deadline = None
        self.preserve_baseline = None

    def run(self, argv, **kwargs):
        guarded = (self.preserve_baseline is not None
                   and (argv[:3] == ['nmcli', 'device', 'set'] or argv[0] == 'sysctl'
                        or (argv[0] == 'ip' and any(word in argv for word in ('set', 'add', 'append', 'flush', 'replace', 'delete')))))
        if guarded:
            self.host_guard()
        result = self.io.run(argv, **kwargs)
        if guarded:
            self.host_guard()
        return result

    def json(self, argv):
        return json.loads(self.run(argv).stdout)

    def ns(self, command, **kwargs):
        return self.run(['ip', 'netns', 'exec', self.saved['namespace'], *command], **kwargs)

    def routes(self, family):
        return self.json(['ip', '-j', '-' + str(family), 'route', 'show', 'table', 'all'])

    def link(self, device, namespace=None):
        command = ['ip'] + (['-n', namespace] if namespace else []) + ['-j', '-d', 'link', 'show', 'dev', device]
        result = self.run(command, check=False)
        rows = json.loads(result.stdout) if result.returncode == 0 else []
        return rows[0] if len(rows) == 1 else None

    def carrier(self, device=INTERFACE):
        # Linux carrier_show returns -EINVAL when netif_running is false.
        # Administrative DOWN therefore gives no evidence of physical unplug.
        link = self.link(device)
        if not link or 'UP' not in link.get('flags', []):
            return None
        try:
            value = self.io.text(f'/sys/class/net/{device}/carrier').strip()
        except OSError as error:
            current = self.link(device)
            if error.errno == errno.EINVAL and current and 'UP' not in current.get('flags', []):
                return None
            raise Refusal('Cannot read actual Ethernet carrier: ' + str(error)) from error
        if value not in ('0', '1'):
            raise Refusal('Unexpected Ethernet carrier value.')
        return value

    def restore_checkpoint(self, step):
        self.saved['restore_step'] = step
        if self.directory:
            self.persist()

    def nm(self, device):
        fields = ('GENERAL.TYPE', 'GENERAL.NM-MANAGED', 'GENERAL.CON-UUID', 'GENERAL.DBUS-PATH', 'GENERAL.STATE')
        values = self.run(['nmcli', '-g', ','.join(fields), 'device', 'show', device]).stdout.splitlines()
        if len(values) != len(fields) or values[1] not in ('yes', 'no'):
            raise Refusal('Cannot capture precise NetworkManager device state.')
        path = values[3]
        if not re.fullmatch(r'/org/freedesktop/NetworkManager/Devices/[0-9]+', path):
            raise Refusal('Unexpected NetworkManager D-Bus path.')
        auto = self.run(['busctl', 'get-property', NM_SERVICE, path, NM_DEVICE, 'Autoconnect']).stdout.strip()
        if auto not in ('b true', 'b false'):
            raise Refusal('Cannot capture NetworkManager Autoconnect.')
        return {'type': values[0], 'managed': values[1], 'connection_uuid': values[2],
                'dbus_path': path, 'state': values[4], 'autoconnect': auto == 'b true'}

    def preflight(self):
        if self.args.interface != INTERFACE or self.args.management_ip != MANAGEMENT or not self.args.confirm_eth1:
            raise Refusal('Require --interface eth-test0 --management-ip 10.10.10.10 --confirm-eth1 after moving only the cable to ETH1.')
        binaries = {name: self.io.which(name) for name in ('ip', 'nmcli', 'busctl', 'dhcpcd', 'dig', 'curl', 'python3', 'sysctl')}
        if any(not value for value in binaries.values()):
            raise Refusal('Missing required tool: ' + ', '.join(name for name, value in binaries.items() if not value))
        if not re.search(r'\bdhcpcd 10\.3\.0\b', self.run(['dhcpcd', '--version']).stdout):
            raise Refusal('This helper requires the locally verified dhcpcd 10.3.0.')
        # The local terminal's namespace is authenticated below by both known physical
        # interfaces, NetworkManager state, and the independent Wi-Fi management path.
        # PID 1's namespace can be unreadable to a non-root dry-run (ptrace policy).
        host_namespace_inode = self.io.namespace_inode('/proc/self/ns/net')
        link = self.link(INTERFACE)
        if not link or link.get('link_type') != 'ether' or link.get('master') or link.get('linkinfo'):
            raise Refusal('Expected an unenslaved physical Ethernet interface.')
        if link.get('address', '').lower() != EXPECTED_MAC or 'UP' not in link.get('flags', []):
            raise Refusal('Wired MAC or initial link state differs.')
        carrier = self.carrier()
        waiting = bool(getattr(self.args, 'wait_link', 0))
        if waiting and (not getattr(self.args, 'session', False) or carrier != '0'):
            raise Refusal('--wait-link requires session mode and the cable initially unplugged.')
        if not waiting and carrier != '1':
            raise Refusal('ETH1 cable has no carrier.')
        nm = self.nm(INTERFACE)
        if nm['type'] != 'ethernet' or nm['connection_uuid'] not in ('', '--'):
            raise Refusal('An active wired NM connection requires separate handling; no changes made.')
        route = self.json(['ip', '-j', '-4', 'route', 'get', MANAGEMENT])
        if len(route) != 1 or route[0].get('dev') == INTERFACE:
            raise Refusal('PVE management must use the existing Wi-Fi route.')
        wifi = route[0].get('dev', '')
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,15}', wifi) or self.nm(wifi)['type'] != 'wifi':
            raise Refusal('Management route is not a NetworkManager Wi-Fi device.')
        source = route[0].get('prefsrc') or route[0].get('src')
        if not source or ipaddress.ip_address(source) not in ipaddress.ip_network('10.10.10.0/24'):
            raise Refusal('Expected a Wi-Fi source in 10.10.10.0/24.')
        for port in (22, 8006):
            self.io.connect((MANAGEMENT, port), source)
        addresses = self.json(['ip', '-j', 'addr', 'show', 'dev', INTERFACE])
        v4 = [item for row in addresses for item in row.get('addr_info', []) if item['family'] == 'inet']
        if len(v4) != 1 or (v4[0]['local'], v4[0]['prefixlen']) != ('10.10.99.55', 24):
            raise Refusal('Expected the original 10.10.99.55/24 wired rescue address.')
        for row in addresses:
            for item in row.get('addr_info', []):
                if item.get('peer') or item.get('dynamic') or item.get('valid_life_time') not in (None, 'forever', 4294967295):
                    raise Refusal('Only stable wired addresses can be restored exactly.')
        routes = {str(family): self.routes(family) for family in (4, 6)}
        for family in (4, 6):
            for row in routes[str(family)]:
                if row.get('dev') == INTERFACE:
                    route_command(family, row, INTERFACE)
        return {'schema': 1, 'interface': INTERFACE, 'management_ip': MANAGEMENT,
                'link': link, 'nm': nm, 'addresses': addresses, 'routes': routes,
                'dns': self.io.dns(), 'wifi': {'interface': wifi, 'source': source},
                'sysctls': {key: self.io.text(f'/proc/sys/net/ipv6/conf/{INTERFACE}/{key}').strip() for key in SYSCTLS},
                'boot_id': self.io.text('/proc/sys/kernel/random/boot_id').strip(),
                'host_netns_inode': host_namespace_inode,
                'binaries': binaries, 'phase': 'PREFLIGHT', 'dhcp': None,
                'initial_carrier': carrier, 'require_unplug_for_nm_restore': waiting}

    def persist(self):
        path = self.directory / 'snapshot.json'
        temp = self.directory / 'snapshot.new'
        with open(temp, 'w') as stream:
            os.chmod(temp, 0o600)
            json.dump(self.saved, stream, indent=2)
            stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
        os.replace(temp, path)

    def host_guard(self):
        baseline = self.preserve_baseline or self.saved
        if self.io.dns() != baseline['dns']:
            raise Refusal('Host resolver changed; test stopped.')
        for family in (4, 6):
            before = [row for row in baseline['routes'][str(family)] if row.get('dev') != INTERFACE]
            after = [row for row in self.routes(family) if row.get('dev') != INTERFACE]
            if routes_key(before) != routes_key(after):
                raise Refusal('Host routes outside the test Ethernet device changed.')
        if self.preserve_baseline is not None:
            for family in (4, 6):
                rules = self.json(['ip', '-j', '-' + str(family), 'rule', 'show'])
                if routes_key(rules) != routes_key(baseline['rules'][str(family)]):
                    raise Refusal('Current host policy rules changed during dedicated recovery.')
            wifi = baseline['wifi']['interface']
            if (self.nm(wifi) != baseline['wifi']['nm']
                or self.link(wifi) != baseline['wifi']['link']
                or address_key(self.json(['ip', '-j', 'addr', 'show', 'dev', wifi])) != address_key(baseline['wifi']['addresses'])):
                raise Refusal('Current Wi-Fi state changed during dedicated recovery.')

    def recovery_expected_routes(self, family):
        original = self.saved['routes'][str(family)]
        if self.preserve_baseline is None:
            return original
        return ([row for row in original if row.get('dev') == INTERFACE]
                + [row for row in self.preserve_baseline['routes'][str(family)] if row.get('dev') != INTERFACE])

    def restore_missing_wired_multicast(self):
        """Only the observed original local kernel route; never replace another NIC's route."""
        if self.preserve_baseline is None:
            return
        original = {'type': 'multicast', 'dst': 'ff00::/8', 'dev': INTERFACE, 'table': 'local',
                    'protocol': 'kernel', 'metric': 256, 'flags': ['linkdown'], 'pref': 'medium'}
        if original not in self.saved['routes']['6']:
            return
        current = self.routes(6)
        if original in current:
            return
        if any(row.get('dev') == INTERFACE and row.get('dst') == 'ff00::/8' for row in current):
            raise Refusal('Original wired multicast route conflicts with current wired state; no route replaced.')
        self.host_guard()
        command = route_command(6, original, INTERFACE)
        # add uses EXCL and rejects a same-prefix/metric route on another NIC;
        # append creates the distinct-device entry without REPLACE or deletion.
        command[3] = 'append'
        self.run(command)
        self.host_guard()
        if original not in self.routes(6):
            raise Refusal('Exact original wired multicast route was not restored; snapshot kept.')

    def certify_generated_wired_nm(self, current):
        """Preserve-host cleanup may certify runtime bookkeeping, never arbitrary profiles."""
        original = self.saved['nm']
        if (self.preserve_baseline is None or original['connection_uuid'] not in ('', '--')
            or original['state'].split()[0] not in ('20', '30') or original['type'] != 'ethernet'
            or original['managed'] != 'yes' or not original['autoconnect']
            or current['type'] != 'ethernet' or current['managed'] != 'yes' or not current['autoconnect']
            or current['state'].split()[0] != '100' or self.carrier() != '0'
            or address_key(self.saved['addresses']) != [('inet', '10.10.99.55', 24, 'global')]):
            raise Refusal('Original NetworkManager state differs; generated-profile exception does not apply.')
        link = self.link(INTERFACE)
        if not link or link.get('address', '').lower() != EXPECTED_MAC:
            raise Refusal('Generated wired profile physical device identity differs.')
        uuid = current['connection_uuid']
        if not re.fullmatch(r'[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}', uuid):
            raise Refusal('Generated wired UUID has invalid syntax.')
        active_path = self.run(['nmcli', '-g', 'GENERAL.CON-PATH', 'device', 'show', INTERFACE]).stdout.strip()
        if not re.fullmatch(r'/org/freedesktop/NetworkManager/ActiveConnection/[0-9]+', active_path):
            raise Refusal('Generated wired active object is not uniquely identified.')
        lookup = ['busctl', 'call', NM_SERVICE, '/org/freedesktop/NetworkManager/Settings',
                  'org.freedesktop.NetworkManager.Settings', 'GetConnectionByUuid', 's', uuid]
        object_value = self.run(lookup).stdout.strip()
        match = re.fullmatch(r'o "(/org/freedesktop/NetworkManager/Settings/[0-9]+)"', object_value)
        if not match:
            raise Refusal('Generated wired UUID does not identify a settings object.')
        path = match[1]
        active_connection = ['busctl', 'get-property', NM_SERVICE, active_path,
                             'org.freedesktop.NetworkManager.Connection.Active', 'Connection']
        if self.run(active_connection).stdout.strip() != object_value:
            raise Refusal('Generated wired active and settings objects do not match.')
        flags = self.run(['busctl', 'get-property', NM_SERVICE, path, NM_SETTINGS_CONNECTION, 'Flags']).stdout.strip()
        filename = self.run(['busctl', 'get-property', NM_SERVICE, path, NM_SETTINGS_CONNECTION, 'Filename']).stdout.strip()
        runtime_file = f'/run/NetworkManager/system-connections/{INTERFACE}.nmconnection'
        if flags != 'u 15' or filename not in ('s ""', f's "{runtime_file}"'):
            raise Refusal('Wired profile is not unsaved/generated/volatile/external or has a persistent/foreign file.')
        if filename != 's ""':
            for parent in ('/run', '/run/NetworkManager', '/run/NetworkManager/system-connections'):
                metadata = self.io.lstat(parent)
                if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o022:
                    raise Refusal('Generated wired runtime profile parent ownership/type differs.')
            metadata = self.io.lstat(runtime_file)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600:
                raise Refusal('Generated wired runtime profile is not a root-owned private regular file.')
        rows = self.run(['nmcli', '-g', ','.join(GENERATED_PROFILE_FIELDS), 'connection', 'show', 'uuid', uuid]).stdout.splitlines()
        if len(rows) != len(GENERATED_PROFILE_FIELDS):
            raise Refusal('Cannot read all fixed generated wired profile fields.')
        values = dict(zip(GENERATED_PROFILE_FIELDS, rows))
        required = {'connection.id': INTERFACE, 'connection.uuid': uuid, 'connection.type': '802-3-ethernet',
                    'connection.interface-name': INTERFACE, 'ipv4.method': 'manual',
                    'ipv4.addresses': '10.10.99.55/24', 'ipv6.method': 'ignore'}
        if (any(values[key] != value for key, value in required.items())
            or any(values[key] not in ('', '--') for key in GENERATED_PROFILE_FIELDS if key not in required)):
            raise Refusal('Generated wired profile differs from the original manual address or contains foreign IP data.')
        self.host_guard()
        if (self.nm(INTERFACE) != current or self.carrier() != '0'
            or address_key(self.json(['ip', '-j', 'addr', 'show', 'dev', INTERFACE])) != address_key(self.saved['addresses'])
            or any(routes_key(self.routes(family)) != routes_key(self.recovery_expected_routes(family)) for family in (4, 6))
            or any(self.io.text(f'/proc/sys/net/ipv6/conf/{INTERFACE}/{key}').strip() != value
                   for key, value in self.saved['sysctls'].items())):
            raise Refusal('Generated profile identity or exact restored network changed during certification.')
        if (self.run(['nmcli', '-g', 'GENERAL.CON-PATH', 'device', 'show', INTERFACE]).stdout.strip() != active_path
            or self.run(lookup).stdout.strip() != object_value
            or self.run(active_connection).stdout.strip() != object_value
            or self.run(['busctl', 'get-property', NM_SERVICE, path, NM_SETTINGS_CONNECTION, 'Flags']).stdout.strip() != flags
            or self.run(['busctl', 'get-property', NM_SERVICE, path, NM_SETTINGS_CONNECTION, 'Filename']).stdout.strip() != filename
            or self.run(['nmcli', '-g', ','.join(GENERATED_PROFILE_FIELDS), 'connection', 'show', 'uuid', uuid]).stdout.splitlines() != rows):
            raise Refusal('Generated wired profile metadata changed during certification.')
        self.host_guard()
        self.saved['preserve_recovery']['nm_runtime_equivalence'] = {
            'network_configuration_restored': True, 'runtime_identity_restored': False,
            'original': original, 'current': current, 'flags': 15,
            'active_path': active_path, 'settings_path': path,
            'volatile_runtime_file': runtime_file if filename != 's ""' else None,
            'persistent_backing_file': None,
            'profile': values, 'profile_modified': False,
            'explanation': 'NetworkManager generated an in-memory external record for the restored manual wired address.'}

    def prepare(self):
        namespaces = self.run(['ip', 'netns', 'list']).stdout.splitlines()
        if any(line.split()[0] == self.saved['namespace'] for line in namespaces if line.split()) or self.link(self.saved['test_device']):
            raise Refusal('Unique test namespace/device name is already in use.')
        self.run(['nmcli', 'device', 'set', INTERFACE, 'autoconnect', 'no'])
        self.run(['nmcli', 'device', 'set', INTERFACE, 'managed', 'no'])
        self.run(['ip', 'netns', 'add', self.saved['namespace']])
        self.saved['namespace_inode'] = self.io.namespace_inode('/var/run/netns/' + self.saved['namespace'])
        self.persist()
        self.run(['ip', 'link', 'set', 'dev', INTERFACE, 'down'])
        self.run(['ip', 'link', 'set', 'dev', INTERFACE, 'netns', self.saved['namespace']])
        self.run(['ip', '-n', self.saved['namespace'], 'link', 'set', 'dev', INTERFACE, 'name', self.saved['test_device']])
        self.ns(['sysctl', '-q', '-w', 'net.ipv6.conf.' + self.saved['test_device'] + '.disable_ipv6=1'])
        self.run(['ip', '-n', self.saved['namespace'], '-4', 'addr', 'flush', 'dev', self.saved['test_device']])
        self.run(['ip', '-n', self.saved['namespace'], 'link', 'set', 'dev', 'lo', 'up'])
        self.run(['ip', '-n', self.saved['namespace'], 'link', 'set', 'dev', self.saved['test_device'], 'up'])
        self.host_guard()
        self.saved['phase'] = 'ISOLATED'; self.persist()

    def dhcp_start(self):
        config = self.directory / 'dhcpcd.conf'
        config.write_text('noipv6\nnoipv4ll\nreboot 0\nscript /bin/true\noption routers,domain_name_servers\nrequire dhcp_server_identifier\n')
        config.chmod(0o600)
        self.log = open(self.directory / 'dhcpcd.log', 'ab', buffering=0)
        os.chmod(self.directory / 'dhcpcd.log', 0o600)
        command = ['ip', 'netns', 'exec', self.saved['namespace'], self.saved['binaries']['dhcpcd'],
                   '-4', '-B', '-L', '--nodev', '-c', '/bin/true', '-f', str(config), self.saved['test_device']]
        self.client = self.io.popen(command, self.log)
        identity = self.io.process(self.client.pid)
        if identity is None:
            raise Refusal('DHCP process exited before identity was captured.')
        self.saved['dhcp'] = {'pid': self.client.pid, 'start': identity['start'], 'config': str(config)}
        self.persist()
        deadline = self.io.now() + 3
        while self.io.now() < deadline:
            current = self.io.process(self.client.pid)
            if current is None or self.client.poll() is not None:
                raise Refusal('DHCP process exited during namespace/exec startup.')
            if current['start'] != identity['start']:
                raise Refusal('DHCP PID identity changed during startup.')
            if (current['netns'] == self.saved['namespace_inode'] and str(config) in current['argv']
                and self.saved['test_device'] in current['argv']
                and current['argv'] and Path(current['argv'][0]).name == 'dhcpcd'):
                self.saved['dhcp']['ready'] = True
                self.persist()
                return
            self.io.sleep(0.1)
        raise Refusal('DHCP client did not enter its expected namespace/exec identity.')

    def validate_lease(self, lease, addresses, routes):
        values = lease_values(lease)
        ipv4 = [item for row in addresses for item in row.get('addr_info', []) if item['family'] == 'inet']
        if len(ipv4) != 1:
            raise Refusal('Expected one DHCP IPv4 address.')
        item = ipv4[0]
        address = ipaddress.ip_address(item['local'])
        if address not in NETWORK or address in (NETWORK.network_address, NETWORK.broadcast_address, ipaddress.ip_address(GATEWAY)) or item['prefixlen'] != 24:
            raise Refusal('DHCP address is outside the planned 10.10.20.0/24 client range.')
        expected = {'ip_address': [str(address)], 'subnet_mask': ['255.255.255.0'],
                    'routers': [GATEWAY], 'domain_name_servers': [GATEWAY], 'dhcp_server_identifier': [GATEWAY]}
        if values != expected:
            raise Refusal('DHCP address/gateway/DNS/server differs from the planned OpenWrt LAN.')
        if len(routes) != 1 or routes[0].get('gateway') != GATEWAY or routes[0].get('dev') != self.saved['test_device']:
            raise Refusal('Namespace default route differs.')
        return {'address': str(address), 'prefix': 24, 'gateway': GATEWAY, 'dns': [GATEWAY], 'server': GATEWAY}

    def dhcp_acquire(self):
        self.dhcp_start()
        deadline = self.io.now() + 45
        while self.io.now() < deadline:
            if self.client.poll() is not None:
                raise Refusal('Foreground DHCP process exited.')
            self.host_guard()
            rows = json.loads(self.ns(['ip', '-j', '-4', 'addr', 'show', 'dev', self.saved['test_device']]).stdout)
            if any(row.get('addr_info') for row in rows):
                break
            self.io.sleep(1)
        else:
            raise Refusal('DHCP timed out after 45 seconds.')
        lease = self.ns(['dhcpcd', '-4', '-U', self.saved['test_device']]).stdout
        routes = json.loads(self.ns(['ip', '-j', '-4', 'route', 'show', 'default']).stdout)
        return self.validate_lease(lease, rows, routes)

    def tests(self):
        result = {'dhcp': self.dhcp_acquire()}
        output = self.ns(['dig', '+time=3', '+tries=1', '@' + GATEWAY, 'www.cloudflare.com', 'A', '+short']).stdout
        answers = []
        for word in output.splitlines():
            try:
                address = ipaddress.ip_address(word.strip())
            except ValueError:
                continue
            if address.version == 4 and address.is_global:
                answers.append(str(address))
        if not answers:
            raise Refusal('No public IPv4 DNS answer from OpenWrt.')
        result['dns_answers'] = answers
        self.ns(['curl', '--noproxy', '*', '--proxy', '', '--fail', '--silent', '--show-error',
                 '--connect-timeout', '5', '--max-time', '12', '--max-filesize', '65536',
                 '--resolve', 'www.cloudflare.com:443:' + answers[0],
                 '--output', str(self.directory / 'https-trace.txt'), 'https://www.cloudflare.com/cdn-cgi/trace'], timeout=15)
        result['https_get_succeeded'] = True
        result['ntp_udp'] = json.loads(self.ns(['python3', '-c', NTP_CODE], timeout=7).stdout)
        result['udp_proxy_proven'] = False
        self.host_guard()
        return result

    def session_guard(self):
        if self.deadline is not None and self.io.now() >= self.deadline:
            raise Interrupted('Session deadline reached; restore the Ethernet device.')
        self.host_guard()
        if self.io.namespace_inode('/var/run/netns/' + self.saved['namespace']) != self.saved['namespace_inode']:
            raise Refusal('Session namespace identity changed.')
        link = self.link(self.saved['test_device'], self.saved['namespace'])
        if not link or link.get('address', '').lower() != EXPECTED_MAC or 'UP' not in link.get('flags', []):
            raise Refusal('Session Ethernet identity or administrative UP state changed.')
        record = self.saved['dhcp']
        identity = self.io.process(record['pid'])
        if (not identity or self.client.poll() is not None or identity['start'] != record['start']
            or identity['netns'] != self.saved['namespace_inode'] or record['config'] not in identity['argv']
            or self.saved['test_device'] not in identity['argv']
            or not identity['argv'] or Path(identity['argv'][0]).name != 'dhcpcd'):
            raise Refusal('Session DHCP process identity changed or exited.')
        rows = self.json(['ip', '-n', self.saved['namespace'], '-j', 'addr', 'show', 'dev', self.saved['test_device']])
        addresses = [(item['local'], item['prefixlen']) for row in rows for item in row.get('addr_info', []) if item['family'] == 'inet']
        if addresses != [(self.saved['session_lease']['address'], 24)]:
            raise Refusal('Session client address changed; stop before attributing new traffic.')
        routes = json.loads(self.ns(['ip', '-j', '-4', 'route', 'show', 'default']).stdout)
        if len(routes) != 1 or routes[0].get('gateway') != GATEWAY or routes[0].get('dev') != self.saved['test_device']:
            raise Refusal('Session default gateway identity changed.')

    def session_probe(self, phase):
        if phase not in PHASES:
            raise Refusal('Unknown fixed probe phase.')
        self.probe_count += 1
        result = {'phase': phase, 'sequence': self.probe_count, 'namespace': self.saved['namespace'],
                  'client_address': self.saved['session_lease']['address'], 'started_unix': time.time(),
                  'dhcp': self.saved['session_lease'], 'udp_proxy_proven': False, 'checks': {}}
        dns_answers = []

        def check(name, callback):
            self.session_guard()  # Identity and host invariants never become soft probe failures.
            item = {'started_unix': time.time()}
            try:
                item.update(ok=True, result=callback())
            except Interrupted:
                raise
            except (Refusal, OSError, ValueError, subprocess.TimeoutExpired) as error:
                item.update(ok=False, error=str(error)[:500])
            self.session_guard()
            item['completed_unix'] = time.time()
            result['checks'][name] = item

        def dns(tcp):
            command = ['dig', '+time=3', '+tries=1', '@' + GATEWAY, 'www.cloudflare.com', 'A', '+short']
            if tcp:
                command.append('+tcp')
            output = self.ns(command, timeout=5).stdout
            answers = []
            for line in output.splitlines():
                try:
                    address = ipaddress.ip_address(line.strip())
                except ValueError:
                    continue
                if address.version == 4 and address.is_global:
                    answers.append(str(address))
            if not answers:
                raise Refusal('No public IPv4 DNS answer from OpenWrt.')
            dns_answers.extend(answers)
            return {'server': GATEWAY, 'transport': 'tcp' if tcp else 'udp', 'answers': answers,
                    'upstream_path_proven': False}

        check('dns_udp', lambda: dns(False))
        check('dns_tcp', lambda: dns(True))

        def trace():
            if not dns_answers:
                raise Refusal('HTTPS trace skipped: neither DNS probe returned a public IPv4.')
            path = self.directory / ('trace-%03d-%s.txt' % (self.probe_count, phase))
            self.ns(['curl', '--noproxy', '*', '--proxy', '', '--fail', '--silent', '--show-error',
                     '--connect-timeout', '5', '--max-time', '12', '--max-filesize', '65536',
                     '--resolve', 'www.cloudflare.com:443:' + dns_answers[0], '--output', str(path),
                     'https://www.cloudflare.com/cdn-cgi/trace'], timeout=15)
            path.chmod(0o600)
            text = path.read_text()
            if len(text) > 65536:
                raise Refusal('HTTPS trace body exceeded the fixed limit.')
            fields = {}
            for line in text.splitlines():
                if '=' in line:
                    key, value = line.split('=', 1)
                    if key in fields:
                        raise Refusal('Duplicate trace field.')
                    fields[key] = value
            if fields.get('h') != 'www.cloudflare.com':
                raise Refusal('Unexpected trace hostname.')
            address = ipaddress.ip_address(fields.get('ip', ''))
            if not address.is_global:
                raise Refusal('Trace did not return a public egress address.')
            return {'egress_ip': str(address), 'resolved_address': dns_answers[0], 'tls_verified': True,
                    'body_file': str(path), 'outbound_tag_proven': False}

        check('https_trace', trace)
        check('pve_tcp22', lambda: json.loads(self.ns(['python3', '-c', TCP_CODE, MANAGEMENT, '22'], timeout=5).stdout))

        def pve_https():
            code = self.ns(['curl', '--noproxy', '*', '--proxy', '', '--insecure', '--fail', '--silent', '--show-error',
                            '--connect-timeout', '3', '--max-time', '8', '--output', '/dev/null',
                            '--write-out', '%{http_code}', 'https://' + MANAGEMENT + ':8006/'], timeout=10).stdout.strip()
            if code != '200':
                raise Refusal('PVE HTTPS did not return HTTP200.')
            return {'target': MANAGEMENT, 'port': 8006, 'http_status': 200, 'tls_verified': False,
                    'purpose': 'downstream service reachability; independent management path was checked before move'}

        check('pve_https8006', pve_https)
        check('servicevm_tcp22', lambda: json.loads(self.ns(['python3', '-c', TCP_CODE, '10.10.20.112', '22'], timeout=5).stdout))
        check('ntp_udp', lambda: json.loads(self.ns(['python3', '-c', NTP_CODE], timeout=7).stdout))
        result['completed_unix'] = time.time()
        result['all_checks_passed'] = all(item['ok'] for item in result['checks'].values())
        with open(self.directory / 'probes.jsonl', 'a') as stream:
            os.chmod(self.directory / 'probes.jsonl', 0o600)
            stream.write(json.dumps(result, separators=(',', ':')) + '\n')
            stream.flush(); os.fsync(stream.fileno())
        return result

    def session(self):
        if getattr(self.args, 'wait_link', 0):
            self.saved['phase'] = 'WAITING_LINK'; self.persist()
            print(json.dumps({'event': 'WAITING_LINK', 'namespace': self.saved['namespace'],
                              'interface': INTERFACE, 'wait_seconds': self.args.wait_link,
                              'instruction': 'Connect only the Ubuntu cable to ETH1; Wi-Fi management remains active.',
                              'receipt': str(self.directory / 'snapshot.json')}), flush=True)
            deadline = min(self.deadline, self.io.now() + self.args.wait_link)
            while self.io.now() < deadline:
                self.host_guard()
                if self.io.namespace_inode('/var/run/netns/' + self.saved['namespace']) != self.saved['namespace_inode']:
                    raise Refusal('Namespace identity changed while waiting for the cable.')
                link = self.link(self.saved['test_device'], self.saved['namespace'])
                if not link or link.get('address', '').lower() != EXPECTED_MAC or 'UP' not in link.get('flags', []):
                    raise Refusal('Test Ethernet identity changed while waiting for the cable.')
                if 'LOWER_UP' in link.get('flags', []):
                    break
                self.io.sleep(1)
            else:
                raise Refusal('No ETH1 cable carrier within the bounded wait.')
        self.saved['session_lease'] = self.dhcp_acquire()
        self.saved['phase'] = 'SESSION_READY'
        raw_uid = os.environ.get('SUDO_UID', '0')
        if not re.fullmatch(r'[0-9]{1,10}', raw_uid) or int(raw_uid) >= 2**32 - 1:
            raise Refusal('Invalid SUDO_UID for session control.')
        uid = int(raw_uid)
        directory = Path(tempfile.mkdtemp(prefix='pve-downstream-control-', dir=RUNROOT))
        directory.chmod(0o711)
        self.saved['control'] = {'directory': str(directory), 'socket': str(directory / 'control.sock'), 'uid': uid}
        self.persist()
        self.control = ControlServer(directory, uid)
        self.session_guard()
        print(json.dumps({'event': 'READY', 'control_socket': str(self.control.path),
                          'receipt': str(self.directory / 'snapshot.json'), 'namespace': self.saved['namespace'],
                          'client_address': self.saved['session_lease']['address'], 'phases': PHASES,
                          'remaining_seconds': max(0, int(self.deadline - self.io.now()))}), flush=True)
        while self.io.now() < self.deadline:
            self.session_guard()
            command = self.control.accept()
            if command is None:
                continue
            peer, request = command
            if request['action'] == 'finish':
                if self.saved.get('require_unplug_for_nm_restore') and 'LOWER_UP' in self.link(self.saved['test_device'], self.saved['namespace']).get('flags', []):
                    self.control.reply(peer, {'accepted': False, 'requires_unplug': True,
                                              'error': 'Unplug the Ubuntu Ethernet cable, then request finish again; Wi-Fi management stays active.'})
                    continue
                self.finish_peer = peer  # Reply only after interface restoration is verified.
                return {'session': True, 'finished': True, 'probe_count': self.probe_count}
            try:
                result = self.session_probe(request['phase'])
            except BaseException:
                peer.close()
                raise
            self.control.reply(peer, {'accepted': True, 'probe': result})
        return {'session': True, 'timed_out': True, 'probe_count': self.probe_count}

    def stop_dhcp(self):
        record = self.saved.get('dhcp')
        if self.client:
            if self.client.poll() is None:
                self.client.terminate()
                try:
                    self.client.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.client.kill(); self.client.wait(timeout=5)
            self.client = None
        elif record:
            identity = self.io.process(record['pid'])
            if identity:
                if (identity['start'] != record['start'] or identity['netns'] != self.saved.get('namespace_inode')
                    or record['config'] not in identity['argv'] or self.saved['test_device'] not in identity['argv']
                    or not any(Path(word).name == 'dhcpcd' for word in identity['argv'])):
                    raise Refusal('Saved DHCP PID no longer identifies this test client; nothing killed.')
                self.io.signal_process(record['pid'], identity, signal.SIGTERM)
                deadline = self.io.now() + 5
                while self.io.process(record['pid']) and self.io.now() < deadline:
                    self.io.sleep(0.1)
                if self.io.process(record['pid']):
                    self.io.signal_process(record['pid'], identity, signal.SIGKILL)
                    deadline = self.io.now() + 5
                    while self.io.process(record['pid']) and self.io.now() < deadline:
                        self.io.sleep(0.1)
                    if self.io.process(record['pid']):
                        raise Refusal('Exact DHCP process did not exit after SIGKILL; snapshot kept.')
        if self.log:
            self.log.close(); self.log = None

    def restore(self):
        if self.preserve_baseline is not None:
            self.host_guard()
        self.restore_checkpoint('stop_exact_dhcp')
        self.stop_dhcp()
        if self.preserve_baseline is not None:
            self.host_guard()
        namespaces = self.run(['ip', 'netns', 'list']).stdout.splitlines()
        exists = any(line.split()[0] == self.saved['namespace'] for line in namespaces if line.split())
        if exists:
            if self.io.namespace_inode('/var/run/netns/' + self.saved['namespace']) != self.saved.get('namespace_inode'):
                raise Refusal('Namespace identity differs; no device moved or namespace deleted.')
            pids = self.run(['ip', 'netns', 'pids', self.saved['namespace']]).stdout.split()
            deadline = self.io.now() + 3
            while pids and self.io.now() < deadline:
                self.io.sleep(0.1)
                pids = self.run(['ip', 'netns', 'pids', self.saved['namespace']]).stdout.split()
            if pids:
                raise Refusal('Namespace still has processes; exact client shutdown requires inspection: ' + ' '.join(pids))
        host = self.link(INTERFACE)
        renamed_host = self.link(self.saved['test_device'])
        if renamed_host:
            if host or renamed_host.get('address', '').lower() != EXPECTED_MAC:
                raise Refusal('Host test device identity/name is ambiguous; no rename performed.')
            self.run(['ip', 'link', 'set', 'dev', self.saved['test_device'], 'name', INTERFACE])
            host = self.link(INTERFACE)
        if host is None and exists:
            device = next((name for name in (self.saved['test_device'], INTERFACE) if self.link(name, self.saved['namespace'])), None)
            if not device:
                raise Refusal('Test Ethernet device was not found; snapshot and namespace kept.')
            link = self.link(device, self.saved['namespace'])
            if link.get('address', '').lower() != EXPECTED_MAC:
                raise Refusal('Namespace Ethernet MAC differs; device kept in place.')
            self.run(['ip', '-n', self.saved['namespace'], 'link', 'set', 'dev', device, 'down'])
            self.run(['ip', '-n', self.saved['namespace'], '-4', 'addr', 'flush', 'dev', device])
            self.run(['ip', '-n', self.saved['namespace'], 'link', 'set', 'dev', device, 'netns', str(os.getpid())])
            if device != INTERFACE:
                self.run(['ip', 'link', 'set', 'dev', device, 'name', INTERFACE])
            host = self.link(INTERFACE)
        if not host or host.get('address', '').lower() != EXPECTED_MAC:
            raise Refusal('Original host Ethernet identity is not restored.')
        self.restore_checkpoint('wired_down_and_nm_inhibit')
        self.run(['ip', 'link', 'set', 'dev', INTERFACE, 'down'])
        # A device returned from another namespace can be a new NM object.
        # Keep it down while waiting for NM, then suppress autoconnection before UP.
        deadline = self.io.now() + 3
        while True:
            try:
                self.nm(INTERFACE)
                break
            except Refusal:
                if self.io.now() >= deadline:
                    raise Refusal('Returned Ethernet is not available in NetworkManager; snapshot kept.')
                self.io.sleep(0.1)
        self.run(['nmcli', 'device', 'set', INTERFACE, 'autoconnect', 'no'])
        self.run(['nmcli', 'device', 'set', INTERFACE, 'managed', 'no'])
        for key, value in self.saved['sysctls'].items():
            self.run(['sysctl', '-q', '-w', f'net.ipv6.conf.{INTERFACE}.{key}={value}'])
        self.restore_checkpoint('flush_wired_state')
        for family in (4, 6):
            self.run(['ip', '-' + str(family), 'addr', 'flush', 'dev', INTERFACE])
            self.run(['ip', '-' + str(family), 'route', 'flush', 'table', 'all', 'dev', INTERFACE])
        measured_carrier = None
        if self.saved.get('require_unplug_for_nm_restore'):
            # This authorized restoration can bring only the empty wired NIC UP.
            # NM remains inhibited; the current external network remains guarded.
            self.restore_checkpoint('verify_wired_carrier_nm_inhibited')
            self.run(['ip', 'link', 'set', 'dev', INTERFACE, 'up'])
            self.io.sleep(6)  # Bound the wait and allow Ethernet negotiation to settle.
            self.host_guard()
            measured_carrier = self.carrier()
            self.run(['ip', 'link', 'set', 'dev', INTERFACE, 'down'])
            # UP may have created automatic wired IPv6 addresses/routes. Keep the
            # device empty for NM settlement, clearing only this exact wired NIC.
            for family in (4, 6):
                self.run(['ip', '-' + str(family), 'addr', 'flush', 'dev', INTERFACE])
                self.run(['ip', '-' + str(family), 'route', 'flush', 'table', 'all', 'dev', INTERFACE])
            if measured_carrier is None:
                raise Refusal('Wired carrier remains unavailable after the guarded UP check; snapshot kept.')
        if self.saved.get('require_unplug_for_nm_restore') and measured_carrier == '0':
            # Let NM observe the returned, empty, DOWN device before adding its
            # static addresses. Otherwise enabling managed after address restore
            # can cause NM to assume those addresses as an external connection.
            # This is ordering only: final UUID/address/route checks stay exact.
            self.host_guard()
            self.restore_checkpoint('settle_empty_wired_nm')
            self.run(['nmcli', 'device', 'set', INTERFACE, 'managed', self.saved['nm']['managed']])
            deadline, consecutive = self.io.now() + 3, 0
            while True:
                # DOWN is unknown, not unplugged. A fresh physical carrier check
                # happens after the original UP state, before autoconnect restore.
                current_carrier = self.carrier()
                if current_carrier is not None and current_carrier != '0':
                    self.run(['nmcli', 'device', 'set', INTERFACE, 'autoconnect', 'no'])
                    self.run(['nmcli', 'device', 'set', INTERFACE, 'managed', 'no'])
                    break  # Restore static state, then use the existing unplug gate.
                nm = self.nm(INTERFACE)
                empty = (nm['managed'] == self.saved['nm']['managed'] and not nm['autoconnect']
                         and nm['connection_uuid'] == self.saved['nm']['connection_uuid']
                         and nm['state'].split()[0] in ('20', '30'))
                consecutive = consecutive + 1 if empty else 0
                if consecutive >= 2:
                    break
                if self.io.now() >= deadline:
                    self.run(['nmcli', 'device', 'set', INTERFACE, 'managed', 'no'])
                    raise Refusal('Returned empty Ethernet has not reached its original inactive NM state; snapshot kept.')
                self.io.sleep(0.1)
        self.restore_checkpoint('restore_wired_static_state')
        for row in self.saved['addresses']:
            for item in row.get('addr_info', []):
                command = ['ip', '-4' if item['family'] == 'inet' else '-6', 'addr', 'add',
                           f"{item['local']}/{item['prefixlen']}", 'dev', INTERFACE]
                if item.get('broadcast'):
                    command += ['broadcast', item['broadcast']]
                if item.get('scope'):
                    command += ['scope', item['scope']]
                if item.get('label') and item['label'] != INTERFACE:
                    command += ['label', item['label']]
                self.run(command)
        for family in (4, 6):
            for row in self.saved['routes'][str(family)]:
                if row.get('dev') == INTERFACE and row.get('protocol') != 'kernel':
                    self.run(route_command(family, row, INTERFACE))
        self.run(['ip', 'link', 'set', 'dev', INTERFACE, 'up' if 'UP' in self.saved['link']['flags'] else 'down'])
        self.restore_missing_wired_multicast()
        if (self.saved.get('require_unplug_for_nm_restore')
            and self.carrier() != '0'):
            # Automatic exit must not enable NM auto-default DHCP on a newly connected cable.
            # Return the NIC/static state now; leave only this wired device inhibited for recovery.
            self.run(['nmcli', 'device', 'set', INTERFACE, 'autoconnect', 'no'])
            self.run(['nmcli', 'device', 'set', INTERFACE, 'managed', 'no'])
            self.host_guard()
            if address_key(self.json(['ip', '-j', 'addr', 'show', 'dev', INTERFACE])) != address_key(self.saved['addresses']):
                raise Refusal('Returned Ethernet addresses differ while waiting for unplug.')
            for family in (4, 6):
                if routes_key(self.routes(family)) != routes_key(self.recovery_expected_routes(family)):
                    raise Refusal('Returned host routes differ while waiting for unplug.')
            self.saved['phase'] = 'RESTORE_WAITING_UNPLUG'; self.persist()
            raise Refusal('Ethernet/static routes returned; wired NM remains managed=no/autoconnect=no. Unplug the cable, then run the printed --recover command.')
        self.restore_checkpoint('restore_wired_nm_settings')
        self.run(['nmcli', 'device', 'set', INTERFACE, 'managed', self.saved['nm']['managed']])
        self.run(['nmcli', 'device', 'set', INTERFACE, 'autoconnect', 'yes' if self.saved['nm']['autoconnect'] else 'no'])
        self.io.sleep(2)
        if (self.saved.get('require_unplug_for_nm_restore')
            and self.carrier() != '0'):
            self.run(['nmcli', 'device', 'set', INTERFACE, 'autoconnect', 'no'])
            self.run(['nmcli', 'device', 'set', INTERFACE, 'managed', 'no'])
            self.restore()  # Return the fixed wired state; the earlier carrier gate leaves NM inhibited.
            raise Refusal('Cable was reconnected during restoration; keep it unplugged until --recover succeeds.')
        self.restore_checkpoint('verify_restored_wired_and_preserved_host')
        self.host_guard()
        if address_key(self.json(['ip', '-j', 'addr', 'show', 'dev', INTERFACE])) != address_key(self.saved['addresses']):
            raise Refusal('Restored Ethernet addresses differ; snapshot/namespace kept.')
        for family in (4, 6):
            if routes_key(self.routes(family)) != routes_key(self.recovery_expected_routes(family)):
                raise Refusal('Restored host routes differ; snapshot/namespace kept.')
        restored_link = self.link(INTERFACE)
        if not restored_link or ('UP' in restored_link['flags']) != ('UP' in self.saved['link']['flags']):
            raise Refusal('Original Ethernet link state differs.')
        nm = self.nm(INTERFACE)
        nm_identity_differs = any(nm[key] != self.saved['nm'][key] for key in ('managed', 'autoconnect', 'connection_uuid'))
        current_carrier = self.carrier()
        carrier_changed = current_carrier is not None and current_carrier != self.saved.get('initial_carrier', '1')
        allowable_carrier_state = (carrier_changed and nm['state'].split()[0] in ('20', '30')
                                  and self.saved['nm']['state'].split()[0] in ('20', '30'))
        nm_state_differs = nm['state'].split()[0] != self.saved['nm']['state'].split()[0] and not allowable_carrier_state
        if nm_identity_differs or nm_state_differs:
            self.certify_generated_wired_nm(nm)
        if exists:
            self.run(['ip', 'netns', 'delete', self.saved['namespace']])
        self.saved['phase'] = 'RESTORED'; self.persist()

    def recovery_command(self):
        return shlex.join(['sudo', sys.executable, str(Path(__file__).resolve()),
                           '--recover', str(self.directory / 'snapshot.json')])

    def execute(self):
        self.deadline = self.io.now() + self.args.timeout
        self.saved = self.preflight()
        if self.args.dry_run:
            return {'dry_run': True, 'preflight_passed': True, 'mutation': False,
                    'wifi_management': self.saved['wifi'], 'planned_namespace_dhcp': '10.10.20.0/24',
                    'requires_sudo_for_real_run': True}
        if os.geteuid() != 0:
            raise Refusal('Run the real test manually with sudo; dry-run needs no sudo.')
        self.directory = Path(tempfile.mkdtemp(prefix='pve-downstream-test-', dir=RUNROOT))
        self.directory.chmod(0o700)
        token = uuid.uuid4().hex[:10]
        self.saved.update(namespace='pveds-' + token, test_device='ds' + token, namespace_inode=None)
        self.persist()
        print('Recovery receipt: ' + str(self.directory / 'snapshot.json') + '\n' + self.recovery_command(), file=sys.stderr)
        failure, result = None, None
        try:
            self.prepare()
            result = self.session() if getattr(self.args, 'session', False) else self.tests()
        except BaseException as error:
            failure = error
        finally:
            for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGALRM):
                signal.signal(signum, signal.SIG_IGN)
            signal.alarm(0)
            if self.control:
                self.control.close()
            try:
                self.restore()
                control_cleanup(self.saved.get('control'))
            except BaseException as error:
                if self.saved['phase'] != 'RESTORE_WAITING_UNPLUG':
                    self.saved['phase'] = 'RESTORE_FAILED'
                self.saved['restore_error'] = str(error)
                self.persist()
                if self.finish_peer:
                    ControlServer.reply(self.finish_peer, {'accepted': True, 'restored': False, 'error': str(error),
                                                           'receipt': str(self.directory / 'snapshot.json')})
                    self.finish_peer = None
                raise Refusal('Restore requires inspection: ' + str(error) + '\nRecovery command: ' + self.recovery_command()) from error
        if failure:
            raise Refusal('Test stopped; original Ethernet restored. ' + str(failure) + '\nReceipt: ' + str(self.directory / 'snapshot.json')) from failure
        result.update(restored=True, receipt=str(self.directory / 'snapshot.json'))
        if self.finish_peer:
            ControlServer.reply(self.finish_peer, {'accepted': True, **result})
            self.finish_peer = None
        return result

    def load_receipt(self, path):
        path = Path(path).absolute()
        if path.name != 'snapshot.json' or path.parent.parent != RUNROOT or not re.fullmatch(r'pve-downstream-test-[A-Za-z0-9_-]+', path.parent.name):
            raise Refusal('Recovery requires this tool\'s private /run snapshot path.')
        for item, mode in ((path.parent, 0o700), (path, 0o600)):
            metadata = item.lstat()
            if stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != mode:
                raise Refusal('Recovery receipt ownership/permissions differ.')
        self.saved = json.loads(path.read_text()); self.directory = path.parent
        if (self.saved.get('schema') != 1 or self.saved.get('interface') != INTERFACE
            or self.saved.get('management_ip') != MANAGEMENT
            or not re.fullmatch(r'pveds-[a-f0-9]{10}', self.saved.get('namespace', ''))
            or not re.fullmatch(r'ds[a-f0-9]{10}', self.saved.get('test_device', ''))
            or self.saved.get('boot_id') != self.io.text('/proc/sys/kernel/random/boot_id').strip()
            or self.saved.get('host_netns_inode') != self.io.namespace_inode('/proc/self/ns/net')):
            raise Refusal('Recovery receipt identity or boot differs; no changes made.')
        return path

    def inspect(self, path):
        """Read fixed diagnostic fields only; no lock, persistence or network probes."""
        path = self.load_receipt(path)
        current_routes = {str(family): self.routes(family) for family in (4, 6)}
        route_diff = {}
        for family in ('4', '6'):
            before, after = self.saved['routes'][family], current_routes[family]
            route_diff[family] = {
                'all_equal': routes_key(before) == routes_key(after),
                'outside_ethernet_equal': routes_key([row for row in before if row.get('dev') != INTERFACE])
                                          == routes_key([row for row in after if row.get('dev') != INTERFACE]),
                'original': [route_key(row) for row in before],
                'current': [route_key(row) for row in after]}
        current_dns = self.io.dns()
        def dns_summary(record):
            return {'target': record['target'], 'mode': record['mode'],
                    'sha256': hashlib.sha256(base64.b64decode(record['data'], validate=True)).hexdigest()}
        current_link = self.link(INTERFACE)
        current_nm = self.nm(INTERFACE) if current_link else None
        current_addresses = self.json(['ip', '-j', 'addr', 'show', 'dev', INTERFACE]) if current_link else []
        current_carrier = self.carrier() if current_link else None
        return {'inspection': True, 'mutation': False, 'receipt': str(path), 'phase': self.saved.get('phase'),
                'last_restore_step': self.saved.get('restore_step'),
                'last_restore_error': self.saved.get('preserve_recovery', {}).get('error') or self.saved.get('restore_error'),
                'same_boot_and_host_namespace': True,
                'nm': {'original': self.saved['nm'], 'current': current_nm},
                'link': {'original': self.saved['link'], 'current': current_link},
                'carrier': current_carrier,
                'carrier_status': 'available' if current_carrier is not None else 'unavailable_interface_down_or_missing',
                'addresses': {'original': self.saved['addresses'], 'current': current_addresses,
                              'equal': address_key(self.saved['addresses']) == address_key(current_addresses)},
                'routes': route_diff,
                'dns': {'equal': current_dns == self.saved['dns'],
                        'original': dns_summary(self.saved['dns']), 'current': dns_summary(current_dns)},
                'recovery_allowed_by_host_guard': current_dns == self.saved['dns']
                    and all(row['outside_ethernet_equal'] for row in route_diff.values())}

    def recover(self, path):
        self.preserve_baseline = None  # Dedicated recovery never changes ordinary recovery semantics.
        path = self.load_receipt(path)
        self.host_guard()  # Refuse changed Wi-Fi/DNS before any recovery mutation.
        self.restore()
        control_cleanup(self.saved.get('control'))
        return {'recovered': True, 'receipt': str(path)}

    def recover_preserve_host_network(self, path):
        """Explicit cleanup authorization adopts today's external state, never writes it."""
        path = self.load_receipt(path)
        # Retain every original receipt field, plus an immutable private byte copy.
        original = self.directory / 'snapshot.original.json'
        source = path.read_bytes()
        if original.exists():
            metadata = original.lstat()
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0
                or stat.S_IMODE(metadata.st_mode) != 0o600):
                raise Refusal('Original private receipt backup identity differs; no recovery started.')
            content = original.read_bytes()
            known = self.saved.get('preserve_original_receipt_sha256')
            if (known and hashlib.sha256(content).hexdigest() != known) or (not known and content != source):
                raise Refusal('Original receipt backup differs; no recovery started.')
        else:
            descriptor = os.open(original, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, 'wb') as stream:
                stream.write(source); stream.flush(); os.fsync(stream.fileno())
            content = source
        self.saved['preserve_original_receipt_sha256'] = hashlib.sha256(content).hexdigest()
        wifi = self.saved['wifi']['interface']
        baseline = {'dns': self.io.dns(), 'routes': {str(family): self.routes(family) for family in (4, 6)},
                    'rules': {str(family): self.json(['ip', '-j', '-' + str(family), 'rule', 'show']) for family in (4, 6)},
                    'wifi': {'interface': wifi, 'nm': self.nm(wifi), 'link': self.link(wifi),
                             'addresses': self.json(['ip', '-j', 'addr', 'show', 'dev', wifi])}}
        if baseline['wifi']['nm']['type'] != 'wifi' or baseline['wifi']['link'] is None:
            raise Refusal('Original Wi-Fi device is unavailable; no recovery started.')
        def digest(value):
            return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        def summary(record):
            return {'dns': {'target': record['dns']['target'], 'mode': record['dns']['mode'],
                            'sha256': hashlib.sha256(base64.b64decode(record['dns']['data'], validate=True)).hexdigest()},
                    'outside_routes_sha256': {family: digest(routes_key([row for row in record['routes'][family]
                                                                        if row.get('dev') != INTERFACE])) for family in ('4', '6')},
                    'wifi': record['wifi'],
                    'rules_sha256': {family: digest(routes_key(record['rules'][family])) for family in ('4', '6')}
                                    if 'rules' in record else None}
        summaries = {'original': summary(self.saved), 'preserved_current': summary(baseline),
                     'original_rules_captured': 'rules' in self.saved}
        self.preserve_baseline = baseline
        self.host_guard()  # Verify capture consistency before persisting/starting recovery.
        self.saved['preserve_recovery'] = {'baseline': baseline, 'summaries': summaries, 'verified': False}
        self.persist()
        try:
            self.restore()
            self.host_guard()
            control_cleanup(self.saved.get('control'))
        except BaseException as error:
            if self.saved.get('phase') != 'RESTORE_WAITING_UNPLUG':
                self.saved['phase'] = 'RESTORE_FAILED_PRESERVE_HOST'
            self.saved['preserve_recovery']['error'] = str(error)
            self.persist()
            raise
        self.saved['preserve_recovery']['verified'] = True
        self.persist()
        return {'recovered': True, 'preserved_host_network': True, 'receipt': str(path),
                'original_receipt_backup': str(original), 'host_network_summaries': summaries,
                'nm_runtime_equivalence': self.saved['preserve_recovery'].get('nm_runtime_equivalence')}


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--interface')
    parser.add_argument('--management-ip')
    parser.add_argument('--confirm-eth1', action='store_true')
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--recover', type=Path)
    parser.add_argument('--inspect', type=Path, metavar='RECEIPT')
    parser.add_argument('--recover-preserve-host-network', type=Path, metavar='RECEIPT')
    parser.add_argument('--session', action='store_true')
    parser.add_argument('--wait-link', type=int, default=0, metavar='SECONDS')
    parser.add_argument('--control', type=Path, metavar='SOCKET')
    parser.add_argument('--phase', choices=PHASES)
    parser.add_argument('--finish', action='store_true')
    parser.add_argument('--timeout', type=int)
    args = parser.parse_args(argv)
    args.timeout = args.timeout if args.timeout is not None else (900 if args.session else 120)
    if not 60 <= args.timeout <= (900 if args.session else 240):
        parser.error('--timeout must be 60..900 for a session, otherwise 60..240 seconds')
    if args.wait_link and (not args.session or not 1 <= args.wait_link <= 120):
        parser.error('--wait-link requires --session and a value of 1..120 seconds')
    if args.control:
        if (bool(args.phase) == args.finish or args.session or args.wait_link or args.recover or args.inspect
            or args.recover_preserve_host_network or args.dry_run
            or args.interface or args.management_ip or args.confirm_eth1):
            parser.error('--control requires exactly --phase PHASE or --finish and no execution flags')
    elif args.phase or args.finish:
        parser.error('--phase/--finish require --control')
    receipts = sum(bool(value) for value in (args.recover, args.inspect, args.recover_preserve_host_network))
    if receipts and (args.dry_run or args.interface or args.management_ip or args.confirm_eth1
                     or args.session or args.wait_link or receipts != 1):
        parser.error('--recover/--inspect are separate receipt operations')
    return args


def main(argv=None):
    args = arguments(argv)
    if args.control:
        result = control_request(args.control, {'action': 'finish'} if args.finish else {'action': 'probe', 'phase': args.phase})
        print(json.dumps(result, indent=2))
        if not result.get('accepted', False):
            raise SystemExit(2)
        return
    tester = Tester(args)
    if args.dry_run:
        print(json.dumps(tester.execute(), indent=2)); return
    if os.geteuid() != 0:
        raise Refusal('Use sudo manually; no privilege escalation is performed by the helper.')
    if args.inspect:
        print(json.dumps(tester.inspect(args.inspect), indent=2)); return
    # This lock is the first mutation, after dry-run/root argument checks.
    with open(RUNROOT / 'pve-downstream-eth-test0.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.recover_preserve_host_network:
            result = tester.recover_preserve_host_network(args.recover_preserve_host_network)
        elif args.recover:
            result = tester.recover(args.recover)
        else:
            def interrupted(signum, frame):
                raise Interrupted('Interrupted by signal ' + str(signum))
            for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGALRM):
                signal.signal(signum, interrupted)
            signal.alarm(args.timeout)
            result = tester.execute()
        print(json.dumps(result, indent=2))


if __name__ == '__main__':
    try:
        main()
    except (Refusal, OSError, subprocess.TimeoutExpired, ValueError) as error:
        print('REFUSED: ' + str(error), file=sys.stderr)
        raise SystemExit(2)
