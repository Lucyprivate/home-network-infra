#!/usr/bin/env python3
"""Local model of kernel/NM/DHCP; never runs the real helper backend."""
import copy
import importlib.util
import io
import json
import signal
import socket
import stat
import struct
import subprocess
import tempfile
import unittest
from argparse import Namespace
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('downstream', Path(__file__).with_name('pve-downstream-test.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Process:
    pid = 4321

    def __init__(self, backend):
        self.backend, self.alive, self.terminated, self.killed = backend, True, False, False

    def poll(self):
        return None if self.alive else 0

    def terminate(self):
        self.terminated = True
        if not self.backend.slow_exit:
            self.alive = False

    def kill(self):
        self.killed = True
        self.alive = False

    def wait(self, timeout):
        if self.alive:
            raise subprocess.TimeoutExpired(['fixture-dhcp'], timeout)
        return 0


class Kernel:
    def __init__(self):
        self.calls, self.connections, self.signals = [], [], []
        self.clock = 0
        self.missing, self.nm_active, self.bad_wifi = None, False, False
        self.tcp_failure, self.no_dhcp, self.slow_exit = False, False, False
        self.fail_once, self.fail_forever = None, None
        self.client = None
        self.ns = {}
        self.wired_nm = {'managed': 'yes', 'autoconnect': True}
        self.flags = ['BROADCAST', 'MULTICAST', 'UP', 'LOWER_UP']
        self.links = {m.INTERFACE: {'ifname': m.INTERFACE, 'ifindex': 2, 'link_type': 'ether',
                                  'address': m.EXPECTED_MAC, 'flags': self.flags.copy()}}
        self.links['wlan0'] = {'ifname': 'wlan0', 'ifindex': 3, 'link_type': 'ether',
                                  'address': '02:00:00:00:00:02', 'flags': ['UP', 'LOWER_UP']}
        self.wifi_addresses = [{'ifname': 'wlan0', 'addr_info': [
            {'family': 'inet', 'local': '10.10.10.73', 'prefixlen': 24, 'scope': 'global'}]}]
        self.rules = {str(family): [{'priority': 0, 'table': 'local'}, {'priority': 32766, 'table': 'main'},
                                    {'priority': 32767, 'table': 'default'}] for family in (4, 6)}
        self.original_addr = [{'ifname': m.INTERFACE, 'addr_info': [
            {'family': 'inet', 'local': '10.10.99.55', 'prefixlen': 24, 'broadcast': '10.10.99.255',
             'scope': 'global', 'label': m.INTERFACE, 'valid_life_time': 4294967295},
            {'family': 'inet6', 'local': 'fe80::100', 'prefixlen': 64,
             'scope': 'link', 'valid_life_time': 4294967295}]}]
        self.addr = copy.deepcopy(self.original_addr)
        self.original_routes = {
            '4': [{'dst': 'default', 'gateway': '10.10.10.1', 'dev': 'wlan0', 'protocol': 'dhcp', 'metric': 600},
                  {'dst': '10.10.10.0/24', 'dev': 'wlan0', 'protocol': 'kernel', 'scope': 'link', 'prefsrc': '10.10.10.73'},
                  {'dst': '10.10.99.0/24', 'dev': m.INTERFACE, 'protocol': 'kernel', 'scope': 'link', 'prefsrc': '10.10.99.55'},
                  {'dst': '10.10.99.55', 'type': 'local', 'table': 'local', 'dev': m.INTERFACE, 'protocol': 'kernel', 'scope': 'host', 'prefsrc': '10.10.99.55'}],
            '6': [{'dst': 'default', 'gateway': 'fe80::1', 'dev': 'wlan0', 'protocol': 'ra', 'metric': 600, 'expires': 600},
                  {'dst': 'fe80::/64', 'dev': m.INTERFACE, 'protocol': 'kernel', 'metric': 256, 'pref': 'medium'}]}
        self.routes = copy.deepcopy(self.original_routes)
        self.dns_state = {'target': '../run/systemd/resolve/stub-resolv.conf', 'mode': 420, 'data': 'cHJpdmF0ZQ=='}
        self.lease = "ip_address='10.10.20.100'\nsubnet_mask=255.255.255.0\nrouters='10.10.20.1'\ndomain_name_servers='10.10.20.1'\ndhcp_server_identifier=10.10.20.1\n"
        self.carrier = '1'
        self.sleep_hook = None
        self.namespace_reads = []
        self.carrier_reads = []

    def which(self, name):
        return None if name == self.missing else '/usr/bin/' + name

    def text(self, path):
        if path.endswith('/carrier'):
            link = self.links.get(m.INTERFACE)
            flags = link.get('flags', []) if link else []
            self.carrier_reads.append({'flags': flags.copy(), 'call_count': len(self.calls)})
            if 'UP' not in flags:
                raise OSError(22, 'Invalid argument')  # Linux carrier_show/netif_running.
            return self.carrier + '\n'
        if path.endswith('/boot_id'):
            return 'fixture-boot\n'
        if '/proc/sys/net/ipv6/conf/' in path:
            return '0\n' if path.endswith('/disable_ipv6') else '1\n'
        raise AssertionError('Unexpected real-file request: ' + path)

    def dns(self):
        return copy.deepcopy(self.dns_state)

    def namespace_inode(self, path):
        self.namespace_reads.append(path)
        if path == '/proc/1/ns/net':
            raise PermissionError('PID 1 namespace is intentionally unreadable to the local user.')
        if path == '/proc/self/ns/net':
            return 111
        if path.startswith('/var/run/netns/'):
            return self.ns[path.rsplit('/', 1)[1]]['inode']
        raise AssertionError('Unexpected namespace path: ' + path)

    def connect(self, target, source):
        self.connections.append((target, source))
        if self.tcp_failure:
            raise OSError('fixture TCP refused')

    def sleep(self, seconds):
        self.clock += seconds
        if self.sleep_hook:
            self.sleep_hook(seconds)

    def now(self):
        return self.clock

    def process(self, pid):
        if self.client is None or not self.client.alive:
            return None
        return {'start': '12345', 'argv': self.client.argv[4:], 'netns': next(iter(self.ns.values()))['inode']}

    def signal_process(self, pid, identity, signum):
        self.signals.append((pid, signum))
        self.client.alive = False

    def popen(self, argv, log):
        self.calls.append(tuple(argv))
        self.client = Process(self); self.client.argv = argv
        ns = self.ns[argv[3]]
        dev = argv[-1]
        if not self.no_dhcp:
            ns['addresses'] = [{'ifname': dev, 'addr_info': [{'family': 'inet', 'local': '10.10.20.100', 'prefixlen': 24, 'scope': 'global'}]}]
            ns['routes'] = [{'dst': 'default', 'gateway': m.GATEWAY, 'dev': dev}]
        return self.client

    def run(self, argv, check=True, timeout=15):
        self.calls.append(tuple(argv))
        if self.fail_once and self.fail_once(argv):
            self.fail_once = None
            raise m.Refusal('injected one-shot command failure')
        if self.fail_forever and self.fail_forever(argv):
            raise m.Refusal('injected persistent command failure')
        out, rc = '', 0
        if argv == ['dhcpcd', '--version']:
            out = 'dhcpcd 10.3.0\n'
        elif argv[:2] == ['nmcli', '-g']:
            wired = argv[-1] == m.INTERFACE
            out = '\n'.join(['ethernet' if wired else 'wifi', self.wired_nm['managed'] if wired else 'yes',
                              'uuid-active' if self.nm_active or not wired else '--',
                              '/org/freedesktop/NetworkManager/Devices/' + ('1' if wired else '2'),
                              '20 (unavailable)' if wired and self.carrier == '0' else '30 (disconnected)']) + '\n'
        elif argv[:2] == ['busctl', 'get-property']:
            out = 'b ' + ('true' if self.wired_nm['autoconnect'] or argv[3].endswith('/2') else 'false') + '\n'
        elif argv[:3] == ['nmcli', 'device', 'set']:
            assert argv[3] == m.INTERFACE, 'Must never change Wi-Fi NM state'
            key, value = argv[4:6]
            self.wired_nm[key] = (value == 'yes') if key == 'autoconnect' else value
        elif argv == ['ip', '-j', '-4', 'route', 'get', m.MANAGEMENT]:
            out = json.dumps([{'dev': m.INTERFACE if self.bad_wifi else 'wlan0', 'prefsrc': '10.10.10.73'}])
        elif argv[:3] == ['ip', '-j', 'addr']:
            out = json.dumps(self.wifi_addresses if argv[-1] == 'wlan0' else (self.addr if m.INTERFACE in self.links else []))
        elif len(argv) == 5 and argv[:2] == ['ip', '-j'] and argv[3:] == ['rule', 'show']:
            out = json.dumps(self.rules[argv[2][1:]])
        elif len(argv) == 7 and argv[:2] == ['ip', '-j'] and argv[3:] == ['route', 'show', 'table', 'all']:
            out = json.dumps(self.routes[argv[2][1:]])
        elif argv[:3] == ['ip', 'netns', 'list']:
            out = ''.join(name + '\n' for name in self.ns)
        elif argv[:3] == ['ip', 'netns', 'add']:
            if argv[3] in self.ns:
                raise m.Refusal('namespace exists')
            self.ns[argv[3]] = {'inode': 222, 'links': {}, 'addresses': [], 'routes': []}
        elif argv[:3] == ['ip', 'netns', 'pids']:
            out = str(self.client.pid) + '\n' if self.client and self.client.alive else ''
        elif argv[:3] == ['ip', 'netns', 'delete']:
            assert not self.ns[argv[3]]['links'], 'Never delete namespace while Ethernet remains inside'
            del self.ns[argv[3]]
        elif argv[:3] == ['ip', 'netns', 'exec']:
            ns = self.ns[argv[3]]; inner = argv[4:]
            if inner[0] == 'sysctl':
                pass
            elif inner[:3] == ['ip', '-j', '-4'] and inner[3] == 'addr':
                out = json.dumps(ns['addresses'])
            elif inner[:3] == ['ip', '-j', '-4'] and inner[3] == 'route':
                out = json.dumps(ns['routes'])
            elif inner[:3] == ['dhcpcd', '-4', '-U']:
                out = self.lease
            elif inner[0] == 'dig':
                assert '@10.10.20.1' in inner
                # Mock a globally routable answer: documentation ranges are
                # intentionally rejected by the runtime's is_global guard.
                out = '1.1.1.1\n'
            elif inner[0] == 'curl':
                assert '--proxy' in inner and '--noproxy' in inner
                if inner[-1].startswith('https://www.cloudflare.com/'):
                    assert '--resolve' in inner
                    Path(inner[inner.index('--output') + 1]).write_text('h=www.cloudflare.com\nip=8.8.8.8\n')
                else:
                    assert inner[-1] == 'https://10.10.10.10:8006/' and '--insecure' in inner
                    out = '200'
            elif inner[:2] == ['python3', '-c']:
                if inner[2] == m.NTP_CODE:
                    out = '{"endpoint":"162.159.200.1:123","source_address":"10.10.20.100","source_port":48231,"sent_unix":946684800,"received_unix":946684800.05,"transmit_nonce":"abcdefgh","response_bytes":48,"stratum":3,"clock_changed":false}'
                else:
                    assert inner[2] == m.TCP_CODE
                    out = json.dumps({'target': inner[3], 'port': int(inner[4]), 'connected': True,
                                      'source_address': '10.10.20.100', 'source_port': 48230})
            else:
                raise AssertionError('Unexpected namespace operation: ' + repr(inner))
        elif argv[0] == 'sysctl':
            assert f'net.ipv6.conf.{m.INTERFACE}.' in argv[-1]
        elif argv[0] == 'ip':
            nsname = argv[2] if argv[1:2] == ['-n'] else None
            inner = argv[3:] if nsname else argv[1:]
            links = self.ns[nsname]['links'] if nsname else self.links
            if inner[:4] == ['-j', '-d', 'link', 'show']:
                row = links.get(inner[-1]); out = json.dumps([row] if row else [])
                rc = 0 if row else 1
            elif nsname and inner[:3] == ['-j', 'addr', 'show']:
                out = json.dumps(self.ns[nsname]['addresses'])
            elif inner[:2] == ['link', 'set'] and inner[-1] in ('up', 'down'):
                if inner[3] != 'lo':
                    row = links[inner[3]]
                    row['flags'] = [flag for flag in row['flags'] if flag != 'UP'] + (['UP'] if inner[-1] == 'up' else [])
            elif inner[:3] == ['link', 'set', 'dev']:
                dev, action, value = inner[3:6]
                row = links[dev]
                if action in ('up', 'down'):
                    raise AssertionError('Unexpected token shape')
                if action == 'name':
                    del links[dev]; row['ifname'] = value; links[value] = row
                elif action == 'netns':
                    del links[dev]
                    if nsname:
                        self.links[dev] = row
                    else:
                        self.ns[value]['links'][dev] = row
                        self.ns[value]['addresses'] = copy.deepcopy(self.addr)
                        self.addr = []
                        for family in ('4', '6'):
                            self.routes[family] = [r for r in self.routes[family] if r.get('dev') != m.INTERFACE]
                else:
                    raise AssertionError('Unexpected link action: ' + repr(inner))
            elif inner[:3] in (['-4', 'addr', 'flush'], ['-6', 'addr', 'flush']):
                if nsname:
                    self.ns[nsname]['addresses'] = []
                else:
                    family = 'inet' if inner[0] == '-4' else 'inet6'
                    if not self.addr:
                        self.addr = [{'ifname': m.INTERFACE, 'addr_info': []}]
                    self.addr[0]['addr_info'] = [item for item in self.addr[0]['addr_info'] if item['family'] != family]
                    self.routes[inner[0][1:]] = [r for r in self.routes[inner[0][1:]] if r.get('dev') != m.INTERFACE]
            elif inner[:3] in (['-4', 'addr', 'add'], ['-6', 'addr', 'add']):
                item = next(item for item in self.original_addr[0]['addr_info'] if inner[3] == f"{item['local']}/{item['prefixlen']}")
                self.addr[0]['addr_info'].append(copy.deepcopy(item))
                family = inner[0][1:]
                self.routes[family].extend(copy.deepcopy([r for r in self.original_routes[family]
                                                        if r.get('dev') == m.INTERFACE and r.get('protocol') == 'kernel']))
            elif inner[:3] in (['-4', 'route', 'replace'], ['-6', 'route', 'replace']):
                family = inner[0][1:]
                self.routes[family].extend(copy.deepcopy([r for r in self.original_routes[family]
                                                        if r.get('dev') == m.INTERFACE and r.get('protocol') != 'kernel']))
            elif inner[:3] in (['-4', 'route', 'flush'], ['-6', 'route', 'flush']):
                assert inner[3:] == ['table', 'all', 'dev', m.INTERFACE]
                self.routes[inner[0][1:]] = [r for r in self.routes[inner[0][1:]] if r.get('dev') != m.INTERFACE]
            else:
                raise AssertionError('Unexpected ip operation: ' + repr(argv))
        else:
            raise AssertionError('Unexpected external command: ' + repr(argv))
        result = subprocess.CompletedProcess(argv, rc, out, '')
        if check and rc:
            raise m.Refusal('fixture command failed')
        return result


class Peer:
    def __init__(self, uid=1000, request=b'{"action":"finish"}\n'):
        self.uid, self.request, self.messages, self.closed = uid, request, [], False

    def settimeout(self, value):
        self.timeout = value

    def getsockopt(self, *args):
        return struct.pack('3i', 1234, self.uid, 1000)

    def recv(self, maximum):
        data, self.request = self.request[:maximum], self.request[maximum:]
        return data

    def sendall(self, data):
        self.messages.append(json.loads(data))

    def close(self):
        self.closed = True


class FakeControl:
    reply = staticmethod(m.ControlServer.reply)

    def __init__(self, backend, events, directory, uid):
        self.backend, self.events, self.path, self.uid = backend, list(events), directory / 'control.sock', uid
        self.closed, self.peers = False, []

    def accept(self):
        self.backend.sleep(1)
        if not self.events:
            return None
        event = self.events.pop(0)
        if callable(event):
            return event()
        peer = Peer(self.uid); self.peers.append(peer)
        return peer, event

    def close(self):
        self.closed = True


class Safety(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack(); self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory(prefix='downstream-fixture-')))
        self.stack.enter_context(patch.object(m, 'RUNROOT', self.root))
        self.stack.enter_context(patch.object(m.os, 'geteuid', lambda: 0))
        self.stack.enter_context(patch.object(m.signal, 'signal', lambda *args: None))
        self.stack.enter_context(patch.object(m.signal, 'alarm', lambda *args: None))
        self.stack.enter_context(patch.object(m.subprocess, 'run', side_effect=AssertionError('real subprocess forbidden')))
        self.stack.enter_context(patch.object(m.subprocess, 'Popen', side_effect=AssertionError('real Popen forbidden')))
        self.stack.enter_context(patch.object(m.socket, 'create_connection', side_effect=AssertionError('real TCP forbidden')))
        self.stack.enter_context(patch.object(m.socket, 'socket', side_effect=AssertionError('real UDP forbidden')))
        self.backend = Kernel()
        self.args = Namespace(interface=m.INTERFACE, management_ip=m.MANAGEMENT, confirm_eth1=True, dry_run=False, timeout=120)
        self.tester = m.Tester(self.args, self.backend)

    def execute(self):
        self.stdout = io.StringIO()
        with redirect_stderr(io.StringIO()), redirect_stdout(self.stdout):
            return self.tester.execute()

    def session_fixture(self, events, wait_link=0, timeout=900):
        self.args.session, self.args.wait_link, self.args.timeout = True, wait_link, timeout
        self.controls, self.cleanups = [], []
        def factory(directory, uid):
            control = FakeControl(self.backend, events, directory, uid)
            self.controls.append(control)
            return control
        def cleanup(record):
            if record:
                self.assertEqual(self.tester.saved['phase'], 'RESTORED')
                self.cleanups.append(record)
                Path(record['directory']).rmdir()
        self.stack.enter_context(patch.object(m, 'ControlServer', side_effect=factory))
        # retain the real, bounded response encoder while replacing the listener backend
        m.ControlServer.reply = FakeControl.reply
        self.stack.enter_context(patch.object(m, 'control_cleanup', cleanup))
        self.stack.enter_context(patch.dict(m.os.environ, {'SUDO_UID': '1000'}))
        if wait_link:
            self.set_carrier('0')

    def set_carrier(self, value):
        self.backend.carrier = value
        for row in [*self.backend.links.values(), *(row for ns in self.backend.ns.values() for row in ns['links'].values())]:
            row['flags'] = [flag for flag in row['flags'] if flag != 'LOWER_UP']
            if value == '1':
                row['flags'].append('LOWER_UP')

    def assert_restored(self):
        self.assertIn(m.INTERFACE, self.backend.links)
        self.assertEqual(m.address_key(self.backend.addr), m.address_key(self.backend.original_addr))
        for family in ('4', '6'):
            self.assertEqual(m.routes_key(self.backend.routes[family]), m.routes_key(self.backend.original_routes[family]))
        self.assertEqual(self.backend.wired_nm, {'managed': 'yes', 'autoconnect': True})
        self.assertFalse(self.backend.ns)
        self.assertEqual(self.tester.saved['phase'], 'RESTORED')

    def recovery_fixture(self):
        self.set_carrier('0')
        self.args.session, self.args.wait_link = True, 120
        self.tester.saved = self.tester.preflight()
        self.tester.saved.update(namespace='pveds-0123456789', test_device='ds0123456789', namespace_inode=222)
        self.tester.directory = self.root / 'pve-downstream-test-fixture'
        self.tester.directory.mkdir(mode=0o700)
        self.tester.persist()
        original_lstat = Path.lstat
        def root_owned(path):
            info = original_lstat(path)
            return Namespace(st_mode=info.st_mode, st_uid=0)
        self.stack.enter_context(patch.object(Path, 'lstat', root_owned))
        self.backend.calls.clear(); self.backend.connections.clear()
        return self.tester.directory / 'snapshot.json'

    def test_full_success_restores_host_and_uses_only_namespace_queries(self):
        result = self.execute()
        self.assertTrue(result['restored'])
        self.assertFalse(result['udp_proxy_proven'])
        self.assertFalse(result['ntp_udp']['clock_changed'])
        self.assert_restored()
        self.assertTrue(self.backend.client.terminated)
        self.assertEqual(self.backend.connections, [((m.MANAGEMENT, 22), '10.10.10.73'), ((m.MANAGEMENT, 8006), '10.10.10.73')])
        for command in self.backend.calls:
            if any(word in command for word in ('dig', 'curl')) or m.NTP_CODE in command:
                self.assertEqual(command[:3], ('ip', 'netns', 'exec'))

    def test_dry_run_is_read_only_and_needs_no_root(self):
        self.args.dry_run = True
        with patch.object(m.os, 'geteuid', lambda: 1000):
            result = self.execute()
        self.assertFalse(result['mutation'])
        self.assertEqual(list(self.root.iterdir()), [])
        self.assertFalse(any(command[:3] == ('nmcli', 'device', 'set') or command[:3] == ('ip', 'netns', 'add') for command in self.backend.calls))

    def test_nonroot_real_run_refuses_before_namespace_or_nm_changes(self):
        with patch.object(m.os, 'geteuid', lambda: 1000), self.assertRaisesRegex(m.Refusal, 'sudo'):
            self.execute()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_explicit_interface_management_and_eth1_confirmation_required(self):
        for field, value in [('interface', 'wlan0'), ('management_ip', '10.10.99.10'), ('confirm_eth1', False)]:
            args = copy.copy(self.args); setattr(args, field, value)
            with self.subTest(field=field), self.assertRaises(m.Refusal):
                m.Tester(args, self.backend).preflight()
        self.assertFalse(self.backend.calls)

    def test_missing_busctl_or_wrong_wifi_refuses_before_changes(self):
        self.backend.missing = 'busctl'
        with self.assertRaisesRegex(m.Refusal, 'Missing required tool'):
            self.execute()
        self.backend.missing = None; self.backend.bad_wifi = True
        with self.assertRaisesRegex(m.Refusal, 'Wi-Fi route'):
            self.execute()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_tcp_management_failure_refuses_before_any_receipt_or_changes(self):
        self.backend.tcp_failure = True
        with self.assertRaises(OSError):
            self.execute()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_active_nm_connection_is_refused(self):
        self.backend.nm_active = True
        with self.assertRaisesRegex(m.Refusal, 'active wired NM'):
            self.execute()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_wrong_mac_and_dynamic_address_refused(self):
        self.backend.links[m.INTERFACE]['address'] = '02:00:00:00:00:01'
        with self.assertRaisesRegex(m.Refusal, 'Wired MAC'):
            self.execute()
        self.backend.links[m.INTERFACE]['address'] = m.EXPECTED_MAC
        self.backend.addr[0]['addr_info'][0]['dynamic'] = True
        with self.assertRaisesRegex(m.Refusal, 'stable wired addresses'):
            self.execute()

    def test_dhcp_timeout_restores_without_queries(self):
        self.backend.no_dhcp = True
        with self.assertRaisesRegex(m.Refusal, 'DHCP timed out'):
            self.execute()
        self.assert_restored()
        self.assertFalse(any('curl' in command for command in self.backend.calls))

    def test_wrong_lease_gateway_dns_server_and_injection_refused(self):
        for old, new in [('routers=\'10.10.20.1\'', 'routers=\'10.10.10.1\''),
                         ('domain_name_servers=\'10.10.20.1\'', 'domain_name_servers=\'10.10.10.1\''),
                         ('dhcp_server_identifier=10.10.20.1', 'dhcp_server_identifier=10.10.10.1'),
                         ('ip_address=\'10.10.20.100\'', 'ip_address=\'$(touch /tmp/forbidden)\'')]:
            with self.subTest(field=old):
                self.backend.lease = self.backend.lease.replace(old, new)
                with self.assertRaises(m.Refusal):
                    self.execute()
                self.assert_restored()
                self.backend.lease = self.backend.lease.replace(new, old)

    def test_partial_namespace_move_and_rename_failures_restore(self):
        predicates = [lambda c: c[:3] == ['ip', 'netns', 'add'],
                      lambda c: 'netns' in c and c[:3] == ['ip', 'link', 'set'],
                      lambda c: c[:2] == ['ip', '-n'] and 'name' in c,
                      lambda c: c[:3] == ['ip', 'netns', 'exec'] and 'sysctl' in c]
        for predicate in predicates:
            with self.subTest(stage=predicate):
                self.backend.fail_once = predicate
                with self.assertRaises(m.Refusal):
                    self.execute()
                self.assert_restored()

    def test_host_rename_failure_after_return_keeps_receipt_then_recovers(self):
        self.backend.fail_once = lambda c: c[:3] == ['ip', 'link', 'set'] and 'name' in c
        with self.assertRaisesRegex(m.Refusal, 'Recovery command'):
            self.execute()
        self.assertEqual(self.tester.saved['phase'], 'RESTORE_FAILED')
        self.assertTrue((self.tester.directory / 'snapshot.json').exists())
        self.assertTrue(self.backend.ns)
        self.tester.restore()
        self.assert_restored()

    def test_keyboard_interrupt_restores(self):
        with patch.object(self.tester, 'tests', side_effect=KeyboardInterrupt()), self.assertRaises(m.Refusal):
            self.execute()
        self.assert_restored()

    def test_curl_or_ntp_timeout_still_restores(self):
        for token in ('curl', 'python3'):
            with self.subTest(token=token):
                self.backend.fail_once = lambda c, token=token: c[:3] == ['ip', 'netns', 'exec'] and token in c
                with self.assertRaises(m.Refusal):
                    self.execute()
                self.assert_restored()

    def test_exact_dhcp_process_kill_fallback(self):
        self.backend.slow_exit = True
        self.execute()
        self.assertTrue(self.backend.client.terminated)
        self.assertTrue(self.backend.client.killed)
        self.assert_restored()

    def test_dhcp_startup_waits_for_exec_and_namespace_identity(self):
        original_process = self.backend.process

        def transitional(pid):
            current = original_process(pid)
            if current and self.backend.clock < 0.2:
                return {**current, 'argv': ['ip', 'netns', 'exec', 'fixture'], 'netns': 111}
            return current

        with patch.object(self.backend, 'process', transitional):
            self.execute()
        self.assertTrue(self.tester.saved['dhcp']['ready'])
        self.assertGreaterEqual(self.backend.clock, 0.2)
        self.assert_restored()

    def test_dhcp_startup_identity_timeout_stops_exact_client(self):
        original_process = self.backend.process

        def wrong_namespace(pid):
            current = original_process(pid)
            return {**current, 'netns': 111} if current else None

        with patch.object(self.backend, 'process', wrong_namespace), self.assertRaisesRegex(m.Refusal, 'namespace/exec identity'):
            self.execute()
        self.assertTrue(self.backend.client.terminated)
        self.assert_restored()
        self.assertFalse(any('dig' in command for command in self.backend.calls))

    def test_privsep_children_get_bounded_exit_grace(self):
        original_run = self.backend.run
        first_seen = [None]

        def delayed_children(argv, **kwargs):
            result = original_run(argv, **kwargs)
            if argv[:3] == ['ip', 'netns', 'pids']:
                if first_seen[0] is None:
                    first_seen[0] = self.backend.clock
                if self.backend.clock - first_seen[0] < 0.2:
                    return subprocess.CompletedProcess(argv, 0, '5555\n', '')
            return result

        with patch.object(self.backend, 'run', delayed_children):
            self.execute()
        self.assert_restored()
        self.assertFalse(self.backend.signals)

    def test_unknown_namespace_process_is_not_killed_or_deleted(self):
        original_run = self.backend.run

        def unknown_process(argv, **kwargs):
            result = original_run(argv, **kwargs)
            return subprocess.CompletedProcess(argv, 0, '99999\n', '') if argv[:3] == ['ip', 'netns', 'pids'] else result

        with patch.object(self.backend, 'run', unknown_process), self.assertRaisesRegex(m.Refusal, 'Namespace still has processes'):
            self.execute()
        self.assertTrue(self.backend.ns)
        self.assertFalse(self.backend.signals)
        self.assertTrue((self.tester.directory / 'snapshot.json').exists())

    def test_returned_wired_stale_routes_are_removed_without_touching_wifi(self):
        original_run = self.backend.run

        def return_route(argv, **kwargs):
            result = original_run(argv, **kwargs)
            if argv[:2] == ['ip', '-n'] and 'netns' in argv:
                self.backend.routes['4'].append({'dst': 'default', 'dev': m.INTERFACE, 'gateway': '10.10.20.1', 'protocol': 'static'})
            return result

        with patch.object(self.backend, 'run', return_route):
            self.execute()
        self.assert_restored()

    def test_cleanup_failure_retains_namespace_and_snapshot(self):
        self.backend.fail_forever = lambda c: c[:3] == ['nmcli', 'device', 'set'] and c[-2:] == ['managed', 'yes']
        with self.assertRaisesRegex(m.Refusal, 'Recovery command'):
            self.execute()
        self.assertTrue(self.backend.ns)
        self.assertTrue((self.tester.directory / 'snapshot.json').exists())
        self.assertFalse(any(c[:3] == ('ip', 'netns', 'delete') for c in self.backend.calls))

    def test_resolver_change_is_detected_and_never_overwritten(self):
        original_tests = self.tester.tests

        def change_dns():
            self.backend.dns_state['data'] = 'external-concurrent-change'
            return original_tests()

        with patch.object(self.tester, 'tests', change_dns), self.assertRaisesRegex(m.Refusal, 'Host resolver changed'):
            self.execute()
        self.assertEqual(self.backend.dns_state['data'], 'external-concurrent-change')
        self.assertTrue((self.tester.directory / 'snapshot.json').exists())
        self.assertTrue(self.backend.ns)

    def test_other_host_route_change_detected_without_overwriting_it(self):
        original_tests = self.tester.tests

        def change_route():
            self.backend.routes['4'][0]['gateway'] = '10.10.10.254'
            return original_tests()

        with patch.object(self.tester, 'tests', change_route), self.assertRaisesRegex(m.Refusal, 'routes outside'):
            self.execute()
        self.assertEqual(self.backend.routes['4'][0]['gateway'], '10.10.10.254')

    def test_recovery_pid_reuse_is_not_signalled(self):
        self.tester.saved = self.tester.preflight()
        self.tester.directory = self.root
        self.tester.saved.update(namespace='pveds-0123456789', namespace_inode=222, test_device='ds0123456789',
                                 dhcp={'pid': 4321, 'start': 'wrong-start', 'config': str(self.root / 'dhcpcd.conf')})
        self.backend.ns['pveds-0123456789'] = {'inode': 222, 'links': {}, 'addresses': [], 'routes': []}
        self.backend.client = Process(self.backend)
        self.backend.client.argv = ['ip', 'netns', 'exec', 'pveds-0123456789', 'dhcpcd', '-f', str(self.root / 'dhcpcd.conf'), 'ds0123456789']
        with self.assertRaisesRegex(m.Refusal, 'nothing killed'):
            self.tester.stop_dhcp()
        self.assertFalse(self.backend.signals)

    def test_lease_parser_never_executes_and_duplicate_fields_refused(self):
        self.assertEqual(m.lease_values("routers='$(id)'\n")['routers'], ['$(id)'])
        with self.assertRaisesRegex(m.Refusal, 'Duplicate'):
            m.lease_values('routers=10.10.20.1\nrouters=10.10.10.1\n')

    def test_nonroundtrippable_routes_refused(self):
        self.backend.routes['4'].append({'dst': 'default', 'dev': m.INTERFACE, 'multipath': [{'gateway': '192.0.2.1'}]})
        with self.assertRaisesRegex(m.Refusal, 'cannot be restored safely'):
            self.execute()

    def test_session_multiple_phases_acquire_dhcp_once_and_finish_after_restore(self):
        self.session_fixture([{'action': 'probe', 'phase': phase} for phase in m.PHASES] + [{'action': 'finish'}])
        result = self.execute()
        self.assert_restored()
        self.assertTrue(result['finished'])
        self.assertEqual(result['probe_count'], len(m.PHASES))
        self.assertEqual(sum('-B' in command for command in self.backend.calls), 1)
        self.assertTrue(self.controls[0].closed)
        self.assertEqual(self.controls[0].uid, 1000)
        ready = json.loads(self.stdout.getvalue())
        self.assertEqual(ready['event'], 'READY')
        evidence = [json.loads(line) for line in (self.tester.directory / 'probes.jsonl').read_text().splitlines()]
        self.assertEqual([item['phase'] for item in evidence], list(m.PHASES))
        self.assertTrue(all(item['all_checks_passed'] for item in evidence))
        self.assertTrue(self.controls[0].peers[-1].messages[0]['restored'])
        self.assertEqual(stat.S_IMODE((self.tester.directory / 'snapshot.json').stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((self.tester.directory / 'probes.jsonl').stat().st_mode), 0o600)
        for command in self.backend.calls:
            if 'curl' in command or 'dig' in command or m.TCP_CODE in command or m.NTP_CODE in command:
                self.assertEqual(command[:3], ('ip', 'netns', 'exec'))
        checks = evidence[0]['checks']
        self.assertEqual(checks['https_trace']['result']['egress_ip'], '8.8.8.8')
        self.assertFalse(checks['pve_https8006']['result']['tls_verified'])
        self.assertEqual(checks['servicevm_tcp22']['result']['target'], '10.10.20.112')
        self.assertEqual(checks['ntp_udp']['result']['source_port'], 48231)
        self.assertFalse(evidence[0]['udp_proxy_proven'])
        self.assertTrue(any('+tcp' in command for command in self.backend.calls if 'dig' in command))

    def test_session_network_probe_failure_is_recorded_and_later_probe_runs(self):
        self.session_fixture([{'action': 'probe', 'phase': 'fault-wait'}, {'action': 'probe', 'phase': 'direct'}, {'action': 'finish'}])
        self.backend.fail_once = lambda command: 'curl' in command
        result = self.execute()
        self.assertEqual(result['probe_count'], 2)
        probes = [peer.messages[0]['probe'] for peer in self.controls[0].peers[:-1]]
        self.assertFalse(probes[0]['checks']['https_trace']['ok'])
        self.assertTrue(probes[0]['checks']['servicevm_tcp22']['ok'])
        self.assertTrue(probes[1]['all_checks_passed'])
        self.assert_restored()

    def test_session_both_dns_failures_skip_trace_but_not_local_or_udp_probes(self):
        self.session_fixture([{'action': 'probe', 'phase': 'direct'}, {'action': 'finish'}])
        self.backend.fail_forever = lambda command: 'dig' in command
        self.execute()
        checks = self.controls[0].peers[0].messages[0]['probe']['checks']
        self.assertFalse(checks['dns_udp']['ok']); self.assertFalse(checks['dns_tcp']['ok'])
        self.assertFalse(checks['https_trace']['ok'])
        self.assertTrue(checks['pve_tcp22']['ok']); self.assertTrue(checks['ntp_udp']['ok'])
        self.assert_restored()

    def test_session_host_dns_change_is_fatal_and_never_overwritten(self):
        def external_change():
            self.backend.dns_state['data'] = 'changed-by-another-actor'
        self.session_fixture([external_change, {'action': 'probe', 'phase': 'baseline'}])
        with self.assertRaisesRegex(m.Refusal, 'Host resolver changed'):
            self.execute()
        self.assertEqual(self.backend.dns_state['data'], 'changed-by-another-actor')
        self.assertTrue(self.controls[0].closed)
        self.assertFalse(self.controls[0].peers)
        self.assertTrue((self.tester.directory / 'snapshot.json').exists())

    def test_session_namespace_identity_change_is_fatal_without_deleting_other_namespace(self):
        def replaced_namespace():
            next(iter(self.backend.ns.values()))['inode'] = 333
        self.session_fixture([replaced_namespace])
        with self.assertRaisesRegex(m.Refusal, 'Namespace identity differs'):
            self.execute()
        self.assertTrue(self.backend.ns)
        self.assertFalse(any(command[:3] == ('ip', 'netns', 'delete') for command in self.backend.calls))

    def test_session_dhcp_start_failure_has_no_ready_control_and_restores(self):
        self.session_fixture([{'action': 'finish'}])
        self.backend.no_dhcp = True
        with self.assertRaisesRegex(m.Refusal, 'DHCP timed out'):
            self.execute()
        self.assertFalse(self.controls)
        self.assertNotIn('READY', self.stdout.getvalue())
        self.assert_restored()

    def test_session_idle_deadline_is_bounded_and_restores(self):
        self.session_fixture([], timeout=60)
        result = self.execute()
        self.assertTrue(result['timed_out'])
        self.assertLessEqual(self.backend.clock, 62)
        self.assert_restored()

    def test_session_interrupt_during_probe_is_not_swallowed_as_network_failure(self):
        self.session_fixture([{'action': 'probe', 'phase': 'baseline'}])
        original_run = self.backend.run
        def interrupted(argv, **kwargs):
            if 'dig' in argv:
                raise m.Interrupted('fixture SIGTERM')
            return original_run(argv, **kwargs)
        with patch.object(self.backend, 'run', interrupted), self.assertRaisesRegex(m.Refusal, 'fixture SIGTERM'):
            self.execute()
        self.assert_restored()

    def test_wait_link_inhibits_nm_before_prompt_then_dhcp_once_after_carrier(self):
        def unplug():
            self.set_carrier('0')
        self.session_fixture([{'action': 'probe', 'phase': 'baseline'}, unplug, {'action': 'finish'}], wait_link=120)
        def insert(seconds):
            if self.backend.clock >= 2 and not self.backend.client:
                self.set_carrier('1')
        self.backend.sleep_hook = insert
        result = self.execute()
        self.assertTrue(result['restored'])
        self.assert_restored()
        events = [json.loads(line)['event'] for line in self.stdout.getvalue().splitlines()]
        self.assertEqual(events, ['WAITING_LINK', 'READY'])
        self.assertEqual(sum('-B' in command for command in self.backend.calls), 1)
        self.assertEqual(self.backend.dns_state['data'], 'cHJpdmF0ZQ==')

    def test_wait_link_timeout_restores_without_dhcp_or_control(self):
        self.session_fixture([], wait_link=3)
        with self.assertRaisesRegex(m.Refusal, 'bounded wait'):
            self.execute()
        self.assert_restored()
        self.assertFalse(self.backend.client)
        self.assertFalse(self.controls)
        self.assertAlmostEqual(self.backend.clock, 11.1)  # Carrier negotiation + empty-NM settlement.

    def test_wait_link_rejects_already_connected_without_mutation(self):
        self.session_fixture([], wait_link=120)
        self.set_carrier('1')
        with self.assertRaisesRegex(m.Refusal, 'initially unplugged'):
            self.execute()
        self.assertFalse(self.tester.directory)
        self.assertFalse(any(command[:3] == ('nmcli', 'device', 'set') for command in self.backend.calls))

    def test_session_wait_link_dry_run_unplugged_is_read_only_and_needs_no_sudo(self):
        self.session_fixture([], wait_link=120)
        self.args.dry_run = True
        with patch.object(m.os, 'geteuid', lambda: 1000):
            result = self.execute()
        self.assertTrue(result['preflight_passed']); self.assertFalse(result['mutation'])
        self.assertFalse(self.tester.directory); self.assertFalse(self.controls)
        self.assertFalse(self.backend.ns)
        self.assertFalse(any(command[:3] == ('nmcli', 'device', 'set') for command in self.backend.calls))
        self.assertEqual(self.backend.wired_nm, {'managed': 'yes', 'autoconnect': True})
        self.assertEqual(self.backend.namespace_reads, ['/proc/self/ns/net'])

    def test_dry_run_pid1_permission_denied_does_not_block_current_namespace_snapshot(self):
        self.args.dry_run = True
        with patch.object(m.os, 'geteuid', lambda: 1000):
            result = self.execute()
        self.assertTrue(result['preflight_passed'])
        self.assertEqual(self.tester.saved['host_netns_inode'], 111)
        self.assertEqual(self.backend.namespace_reads, ['/proc/self/ns/net'])
        self.assertFalse(self.tester.directory)

    def test_wait_link_finish_refuses_connected_then_accepts_unplugged(self):
        self.session_fixture([{'action': 'finish'}, lambda: self.set_carrier('0'), {'action': 'finish'}], wait_link=10)
        self.backend.sleep_hook = lambda seconds: self.set_carrier('1') if not self.backend.client else None
        self.execute()
        messages = [peer.messages[0] for peer in self.controls[0].peers]
        self.assertFalse(messages[0]['accepted']); self.assertTrue(messages[0]['requires_unplug'])
        self.assertTrue(messages[1]['restored'])
        self.assert_restored()

    def test_wait_link_interrupt_connected_returns_static_nic_but_keeps_nm_inhibited_until_recover(self):
        self.session_fixture([lambda: (_ for _ in ()).throw(m.Interrupted('fixture signal'))], wait_link=10)
        self.backend.sleep_hook = lambda seconds: self.set_carrier('1') if not self.backend.client else None
        with self.assertRaisesRegex(m.Refusal, 'Unplug the cable'):
            self.execute()
        self.assertIn(m.INTERFACE, self.backend.links)
        self.assertEqual(self.backend.wired_nm, {'managed': 'no', 'autoconnect': False})
        self.assertEqual(m.routes_key(self.backend.routes['4']), m.routes_key(self.backend.original_routes['4']))
        self.assertEqual(self.backend.dns_state['data'], 'cHJpdmF0ZQ==')
        self.assertEqual(self.tester.saved['phase'], 'RESTORE_WAITING_UNPLUG')
        self.assertTrue(self.backend.ns)
        self.assertTrue((self.tester.directory / 'snapshot.json').exists())
        self.assertFalse(self.cleanups)
        self.backend.sleep_hook = None; self.set_carrier('0')
        original_lstat = Path.lstat
        def owner_lstat(path):
            info = original_lstat(path)
            class Owned:
                st_mode, st_uid = info.st_mode, 0
            return Owned()
        with patch.object(Path, 'lstat', owner_lstat):
            result = self.tester.recover(self.tester.directory / 'snapshot.json')
        self.assertTrue(result['recovered']); self.assert_restored()

    def test_wait_link_replug_during_nm_restore_returns_to_inhibited_state(self):
        self.session_fixture([lambda: self.set_carrier('0'), {'action': 'finish'}], wait_link=10)
        def physical_change(seconds):
            if not self.backend.client or (m.INTERFACE in self.backend.links and self.backend.wired_nm['managed'] == 'yes'):
                self.set_carrier('1')
        self.backend.sleep_hook = physical_change
        with self.assertRaisesRegex(m.Refusal, 'Unplug the cable'):
            self.execute()
        self.assertEqual(self.backend.wired_nm, {'managed': 'no', 'autoconnect': False})
        self.assertEqual(self.tester.saved['phase'], 'RESTORE_WAITING_UNPLUG')
        self.assertFalse(self.controls[0].peers[0].messages[0]['restored'])
        self.assertEqual(m.routes_key(self.backend.routes['4']), m.routes_key(self.backend.original_routes['4']))

    def test_recover_unplugged_manages_empty_device_before_static_refill(self):
        path = self.recovery_fixture()
        original_run = self.backend.run
        def assume_on_transition(argv, **kwargs):
            if (argv == ['nmcli', 'device', 'set', m.INTERFACE, 'managed', 'yes']
                and self.backend.wired_nm['managed'] == 'no' and m.address_key(self.backend.addr)):
                self.backend.nm_active = True
            return original_run(argv, **kwargs)
        with patch.object(self.backend, 'run', assume_on_transition):
            self.assertTrue(self.tester.recover(path)['recovered'])
        self.assert_restored()
        managed = self.backend.calls.index(('nmcli', 'device', 'set', m.INTERFACE, 'managed', 'yes'))
        refill = next(i for i, command in enumerate(self.backend.calls) if command[:4] == ('ip', '-4', 'addr', 'add'))
        auto = self.backend.calls.index(('nmcli', 'device', 'set', m.INTERFACE, 'autoconnect', 'yes'))
        self.assertLess(managed, refill); self.assertLess(refill, auto)

    def test_recover_empty_device_new_uuid_refused_without_accepting_or_deleting_profile(self):
        path = self.recovery_fixture()
        self.backend.nm_active = True
        with self.assertRaisesRegex(m.Refusal, 'original inactive NM state'):
            self.tester.recover(path)
        self.assertTrue(path.exists()); self.assertEqual(self.backend.wired_nm['managed'], 'no')
        self.assertFalse(any(command[:4] == ('ip', '-4', 'addr', 'add') for command in self.backend.calls))
        self.assertFalse(any(command[:2] == ('nmcli', 'connection') for command in self.backend.calls))

    def test_recover_final_new_uuid_still_refused(self):
        path = self.recovery_fixture()
        original_run = self.backend.run
        def assume_on_address(argv, **kwargs):
            result = original_run(argv, **kwargs)
            if argv[:4] == ['ip', '-4', 'addr', 'add']:
                self.backend.nm_active = True
            return result
        with patch.object(self.backend, 'run', assume_on_address), self.assertRaisesRegex(m.Refusal, 'Original NetworkManager state differs'):
            self.tester.recover(path)
        self.assertTrue(path.exists()); self.assertNotEqual(self.tester.saved['phase'], 'RESTORED')

    def test_recover_changed_wifi_refuses_before_any_mutation(self):
        path = self.recovery_fixture()
        self.backend.routes['4'][0]['gateway'] = '10.10.20.1'
        with self.assertRaisesRegex(m.Refusal, 'Host routes outside'):
            self.tester.recover(path)
        self.assertTrue(path.exists()); self.assertFalse(self.backend.signals)
        self.assertEqual(self.backend.wired_nm, {'managed': 'yes', 'autoconnect': True})
        self.assertTrue(all(command[:3] != ('nmcli', 'device', 'set') and 'flush' not in command
                            and 'set' not in command and 'delete' not in command for command in self.backend.calls))

    def test_inspect_private_receipt_reports_diffs_without_mutation_or_dns_body(self):
        path = self.recovery_fixture()
        before = path.read_bytes()
        self.backend.nm_active = True
        self.backend.routes['4'][0]['gateway'] = '10.10.20.1'
        self.backend.dns_state['data'] = 'Y2hhbmdlZA=='
        result = self.tester.inspect(path)
        self.assertFalse(result['mutation']); self.assertTrue(result['inspection'])
        self.assertFalse(result['recovery_allowed_by_host_guard'])
        self.assertFalse(result['routes']['4']['outside_ethernet_equal']); self.assertFalse(result['dns']['equal'])
        self.assertEqual(result['nm']['original']['connection_uuid'], '--')
        self.assertEqual(result['nm']['current']['connection_uuid'], 'uuid-active')
        self.assertEqual(len(result['dns']['current']['sha256']), 64)
        encoded = json.dumps(result)
        self.assertNotIn('cHJpdmF0ZQ==', encoded); self.assertNotIn('Y2hhbmdlZA==', encoded)
        self.assertEqual(path.read_bytes(), before); self.assertFalse(self.backend.connections)
        self.assertTrue(all(command[:2] in (('ip', '-j'), ('nmcli', '-g'), ('busctl', 'get-property'))
                            for command in self.backend.calls))

    def test_inspect_main_does_not_create_lock_or_run_preflight(self):
        class ReadOnly:
            def inspect(self, path):
                return {'inspection': True, 'mutation': False}
        with patch.object(m, 'Tester', return_value=ReadOnly()), \
             patch('builtins.open', side_effect=AssertionError('No lock or write for inspection')), \
             redirect_stdout(io.StringIO()) as output:
            m.main(['--inspect', str(self.root / 'pve-downstream-test-fixture/snapshot.json')])
        self.assertFalse(json.loads(output.getvalue())['mutation'])

    def preserve_fixture(self):
        path = self.recovery_fixture()
        self.backend.routes['4'][0]['gateway'] = '10.10.10.254'
        self.backend.routes['6'][0]['gateway'] = 'fe80::2'
        self.backend.dns_state['data'] = 'bmV3LXJlc29sdmVy'
        self.backend.rules['4'].insert(1, {'priority': 100, 'table': '900'})
        self.backend.wifi_addresses[0]['addr_info'][0]['local'] = '10.10.10.74'
        self.backend.ns[self.tester.saved['namespace']] = {'inode': 222, 'links': {}, 'addresses': [], 'routes': []}
        return path

    def test_dedicated_recovery_preserves_current_external_network_and_original_receipt(self):
        path = self.preserve_fixture()
        old = path.read_bytes(); original_fields = json.loads(old)
        current = copy.deepcopy((self.backend.routes, self.backend.rules, self.backend.dns_state,
                                 self.backend.wifi_addresses, self.backend.links['wlan0']))
        result = self.tester.recover_preserve_host_network(path)
        self.assertTrue(result['preserved_host_network']); self.assertTrue(result['recovered'])
        self.assertFalse(self.backend.ns); self.assertTrue(self.tester.saved['preserve_recovery']['verified'])
        self.assertEqual((path.parent / 'snapshot.original.json').read_bytes(), old)
        self.assertEqual(stat.S_IMODE((path.parent / 'snapshot.original.json').stat().st_mode), 0o600)
        for field in ('routes', 'dns', 'wifi', 'nm', 'addresses', 'link', 'boot_id', 'host_netns_inode'):
            self.assertEqual(self.tester.saved[field], original_fields[field])
        after = (self.backend.routes, self.backend.rules, self.backend.dns_state,
                 self.backend.wifi_addresses, self.backend.links['wlan0'])
        self.assertEqual(after, current)
        self.assertEqual(m.address_key(self.backend.addr), m.address_key(self.backend.original_addr))
        self.assertEqual(self.backend.wired_nm, {'managed': 'yes', 'autoconnect': True})
        self.assertFalse(self.backend.connections)
        for command in self.backend.calls:
            if 'flush' in command or 'replace' in command or 'set' in command or ('addr' in command and 'add' in command):
                self.assertTrue(m.INTERFACE in command or command[0] == 'sysctl')
            if 'rule' in command:
                self.assertEqual(command[-1], 'show')
        self.assertNotIn('bmV3LXJlc29sdmVy', json.dumps(result))
        self.assertFalse(result['host_network_summaries']['original_rules_captured'])

    def test_dedicated_recovery_concurrent_external_change_rejected_without_overwrite(self):
        for kind in ('route', 'rule', 'dns', 'wifi'):
            with self.subTest(kind=kind):
                # Independent instance/receipt for each external mutation.
                self.backend = Kernel(); self.tester = m.Tester(self.args, self.backend)
                # Avoid sharing a previous fixture receipt/backup.
                with tempfile.TemporaryDirectory(dir=self.root, prefix='preserve-fixture-') as directory:
                    with patch.object(m, 'RUNROOT', Path(directory)):
                        original_root, self.root = self.root, Path(directory)
                        try:
                            path = self.preserve_fixture()
                            original_run, changed = self.backend.run, [False]
                            def concurrent(argv, **kwargs):
                                result = original_run(argv, **kwargs)
                                if not changed[0] and argv == ['nmcli', 'device', 'set', m.INTERFACE, 'autoconnect', 'no']:
                                    changed[0] = True
                                    if kind == 'route': self.backend.routes['4'][0]['gateway'] = '10.10.10.253'
                                    if kind == 'rule': self.backend.rules['4'].append({'priority': 200, 'table': '901'})
                                    if kind == 'dns': self.backend.dns_state['data'] = 'Y29uY3VycmVudA=='
                                    if kind == 'wifi': self.backend.wifi_addresses[0]['addr_info'][0]['local'] = '10.10.10.75'
                                return result
                            with patch.object(self.backend, 'run', concurrent), self.assertRaises(m.Refusal):
                                self.tester.recover_preserve_host_network(path)
                            self.assertTrue(changed[0]); self.assertTrue(path.exists()); self.assertTrue(self.backend.ns)
                            self.assertFalse(self.tester.saved['preserve_recovery']['verified'])
                            self.assertEqual(self.tester.saved['phase'], 'RESTORE_FAILED_PRESERVE_HOST')
                            self.assertFalse(any('flush' in command for command in self.backend.calls))
                            if kind == 'dns': self.assertEqual(self.backend.dns_state['data'], 'Y29uY3VycmVudA==')
                        finally:
                            self.root = original_root

    def test_ordinary_recovery_still_refuses_old_snapshot_after_dedicated_recovery(self):
        path = self.preserve_fixture()
        self.tester.recover_preserve_host_network(path)
        before = len(self.backend.calls)
        with self.assertRaisesRegex(m.Refusal, 'Host resolver changed'):
            self.tester.recover(path)
        self.assertIsNone(self.tester.preserve_baseline)
        self.assertFalse(any('set' in command or 'flush' in command or 'delete' in command
                             for command in self.backend.calls[before:]))

    def test_dedicated_recovery_retains_strict_original_wired_uuid(self):
        path = self.preserve_fixture()
        self.backend.nm_active = True
        with self.assertRaisesRegex(m.Refusal, 'original inactive NM state'):
            self.tester.recover_preserve_host_network(path)
        self.assertFalse(self.tester.saved['preserve_recovery']['verified'])
        self.assertTrue(self.backend.ns); self.assertTrue(path.exists())
        self.assertFalse(any(command[:2] == ('nmcli', 'connection') for command in self.backend.calls))

    def generated_profile_fixture(self):
        # The measured receipt had no IPv6 address: addr add cannot regenerate
        # the missing local multicast route, unlike the old simplified backend.
        self.backend.original_addr[0]['addr_info'] = self.backend.original_addr[0]['addr_info'][:1]
        self.backend.addr = copy.deepcopy(self.backend.original_addr)
        route = {'type': 'multicast', 'dst': 'ff00::/8', 'dev': m.INTERFACE, 'table': 'local',
                 'protocol': 'kernel', 'metric': 256, 'flags': ['linkdown'], 'pref': 'medium'}
        self.backend.original_routes['6'] = [self.backend.original_routes['6'][0], route,
            dict(route, dev='wlan0', flags=[]), dict(route, dev='singbox_tun', flags=[])]
        self.backend.routes = copy.deepcopy(self.backend.original_routes)
        path = self.preserve_fixture()
        self.generated = False
        self.generated_uuid = '22222222-2222-4222-8222-222222222222'
        self.generated_flags, self.generated_filename = 'u 15', 's "/run/NetworkManager/system-connections/eth-test0.nmconnection"'
        self.generated_active_object = 'o "/org/freedesktop/NetworkManager/Settings/15"'
        self.generated_values = {key: '' for key in m.GENERATED_PROFILE_FIELDS}
        self.generated_values.update({'connection.id': m.INTERFACE, 'connection.uuid': self.generated_uuid,
            'connection.type': '802-3-ethernet', 'connection.interface-name': m.INTERFACE,
            'ipv4.method': 'manual', 'ipv4.addresses': '10.10.99.55/24', 'ipv6.method': 'ignore'})
        self.generated_file_mode, self.generated_file_uid = stat.S_IFREG | 0o600, 0
        self.generated_hook = None
        original_run = self.backend.run
        def backend_run(argv, **kwargs):
            out = None
            if argv[:3] == ['ip', '-6', 'route'] and argv[3] == 'append':
                self.backend.calls.append(tuple(argv))
                self.assertEqual(argv, ['ip', '-6', 'route', 'append', 'multicast', 'ff00::/8',
                    'table', 'local', 'dev', m.INTERFACE, 'proto', 'kernel', 'metric', '256', 'pref', 'medium'])
                self.assertNotIn(route, self.backend.routes['6'])
                self.backend.routes['6'].append(copy.deepcopy(route))
                if self.generated_hook: self.generated_hook('append')
                return subprocess.CompletedProcess(argv, 0, '', '')
            if argv[:2] == ['nmcli', '-g']:
                if argv[2] == 'GENERAL.CON-PATH':
                    out = '/org/freedesktop/NetworkManager/ActiveConnection/23\n'
                elif argv[2] == ','.join(m.GENERATED_PROFILE_FIELDS):
                    self.assertEqual(argv[3:], ['connection', 'show', 'uuid', self.generated_uuid])
                    out = '\n'.join(self.generated_values[key] for key in m.GENERATED_PROFILE_FIELDS) + '\n'
                    if self.generated_hook: self.generated_hook('profile')
            elif argv[:2] == ['busctl', 'call'] and argv[-3:-1] == ['GetConnectionByUuid', 's']:
                self.assertEqual(argv[3], '/org/freedesktop/NetworkManager/Settings')
                self.assertEqual(argv[-1], self.generated_uuid)
                out = 'o "/org/freedesktop/NetworkManager/Settings/15"\n'
            elif argv[:2] == ['busctl', 'get-property'] and argv[4] == 'org.freedesktop.NetworkManager.Connection.Active':
                self.assertEqual(argv[3], '/org/freedesktop/NetworkManager/ActiveConnection/23')
                self.assertEqual(argv[-1], 'Connection')
                out = self.generated_active_object + '\n'
            elif argv[:2] == ['busctl', 'get-property'] and argv[4] == m.NM_SETTINGS_CONNECTION:
                self.assertEqual(argv[3], '/org/freedesktop/NetworkManager/Settings/15')
                out = (self.generated_flags if argv[-1] == 'Flags' else self.generated_filename) + '\n'
            if out is not None:
                self.backend.calls.append(tuple(argv)); return subprocess.CompletedProcess(argv, 0, out, '')
            result = original_run(argv, **kwargs)
            if argv == ['ip', 'link', 'set', 'dev', m.INTERFACE, 'up'] and self.backend.addr[0]['addr_info']:
                self.generated = True
            if (self.generated and argv[:2] == ['nmcli', '-g'] and argv[-1] == m.INTERFACE):
                lines = result.stdout.splitlines(); lines[2] = self.generated_uuid; lines[4] = '100 (connected (externally))'
                result.stdout = '\n'.join(lines) + '\n'
            return result
        self.stack.enter_context(patch.object(self.backend, 'run', backend_run))
        def lstat(name):
            return Namespace(st_mode=self.generated_file_mode if name.endswith('.nmconnection') else stat.S_IFDIR | 0o755,
                             st_uid=self.generated_file_uid)
        self.backend.lstat = lstat
        return path

    def test_measured_no_ipv6_address_multicast_missing_and_generated_nm_is_certified(self):
        path = self.generated_profile_fixture()
        original = path.read_bytes()
        external = {family: [r for r in self.backend.routes[family] if r.get('dev') != m.INTERFACE] for family in ('4', '6')}
        result = self.tester.recover_preserve_host_network(path)
        proof = result['nm_runtime_equivalence']
        self.assertTrue(result['recovered']); self.assertTrue(proof['network_configuration_restored'])
        self.assertFalse(proof['runtime_identity_restored']); self.assertFalse(proof['profile_modified'])
        self.assertEqual(proof['original']['connection_uuid'], '--')
        self.assertEqual(proof['current']['connection_uuid'], self.generated_uuid)
        self.assertEqual(proof['active_path'], '/org/freedesktop/NetworkManager/ActiveConnection/23')
        self.assertEqual(proof['settings_path'], '/org/freedesktop/NetworkManager/Settings/15')
        self.assertEqual((path.parent / 'snapshot.original.json').read_bytes(), original)
        self.assertFalse(self.backend.ns)
        for family in ('4', '6'):
            self.assertEqual([r for r in self.backend.routes[family] if r.get('dev') != m.INTERFACE], external[family])
        self.assertFalse(any(c[:2] == ('nmcli', 'connection') or 'replace' in c for c in self.backend.calls))

    def test_generated_nm_empty_filename_is_allowed_with_flags15(self):
        path = self.generated_profile_fixture(); self.generated_filename = 's ""'
        self.assertTrue(self.tester.recover_preserve_host_network(path)['recovered'])

    def test_generated_nm_saved_foreign_or_symlink_profile_refused(self):
        cases = ('flags', 'persistent_file', 'foreign_run_file', 'symlink', 'owner', 'mode')
        for kind in cases:
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(dir=self.root) as directory:
                old_root = self.root; self.root = Path(directory)
                self.backend = Kernel(); self.tester = m.Tester(self.args, self.backend)
                with patch.object(m, 'RUNROOT', self.root):
                    path = self.generated_profile_fixture()
                    if kind == 'flags': self.generated_flags = 'u 1'
                    if kind == 'persistent_file': self.generated_filename = 's "/etc/NetworkManager/system-connections/eth-test0.nmconnection"'
                    if kind == 'foreign_run_file': self.generated_filename = 's "/run/NetworkManager/system-connections/foreign.nmconnection"'
                    if kind == 'symlink': self.generated_file_mode = stat.S_IFLNK | 0o600
                    if kind == 'owner': self.generated_file_uid = 1000
                    if kind == 'mode': self.generated_file_mode = stat.S_IFREG | 0o644
                    with self.assertRaises(m.Refusal): self.tester.recover_preserve_host_network(path)
                    self.assertTrue(self.backend.ns); self.assertFalse(self.tester.saved['preserve_recovery']['verified'])
                self.root = old_root

    def test_generated_nm_foreign_dns_gateway_routes_rule_or_ipv6_refused(self):
        for key in ('ipv4.dns', 'ipv4.gateway', 'ipv4.routes', 'ipv4.routing-rules',
                    'ipv6.addresses', 'ipv6.routes', 'ipv6.gateway', 'ipv6.dns', 'ipv6.routing-rules'):
            with self.subTest(field=key), tempfile.TemporaryDirectory(dir=self.root) as directory:
                old_root = self.root; self.root = Path(directory)
                self.backend = Kernel(); self.tester = m.Tester(self.args, self.backend)
                with patch.object(m, 'RUNROOT', self.root):
                    path = self.generated_profile_fixture(); self.generated_values[key] = 'FOREIGN'
                    with self.assertRaisesRegex(m.Refusal, 'foreign IP data'):
                        self.tester.recover_preserve_host_network(path)
                    self.assertTrue(self.backend.ns)
                self.root = old_root

    def test_generated_profile_changes_during_certificate_refuse(self):
        path = self.generated_profile_fixture()
        def change(event):
            if event == 'profile': self.generated_flags = 'u 1'
        self.generated_hook = change
        with self.assertRaisesRegex(m.Refusal, 'metadata changed'):
            self.tester.recover_preserve_host_network(path)
        self.assertTrue(self.backend.ns)

    def test_generated_active_connection_must_reference_current_uuid_settings_object(self):
        path = self.generated_profile_fixture()
        self.generated_active_object = 'o "/org/freedesktop/NetworkManager/Settings/999"'
        with self.assertRaisesRegex(m.Refusal, 'active and settings objects do not match'):
            self.tester.recover_preserve_host_network(path)
        self.assertTrue(self.backend.ns)

    def test_multicast_append_external_mutation_is_detected_not_overwritten(self):
        path = self.generated_profile_fixture()
        def change(event):
            if event == 'append': self.backend.routes['6'][0]['gateway'] = 'fe80::99'
        self.generated_hook = change
        with self.assertRaisesRegex(m.Refusal, 'routes outside'):
            self.tester.recover_preserve_host_network(path)
        self.assertEqual(self.backend.routes['6'][0]['gateway'], 'fe80::99'); self.assertTrue(self.backend.ns)

    def test_generated_certificate_only_preserve_host_original_inactive_without_ipv6(self):
        path = self.generated_profile_fixture()
        original_run = self.backend.run
        # Certification cannot become a general UUID whitelist.
        self.tester.preserve_baseline = None
        self.generated = True
        current = self.tester.nm(m.INTERFACE)
        with self.assertRaises(m.Refusal): self.tester.certify_generated_wired_nm(current)
        self.tester.preserve_baseline = {'fixture': True}
        self.tester.saved['nm']['connection_uuid'] = 'original-user-profile'
        with self.assertRaises(m.Refusal): self.tester.certify_generated_wired_nm(current)
        self.tester.saved['nm']['connection_uuid'] = '--'
        self.tester.saved['addresses'][0]['addr_info'].append({'family': 'inet6', 'local': 'fe80::1', 'prefixlen': 64, 'scope': 'link'})
        with self.assertRaises(m.Refusal): self.tester.certify_generated_wired_nm(current)

    def test_dedicated_recovery_original_backup_tamper_refuses_before_network_mutation(self):
        path = self.preserve_fixture()
        self.tester.recover_preserve_host_network(path)
        backup = path.parent / 'snapshot.original.json'
        backup.write_text('{}')
        before = len(self.backend.calls)
        with self.assertRaisesRegex(m.Refusal, 'Original receipt backup differs'):
            self.tester.recover_preserve_host_network(path)
        self.assertEqual(len(self.backend.calls), before)

    def test_inspect_down_interface_carrier_is_unknown_without_sysfs_error_or_mutation(self):
        path = self.recovery_fixture()
        self.backend.links[m.INTERFACE]['flags'].remove('UP')
        self.backend.addr = []
        self.tester.saved['restore_step'] = 'flush_wired_state'; self.tester.persist()
        reads = len(self.backend.carrier_reads)
        before = path.read_bytes()
        result = self.tester.inspect(path)
        self.assertIsNone(result['carrier'])
        self.assertEqual(result['carrier_status'], 'unavailable_interface_down_or_missing')
        self.assertEqual(result['last_restore_step'], 'flush_wired_state')
        self.assertEqual(len(self.backend.carrier_reads), reads)
        self.assertEqual(path.read_bytes(), before)
        self.assertFalse(any('set' in command or 'flush' in command for command in self.backend.calls))

    def test_dedicated_recovery_resumes_actual_down_empty_state_and_checks_real_up_carrier(self):
        path = self.preserve_fixture()
        self.backend.links[m.INTERFACE]['flags'].remove('UP')
        self.backend.addr = []
        for family in ('4', '6'):
            self.backend.routes[family] = [row for row in self.backend.routes[family] if row.get('dev') != m.INTERFACE]
        self.backend.wired_nm = {'managed': 'no', 'autoconnect': False}
        self.backend.carrier_reads.clear()
        result = self.tester.recover_preserve_host_network(path)
        self.assertTrue(result['recovered']); self.assertTrue(result['preserved_host_network'])
        self.assertFalse(self.backend.ns)
        self.assertEqual(m.address_key(self.backend.addr), m.address_key(self.backend.original_addr))
        self.assertTrue(self.backend.carrier_reads)
        self.assertTrue(all('UP' in read['flags'] for read in self.backend.carrier_reads))
        first = self.backend.carrier_reads[0]['call_count']
        prior = self.backend.calls[:first]
        self.assertIn(('nmcli', 'device', 'set', m.INTERFACE, 'managed', 'no'), prior)
        self.assertIn(('nmcli', 'device', 'set', m.INTERFACE, 'autoconnect', 'no'), prior)
        self.assertIn(('ip', 'link', 'set', 'dev', m.INTERFACE, 'up'), prior)
        self.assertFalse(any(command == ('nmcli', 'device', 'set', m.INTERFACE, 'managed', 'yes') for command in prior))
        self.assertGreaterEqual(self.backend.clock, 6)

    def test_down_does_not_imply_unplugged_connected_up_check_keeps_nm_inhibited(self):
        path = self.preserve_fixture()
        self.backend.links[m.INTERFACE]['flags'].remove('UP')
        self.set_carrier('1')
        with self.assertRaisesRegex(m.Refusal, 'Unplug the cable'):
            self.tester.recover_preserve_host_network(path)
        self.assertEqual(self.backend.wired_nm, {'managed': 'no', 'autoconnect': False})
        self.assertTrue(self.backend.ns); self.assertTrue(path.exists())
        self.assertEqual(self.tester.saved['phase'], 'RESTORE_WAITING_UNPLUG')
        self.assertEqual(m.address_key(self.backend.addr), m.address_key(self.backend.original_addr))
        self.assertFalse(any(command == ('nmcli', 'device', 'set', m.INTERFACE, 'autoconnect', 'yes') for command in self.backend.calls))

    def test_up_carrier_read_error_is_not_silently_treated_as_unplugged(self):
        path = self.preserve_fixture()
        original_text = self.backend.text
        def unreadable(path):
            if path.endswith('/carrier'):
                raise OSError(22, 'Invalid argument')
            return original_text(path)
        with patch.object(self.backend, 'text', unreadable), self.assertRaisesRegex(m.Refusal, 'Cannot read actual Ethernet carrier'):
            self.tester.recover_preserve_host_network(path)
        self.assertTrue(self.backend.ns)
        self.assertFalse(any(command == ('nmcli', 'device', 'set', m.INTERFACE, 'managed', 'yes') for command in self.backend.calls))
        self.assertEqual(self.tester.saved['restore_step'], 'verify_wired_carrier_nm_inhibited')


class Protocol(unittest.TestCase):
    def test_only_fixed_phase_and_finish_objects_accepted(self):
        for phase in m.PHASES:
            self.assertEqual(m.request_decode(json.dumps({'action': 'probe', 'phase': phase}).encode() + b'\n')['phase'], phase)
        self.assertEqual(m.request_decode(b'{"action":"finish"}\n'), {'action': 'finish'})
        for payload in (b'{"action":"probe","phase":"$(id)"}\n', b'{"action":"finish","command":"id"}\n',
                        b'{"action":"probe","phase":["baseline"]}\n', b'[]\n',
                        b'{"action":"finish","action":"probe"}\n', b'{"action":"finish"}',
                        b'{"action":"finish"}\n{}\n', b'x' * 513 + b'\n'):
            with self.subTest(payload=payload[:100]), self.assertRaises(m.Refusal):
                m.request_decode(payload)

    def test_receive_rejects_oversize_eof_and_multiple_frames(self):
        for data in (b'x' * 513, b'{"action":"finish"}', b'{}\n{}\n'):
            with self.assertRaises(m.Refusal):
                m.receive_line(Peer(request=data), 512)

    def test_peer_credentials_reject_other_uid_before_reading_request(self):
        server = m.ControlServer.__new__(m.ControlServer)
        server.uid = 1000
        peer = Peer(uid=1001)
        class Listener:
            def accept(self):
                return peer, None
        server.socket = Listener()
        self.assertIsNone(server.accept())
        self.assertTrue(peer.closed)
        self.assertEqual(peer.request, b'{"action":"finish"}\n')
        self.assertFalse(peer.messages[0]['accepted'])

    def test_peer_credentials_allow_only_sudo_uid_and_root(self):
        for uid in (0, 1000):
            server = m.ControlServer.__new__(m.ControlServer)
            server.uid = 1000
            peer = Peer(uid=uid)
            class Listener:
                def accept(self):
                    return peer, None
            server.socket = Listener()
            returned, request = server.accept()
            self.assertIs(returned, peer); self.assertEqual(request, {'action': 'finish'})

    def test_cli_separates_session_control_recovery_and_bounded_timeout(self):
        self.assertEqual(m.arguments(['--session']).timeout, 900)
        self.assertEqual(m.arguments([]).timeout, 120)
        self.assertEqual(m.arguments(['--control', '/run/placeholder', '--phase', 'group']).phase, 'group')
        self.assertTrue(m.arguments(['--inspect', '/run/snapshot.json']).inspect)
        self.assertTrue(m.arguments(['--recover-preserve-host-network', '/run/snapshot.json']).recover_preserve_host_network)
        for argv in (['--timeout', '900'], ['--session', '--timeout', '901'], ['--wait-link', '120'],
                     ['--session', '--wait-link', '121'], ['--control', '/run/placeholder'],
                     ['--control', '/run/placeholder', '--phase', 'direct', '--finish'],
                     ['--control', '/run/placeholder', '--finish', '--session'],
                     ['--recover', '/run/snapshot.json', '--session'],
                     ['--inspect', '/run/snapshot.json', '--recover', '/run/snapshot.json'],
                     ['--inspect', '/run/snapshot.json', '--dry-run'],
                     ['--inspect', '/run/snapshot.json', '--session'],
                     ['--recover-preserve-host-network', '/run/snapshot.json', '--recover', '/run/snapshot.json'],
                     ['--recover-preserve-host-network', '/run/snapshot.json', '--session'],
                     ['--recover-preserve-host-network', '/run/snapshot.json', '--dry-run']):
            with self.subTest(argv=argv), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                m.arguments(argv)

    def test_control_client_checks_private_path_and_root_peer_before_send(self):
        runroot = Path('/fixture-run')
        path = runroot / 'pve-downstream-control-abcdef' / 'control.sock'
        def metadata(item):
            return Namespace(st_mode=(stat.S_IFSOCK | 0o600) if item == path else (stat.S_IFDIR | 0o711),
                             st_uid=1000 if item == path else 0)
        class Client(Peer):
            def __enter__(self):
                return self
            def __exit__(self, *args):
                self.close()
            def connect(self, target):
                self.target = target
        for uid in (0, 1001):
            peer = Client(uid=uid, request=b'{"accepted":true,"restored":true}\n')
            with patch.object(m, 'RUNROOT', runroot), patch.object(Path, 'lstat', metadata), \
                 patch.object(m.os, 'geteuid', lambda: 1000), patch.object(m.socket, 'socket', return_value=peer):
                if uid == 0:
                    result = m.control_request(path, {'action': 'finish'})
                    self.assertTrue(result['restored']); self.assertEqual(peer.messages, [{'action': 'finish'}])
                else:
                    with self.assertRaisesRegex(m.Refusal, 'not root'):
                        m.control_request(path, {'action': 'finish'})
                    self.assertFalse(peer.messages)
            self.assertTrue(peer.closed)

    def test_control_client_rejects_wrong_owner_mode_type_and_caller_before_connect(self):
        runroot = Path('/fixture-run')
        path = runroot / 'pve-downstream-control-abcdef' / 'control.sock'
        cases = [(0o777, 0, stat.S_IFSOCK, 0o600, 1000, 1000),
                 (0o711, 1000, stat.S_IFSOCK, 0o600, 1000, 1000),
                 (0o711, 0, stat.S_IFSOCK, 0o666, 1000, 1000),
                 (0o711, 0, stat.S_IFREG, 0o600, 1000, 1000),
                 (0o711, 0, stat.S_IFSOCK, 0o600, 1000, 1001)]
        for parent_mode, parent_uid, kind, mode, uid, caller in cases:
            def metadata(item):
                return Namespace(st_mode=kind | mode if item == path else stat.S_IFDIR | parent_mode,
                                 st_uid=uid if item == path else parent_uid)
            with self.subTest(case=(parent_mode, parent_uid, kind, mode, uid, caller)), \
                 patch.object(m, 'RUNROOT', runroot), patch.object(Path, 'lstat', metadata), \
                 patch.object(m.os, 'geteuid', lambda: caller), \
                 patch.object(m.socket, 'socket', side_effect=AssertionError('socket must not be opened')):
                with self.assertRaisesRegex(m.Refusal, 'ownership/permissions'):
                    m.control_request(path, {'action': 'finish'})

    def test_server_creation_sets_traverse_only_directory_and_owner_only_socket(self):
        calls = []
        class Listener:
            def bind(self, path): calls.append(('bind', path))
            def listen(self, backlog): calls.append(('listen', backlog))
            def settimeout(self, timeout): calls.append(('timeout', timeout))
            def close(self): calls.append(('close',))
        directory = Path('/fixture-run/pve-downstream-control-abcdef')
        with patch.object(m.socket, 'socket', return_value=Listener()), \
             patch.object(m.os, 'chmod', side_effect=lambda path, mode, **kwargs: calls.append(('chmod', str(path), mode))), \
             patch.object(m.os, 'chown', side_effect=lambda path, uid, gid: calls.append(('chown', str(path), uid, gid))):
            server = m.ControlServer(directory, 1000)
            server.close()
        self.assertIn(('chmod', str(directory), 0o711), calls)
        self.assertIn(('chmod', str(directory / 'control.sock'), 0o600), calls)
        self.assertIn(('chown', str(directory / 'control.sock'), 1000, -1), calls)
        self.assertLess(calls.index(('chmod', str(directory / 'control.sock'), 0o600)), calls.index(('listen', 4)))


if __name__ == '__main__':
    unittest.main(verbosity=2)
