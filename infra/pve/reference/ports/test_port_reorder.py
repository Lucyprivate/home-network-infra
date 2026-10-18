#!/usr/bin/python3
"""Private local fixtures: no subprocess, socket, PVE or host network access.

The fake kernel implements a successful reload plus injected partial failures.
It intentionally does not decide whether any script safety gate should pass.
"""
import copy
import importlib.machinery
import importlib.util
import io
import json
import re
import socket
import subprocess
import tempfile
import unittest
from contextlib import ExitStack, redirect_stdout
from pathlib import Path
from unittest.mock import patch

SCRIPT = Path(__file__).with_name('pve-port-reorder')
loader = importlib.machinery.SourceFileLoader('port_reorder_fixture', str(SCRIPT))
spec = importlib.util.spec_from_loader(loader.name, loader)
m = importlib.util.module_from_spec(spec)
loader.exec_module(m)

BASE = '''auto lo
iface lo inet loopback

# ETH0 - WAN; production VM bridge
iface enp2s0 inet manual
auto vmbr0
iface vmbr0 inet manual
        bridge-ports enp2s0
        bridge-stp off
        bridge-fd 0

# ETH1 - LAN; production VM bridge
iface enp3s0 inet manual
auto vmbr1
iface vmbr1 inet static
        address 10.10.20.10/24
        bridge-ports enp3s0
        bridge-stp off
        bridge-fd 0

# ETH2 - current direct management
iface enp4s0 inet manual
auto vmbr2
iface vmbr2 inet static
        address 10.10.99.10/24
        gateway 10.10.99.2
        bridge-ports enp4s0
        bridge-stp off
        bridge-fd 0

iface enp5s0 inet manual

source /etc/network/interfaces.d/*
'''
INITIAL_SESSION = '10.10.99.55 40001 10.10.99.10 22'
FRESH_SESSION = '10.10.99.55 40002 10.10.99.10 22'


def addr(name, *items):
    return {'ifname': name, 'addr_info': [
        {'family': 'inet', 'local': ip, 'prefixlen': prefix, 'scope': 'global'}
        for ip, prefix in items]}


class RawSocket:
    def __init__(self, fixture):
        self.fixture = fixture
        self.bound = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def bind(self, address):
        self.bound = address

    def send(self, packet):
        self.fixture.packets.append((self.bound, packet))
        return len(packet)


class PortTransactions(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.temp = self.stack.enter_context(tempfile.TemporaryDirectory(prefix='port-fixture-'))
        self.base = Path(self.temp)
        replacements = {
            'ROOT': self.base / 'state', 'UNITS': self.base / 'units',
            'NET': self.base / 'interfaces', 'PENDING': self.base / 'interfaces.new',
            'RA': self.base / 'bridge-ra.conf', 'DNS': self.base / 'resolv.conf',
            'HOSTS': self.base / 'hosts', 'SYSNET': self.base / 'sysnet',
            'SYSCTL': self.base / 'sysctl',
        }
        for key, value in replacements.items():
            self.stack.enter_context(patch.object(m, key, value))
        self.stack.enter_context(patch.object(m, 'FILES', (m.NET, m.PENDING, m.RA, m.DNS, m.HOSTS)))
        protected_paths = tuple(str(self.base / ('protected-' + str(i))) for i in range(5))
        self.stack.enter_context(patch.object(m, 'PROTECTED', protected_paths))
        for i, path in enumerate(protected_paths):
            Path(path).write_text('unchanged production fixture ' + str(i) + '\n')
        self.modprobe = self.base / 'modprobe.d'
        self.modprobe.mkdir()
        (self.modprobe / 'fixture.conf').write_text('options fixture inert=1\n')
        original_glob = Path.glob

        def glob(path, pattern, *args, **kwargs):
            if str(path) == '/etc/modprobe.d':
                return original_glob(self.modprobe, pattern, *args, **kwargs)
            if not path.is_relative_to(self.base):
                raise AssertionError('Glob outside private fixture: ' + str(path))
            return original_glob(path, pattern, *args, **kwargs)

        self.stack.enter_context(patch.object(Path, 'glob', glob))
        m.NET.write_text(BASE)
        m.DNS.write_text('# fixture resolver\nsearch fixture.invalid\nnameserver 10.10.99.2\n')
        m.HOSTS.write_text('127.0.0.1 localhost\n10.10.99.10 pve\n')
        for path in (m.NET, m.DNS, m.HOSTS):
            path.chmod(0o644)
        self.now = 1000
        self.routes = [{'dst': 'default', 'dev': 'vmbr2', 'gateway': '10.10.99.2',
                        'protocol': 'kernel', 'metric': 0}]
        self.rows = [addr('lo', ('127.0.0.1', 8)), addr('vmbr0'),
                     addr('vmbr1', ('10.10.20.10', 24)), addr('vmbr2', (m.IP, 24)),
                     addr('enp4s0'), addr('enp5s0')]
        self.saved_rows = copy.deepcopy(self.rows)
        self.saved_routes = copy.deepcopy(self.routes)
        self.commands, self.events, self.packets = [], [], []
        self.armed = set()
        self.reload_fault = None
        self.ifquery_result = None
        self.fdb = []
        for dev, mac in m.MACS.items():
            directory = m.SYSNET / dev
            directory.mkdir(parents=True)
            (directory / 'address').write_text(mac + '\n')
            (directory / 'flags').write_text('0x1\n' if dev != 'enp5s0' else '0x0\n')
            (directory / 'carrier').write_text('1\n' if dev == 'enp4s0' else '0\n')
        for dev, mac in [('vmbr0', m.MACS['enp2s0']), ('vmbr1', m.MACS['enp3s0']),
                         ('vmbr2', m.MACS['enp4s0']), ('vmbr3', m.MACS['enp5s0'])]:
            directory = m.SYSNET / dev
            directory.mkdir(parents=True)
            (directory / 'address').write_text(mac + '\n')
        self.set_ports('vmbr0', ['enp2s0'])
        self.set_ports('vmbr1', ['enp3s0'])
        self.set_ports('vmbr2', ['enp4s0'])
        self.set_ports('vmbr3', [])
        for dev in ('vmbr0', 'vmbr1', 'vmbr2', 'vmbr3', 'enp4s0', 'enp5s0'):
            directory = m.SYSCTL / dev
            directory.mkdir(parents=True)
            for key in ('accept_ra', 'accept_ra_defrtr'):
                (directory / key).write_text('1\n')
        self.stack.enter_context(patch.dict(m.os.environ, {'SSH_CONNECTION': INITIAL_SESSION}))
        self.stack.enter_context(patch.object(m.time, 'time', lambda: self.now))
        self.stack.enter_context(patch.object(m.time, 'sleep', lambda duration: None))
        self.stack.enter_context(patch.object(m, 'run', self.fake_run))
        self.stack.enter_context(patch.object(m, 'cleanup', self.fake_cleanup))
        self.stack.enter_context(patch.object(m.subprocess, 'run', side_effect=AssertionError('REAL subprocess forbidden')))
        self.stack.enter_context(patch.object(m.socket, 'socket', lambda *args, **kwargs: RawSocket(self)))
        original_read = Path.read_text

        def read_text(path, *args, **kwargs):
            if str(path) == '/proc/sys/kernel/random/boot_id':
                return 'fixture-boot-id\n'
            if not path.is_relative_to(self.base):
                raise AssertionError('Read outside private fixture: ' + str(path))
            return original_read(path, *args, **kwargs)

        self.stack.enter_context(patch.object(Path, 'read_text', read_text))
        original_read_bytes = Path.read_bytes

        def read_bytes(path):
            if not path.is_relative_to(self.base):
                raise AssertionError('Read bytes outside private fixture: ' + str(path))
            return original_read_bytes(path)

        self.stack.enter_context(patch.object(Path, 'read_bytes', read_bytes))

    def quiet(self, function, *args):
        with redirect_stdout(io.StringIO()):
            return function(*args)

    def set_ports(self, bridge, devices):
        directory = m.SYSNET / bridge / 'brif'
        directory.mkdir(parents=True, exist_ok=True)
        for child in directory.iterdir():
            child.unlink()
        for dev in devices:
            (directory / dev).touch()

    def cable_eth3(self):
        (m.SYSNET / 'enp4s0' / 'carrier').write_text('0\n')
        (m.SYSNET / 'enp5s0' / 'carrier').write_text('1\n')
        self.fdb = [{'mac': m.CLIENT_MAC, 'ifname': 'enp5s0', 'state': 'reachable'}]

    def fake_cleanup(self, transaction):
        self.events.append(('cleanup', transaction, m.state()['phase']))
        self.armed.discard(transaction)
        for suffix in ('.timer', '.service'):
            (m.UNITS / (m.unit(transaction) + suffix)).unlink(missing_ok=True)

    def fake_reload(self):
        text = m.NET.read_text()
        self.rows = copy.deepcopy(self.saved_rows)
        self.routes = copy.deepcopy(self.saved_routes)
        if '\niface vmbr3 inet static\n' in text:
            for row in self.rows:
                if row['ifname'] == 'vmbr2':
                    row['addr_info'] = []
            self.rows.append(addr('vmbr3', (m.IP, 24)))
            self.routes = []
            self.set_ports('vmbr2', ['enp4s0'])
            self.set_ports('vmbr3', ['enp5s0'])
        else:
            dual = 'bridge-ports enp4s0 enp5s0\n' in text
            self.set_ports('vmbr2', ['enp4s0', 'enp5s0'] if dual else ['enp4s0'])
            self.set_ports('vmbr3', [])
        self.events.append(('reload',))
        if self.reload_fault:
            self.reload_fault()

    def fake_run(self, argv, check=True, timeout=70):
        self.commands.append(tuple(argv))
        output = ''
        if argv == ['ip', '-j', '-4', 'addr', 'show']:
            output = json.dumps(self.rows)
        elif argv == ['ip', '-j', '-4', 'route', 'show', 'default']:
            output = json.dumps(self.routes)
        elif argv == ['bridge', '-j', 'fdb', 'show', 'br', 'vmbr2']:
            output = json.dumps(self.fdb)
        elif argv[0] == 'ifquery':
            candidate = Path(argv[2]).read_text()
            # The live ifquery --list reports auto interfaces only.
            output = self.ifquery_result or 'lo vmbr0 vmbr1 vmbr2' + (
                ' vmbr3\n' if '\niface vmbr3 inet static\n' in candidate else '\n')
        elif argv == ['ifreload', '-a']:
            self.fake_reload()
        elif argv[:4] == ['ip', '-4', 'addr', 'del']:
            address, dev = argv[4].split('/')[0], argv[6]
            for row in self.rows:
                if row['ifname'] == dev:
                    row['addr_info'] = [item for item in row['addr_info'] if item['local'] != address]
            self.events.append(('delete-address', dev, address))
        elif argv[:4] == ['ip', '-4', 'route', 'del']:
            self.routes = [route for route in self.routes if not (
                route.get('gateway') == argv[6] and route.get('dev') == argv[8])]
        elif argv[:3] == ['ip', 'link', 'set']:
            self.assertEqual(argv[-1], 'down')
            (m.SYSNET / argv[4] / 'flags').write_text('0x0\n')
        elif argv[0] == 'systemctl':
            if argv[1:3] == ['enable', '--now']:
                name = argv[-1].removeprefix('codex-pve-port-').removesuffix('.timer')
                self.armed.add(name)
                self.events.append(('arm', name))
            elif argv[1] == 'is-active':
                output = 'active\n'
            elif argv[1] != 'daemon-reload':
                raise AssertionError('Unexpected systemctl operation: ' + repr(argv))
        elif argv[0] == 'systemd-run':
            self.events.append(('schedule-apply', argv[-1]))
        else:
            raise AssertionError('Unexpected external operation: ' + repr(argv))
        return subprocess.CompletedProcess(argv, 0, output, '')

    def start_expand(self, apply=True, confirm=False):
        self.quiet(m.begin, 'expand')
        transaction = m.state()['transaction']
        if apply:
            self.quiet(m.apply, transaction)
        if confirm:
            m.os.environ['SSH_CONNECTION'] = FRESH_SESSION
            self.quiet(m.confirm)
        return transaction

    def start_final(self, apply=True):
        self.start_expand(confirm=True)
        self.cable_eth3()
        m.os.environ['SSH_CONNECTION'] = '10.10.99.55 40003 10.10.99.10 22'
        self.quiet(m.begin, 'final')
        transaction = m.state()['transaction']
        if apply:
            self.quiet(m.apply, transaction)
        return transaction

    def assert_armed_pending(self, transaction):
        self.assertIn(transaction, self.armed)
        self.assertTrue(m.state()['phase'].endswith('-pending'))

    def test_expand_preserves_wan_lan_addresses_and_default(self):
        prefix = m.immutable_prefix(BASE)
        before = copy.deepcopy(self.rows)
        transaction = self.start_expand()
        self.assertEqual(m.immutable_prefix(m.NET.read_text()), prefix)
        self.assertEqual(m.address_set(self.rows), m.address_set(before))
        self.assertEqual(m.route_set(self.routes), m.route_set(self.saved_routes))
        self.assertEqual(m.ports('vmbr0'), ['enp2s0'])
        self.assertEqual(m.ports('vmbr1'), ['enp3s0'])
        self.assertEqual(m.ports('vmbr2'), ['enp4s0', 'enp5s0'])
        self.assert_armed_pending(transaction)
        self.assertLess([event[0] for event in self.events].index('arm'),
                        [event[0] for event in self.events].index('schedule-apply'))

    def test_final_one_rescue_owner_no_default_or_dns(self):
        prefix = m.immutable_prefix(BASE)
        transaction = self.start_final()
        self.assertEqual(m.owners(), ['vmbr3'])
        self.assertEqual(m.ports('vmbr2'), ['enp4s0'])
        self.assertEqual(m.ports('vmbr3'), ['enp5s0'])
        self.assertEqual(m.owners('10.10.10.10'), [])
        self.assertEqual(self.routes, [])
        self.assertNotRegex(m.DNS.read_text(), r'(?m)^\s*nameserver\s')
        self.assertIn('search fixture.invalid', m.DNS.read_text())
        self.assertEqual(m.immutable_prefix(m.NET.read_text()), prefix)
        self.assert_armed_pending(transaction)
        self.assertIn(('delete-address', 'vmbr2', m.IP), self.events)

    def test_rollback_final_restores_dual_baseline_before_timer_disarm(self):
        transaction = self.start_final()
        snap = m.manifest(transaction)
        self.quiet(m.rollback, transaction)
        self.assertEqual(m.state()['phase'], 'expand-confirmed')
        self.assertEqual(m.owners(), ['vmbr2'])
        self.assertEqual(m.ports('vmbr2'), ['enp4s0', 'enp5s0'])
        self.assertEqual(m.address_set(self.rows), m.address_set(snap['ipv4_before']))
        self.assertEqual(m.route_set(self.routes), m.route_set(snap['routes_before']))
        self.assertTrue(m.files_match(snap))
        self.assertNotIn(transaction, self.armed)
        self.assertEqual(self.events[-1], ('cleanup', transaction, 'expand-confirmed'))
        self.assertIn(('delete-address', 'vmbr3', m.IP), self.events)

    def test_rollback_expand_restores_eth2_only_and_link_flags(self):
        transaction = self.start_expand()
        (m.SYSNET / 'enp5s0' / 'flags').write_text('0x1\n')
        self.quiet(m.rollback, transaction)
        self.assertEqual(m.state()['phase'], 'initial')
        self.assertEqual(m.ports('vmbr2'), ['enp4s0'])
        self.assertEqual((m.SYSNET / 'enp5s0' / 'flags').read_text().strip(), '0x0')
        self.assertEqual(m.NET.read_text(), BASE)

    def test_confirmation_rejects_same_tcp_and_accepts_new_tcp(self):
        transaction = self.start_expand()
        with self.assertRaisesRegex(m.Refusal, 'fresh TCP'):
            self.quiet(m.confirm)
        self.assert_armed_pending(transaction)
        m.os.environ['SSH_CONNECTION'] = FRESH_SESSION
        self.quiet(m.confirm)
        self.assertEqual(m.state()['phase'], 'expand-confirmed')
        self.assertNotIn(transaction, self.armed)

    def test_confirmation_deadline_does_not_disarm_timer(self):
        transaction = self.start_expand()
        m.os.environ['SSH_CONNECTION'] = FRESH_SESSION
        self.now = m.state()['deadline_unix']
        with self.assertRaisesRegex(m.Refusal, 'deadline'):
            self.quiet(m.confirm)
        self.assert_armed_pending(transaction)

    def test_begin_rejects_gui_pending_without_arming(self):
        m.PENDING.write_text('GUI pending fixture\n')
        with self.assertRaisesRegex(m.Refusal, 'pending PVE GUI'):
            self.quiet(m.begin, 'expand')
        self.assertFalse(self.armed)
        self.assertEqual(m.NET.read_text(), BASE)

    def test_apply_rejects_gui_pending_added_after_staging(self):
        transaction = self.start_expand(apply=False)
        m.PENDING.write_text('GUI pending after begin\n')
        with self.assertRaises(m.Refusal):
            self.quiet(m.apply, transaction)
        self.assertEqual(m.NET.read_text(), BASE)
        self.assertNotIn(('reload',), self.events)
        self.assert_armed_pending(transaction)

    def test_apply_rejects_owned_file_concurrent_edit(self):
        transaction = self.start_expand(apply=False)
        m.DNS.write_text('nameserver 203.0.113.5\n')
        with self.assertRaisesRegex(m.Refusal, 'Managed files changed'):
            self.quiet(m.apply, transaction)
        self.assertEqual(m.NET.read_text(), BASE)
        self.assert_armed_pending(transaction)

    def test_apply_rejects_owned_file_mode_change(self):
        transaction = self.start_expand(apply=False)
        m.DNS.chmod(0o600)
        with self.assertRaisesRegex(m.Refusal, 'Managed files changed'):
            self.quiet(m.apply, transaction)
        self.assertEqual(m.NET.read_text(), BASE)
        self.assert_armed_pending(transaction)

    def test_begin_expand_rejects_wrong_cable(self):
        self.cable_eth3()
        with self.assertRaisesRegex(m.Refusal, 'ETH2-only'):
            self.quiet(m.begin, 'expand')
        self.assertFalse(self.armed)

    def test_begin_expand_rejects_occupied_eth3(self):
        next(row for row in self.rows if row['ifname'] == 'enp5s0')['addr_info'] = addr(
            'unused', ('198.51.100.9', 24))['addr_info']
        with self.assertRaisesRegex(m.Refusal, 'already has IPv4'):
            self.quiet(m.begin, 'expand')
        self.assertFalse(self.armed)

    def test_begin_rejects_physical_mac_mismatch(self):
        (m.SYSNET / 'enp5s0' / 'address').write_text('02:00:00:00:00:01\n')
        with self.assertRaisesRegex(m.Refusal, 'Physical MAC'):
            self.quiet(m.begin, 'expand')
        self.assertFalse(self.armed)

    def test_final_rejects_two_connected_management_ports(self):
        self.start_expand(confirm=True)
        (m.SYSNET / 'enp5s0' / 'carrier').write_text('1\n')
        with self.assertRaisesRegex(m.Refusal, 'Move only'):
            self.quiet(m.begin, 'final')
        self.assertEqual(m.state()['phase'], 'expand-confirmed')

    def test_final_rejects_static_or_wrong_fdb_entry(self):
        self.start_expand(confirm=True)
        self.cable_eth3()
        for entry in [
            {'mac': m.CLIENT_MAC, 'ifname': 'enp4s0', 'state': 'reachable'},
            {'mac': m.CLIENT_MAC, 'ifname': 'enp5s0', 'state': 'permanent'},
            {'mac': '02:00:00:00:00:99', 'ifname': 'enp5s0', 'state': 'reachable'},
        ]:
            self.fdb = [entry]
            with self.subTest(entry=entry), self.assertRaisesRegex(m.Refusal, 'not learned'):
                self.quiet(m.begin, 'final')
        self.assertEqual(m.state()['phase'], 'expand-confirmed')

    def test_apply_protected_change_refuses_before_network_write(self):
        transaction = self.start_expand(apply=False)
        Path(m.PROTECTED[0]).write_text('concurrent VM edit\n')
        with self.assertRaisesRegex(m.Refusal, 'Protected'):
            self.quiet(m.apply, transaction)
        self.assertEqual(m.NET.read_text(), BASE)
        self.assertNotIn(('reload',), self.events)
        self.assert_armed_pending(transaction)

    def test_confirm_protected_change_keeps_timer(self):
        transaction = self.start_expand()
        m.os.environ['SSH_CONNECTION'] = FRESH_SESSION
        Path(m.PROTECTED[2]).write_text('concurrent VFIO edit\n')
        with self.assertRaisesRegex(m.Refusal, 'Protected'):
            self.quiet(m.confirm)
        self.assert_armed_pending(transaction)

    def test_new_modprobe_file_is_protected_change(self):
        transaction = self.start_expand(apply=False)
        (self.modprobe / 'new.conf').write_text('options fixture changed=1\n')
        with self.assertRaisesRegex(m.Refusal, 'Protected'):
            self.quiet(m.apply, transaction)
        self.assertEqual(m.NET.read_text(), BASE)
        self.assert_armed_pending(transaction)

    def test_verify_rejects_guest_bridge_members_changed(self):
        transaction = self.start_expand()
        self.set_ports('vmbr1', ['enp3s0', 'enp4s0'])
        with self.assertRaisesRegex(m.Refusal, 'Guest bridge'):
            m.verify('expand', m.manifest(transaction))
        self.assert_armed_pending(transaction)

    def test_verify_rejects_wan_lan_runtime_address_loss(self):
        transaction = self.start_expand()
        next(row for row in self.rows if row['ifname'] == 'vmbr1')['addr_info'] = []
        with self.assertRaises(m.Refusal):
            m.verify('expand', m.manifest(transaction))
        self.assert_armed_pending(transaction)

    def test_final_rejects_duplicate_rescue_or_active_management_address(self):
        transaction = self.start_final()
        snap = m.manifest(transaction)
        self.rows.append(addr('rogue', (m.IP, 24)))
        with self.assertRaisesRegex(m.Refusal, 'address owner'):
            m.verify('final', snap)
        self.rows.pop()
        self.rows.append(addr('vmbr2', ('10.10.10.10', 24)))
        with self.assertRaisesRegex(m.Refusal, 'address owner'):
            m.verify('final', snap)
        self.assert_armed_pending(transaction)

    def test_final_rejects_default_or_dns_or_wrong_bridge_mac(self):
        transaction = self.start_final()
        snap = m.manifest(transaction)
        self.routes = [{'dst': 'default', 'gateway': '192.0.2.1', 'dev': 'vmbr0'}]
        with self.assertRaisesRegex(m.Refusal, 'default route'):
            m.verify('final', snap)
        self.routes = []
        m.DNS.write_text('nameserver 192.0.2.53\n')
        with self.assertRaisesRegex(m.Refusal, 'no nameserver'):
            m.verify('final', snap)
        m.DNS.write_text('# no upstream\n')
        (m.SYSNET / 'vmbr3' / 'address').write_text('02:00:00:00:00:09\n')
        with self.assertRaisesRegex(m.Refusal, 'MAC differs'):
            m.verify('final', snap)
        self.assert_armed_pending(transaction)

    def test_rollback_failed_routes_keeps_timer_and_pending_state(self):
        transaction = self.start_final()
        self.reload_fault = lambda: self.routes.clear()
        with self.assertRaisesRegex(m.Refusal, 'defaults differ'):
            self.quiet(m.rollback, transaction)
        self.assert_armed_pending(transaction)
        self.assertNotEqual(self.events[-1][0], 'cleanup')
        self.reload_fault = None
        self.quiet(m.rollback, transaction)
        self.assertNotIn(transaction, self.armed)

    def test_rollback_failed_lan_address_keeps_timer(self):
        transaction = self.start_final()

        def lose_lan():
            next(row for row in self.rows if row['ifname'] == 'vmbr1')['addr_info'] = []

        self.reload_fault = lose_lan
        with self.assertRaisesRegex(m.Refusal, 'IPv4 addresses differ'):
            self.quiet(m.rollback, transaction)
        self.assert_armed_pending(transaction)

    def test_rollback_failed_file_restore_keeps_timer(self):
        transaction = self.start_final()
        self.reload_fault = lambda: m.DNS.write_text('nameserver 203.0.113.53\n')
        with self.assertRaisesRegex(m.Refusal, 'files/defaults differ'):
            self.quiet(m.rollback, transaction)
        self.assert_armed_pending(transaction)

    def test_rollback_failed_membership_keeps_timer(self):
        transaction = self.start_final()
        self.reload_fault = lambda: self.set_ports('vmbr2', ['enp4s0'])
        with self.assertRaisesRegex(m.Refusal, 'Rollback port membership'):
            self.quiet(m.rollback, transaction)
        self.assert_armed_pending(transaction)

    def test_rollback_failed_protected_check_keeps_timer(self):
        transaction = self.start_final()
        Path(m.PROTECTED[1]).write_text('concurrent protected VM edit\n')
        with self.assertRaisesRegex(m.Refusal, 'Protected'):
            self.quiet(m.rollback, transaction)
        self.assert_armed_pending(transaction)

    def test_manual_original_rollback_on_eth3_refuses_without_changes(self):
        self.start_expand(confirm=True)
        self.cable_eth3()
        before = m.NET.read_bytes()
        commands_before = len(self.commands)
        with self.assertRaisesRegex(m.Refusal, 'requires the PC cable on ETH2'):
            self.quiet(m.rollback)
        self.assertEqual(m.NET.read_bytes(), before)
        self.assertEqual(m.state()['phase'], 'expand-confirmed')
        self.assertFalse(any(command[0] in ('ifreload', 'ip')
                             for command in self.commands[commands_before:]))

    def test_stale_expand_timer_cannot_revert_final_pending(self):
        transaction = self.start_final()
        old = next(event[1] for event in self.events if event[0] == 'arm' and event[1].startswith('expand-'))
        before = m.NET.read_bytes()
        self.quiet(m.rollback, old)
        self.assertEqual(m.NET.read_bytes(), before)
        self.assertEqual(m.owners(), ['vmbr3'])
        self.assert_armed_pending(transaction)

    def test_ifreload_failure_leaves_rollback_armed(self):
        transaction = self.start_expand(apply=False)

        def fail_reload():
            raise subprocess.TimeoutExpired(['ifreload', '-a'], 70)

        self.reload_fault = fail_reload
        with self.assertRaises(subprocess.TimeoutExpired):
            self.quiet(m.apply, transaction)
        self.assert_armed_pending(transaction)
        self.reload_fault = None
        self.quiet(m.rollback, transaction)
        self.assertEqual(m.state()['phase'], 'initial')

    def test_bad_ifquery_listing_refuses_before_arm(self):
        self.ifquery_result = 'lo vmbr2 vmbr2\n'
        with self.assertRaisesRegex(m.Refusal, 'Candidate interface'):
            self.quiet(m.begin, 'expand')
        self.assertFalse(self.armed)
        self.assertEqual(m.NET.read_text(), BASE)

    def test_candidate_mac_format_and_port_ownership(self):
        text = m.final_candidate(m.expand_candidate(BASE))
        rows = re.findall(r'^\s*hwaddress\s+(.+)$', text, re.M)
        self.assertEqual(len(rows), 2)
        for value, expected in zip(rows, [m.MACS['enp4s0'], m.MACS['enp5s0']]):
            # Official ifupdown2 utils.strip_hwaddress permits the ether prefix.
            normalized = value[5:].strip() if value.startswith('ether') else value
            self.assertRegex(normalized, r'^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$')
            self.assertEqual(normalized, expected)
        self.assertEqual(m.immutable_prefix(text), m.immutable_prefix(BASE))

    def test_malformed_candidate_inputs_refused(self):
        for text in [BASE.replace('# ETH2 -', '# renamed -'),
                     BASE.replace('gateway 10.10.99.2', 'gateway 10.10.99.9'),
                     BASE.replace('bridge-ports enp4s0', 'bridge-ports enp4s0 enp3s0')]:
            with self.subTest(text=text), self.assertRaises(m.Refusal):
                m.final_candidate(m.expand_candidate(text))
        with self.assertRaises(m.Refusal):
            m.final_candidate(m.expand_candidate(BASE) + 'auto unexpected\n')

    def test_raw_arp_is_local_mock_and_correct_rescue_address(self):
        self.start_final()
        final_packets = [packet for bind, packet in self.packets if bind == ('vmbr3', 0)]
        self.assertEqual(len(final_packets), 3)
        expected_mac = bytes.fromhex(m.MACS['enp5s0'].replace(':', ''))
        for packet in final_packets:
            self.assertEqual(packet[:6], b'\xff' * 6)
            self.assertEqual(packet[6:12], expected_mac)
            self.assertEqual(packet[28:32], socket.inet_aton(m.IP))
            self.assertEqual(packet[38:42], socket.inet_aton(m.IP))


if __name__ == '__main__':
    unittest.main(verbosity=2)
