#!/usr/bin/env python3
"""Local mocks only: never runs ip/ifreload/systemctl or opens raw sockets."""
import argparse
import importlib.machinery
import importlib.util
import json
import os
import socket
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

loader = importlib.machinery.SourceFileLoader('uplink', str(Path(__file__).with_name('pve-uplink-switch')))
spec = importlib.util.spec_from_loader(loader.name, loader)
m = importlib.util.module_from_spec(spec)
loader.exec_module(m)
REAL_ARM_TIMER = m.arm_timer

ORIGINAL = '''auto lo
iface lo inet loopback

iface enp2s0 inet manual
iface enp3s0 inet manual
iface enp4s0 inet manual
iface enp5s0 inet manual

auto vmbr0
iface vmbr0 inet manual
    bridge-ports enp2s0
    bridge-stp off
    bridge-fd 0

auto vmbr1
iface vmbr1 inet manual
    bridge-ports enp3s0
    bridge-stp off
    bridge-fd 0

auto vmbr2
iface vmbr2 inet manual
    hwaddress ether 02:00:00:00:10:02
    bridge-ports enp4s0
    bridge-stp off
    bridge-fd 0

auto vmbr3
iface vmbr3 inet static
    address 10.10.99.10/24
    hwaddress ether 02:00:00:00:10:03
    bridge-ports enp5s0
    bridge-stp off
    bridge-fd 0

source /etc/network/interfaces.d/*
'''


class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.events = []
        for constant, relative in [('INTERFACES', 'interfaces'), ('PENDING', 'interfaces.new'),
                                   ('RA_FILE', 'bridge-ra.conf'), ('RESOLVER', 'resolv.conf'),
                                   ('HOSTS', 'hosts'), ('STATE_DIR', 'state'), ('UNITS', 'units'),
                                   ('SYSNET', 'sysnet'), ('SYSCTL_DIR', 'sysctl')]:
            self.addCleanup(patch.stopall)
            patch.object(m, constant, self.root / relative).start()
        m.STATE_DIR.mkdir()
        m.UNITS.mkdir()
        physical = m.SYSNET / m.UPLINK
        physical.mkdir(parents=True)
        (physical / 'address').write_text(m.MAC + '\n')
        (physical / 'carrier').write_text('1\n')
        (physical / 'flags').write_text('0x1003\n')
        for port, bridge, mac in ((m.UPLINK, m.MANAGEMENT, m.MAC),
                                 (m.RESCUE_PORT, m.RESCUE, m.RESCUE_MAC)):
            (m.SYSNET / bridge).mkdir(parents=True)
            (m.SYSNET / bridge / 'address').write_text(mac + '\n')
            (m.SYSNET / port).mkdir(parents=True, exist_ok=True)
            (m.SYSNET / port / 'address').write_text(mac + '\n')
            (m.SYSNET / port / 'master').symlink_to(m.SYSNET / bridge, target_is_directory=True)
        ra = m.SYSCTL_DIR / m.UPLINK
        ra.mkdir(parents=True)
        (ra / 'accept_ra').write_text('1\n')
        (ra / 'accept_ra_defrtr').write_text('1\n')
        m.INTERFACES.write_text(ORIGINAL)
        self.initial_ra = '# reordered offline baseline\nnet.ipv6.conf.vmbr3.accept_ra=0\n'
        m.RA_FILE.write_text(self.initial_ra)
        m.RESOLVER.write_text('search local\n')
        m.HOSTS.write_text('127.0.0.1 localhost\n10.10.99.10 hypervisor.example.test pve\n::1 localhost ip6-localhost\n')
        self.run_patch = patch.object(m, 'run', side_effect=self.fake_run)
        self.run_mock = self.run_patch.start()
        self.cleanup_mock = patch.object(m, 'cleanup_timer', side_effect=lambda *a, **k: self.events.append('cleanup')).start()
        patch.object(m, 'arm_timer', side_effect=lambda *a: self.events.append('timer')).start()
        patch.dict(os.environ, {'SSH_CONNECTION': '10.10.99.20 45000 10.10.99.10 22'}).start()

    def fake_run(self, argv, **kwargs):
        if argv[0] == 'ifquery':
            text = Path(argv[2]).read_text()
            names = [stanza[0] for stanza in m.current_stanzas(text)]
            output = '\n'.join(names) + '\n'
        elif argv == ['ip', '-j', '-4', 'route', 'show', 'default']:
            if 'gateway 10.10.10.1' in m.INTERFACES.read_text():
                output = json.dumps([{'dev': m.MANAGEMENT, 'gateway': m.NEW_GATEWAY}])
            else:
                output = '[]'
        elif argv == ['ip', '-j', '-6', 'route', 'show', 'default']:
            output = '[]'
        elif argv[:5] == ['ip', '-j', '-4', 'addr', 'show']:
            config = m.INTERFACES.read_text()
            address = m.RESCUE_IP if argv[-1] == m.RESCUE else m.NEW_IP if argv[-1] == m.MANAGEMENT and 'address ' + m.NEW_IP + '/24' in config else None
            output = json.dumps([{'addr_info': [{'local': address, 'prefixlen': 24}] if address else []}])
        elif argv == ['ifreload', '-a']:
            self.events.append('ifreload')
            output = ''
        elif argv[:2] == ['getent', 'ahostsv4']:
            output = (m.NEW_IP if argv[2] in ('pve', 'hypervisor.example.test') else '203.0.113.83') + ' STREAM\n'
        else:
            output = ''
        return argparse.Namespace(returncode=0, stdout=output, stderr='')

    def args(self, command, reserved=False):
        return argparse.Namespace(command=command, address_reserved=reserved, transaction=None)

    def staged(self):
        m.begin_phase('stage', m.read_state(), m.stage_candidate(ORIGINAL))
        with patch.dict(os.environ, {'SSH_CONNECTION': '10.10.10.20 46000 10.10.10.10 22'}):
            m.execute(self.args('confirm-stage'))
        return m.read_state()

    def test_candidate_preserves_existing_bridges_and_rescue(self):
        candidate = m.stage_candidate(ORIGINAL)
        def block(text, name):
            stanza = next(s for s in m.current_stanzas(text) if s[0] == name)
            return text[stanza[3]:stanza[4]]
        for bridge in ('vmbr0', 'vmbr1', 'vmbr3'):
            self.assertEqual(block(candidate, bridge), block(ORIGINAL, bridge))
        self.assertEqual(candidate.count('iface vmbr3'), 1)
        self.assertEqual(candidate.count('address 10.10.10.10/24'), 1)
        self.assertNotIn('gateway ', candidate)
        self.assertNotIn('gateway 10.10.10.1', candidate)
        committed = m.commit_candidate(candidate)
        self.assertNotIn('gateway 10.10.99.2', committed)
        self.assertEqual(committed.count('gateway 10.10.10.1'), 1)
        self.assertIn('address 10.10.99.10/24', committed)
        self.assertIn('bridge-ports enp4s0', committed)
        self.assertIn('bridge-ports enp2s0', committed)

    def test_no_reservation_refuses_before_network_or_file_changes(self):
        with self.assertRaises(m.Refusal):
            m.execute(self.args('stage'))
        self.run_mock.assert_not_called()
        self.assertEqual(m.INTERFACES.read_text(), ORIGINAL)
        self.assertFalse((m.STATE_DIR / 'state.json').exists())

    def test_real_bridge_mac_directives_survive_stage_commit_and_rollback(self):
        candidate = m.stage_candidate(ORIGINAL)
        committed = m.commit_candidate(candidate)
        for text in (candidate, committed):
            self.assertEqual(text.count('hwaddress ether ' + m.MAC), 1)
            self.assertEqual(text.count('hwaddress ether ' + m.RESCUE_MAC), 1)
        stage = self.staged()
        m.begin_phase('commit', stage, m.commit_candidate(m.INTERFACES.read_text()))
        m.restore_snapshot(m.read_state()['transaction'])
        m.restore_snapshot(stage['stage_snapshot'])
        self.assertEqual(m.INTERFACES.read_text(), ORIGINAL)

    def test_no_carrier_refuses_before_network_or_file_changes(self):
        (m.SYSNET / m.UPLINK / 'carrier').write_text('0\n')
        with self.assertRaises(m.Refusal):
            m.execute(self.args('stage', True))
        self.assertNotIn('ifreload', self.events)
        self.assertEqual(m.INTERFACES.read_text(), ORIGINAL)

    def test_down_unconnected_port_is_restored_on_refusal(self):
        (m.SYSNET / m.UPLINK / 'flags').write_text('0x1002\n')
        (m.SYSNET / m.UPLINK / 'carrier').write_text('0\n')
        with patch.object(m.time, 'sleep'):
            with self.assertRaises(m.Refusal):
                m.execute(self.args('stage', True))
        self.assertIn(unittest.mock.call(['ip', 'link', 'set', 'dev', m.UPLINK, 'up']), self.run_mock.call_args_list)
        self.assertIn(unittest.mock.call(['ip', 'link', 'set', 'dev', m.UPLINK, 'down'], check=False), self.run_mock.call_args_list)
        self.assertEqual(m.INTERFACES.read_text(), ORIGINAL)
        self.assertFalse((m.STATE_DIR / 'snapshots').exists())
        self.assertEqual((m.SYSCTL_DIR / m.UPLINK / 'accept_ra').read_text(), '1\n')
        self.assertEqual((m.SYSCTL_DIR / m.UPLINK / 'accept_ra_defrtr').read_text(), '1\n')

    def test_duplicate_ip_refuses_without_altering_existing_management_bridge(self):
        def duplicate(ip):
            self.assertEqual((m.SYSCTL_DIR / m.UPLINK / 'accept_ra').read_text(), '0\n')
            self.assertEqual((m.SYSCTL_DIR / m.UPLINK / 'accept_ra_defrtr').read_text(), '0\n')
            return True
        with patch.object(m, 'arp_probe', side_effect=duplicate) as probe:
            with self.assertRaises(m.Refusal):
                m.execute(self.args('stage', True))
        probe.assert_called_once_with(m.NEW_IP)
        self.assertEqual(m.INTERFACES.read_text(), ORIGINAL)
        self.assertFalse((m.STATE_DIR / 'snapshots').exists())
        self.assertEqual((m.SYSCTL_DIR / m.UPLINK / 'accept_ra').read_text(), '1\n')

    def test_different_gui_pending_file_refuses(self):
        m.PENDING.write_text(ORIGINAL + '# pending GUI change\n')
        with self.assertRaises(m.Refusal):
            m.pending_guard()
        self.assertTrue(m.PENDING.exists())

    def test_timer_precedes_application_and_stage_rollback_restores_pending(self):
        m.PENDING.write_text(ORIGINAL)
        m.begin_phase('stage', m.read_state(), m.stage_candidate(ORIGINAL))
        self.assertLess(self.events.index('timer'), self.events.index('ifreload'))
        self.assertFalse(m.PENDING.exists())
        transaction = m.read_state()['transaction']
        m.restore_snapshot(transaction)
        self.assertEqual(m.INTERFACES.read_text(), ORIGINAL)
        self.assertEqual(m.PENDING.read_text(), ORIGINAL)
        self.assertEqual(m.read_state()['phase'], 'initial')
        self.assertEqual(m.RA_FILE.read_text(), self.initial_ra)
        self.assertEqual((m.SYSCTL_DIR / m.UPLINK / 'accept_ra').read_text(), '1\n')

    def test_stage_snapshot_preserves_physical_ra_before_guard(self):
        with patch.object(m, 'arp_probe', return_value=False):
            m.execute(self.args('stage', True))
        self.assertEqual((m.SYSCTL_DIR / m.UPLINK / 'accept_ra').read_text(), '0\n')
        transaction = m.read_state()['transaction']
        manifest = json.loads((m.STATE_DIR / 'snapshots' / transaction / 'snapshot.json').read_text())
        self.assertEqual(manifest['sysctls'][str(m.SYSCTL_DIR / m.UPLINK / 'accept_ra')], '1')
        m.restore_snapshot(transaction)
        self.assertEqual((m.SYSCTL_DIR / m.UPLINK / 'accept_ra').read_text(), '1\n')

    def test_new_ssh_destination_and_connection_required(self):
        m.begin_phase('stage', m.read_state(), m.stage_candidate(ORIGINAL))
        with self.assertRaises(m.Refusal):
            m.execute(self.args('confirm-stage'))
        session = '10.10.10.20 45000 10.10.10.10 22'
        m.save_state({**m.read_state(), 'initiating_session': session})
        with patch.dict(os.environ, {'SSH_CONNECTION': session}):
            with self.assertRaises(m.Refusal):
                m.execute(self.args('confirm-stage'))

    def test_commit_rollback_returns_to_confirmed_stage(self):
        stage = self.staged()
        staged_config = m.INTERFACES.read_text()
        with patch.dict(os.environ, {'SSH_CONNECTION': '10.10.10.20 47000 10.10.10.10 22'}):
            m.begin_phase('commit', stage, m.commit_candidate(staged_config))
        self.assertIn('nameserver 10.10.10.1', m.RESOLVER.read_text())
        self.assertIn('10.10.10.10\thypervisor.example.test pve', m.HOSTS.read_text())
        m.restore_snapshot(m.read_state()['transaction'])
        self.assertEqual(m.INTERFACES.read_text(), staged_config)
        self.assertEqual(m.read_state(), stage)
        self.assertEqual(m.RESOLVER.read_text(), 'search local\n')
        self.assertIn('10.10.99.10 hypervisor.example.test pve', m.HOSTS.read_text())

    def test_commit_confirmation_checks_live_dns_then_clears_timer(self):
        stage = self.staged()
        with patch.dict(os.environ, {'SSH_CONNECTION': '10.10.10.20 47000 10.10.10.10 22'}):
            m.begin_phase('commit', stage, m.commit_candidate(m.INTERFACES.read_text()))
        with patch.dict(os.environ, {'SSH_CONNECTION': '10.10.10.20 48000 10.10.10.10 22'}):
            with patch.object(m, 'direct_dns_probe', return_value=False):
                with self.assertRaises(m.Refusal):
                    m.execute(self.args('confirm-commit'))
            self.assertEqual(m.read_state()['phase'], 'commit-pending')
            with patch.object(m, 'direct_dns_probe', return_value=True):
                m.execute(self.args('confirm-commit'))
        self.assertEqual(m.read_state()['phase'], 'committed')

    def test_reload_failure_restores_original_immediately(self):
        real_fake = self.fake_run
        failed = False
        def failing(argv, **kwargs):
            nonlocal failed
            if argv == ['ifreload', '-a'] and not failed:
                failed = True
                raise m.Refusal('mock reload failure')
            return real_fake(argv, **kwargs)
        with patch.object(m, 'run', side_effect=failing):
            with self.assertRaises(m.Refusal):
                m.begin_phase('stage', m.read_state(), m.stage_candidate(ORIGINAL))
        self.assertEqual(m.INTERFACES.read_text(), ORIGINAL)
        self.assertEqual(m.read_state()['phase'], 'initial')

    def test_failed_restore_keeps_pending_state_and_timer_for_retry(self):
        m.begin_phase('stage', m.read_state(), m.stage_candidate(ORIGINAL))
        state = m.read_state()
        self.cleanup_mock.reset_mock()
        real_fake = self.fake_run
        def failing(argv, **kwargs):
            if argv == ['ifreload', '-a']:
                raise m.Refusal('mock restore reload failure')
            return real_fake(argv, **kwargs)
        with patch.object(m, 'run', side_effect=failing):
            with self.assertRaises(m.Refusal):
                m.restore_snapshot(state['transaction'])
        self.assertEqual(m.read_state(), state)
        self.cleanup_mock.assert_not_called()
        m.restore_snapshot(state['transaction'])
        self.assertEqual(m.read_state()['phase'], 'initial')
        self.cleanup_mock.assert_called_once()

    def test_hosts_preserves_unrelated_aliases_and_ipv6(self):
        candidate = m.hosts_candidate('127.0.0.1 localhost\n10.10.99.10 hypervisor.example.test pve other # keep\n::1 localhost ip6-localhost\n')
        self.assertIn('10.10.99.10\tother # keep', candidate)
        self.assertIn('::1 localhost ip6-localhost', candidate)
        self.assertEqual(candidate.count('hypervisor.example.test'), 1)
        self.assertNotIn('disable_ipv6', m.ra_content())
        self.assertIn('net.ipv6.conf.enp4s0.accept_ra=0', m.ra_content())
        self.assertIn('net.ipv6.conf.vmbr3.accept_ra=0', m.ra_content())
        self.assertIn('net.ipv6.conf.enp5s0.accept_ra=0', m.ra_content())

    def test_legacy_state_is_refused_before_commands_or_writes(self):
        (m.STATE_DIR / 'state.json').write_text(json.dumps({'phase': 'initial'}))
        for command in ('stage', 'rollback', 'status'):
            with self.assertRaises(m.Refusal):
                m.execute(self.args(command, True))
        self.run_mock.assert_not_called()
        self.assertEqual(m.INTERFACES.read_text(), ORIGINAL)

    def test_legacy_snapshot_refused_even_without_state(self):
        directory = m.STATE_DIR / 'snapshots' / 'stage-aaaaaaaaaaaa'
        directory.mkdir(parents=True)
        (directory / 'snapshot.json').write_text(json.dumps({'previous_state': {'phase': 'initial'}}))
        with self.assertRaises(m.Refusal):
            m.read_state()
        with self.assertRaises(m.Refusal):
            m.restore_snapshot('stage-aaaaaaaaaaaa')
        self.run_mock.assert_not_called()
        self.assertEqual(m.INTERFACES.read_text(), ORIGINAL)

    def test_old_or_unversioned_rollback_unit_refused(self):
        (m.UNITS / 'codex-pve-uplink-stage-aaaaaaaaaaaa.timer').write_text('[Timer]\n')
        with self.assertRaises(m.Refusal):
            m.execute(self.args('stage', True))
        self.run_mock.assert_not_called()

    def test_old_port_order_and_double_rescue_port_refused(self):
        for candidate in (ORIGINAL.replace('bridge-ports enp4s0', 'bridge-ports enp5s0'),
                          ORIGINAL.replace('bridge-ports enp5s0', 'bridge-ports enp4s0 enp5s0'),
                          ORIGINAL.replace('iface vmbr2 inet manual', 'iface vmbr2 inet static\n    address 10.10.99.10/24')):
            with self.assertRaises(m.Refusal):
                m.stage_candidate(candidate)

    def test_stage_refuses_unexpected_live_default_or_dns(self):
        with patch.object(m, 'ipv4_defaults', return_value=[{'dev': m.RESCUE, 'gateway': '10.10.99.2'}]):
            with self.assertRaises(m.Refusal):
                m.execute(self.args('stage', True))
        m.RESOLVER.write_text('nameserver 10.10.99.2\n')
        with self.assertRaises(m.Refusal):
            m.execute(self.args('stage', True))
        self.assertNotIn('ifreload', self.events)
        self.assertEqual(m.INTERFACES.read_text(), ORIGINAL)

    def test_wrong_bridge_master_or_mac_refused(self):
        master = m.SYSNET / m.UPLINK / 'master'
        master.unlink()
        master.symlink_to(m.SYSNET / m.RESCUE, target_is_directory=True)
        with self.assertRaises(m.Refusal):
            m.execute(self.args('stage', True))
        master.unlink()
        master.symlink_to(m.SYSNET / m.MANAGEMENT, target_is_directory=True)
        (m.SYSNET / m.MANAGEMENT / 'address').write_text(m.RESCUE_MAC + '\n')
        with self.assertRaises(m.Refusal):
            m.execute(self.args('stage', True))
        self.assertNotIn('ifreload', self.events)

    def test_confirmation_expired_keeps_timer_and_pending(self):
        m.begin_phase('stage', m.read_state(), m.stage_candidate(ORIGINAL))
        state = m.read_state()
        m.save_state({**state, 'deadline_unix': 0})
        self.cleanup_mock.reset_mock()
        with patch.dict(os.environ, {'SSH_CONNECTION': '10.10.10.20 46000 10.10.10.10 22'}):
            with self.assertRaises(m.Refusal):
                m.execute(self.args('confirm-stage'))
        self.assertEqual(m.read_state()['phase'], 'stage-pending')
        self.cleanup_mock.assert_not_called()

    def test_commit_confirm_refuses_extra_dns_server_or_wrong_default(self):
        stage = self.staged()
        with patch.dict(os.environ, {'SSH_CONNECTION': '10.10.10.20 47000 10.10.10.10 22'}):
            m.begin_phase('commit', stage, m.commit_candidate(m.INTERFACES.read_text()))
        m.RESOLVER.write_text('nameserver 10.10.10.1\nnameserver 1.1.1.1\n')
        with patch.dict(os.environ, {'SSH_CONNECTION': '10.10.10.20 48000 10.10.10.10 22'}):
            with self.assertRaises(m.Refusal):
                m.execute(self.args('confirm-commit'))
            m.RESOLVER.write_text('nameserver 10.10.10.1\n')
            with patch.object(m, 'ipv4_defaults', return_value=[{'dev': m.RESCUE, 'gateway': m.NEW_GATEWAY}]):
                with self.assertRaises(m.Refusal):
                    m.execute(self.args('confirm-commit'))
        self.assertEqual(m.read_state()['phase'], 'commit-pending')

    def test_timers_are_v2_persistent_and_retry_failed_restore(self):
        REAL_ARM_TIMER('stage-aaaaaaaaaaaa')
        service = (m.UNITS / (m.UNIT_PREFIX + 'stage-aaaaaaaaaaaa.service')).read_text()
        timer = (m.UNITS / (m.UNIT_PREFIX + 'stage-aaaaaaaaaaaa.timer')).read_text()
        self.assertIn('# layout=' + m.LAYOUT, service)
        self.assertIn('Restart=on-failure\nRestartSec=15s', service)
        self.assertIn('StartLimitIntervalSec=0', service)
        self.assertIn('OnActiveSec=300s', timer)
        self.assertIn('Persistent=true', timer)
        m.layout_guard()

    def test_raw_arp_detects_foreign_mac_claim(self):
        foreign = bytes.fromhex('001122334455')
        own = bytes.fromhex(m.MAC.replace(':', ''))
        packet = own + foreign + b'\x08\x06' + struct.pack('!HHBBH', 1, 0x0800, 6, 4, 2)
        packet += foreign + socket.inet_aton(m.NEW_IP) + own + b'\x00' * 4
        from unittest.mock import MagicMock
        raw = MagicMock()
        raw.__enter__.return_value = raw
        raw.recv.return_value = packet
        with patch.object(m.socket, 'socket', return_value=raw), patch.object(m.select, 'select', return_value=([raw], [], [])):
            self.assertTrue(m.arp_probe(m.NEW_IP))
        raw.bind.assert_called_once_with((m.UPLINK, 0))


if __name__ == '__main__':
    unittest.main(verbosity=2)
