#!/usr/bin/env python3
"""Offline fixtures only; never invokes SSH or a real network command."""
import ast
import base64
import copy
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('readiness', Path(__file__).with_name('router-readiness-check.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def nft_rule():
    return {'nftables': [{'rule': {'family': 'inet', 'table': 'fw4', 'chain': 'input_wan',
        'comment': '!fw4: Allow upstream HTTPS and SSH', 'expr': [
            {'match': {'op': '==', 'left': {'payload': {'protocol': 'ip', 'field': 'saddr'}}, 'right': {'prefix': {'addr': '10.10.10.0', 'len': 24}}}},
            {'match': {'op': '==', 'left': {'payload': {'protocol': 'tcp', 'field': 'dport'}}, 'right': {'set': [22, 443]}}},
            {'counter': {'packets': 0, 'bytes': 0}}, {'accept': None}]}}]}


def fixture(upstream=False):
    pve = {'ssh_session': '10.10.99.55 41000 10.10.99.10 22', 'addresses': [],
           'defaults': [], 'ipv6_defaults': [], 'nameservers': [], 'host_aliases': {}, 'links': {},
           'pve_guests_enabled': True, 'uplink_state': {}, 'vms': {
               '100': {'exists': True, 'status': 'running', 'onboot': '1', 'startup': 'order=1,up=30'},
               '150': {'exists': True, 'status': 'running', 'onboot': '1', 'startup': 'order=2'},
               '199': {'exists': True, 'status': 'stopped', 'onboot': '0'}}}
    for bridge, (port, mac) in m.PORTS.items():
        pve['links'][port] = {'mac': mac, 'master': bridge, 'carrier': '1' if port == 'enp5s0' else '0'}
        pve['links'][bridge] = {'mac': mac, 'carrier': '1', 'master': None}
        pve['addresses'].append({'ifname': bridge, 'addr_info': []})
    pve['addresses'][-1]['addr_info'] = [{'family': 'inet', 'local': '10.10.99.10', 'prefixlen': 24}]
    pve['host_aliases'] = {name: ['10.10.99.10'] for name in ('pve', 'hypervisor.example.test')}
    uci = {
        'network.lan.device': 'br-lan', 'network.lan.delegate': '0', 'network.lan.ip6assign': None,
        'network.@device[0].ports': 'eth1', 'network.wan.device': 'eth0', 'network.wan.proto': 'dhcp',
        'network.wan.peerdns': '1', 'network.wan6.disabled': '1',
        'dhcp.lan.start': '100', 'dhcp.lan.limit': '150', 'dhcp.lan.leasetime': '12h',
        'dhcp.lan.ignore': '0', 'dhcp.lan.dhcpv4': 'server', 'dhcp.wan.ignore': '1',
        'dhcp.codex_servicevm.mac': '02:00:00:00:30:01', 'dhcp.codex_servicevm.ip': '10.10.20.112',
        'firewall.@zone[0].name': 'lan', 'firewall.@zone[0].network': 'lan',
        'firewall.@zone[1].name': 'wan', 'firewall.@zone[1].network': 'wan wan6',
        'firewall.@zone[1].input': 'REJECT', 'firewall.@zone[1].forward': 'DROP', 'firewall.@zone[1].masq': '1',
        'firewall.@forwarding[0].src': 'lan', 'firewall.@forwarding[0].dest': 'wan',
        'homeproxy.server.enabled': '0', 'firewall.codex_upstream_admin': 'rule',
        'firewall.codex_upstream_admin.name': 'Allow upstream HTTPS and SSH',
        'firewall.codex_upstream_admin.src': 'wan', 'firewall.codex_upstream_admin.src_ip': '10.10.10.0/24',
        'firewall.codex_upstream_admin.family': 'ipv4', 'firewall.codex_upstream_admin.proto': 'tcp',
        'firewall.codex_upstream_admin.dest_port': '22 443', 'firewall.codex_upstream_admin.target': 'ACCEPT',
        'firewall.codex_upstream_admin.dest': None, 'firewall.codex_upstream_admin.enabled': None,
        'firewall.codex_lan_ipv6_block': 'rule', 'firewall.codex_lan_ipv6_block.src': 'lan',
        'firewall.codex_lan_ipv6_block.dest': 'wan', 'firewall.codex_lan_ipv6_block.family': 'ipv6',
        'firewall.codex_lan_ipv6_block.proto': 'all', 'firewall.codex_lan_ipv6_block.target': 'REJECT',
    }
    for key in ('dhcpv6', 'ra', 'ndp'):
        uci['dhcp.lan.' + key] = 'disabled'
    ow = {'ssh_session': 'fe80::1 42000 fe80::2 22',
          'lan': {'up': True, 'device': 'br-lan', 'l3_device': 'br-lan', 'ipv4-address': [{'address': '10.10.20.1', 'mask': 24}]},
          'wan': {'up': False, 'pending': True, 'device': 'eth0', 'ipv4-address': []}, 'wan6': {'up': False},
          'default_routes': [], 'wan_dns': [], 'leases_servicevm': [{'mac': '02:00:00:00:30:01', 'address': '10.10.20.112', 'hostname': 'service-host'}],
          'guard': {'mode': 'DIRECT_LATCHED', 'main_node': 'nil', 'homeproxy_autostart': 'disabled', 'internet': 'unverified'},
          'guard_enabled': True, 'uci': uci, 'input_wan': nft_rule(), 'collection_available': {},
          'services': {name: {'registered': True, 'running': True, 'listeners': []} for name in ('dnsmasq', 'uhttpd', 'dropbear', 'homeproxy-guard')}}
    ow['services']['uhttpd']['listeners'] = [{'kind': 'https', 'bind': '0.0.0.0:443'}]
    ow['services']['dropbear']['listeners'] = [{'kind': 'ssh', 'bind': '22'}]
    if upstream:
        pve['ssh_session'] = '10.10.10.73 41000 10.10.10.10 22'
        pve['links']['enp2s0']['carrier'] = pve['links']['enp4s0']['carrier'] = '1'
        pve['addresses'][2]['addr_info'] = [{'family': 'inet', 'local': '10.10.10.10', 'prefixlen': 24}]
        pve['defaults'] = [{'dev': 'vmbr2', 'gateway': '10.10.10.1'}]
        pve['nameservers'] = ['10.10.10.1']
        pve['host_aliases'] = {name: ['10.10.10.10'] for name in ('pve', 'hypervisor.example.test')}
        pve['uplink_state'] = {'layout': 'router-first-v2-management-vmbr2-rescue-vmbr3', 'phase': 'committed'}
        ow['ssh_session'] = '10.10.10.73 42000 10.10.10.2 22'
        ow['wan'] = {'up': True, 'pending': False, 'device': 'eth0', 'l3_device': 'eth0', 'ipv4-address': [{'address': '10.10.10.2', 'mask': 24}], 'data': {'password': 'NEVER_REPORT_THIS'}}
        ow['default_routes'] = [{'dev': 'eth0', 'gateway': '10.10.10.1'}]
        ow['wan_dns'] = ['10.10.10.1']
    return pve, ow


def checks(report):
    return {row['name']: row['status'] for section in report['sections'].values() for row in section['checks']}


class Tests(unittest.TestCase):
    def render_in_shell(self, encoder, queries):
        # Only a tiny fixed printf fixture is run locally. The fake ucode models
        # the encoder exit contract; no SSH, UCI, ubus or real interface query.
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            if encoder is not None:
                fake = path / 'ucode'
                fake.write_text(encoder)
                fake.chmod(0o700)
            return subprocess.run(['/bin/sh'], input=m.openwrt_script(queries), text=True,
                                  capture_output=True, env={**os.environ, 'PATH': str(path)})

    def test_renderer_runs_and_preserves_multiline_and_empty_exit_fields(self):
        encoder = '#!/usr/bin/python3\nimport sys,base64\nsys.stdout.write(base64.b64encode(sys.stdin.buffer.read()).decode())\n'
        queries = {'data': ['printf', '%s', 'line one\nline two'], 'empty': ['true'],
                   'absent': ['false']}
        result = self.render_in_shell(encoder, queries)
        self.assertEqual(result.returncode, 0, result.stderr)
        parsed = m.parse_records(result.stdout, queries)
        self.assertEqual(parsed['data'], {'rc': 0, 'value': 'line one\nline two'})
        self.assertEqual(parsed['empty'], {'rc': 0, 'value': ''})
        self.assertEqual(parsed['absent'], {'rc': 1, 'value': ''})

    def test_renderer_missing_failing_or_empty_encoder_aborts_collection(self):
        for encoder in (None, '#!/bin/sh\nexit 1\n', '#!/bin/sh\nexit 0\n'):
            result = self.render_in_shell(encoder, {'data': ['printf', '%s', 'nonempty'], 'after': ['true']})
            self.assertEqual(result.returncode, 95)
            self.assertNotIn('RRC1 after', result.stdout)
            with patch.object(m.subprocess, 'run', return_value=result):
                with self.assertRaises(m.CollectionError):
                    m.ssh_run('openwrt100', 'sh -s', 'fixture', Path('/mock'), 30)

    def test_offline_pass_marks_upstream_skipped_and_internet_not_tested(self):
        report = m.assess(*fixture(), 'offline')
        self.assertEqual(report['overall'], 'PASS')
        self.assertEqual(report['sections']['upstream']['status'], 'SKIP')
        self.assertEqual(report['internet_status'], 'NOT_TESTED')

    def test_upstream_inventory_pass_is_not_internet_pass(self):
        report = m.assess(*fixture(True), 'upstream')
        self.assertEqual(report['overall'], 'PASS')
        self.assertEqual(checks(report)['internet_and_client_services'], 'SKIP')
        self.assertEqual(report['internet_status'], 'NOT_TESTED')
        self.assertNotIn('NEVER_REPORT_THIS', json.dumps(report))

    def test_upstream_refuses_rescue_connections_even_if_configuration_is_right(self):
        pve, ow = fixture(True)
        pve['ssh_session'] = '10.10.99.55 41000 10.10.99.10 22'
        ow['ssh_session'] = 'fe80::1 42000 fe80::2 22'
        report = m.assess(pve, ow, 'upstream')
        self.assertEqual(report['overall'], 'FAIL')
        self.assertEqual(checks(report)['pve_ssh_destination'], 'FAIL')
        self.assertEqual(checks(report)['openwrt_ssh_destination'], 'FAIL')

    def test_no_physical_wan_carrier_skips_dhcp_checks_despite_virtual_interface(self):
        pve, ow = fixture(True)
        pve['links']['enp2s0']['carrier'] = '0'
        report = m.assess(pve, ow, 'upstream')
        self.assertEqual(report['overall'], 'INCOMPLETE')
        self.assertEqual(checks(report)['wan_dhcp_address'], 'SKIP')

    def test_wan_wrong_address_or_gateway_or_dns_fails(self):
        for field in ('address', 'gateway', 'dns'):
            pve, ow = fixture(True)
            if field == 'address': ow['wan']['ipv4-address'][0]['address'] = '10.10.10.99'
            if field == 'gateway': ow['default_routes'][0]['gateway'] = '10.10.10.254'
            if field == 'dns': ow['wan_dns'] = []
            self.assertEqual(m.assess(pve, ow, 'upstream')['overall'], 'FAIL', field)

    def test_unexpected_default_dns_or_rescue_loss_fails(self):
        for field in ('default', 'dns', 'rescue'):
            pve, ow = fixture()
            if field == 'default': pve['defaults'] = [{'dev': 'vmbr3', 'gateway': '10.10.99.2'}]
            if field == 'dns': pve['nameservers'] = ['10.10.99.2']
            if field == 'rescue': pve['addresses'][3]['addr_info'] = []
            self.assertEqual(m.assess(pve, ow, 'offline')['overall'], 'FAIL', field)

    def test_wrong_order_delay_and_diagnostic_autostart_fail(self):
        for vmid, key, value in (('100', 'startup', 'order=2,up=30'), ('100', 'startup', 'order=1,up=0'),
                                 ('150', 'onboot', '0'), ('199', 'onboot', '1')):
            pve, ow = fixture()
            pve['vms'][vmid][key] = value
            self.assertEqual(m.assess(pve, ow, 'offline')['overall'], 'FAIL')

    def test_upstream_admin_rule_cannot_open_forwarding_or_port80(self):
        for key, value in (('dest', 'lan'), ('src_ip', '0.0.0.0/0'), ('dest_port', '22 80 443'), ('family', 'any')):
            pve, ow = fixture()
            ow['uci']['firewall.codex_upstream_admin.' + key] = value
            self.assertEqual(checks(m.assess(pve, ow, 'offline'))['restricted_upstream_router_admin_input'], 'FAIL')

    def test_runtime_nft_rule_must_keep_source_ports_and_input_chain(self):
        self.assertTrue(m.runtime_admin_rule(nft_rule()))
        for variant in ('source', 'ports', 'chain', 'duplicate'):
            data = nft_rule()
            rule = data['nftables'][0]['rule']
            if variant == 'source': rule['expr'][0]['match']['right']['prefix']['len'] = 0
            if variant == 'ports': rule['expr'][1]['match']['right']['set'] = [22, 80, 443]
            if variant == 'chain': rule['chain'] = 'forward_wan'
            if variant == 'duplicate': data['nftables'].append(copy.deepcopy(data['nftables'][0]))
            self.assertFalse(m.runtime_admin_rule(data), variant)

    def test_guard_consistency_offline_direct_and_upstream_proxy(self):
        pve, ow = fixture()
        ow['guard']['main_node'] = 'urltest'
        self.assertEqual(m.assess(pve, ow, 'offline')['overall'], 'FAIL')
        pve, ow = fixture(True)
        ow['guard'] = {'mode': 'PROXY', 'main_node': 'urltest', 'homeproxy_autostart': 'enabled'}
        self.assertEqual(m.assess(pve, ow, 'upstream')['overall'], 'PASS')

    def test_missing_dhcp_mac_is_failure_not_exception_and_absent_lease_skips(self):
        pve, ow = fixture()
        ow['uci']['dhcp.codex_servicevm.mac'] = None
        ow['leases_servicevm'] = []
        result = checks(m.assess(pve, ow, 'offline'))
        self.assertEqual(result['servicehost_dhcp_reservation'], 'FAIL')
        self.assertEqual(result['servicehost_observed_lease'], 'SKIP')

    def test_pending_or_old_uplink_state_and_unexpected_ipv6_fail(self):
        for state in ({'phase': 'stage-pending'}, {'layout': 'old', 'phase': 'initial'}):
            pve, ow = fixture()
            pve['uplink_state'] = state
            self.assertEqual(m.assess(pve, ow, 'offline')['overall'], 'FAIL')
        pve, ow = fixture()
        ow['wan6']['up'] = True
        pve['ipv6_defaults'] = [{'dev': 'vmbr2'}]
        result = checks(m.assess(pve, ow, 'offline'))
        self.assertEqual(result['no_pve_ipv6_default_route'], 'FAIL')
        self.assertEqual(result['initial_ipv4_only'], 'FAIL')

    def test_frames_reject_duplicate_truncated_unknown_or_invalid_base64(self):
        record = 'RRC1 label 0 ' + base64.b64encode(b'test\nvalue').decode() + '\n'
        self.assertEqual(m.parse_records(record, {'label'})['label']['value'], 'test\nvalue')
        for raw in (record + record, '', record.replace('label', 'other'), 'RRC1 label 0 @@@\n', record.replace(' 0 ', ' 999 ')):
            with self.assertRaises(m.CollectionError): m.parse_records(raw, {'label'})

    def test_guard_parser_refuses_duplicate_fields(self):
        with self.assertRaises(m.CollectionError): m.parse_kv('mode=PROXY\nmode=DIRECT_LATCHED\n')

    def test_service_sanitization_excludes_credentials_commands_and_stopped_listeners(self):
        data = {'uhttpd': {'instances': {
            'live': {'running': True, 'command': ['/usr/sbin/uhttpd', '--password', 'SECRET_VALUE', '-s', '0.0.0.0:443']},
            'old': {'running': False, 'command': ['/usr/sbin/uhttpd', '-p', '127.0.0.1:80']}}}}
        result = m.sanitize_service(data, 'uhttpd')
        self.assertEqual(result['listeners'], [{'kind': 'https', 'bind': '0.0.0.0:443'}])
        self.assertNotIn('SECRET_VALUE', json.dumps(result))
        self.assertNotIn('command', result)

    def test_collection_uses_new_aliases_for_upstream_without_running_real_ssh(self):
        pve, ow = fixture(True)
        fake_records = {key: {'rc': 1, 'value': ''} for key in m.openwrt_queries()}
        with patch.object(m, 'ssh_run', return_value=json.dumps(pve)) as ssh, \
             patch.object(m, 'parse_records', return_value=fake_records), \
             patch.object(m, 'summarize_openwrt', return_value=ow):
            m.collect(Path('/mock/config'), 30, 'upstream')
        self.assertEqual([call.args[0] for call in ssh.call_args_list], ['pve-uplink', 'openwrt-wan'])
        with patch.object(m, 'ssh_run', return_value=json.dumps(pve)) as ssh, \
             patch.object(m, 'parse_records', return_value=fake_records), \
             patch.object(m, 'summarize_openwrt', return_value=ow):
            m.collect(Path('/mock/config'), 30, 'offline')
        self.assertEqual([call.args[0] for call in ssh.call_args_list], ['pve', 'openwrt100'])

    def test_ssh_error_never_returns_arbitrary_stderr(self):
        fake = subprocess.CompletedProcess([], 255, stdout='', stderr='SECRET_ERROR')
        with patch.object(m.subprocess, 'run', return_value=fake):
            with self.assertRaises(m.CollectionError) as error:
                m.ssh_run('pve', 'python3 -', m.PVE_SCRIPT, Path('/mock'), 30)
        self.assertNotIn('SECRET_ERROR', str(error.exception))

    def test_collection_payloads_are_read_only(self):
        ast.parse(m.PVE_SCRIPT)
        queries = m.openwrt_queries()
        self.assertEqual(queries['guard'], ['/usr/sbin/homeproxy-guard', 'status'])
        self.assertNotIn('pve-uplink-switch', m.PVE_SCRIPT)
        for argv in queries.values():
            self.assertNotIn(argv[0], ('curl', 'ping', 'modprobe', 'ifup', 'ifdown', 'reboot'))
            if argv[0] == 'uci': self.assertEqual(argv[2], 'get')
            if argv[0] == 'ip': self.assertNotIn('set', argv)
            if argv[0].startswith('/etc/init.d/'): self.assertEqual(argv[-1], 'enabled')


if __name__ == '__main__':
    unittest.main(verbosity=2)
