#!/usr/bin/env python3
"""Offline guard lifecycle and ownership regression tests; never invoke nft/Docker."""
import copy
import sys
if sys.platform == "win32":
    import types
    sys.modules.setdefault("fcntl", types.SimpleNamespace())
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('guard', Path(__file__).with_name('network_guard.py'))
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


def fixture():
    return {'nftables': [
        {'metainfo': {'version': '1.1.6'}},
        {'table': {'family': 'inet', 'name': guard.TABLE, 'handle': 8, 'comment': guard.CREATOR}},
        {'chain': {'family': 'inet', 'table': guard.TABLE, 'name': 'forward', 'handle': 9,
                   'type': 'filter', 'hook': 'forward', 'prio': -30, 'policy': 'accept'}},
        {'rule': {'family': 'inet', 'table': guard.TABLE, 'chain': 'forward', 'handle': 10,
                  'expr': [{'match': {'op': '==', 'left': {'meta': {'key': 'oifname'}},
                                      'right': guard.BRIDGE}}, {'counter': {'packets': 12, 'bytes': 1200}}, {'accept': None}]}},
        {'rule': {'family': 'inet', 'table': guard.TABLE, 'chain': 'forward', 'handle': 11,
                  'expr': [{'counter': {'packets': 0, 'bytes': 0}}, {'drop': None}]}}
    ]}


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.table = fixture()
        self.owner = {'table_identity': guard.identity(self.table)}

    def test_render_has_paired_interfaces_sources_and_post_dnat_targets(self):
        text = guard.render()
        self.assertIn('iifname "ens18" ip saddr 10.10.20.0/24', text)
        self.assertIn('iifname "jf-uplink" ip saddr 10.10.10.0/24', text)
        self.assertIn('iifname "tailscale0" ip saddr 100.100.10.1/32', text)
        forwards = [line for line in text.splitlines() if 'ct status dnat' in line]
        self.assertEqual(len(forwards), len(guard.INGRESS) * len(guard.SERVICES))
        for interface, source in guard.INGRESS:
            for address, port in guard.SERVICES:
                self.assertTrue(any(f'iifname "{interface}"' in line and f'ip saddr {source}' in line and
                                    f'ip daddr {address} tcp dport {port} ' in line for line in forwards))
        self.assertFalse(any('tcp dport 8081 ' in line for line in forwards))

    def test_render_only_filters_ingress_into_new_bridge(self):
        text = guard.render()
        self.assertIn('oifname "br-home-tools" ct state { established, related }', text)
        self.assertIn('oifname "br-home-tools" counter drop', text)
        self.assertEqual(text.count('policy accept;'), 2)
        self.assertNotIn('hook output', text)
        self.assertNotIn('flush ', text)
        self.assertNotIn('stirling', text)
        self.assertNotIn('jf_livetv', text)
        non_ipv6_iif_drops = [line for line in text.splitlines() if 'iifname' in line and 'drop' in line and 'ipv6' not in line]
        self.assertEqual(non_ipv6_iif_drops, [])

    def test_dynamic_handles_and_counter_values_do_not_change_identity(self):
        other = copy.deepcopy(self.table)
        other['nftables'][1]['table']['handle'] = 900
        other['nftables'][3]['rule']['handle'] = 800
        other['nftables'][3]['rule']['expr'][1]['counter'] = {'packets': 99999, 'bytes': 777777}
        self.assertEqual(guard.identity(self.table), guard.identity(other))

    def test_rule_order_and_verdict_changes_are_detected(self):
        other = copy.deepcopy(self.table)
        other['nftables'][-2:] = reversed(other['nftables'][-2:])
        self.assertNotEqual(guard.identity(self.table), guard.identity(other))
        other = copy.deepcopy(self.table)
        other['nftables'][-1]['rule']['expr'][-1] = {'accept': None}
        self.assertNotEqual(guard.identity(self.table), guard.identity(other))

    def test_apply_foreign_table_refuses_before_mutation(self):
        with patch.object(guard, 'read_owner', return_value=None), patch.object(guard, 'read_table', return_value=self.table), patch.object(guard, 'call') as call:
            with self.assertRaises(guard.Refused): guard.apply()
            call.assert_not_called()

    def test_apply_existing_owned_table_is_idempotent(self):
        with patch.object(guard, 'read_owner', return_value=self.owner), patch.object(guard, 'read_table', return_value=self.table), patch.object(guard, 'call') as call:
            self.assertFalse(guard.apply()['changed'])
            call.assert_not_called()

    def test_apply_missing_table_recreates_after_valid_owner(self):
        with patch.object(guard, 'read_owner', return_value=self.owner), patch.object(guard, 'read_table', side_effect=[None, self.table]), patch.object(guard, 'call') as call, patch.object(guard, 'write_owner') as write:
            self.assertTrue(guard.apply()['changed'])
            self.assertEqual(call.call_args_list[0].args[0], ['nft', '-c', '-f', '-'])
            self.assertEqual(call.call_args_list[1].args[0], ['nft', '-f', '-'])
            write.assert_not_called()

    def test_check_never_mutates_and_missing_table_refuses(self):
        with patch.object(guard, 'read_owner', return_value=self.owner), patch.object(guard, 'read_table', return_value=None), patch.object(guard, 'call') as call, patch.object(guard, 'write_owner') as write:
            with self.assertRaises(guard.Refused): guard.check()
            call.assert_not_called(); write.assert_not_called()

    def test_remove_live_container_refuses_before_firewall_delete(self):
        with patch.object(guard, 'read_owner', return_value=self.owner), patch.object(guard, 'read_table', return_value=self.table), patch.object(guard, 'stopped_containers', side_effect=guard.Refused('running')), patch.object(guard, 'call') as call:
            with self.assertRaises(guard.Refused): guard.remove()
            call.assert_not_called()

    def test_remove_changed_table_refuses(self):
        other = copy.deepcopy(self.table)
        other['nftables'][-1]['rule']['expr'][-1] = {'accept': None}
        with patch.object(guard, 'read_owner', return_value=self.owner), patch.object(guard, 'read_table', return_value=other), patch.object(guard, 'stopped_containers'), patch.object(guard, 'call') as call:
            with self.assertRaises(guard.Refused): guard.remove()
            call.assert_not_called()

    def test_remove_only_named_table_after_containers_stop(self):
        with patch.object(guard, 'read_owner', return_value=self.owner), patch.object(guard, 'read_table', side_effect=[self.table, None]), patch.object(guard, 'stopped_containers') as stopped, patch.object(guard, 'call') as call:
            self.assertEqual(guard.remove(), {'state': 'REMOVED', 'changed': True})
            stopped.assert_called_once()
            call.assert_called_once_with(['nft', 'delete', 'table', 'inet', guard.TABLE])

    def test_docker_absent_or_stopped_accepted_other_project_ignored(self):
        data = '\n'.join(json.dumps(row) for row in [
            {'Names': 'filebrowser', 'State': 'exited'},
            {'Names': 'homepage', 'State': 'created'},
            {'Names': 'stirling-pdf', 'State': 'running'}])
        with patch.object(guard, 'call', return_value=data): guard.stopped_containers()

    def test_docker_paused_restarting_or_unknown_rejected(self):
        for state in ('running', 'paused', 'restarting', 'unknown', None):
            with self.subTest(state=state), patch.object(guard, 'call', return_value=json.dumps({'Names': 'portainer', 'State': state})):
                with self.assertRaises(guard.Refused): guard.stopped_containers()


if __name__ == '__main__':
    unittest.main(verbosity=2)
