#!/usr/bin/env python3
"""Offline invariants; no service commands, network requests or machine state."""
import ast
import ipaddress
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
SERVER = ROOT / 'infra/headscale/server'
SITE = json.loads((ROOT / 'config/site.example.json').read_text())

def render(path):
    return re.sub(r'\{\{([A-Z][A-Z0-9_]*)\}\}',
                  lambda match: str(SITE[match.group(1)]), path.read_text())

def load_validator():
    # Extract pure validation functions only. The Linux runtime ownership helper
    # imports grp; no ownership/service code is executed by these portable tests.
    import hashlib
    import types
    tree = ast.parse((SERVER / 'refresh-derp-map.py').read_text())
    selected = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                and node.name in ('sha', 'lower_keys', 'validate')]
    if len(selected) != 3:
        raise AssertionError('Pure validator function set changed')
    namespace = {'hashlib': hashlib, 'json': json, 're': re, 'MAX_BYTES': 2097152}
    exec(compile(ast.Module(body=selected, type_ignores=[]), '<pure DERP validator>', 'exec'), namespace)
    return types.SimpleNamespace(**namespace)

class ControlPlaneTests(unittest.TestCase):
    def test_policy_preserves_individual_access(self):
        policy = json.loads(render(SERVER / 'policy.hujson.tmpl'))
        self.assertEqual(len(policy['grants']), 5)
        self.assertEqual(len(policy['tests']), 14)
        windows = SITE['WINDOWS_TAIL_IP'] + '/32'
        tablet = SITE['TABLET_TAIL_IP'] + '/32'
        rdp = [grant for grant in policy['grants'] if
               windows in grant['dst'] and
               any(port in ('*', 'tcp:3389', 'udp:3389') for port in grant['ip'])]
        self.assertEqual(rdp, [{'src': [tablet], 'dst': [windows],
                               'ip': ['tcp:3389', 'udp:3389']}])
        for grant in policy['grants']:
            self.assertTrue(all(src.endswith('/32') for src in grant['src']))
            self.assertNotIn('*', grant['dst'])
        for peer in ('LINUX_TAIL_IP', 'APP_TAIL_IP', 'EXIT_TAIL_IP'):
            for proto in ('tcp', 'udp'):
                tests = [test for test in policy['tests'] if
                         test['src'] == SITE[peer] and test.get('proto') == proto]
                self.assertTrue(any(SITE['WINDOWS_TAIL_IP'] + ':3389' in
                                    test.get('deny', []) for test in tests))

    def test_example_roles_are_unique_and_inside_tailnet(self):
        names = ('LINUX_TAIL_IP', 'APP_TAIL_IP', 'TABLET_TAIL_IP',
                 'EXIT_TAIL_IP', 'WINDOWS_TAIL_IP')
        values = [ipaddress.ip_address(SITE[name]) for name in names]
        self.assertEqual(len(set(values)), 5)
        prefix = ipaddress.ip_network(SITE['TAILNET_CIDR'])
        self.assertTrue(all(address in prefix for address in values))

    def test_dns_and_admin_listeners_remain_private(self):
        config = render(SERVER / 'config.yaml.tmpl')
        self.assertIn('magic_dns: true', config)
        self.assertIn('base_domain: "' + SITE['MAGICDNS_DOMAIN'] + '"', config)
        self.assertIn('override_local_dns: false', config)
        self.assertIn('global: []', config)
        self.assertIn('v4: ' + SITE['TAILNET_CIDR'], config)
        for port in (18080, 9090, 50443):
            self.assertIn('127.0.0.1:' + str(port), config)
        self.assertNotIn('0.0.0.0:9090', config)
        self.assertNotIn('0.0.0.0:50443', config)

    def test_derp_map_rejects_embedded_collision_and_duplicate_fields(self):
        module = load_validator()
        valid = {'Regions': {'1': {'RegionID': 1, 'RegionCode': 'test',
                 'RegionName': 'Synthetic region', 'Nodes': [{'Name': 'test-a',
                 'RegionID': 1, 'HostName': 'relay.example.com'}]}}}
        encoded = json.dumps(valid).encode()
        output, info = module.validate(encoded)
        self.assertEqual(info['regions'], 1)
        self.assertEqual(info['nodes'], 1)
        self.assertTrue(output.startswith(b'regions:\n  1:'))
        invalid = {'regions': {'999': {'regionid': 999}}}
        with self.assertRaises(ValueError):
            module.validate(json.dumps(invalid).encode())
        with self.assertRaises(ValueError):
            module.validate(b'{"Regions":{},"regions":{}}')
        with self.assertRaises(ValueError):
            module.validate(b'x' * (module.MAX_BYTES + 1))

if __name__ == '__main__':
    unittest.main()
