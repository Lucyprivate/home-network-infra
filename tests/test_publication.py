import base64
import importlib.util
import json
import tempfile
import unittest
import urllib.parse
import zlib
from unittest.mock import patch
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


scan = load("check_publication")
render = load("render")


class PrivacyTests(unittest.TestCase):
    def identifier(self):
        return '_'.join(['PRIVATE', 'SYNTHETIC', 'IDENTIFIER'])

    def external_address(self):
        return '.'.join(str(n) for n in range(11, 15))

    def secret(self):
        return ''.join(chr(65 + (n * 7) % 26) for n in range(32))

    def assert_rule(self, rule, source, deny=()):
        issues = scan.check_text('fixture', source, deny)
        self.assertTrue(any(row['rule'] == rule for row in issues), issues)
        self.assertTrue(all(set(row) == {'path', 'rule'} for row in issues))

    def test_detects_embedded_identifier_without_reporting_it(self):
        value = "PRIVATE_SYNTHETIC_IDENTIFIER"
        payload = base64.b64encode((value + " padding" * 12).encode()).decode()
        issues = scan.check_text("fixture.py", payload, [value])
        self.assertTrue(any(row["rule"] == "private-denylist" for row in issues))
        self.assertNotIn(value, json.dumps(issues))

    def test_excludes_archives_even_with_text_extension(self):
        self.assertTrue(scan.check_bytes("fixture.txt", b"PK\x03\x04payload"))

    def test_rejects_external_address(self):
        # A generated value avoids treating a four-part release version as a fixture.
        value = ".".join(map(str, [11, 12, 13, 14]))
        self.assertTrue(scan.check_text("fixture", value))

    def test_allows_documentation_and_protocol_addresses(self):
        self.assertEqual([], scan.check_text("fixture", "198.51.100.10 10.10.20.1 100.100.10.3 100.100.100.100 0.0.0.0"))

    def test_detects_personal_filename(self):
        issues = scan.check_bytes("PRIVATE_FIXTURE.txt", b"safe", ["PRIVATE_FIXTURE"])
        self.assertTrue(issues)
        self.assertNotIn('PRIVATE_FIXTURE', json.dumps(issues))

    def test_utf16_encoded_identifier_detected(self):
        value = 'PRIVATE_SYNTHETIC_IDENTIFIER'
        payload = base64.b64encode(value.encode('utf-16-le')).decode()
        self.assertTrue(scan.check_text('fixture', payload, [value]))

    def test_short_encoded_identifier_detected(self):
        value = 'PRIVATE_FIXTURE'
        payload = base64.b64encode(value.encode()).decode()
        self.assertTrue(scan.check_text('fixture', payload, [value]))

    def test_realistic_ipv6_host_refused(self):
        ip = ':'.join(format(n, 'x') for n in range(11, 19))
        self.assertTrue(scan.check_text('fixture', ip))

    def test_non_example_randomized_mac_refused(self):
        mac = ':'.join(format(n, '02x') for n in range(11, 17))
        self.assertTrue(scan.check_text('fixture', mac))

    def test_numeric_bytes_address_checked(self):
        text = 'packet = bytes({})'.format(list(range(11, 15)))
        self.assertTrue(scan.check_text('fixture.py', text))

    def test_numeric_array_private_denylist_checked(self):
        value = '.'.join(map(str, [11, 12, 13, 14]))
        self.assertTrue(scan.check_text('fixture.py', 'data={}'.format(list(range(11, 15))), [value]))

    def test_escaped_regex_address_checked(self):
        value = '.'.join(map(str, [11,12,13,14]))
        self.assertTrue(scan.check_text('fixture.py', value.replace('.', r'\.'), [value]))

    def test_escaped_literal_identifier_checked(self):
        value = 'PRIVATE_FIXTURE'
        encoded = ''.join('\\x' + format(ord(c), '02x') for c in value)
        self.assertTrue(scan.check_text('fixture.py', 'value="' + encoded + '"', [value]))

    def test_url_user_password_refused(self):
        self.assert_rule('url-credentials', 'https://' + self.secret() + ':' + self.secret()[::-1] + '@example.com/resource')

    def test_url_without_userinfo_allowed(self):
        self.assertEqual([], scan.check_text('fixture', 'https://example.com/resource?name=service'))

    def test_username_only_url_token_refused(self):
        self.assert_rule('url-credentials', 'https://' + self.secret() + '@example.com')

    def test_url_negative_fixture_exception_is_exact(self):
        source = 'https://' + 'user' + '@hs.example.com'
        path = 'tests/test_publication.py'
        self.assertEqual([], scan.check_text(path, source))
        self.assertTrue(scan.check_text('fixture', source))
        self.assertTrue(scan.check_text(path, 'https://' + self.secret() + '@hs.example.com'))
        self.assertTrue(scan.check_text(path, source.replace('user@', 'user:@')))
        self.assertTrue(scan.check_text(path, source.replace('hs.example.com', 'other.example.com')))

    def test_percent_encoded_url_credentials_refused(self):
        value = 'https://' + self.secret() + ':' + self.secret()[::-1] + '@example.com'
        self.assert_rule('url-credentials', urllib.parse.quote(value, safe=''))

    def test_unquoted_secret_assignments_refused(self):
        for name in ('PASSWORD', 'PRIVATE_KEY', 'AWS_SECRET_ACCESS_KEY', 'API_TOKEN'):
            with self.subTest(name=name):
                self.assert_rule('credential-literal', name + '=' + self.secret())

    def test_quoted_secret_with_punctuation_refused(self):
        self.assert_rule('credential-literal', 'password="' + self.secret() + '!#^&*"')

    def test_empty_and_variable_secret_inputs_allowed(self):
        for value in ('PASSWORD=\nPRIVATE_KEY=\n', 'PASSWORD=${LOCAL_PASSWORD}', 'PRIVATE_KEY={{LOCAL_KEY}}', 'password=""', 'private_key: null'):
            with self.subTest(value=value):
                self.assertEqual([], scan.check_text('fixture', value))

    def test_secret_prefixes_are_not_placeholders(self):
        for prefix in ('/', '{', '$', '<'):
            self.assert_rule('credential-literal', 'password="' + prefix + self.secret() + '!12"')

    def test_malformed_and_defaulted_placeholders_refused(self):
        for value in ('${' + self.secret(), '${LOCAL_PASSWORD:-' + self.secret() + '}', '{{' + self.secret() + '!}}'):
            self.assert_rule('credential-literal', 'PASSWORD=' + value)

    def test_bare_wireguard_key_refused(self):
        value = base64.b64encode(bytes(range(32))).decode()
        for token in (value, value.rstrip('='), value.replace('+', '-').replace('/', '_')):
            self.assert_rule('bare-wireguard-key', token)

    def test_public_hashes_and_urls_are_not_keys(self):
        self.assertEqual([], scan.check_text('fixture', 'a' * 64 + ' https://example.com/' + 'reference' * 8))

    def test_key_fixture_exception_is_path_and_value_specific(self):
        value = base64.b64encode(bytes(32)).decode()
        path = 'infra/openwrt/wireguard/luci/backend/test_rpc.py'
        self.assertEqual([], scan.check_text(path, value))
        self.assert_rule('bare-wireguard-key', value)
        self.assertTrue(scan.check_text(path, base64.b64encode(bytes(range(32))).decode()))

    def test_common_cloud_and_service_tokens_refused(self):
        fixtures = [('aws-access-key', 'AKIA', 16), ('service-token', 'AIza', 35),
                    ('service-token', 'xoxb-', 24), ('service-token', 'sk_live_', 24),
                    ('service-token', 'glpat-', 24), ('github-token', 'ghp_', 24)]
        for rule, prefix, size in fixtures:
            with self.subTest(prefix=prefix):
                self.assert_rule(rule, prefix + ''.join(chr(65 + n % 26) for n in range(size)))

    def test_nested_percent_hex_base64_identifier_refused(self):
        value = self.identifier()
        payload = base64.b64encode(value.encode()).decode().encode().hex()
        source = ''.join('%' + format(ord(c), '02X') for c in payload)
        self.assert_rule('private-denylist', source, [value])

    def test_character_escapes_refused(self):
        value = self.identifier()
        for style in ('x', 'u', 'brace', 'octal'):
            if style == 'brace':
                encoded = ''.join('\\u{' + format(ord(c), 'x') + '}' for c in value)
            elif style == 'octal':
                encoded = ''.join('\\' + format(ord(c), '03o') for c in value)
            else:
                encoded = ''.join('\\' + style + format(ord(c), '02x' if style == 'x' else '04x') for c in value)
            self.assert_rule('private-denylist', 'const value="' + encoded + '";', [value])

    def test_python_and_javascript_static_concatenation_refused(self):
        value = self.identifier()
        source = '"' + value[:7] + '" + "' + value[7:] + '"'
        for prefix in ('value = ', 'const value = '):
            self.assert_rule('private-denylist', prefix + source, [value])

    def test_static_join_and_fromhex_refused(self):
        value = self.identifier()
        source = "value = ''.join(" + repr([value[:7], value[7:]]) + ')'
        self.assert_rule('private-denylist', source, [value])
        source = "value = bytes.fromhex('" + value.encode().hex() + "')"
        self.assert_rule('private-denylist', source, [value])

    def test_nested_compression_refused(self):
        value = self.identifier()
        payload = base64.b64encode(zlib.compress(base64.b64encode(value.encode()))).decode()
        self.assert_rule('private-denylist', payload, [value])

    def test_excessively_nested_encoding_is_reported(self):
        value = self.identifier()
        for _ in range(scan.MAX_DEPTH + 2):
            value = base64.b64encode(value.encode()).decode()
        self.assert_rule('unresolved-nested-encoding', value)

    def test_payload_and_aggregate_boundaries_are_reported(self):
        with patch.object(scan, 'MAX_PAYLOAD', 64):
            self.assert_rule('encoded-inspection-limit', 'x' * 65)
        with patch.object(scan, 'MAX_DECODED_TOTAL', 64):
            self.assert_rule('encoded-inspection-limit', base64.b64encode(self.secret().encode()).decode())

    def test_candidate_count_boundary_is_reported(self):
        source = '\n'.join(repr('fixture-' + str(n)) for n in range(10))
        with patch.object(scan, 'MAX_CANDIDATES', 3):
            self.assert_rule('encoded-inspection-limit', source)

    def test_compressed_payload_expansion_is_bounded(self):
        source = base64.b64encode(zlib.compress(('safe ' * 500).encode())).decode()
        with patch.object(scan, 'MAX_PAYLOAD', 256):
            self.assert_rule('oversized-encoded-payload', source)

    def test_queued_decompression_stops_at_aggregate_budget(self):
        payloads = [base64.b64encode(zlib.compress(('fixture-' + str(n) + ' ' * 3000).encode())).decode() for n in range(40)]
        source = '\n'.join(payloads)
        original = scan._derived
        produced = []

        def watched(*args):
            for kind, value in original(*args):
                produced.append(len(value))
                yield kind, value

        with patch.object(scan, 'MAX_PAYLOAD', 4096), patch.object(scan, 'MAX_DECODED_TOTAL', 16384), patch.object(scan, '_derived', watched):
            self.assert_rule('encoded-inspection-limit', source)
        # One rejected candidate can be produced, but it cannot enter the queue.
        self.assertLessEqual(len(source) + sum(produced), 16384 + 4096)

    def test_source_calls_are_never_executed(self):
        source = 'open("should-not-exist", "w").write("unsafe")'
        with patch('builtins.open') as external_open:
            scan.check_text('fixture', source)
            external_open.assert_not_called()

    def test_issue_records_do_not_disclose_secret(self):
        secret = self.secret()
        issues = scan.check_text('fixture', 'PASSWORD=' + secret)
        self.assertTrue(issues)
        self.assertNotIn(secret, json.dumps(issues))


class RenderTests(unittest.TestCase):
    def site(self):
        return json.loads((ROOT / 'config/site.example.json').read_text())

    def test_site_is_consistent(self):
        render.validate_site(json.loads((ROOT / "config/site.example.json").read_text()))

    def test_missing_key_refuses(self):
        with self.assertRaises(ValueError):
            render.render_text("{{MISSING_VALUE}}", {})

    def test_recursive_value_refuses(self):
        with self.assertRaises(ValueError):
            render.validate_site({"VALUE": "{{OTHER}}"})

    def test_render_is_literal_and_does_not_evaluate_commands(self):
        self.assertEqual("$(no-execution)", render.render_text("{{VALUE}}", {"VALUE": "$(no-execution)"}))

    def test_source_output_overlap_refuses(self):
        with self.assertRaises(ValueError):
            render.render(ROOT / "config/site.example.json", ROOT / "infra")

    def test_gateway_injection_refuses(self):
        site = self.site()
        site['UPLINK_GATEWAY'] = '10.10.10.1; command'
        with self.assertRaises(ValueError):
            render.validate_site(site)

    def test_control_url_userinfo_refuses(self):
        site = self.site()
        site['HEADSCALE_URL'] = 'https://user@hs.example.com'
        with self.assertRaises(ValueError):
            render.validate_site(site)

    def test_domain_shell_characters_refuse(self):
        site = self.site()
        site['MAGICDNS_DOMAIN'] = 'example.test;command'
        with self.assertRaises(ValueError):
            render.validate_site(site)

    def test_unknown_key_refuses(self):
        site = self.site()
        site['EXTRA'] = 'value'
        with self.assertRaises(ValueError):
            render.validate_site(site)


if __name__ == "__main__":
    unittest.main()
