#!/usr/bin/env python3
"""Pure anonymous service-contract regression checks; no live tools are run."""
import ast
import copy
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import sys
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if sys.platform == "win32":
    sys.modules.setdefault("fcntl", types.SimpleNamespace())


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


jf = load("jellyfin_guard", "jellyfin/network_guard.py")
pdf = load("pdf_guard", "stirling-pdf/network_guard.py")
gate = load("playback_gate", "jellyfin/playback_gate.py")
zero = load("zero_swap", "stirling-pdf/ocr/paddle_zero_swap_order5.py")


class RoutingAndOwnership(unittest.TestCase):
    def test_foreign_priority_and_table_rules_are_refused(self):
        for value in [
            {"priority": 15200, "src": "172.28.40.3", "table": 999},
            {"priority": 15299, "src": "172.28.40.3", "table": 152},
            {"priority": 15200, "src": "172.28.40.3", "table": 152, "fwmark": "0x1"},
        ]:
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                jf.validate_rules([value])

    def test_withdrawal_keeps_unreachable_default_and_foreign_routes(self):
        routes = [
            {"dst": "default", "type": "unreachable", "metric": 32760},
            {"dst": "default", "gateway": "10.10.10.1", "dev": "jf-uplink", "metric": 100},
            {"dst": "default", "gateway": "10.10.10.9", "dev": "other", "metric": 900},
        ]
        with patch.object(jf, "OWNER") as owner, patch.object(jf, "load_owner"), patch.object(jf, "read_routes", return_value=routes), patch.object(jf, "run") as run:
            owner.exists.return_value = True
            jf.withdraw_default()
            run.assert_called_once_with(["ip", "-4", "route", "del", "default", "via", "10.10.10.1", "dev", "jf-uplink", "table", "152", "metric", "100"])

    def test_main_default_change_is_rejected(self):
        jf.validate_original_default([{"dev": "ens18", "gateway": "10.10.20.1"}])
        with self.assertRaises(RuntimeError):
            jf.validate_original_default([{"dev": "ens18", "gateway": "10.10.10.1"}])

    def test_membership_is_exact_canonical_ipv4_hosts(self):
        valid = ["100.100.10.1", "100.100.10.3", "100.100.10.5"]
        self.assertEqual(jf.authorized_client_addresses(valid), valid)
        for invalid in [valid[::-1], valid + ["100.100.10.3"], ["100.100.10.0/24"], ["::1"], ["10.10.10.1"], ["100.100.10.3"]]:
            with self.subTest(invalid=invalid), self.assertRaises(RuntimeError):
                jf.authorized_client_addresses(invalid)

    def test_pdf_modified_table_refuses_without_mutation(self):
        document = pdf.expected_document()
        modified = copy.deepcopy(document)
        modified["nftables"][-1]["rule"]["expr"][-1] = {"accept": None}
        with patch.object(pdf, "call") as call, self.assertRaises(pdf.Refused):
            pdf.validate(modified, {"state": "ACTIVE"})
        call.assert_not_called()

    def test_pdf_egress_drop_and_ipv6_drop_are_present(self):
        rules = pdf.rules()
        self.assertTrue(any(x["rule"]["chain"] == "forward" and {"counter": "egress_denied"} in x["rule"]["expr"] and x["rule"]["expr"][-1] == {"drop": None} for x in rules))
        self.assertTrue(any({"counter": "ipv6_denied"} in x["rule"]["expr"] and x["rule"]["expr"][-1] == {"drop": None} for x in rules))

    def test_reference_resource_contract_and_readonly_model_runtime(self):
        config = json.loads((ROOT / "stirling-pdf/compose.reference.yaml").read_text())
        with patch.object(zero, "ROOT", PurePosixPath("/srv/stirling-pdf")):
            zero.validate_compose(config)
        modified = copy.deepcopy(config)
        modified["services"]["stirling"]["volumes"][-1]["read_only"] = False
        with patch.object(zero, "ROOT", PurePosixPath("/srv/stirling-pdf")), self.assertRaises(zero.Refused):
            zero.validate_compose(modified)
        modified = copy.deepcopy(config)
        modified["services"]["stirling"]["memswap_limit"] = "2048m"
        with patch.object(zero, "ROOT", PurePosixPath("/srv/stirling-pdf")), self.assertRaises(zero.Refused):
            zero.validate_compose(modified)


class PlaybackIsolation(unittest.TestCase):
    def setUp(self):
        class FakeAPI:
            def authenticate(self, token):
                return "synthetic-user"
            def sessions(self, token):
                return []
        self.now = [100.0]
        self.gate = gate.LeaseGate(FakeAPI(), clock=lambda: self.now[0])
        self.token = "synthetic-token-value"

    def headers(self, device, client="100.100.10.3"):
        return {"X-Emby-Token": self.token, "X-Emby-Device-Id": device, "X-Jf-Live-Client": client}

    def test_second_device_is_refused_and_stop_has_settling_delay(self):
        self.assertEqual(self.gate.authorize(self.headers("device-a"), "/items/demo/playbackinfo"), 204)
        with self.assertRaises(gate.GateError) as error:
            self.gate.authorize(self.headers("device-b"), "/items/demo/playbackinfo")
        self.assertIn(error.exception.status, (403, 423))
        self.gate.authorize(self.headers("device-a"), "/sessions/playing/stopped")
        with self.assertRaises(gate.GateError):
            self.gate.authorize({**self.headers("device-b"), "X-Emby-Token": "another-synthetic-token"}, "/items/demo/playbackinfo")
        self.now[0] += 3
        self.assertEqual(self.gate.authorize({**self.headers("device-b"), "X-Emby-Token": "another-synthetic-token"}, "/items/demo/playbackinfo"), 204)

    def test_cached_segment_needs_manifest_scope_and_does_not_renew_lease(self):
        item, cache = "a" * 32, "b" * 32
        uri = f"/videos/{item}/hls/{cache}/{cache}0.ts"
        bare = {"X-Jf-Live-Client": "100.100.10.3"}
        with self.assertRaises(gate.GateError):
            self.gate.authorize(bare, uri)
        self.gate.authorize(self.headers("device-a"), f"/videos/{item}/main.m3u8")
        touched = self.gate.touched
        self.now[0] += 5
        self.assertEqual(self.gate.authorize(bare, uri), 204)
        self.assertEqual(self.gate.touched, touched)
        with self.assertRaises(gate.GateError):
            self.gate.authorize({"X-Jf-Live-Client": "100.100.10.5"}, uri)
        self.now[0] += 50
        with self.assertRaises(gate.GateError):
            self.gate.authorize(bare, uri)

    def test_conflicting_authentication_and_static_bypass_fail(self):
        with self.assertRaises(gate.GateError):
            gate.request_identity({"X-Emby-Token": "synthetic-token-value"}, {"api_key": ["another-synthetic-token"]})
        for uri in ["/items/demo/playbackinfo?EnableDirectPlay=true", "/videos/demo/stream.m3u8?static=true"]:
            with self.subTest(uri=uri), self.assertRaises(gate.GateError):
                gate.classify(uri)


class IntegrityPins(unittest.TestCase):
    def test_ocr_source_manifest_and_internal_pins(self):
        root = ROOT / "stirling-pdf/ocr"
        files = json.loads((root.parent / "ocr-source.lock.json").read_text())["files"]
        for name, expected in files.items():
            self.assertEqual(hashlib.sha256((root / name).read_bytes()).hexdigest(), expected, name)
        assignments = {}
        for node in ast.parse((root / "paddle_plugin.py").read_text()).body:
            if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name) and isinstance(node.value, ast.Constant):
                assignments[node.targets[0].id] = node.value.value
        for key, name in [("PROBE_SHA256", "paddle_probe.py"), ("GEOMETRY_SHA256", "paddle_geometry4.py"), ("RENDERER_SHA256", "paddle_renderer5.py"), ("LAYOUT_SHA256", "paddle_layout_v2.py")]:
            self.assertEqual(assignments[key], files[name])

    def test_parent_slice_matches_guard_bytes(self):
        self.assertEqual((ROOT / "stirling-pdf/systemd/stirling-pdf.slice").read_bytes(), zero.SLICE_UNIT)


if __name__ == "__main__":
    unittest.main(verbosity=2)
