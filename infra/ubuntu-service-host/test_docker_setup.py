#!/usr/bin/env python3
"""Offline safety checks: no apt, Docker, services, or remote connections."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


install = load("install_test", "docker-install.py")
verify = load("verify_test", "docker-verify.py")


class SafetyTests(unittest.TestCase):
    def test_supported_release(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "os-release"
            path.write_text('ID=ubuntu\nVERSION_ID="26.04"\nVERSION_CODENAME=resolute\n')
            self.assertEqual(install.read_os_release(path), ("26.04", "resolute"))

    def test_other_os_and_mismatched_codename(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "os-release"
            for content in ('ID=debian\nVERSION_ID="26.04"\nVERSION_CODENAME=resolute\n',
                            'ID=ubuntu\nVERSION_ID="26.04"\nVERSION_CODENAME=noble\n'):
                path.write_text(content)
                with self.assertRaises(install.Refused):
                    install.read_os_release(path)

    def test_merge_preserves_existing_fields_without_mutating_input(self):
        previous = {"data-root": "/var/lib/custom", "ipv6": False,
                    "registry-mirrors": ["https://mirror.example"],
                    "log-opts": {"compress": "false"}, "dns": ["10.10.10.1"]}
        result = install.merge_daemon(previous)
        self.assertEqual(result["data-root"], previous["data-root"])
        self.assertEqual(result["registry-mirrors"], previous["registry-mirrors"])
        self.assertEqual(result["log-opts"], {"compress": "false", "max-size": "10m", "max-file": "3"})
        self.assertEqual(result["dns"], ["10.10.20.1"])
        self.assertEqual(result["log-driver"], "local")
        self.assertEqual(previous["dns"], ["10.10.10.1"])

    def test_unsupported_logging_options_and_types_refused(self):
        for value in ([], {"log-opts": []}, {"log-opts": {"syslog-address": "tcp://example:514"}}):
            with self.assertRaises(install.Refused):
                install.merge_daemon(value)

    def test_unsafe_state_directory_refused(self):
        for path in ("/", "/etc", "/var/lib", "/tmp/docker-state", "/var/lib/servicehost-setup/../.."):
            with self.assertRaises(install.Refused):
                install.allowed_state_directory(path)

    def test_atomic_write_does_not_follow_symlink(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "target"
            target.write_text("original")
            link = Path(folder) / "link"
            link.symlink_to(target)
            with self.assertRaises(install.Refused):
                install.atomic_bytes(link, b"replacement")
            self.assertEqual(target.read_text(), "original")

    def test_existing_workloads_refused(self):
        for harmful in (("docker", "ps", "-aq"), ("docker", "image", "ls", "-q"),
                        ("docker", "volume", "ls", "-q")):
            class Fake:
                def run(self, argv, **kwargs):
                    return SimpleNamespace(returncode=0, stdout="existing-id\n" if tuple(argv) == harmful else "")
            with patch.object(install.shutil, "which", side_effect=lambda name: "/bin/docker" if name == "docker" else None):
                with self.assertRaises(install.Refused):
                    install.assert_no_workloads(Fake())

    def test_custom_network_refused(self):
        class Fake:
            def run(self, argv, **kwargs):
                return SimpleNamespace(returncode=0, stdout="bridge\nhost\nnone\nproduction\n" if argv[:3] == ["docker", "network", "ls"] else "")
        with patch.object(install.shutil, "which", side_effect=lambda name: "/bin/docker" if name == "docker" else None):
            with self.assertRaises(install.Refused):
                install.assert_no_workloads(Fake())

    def test_non_docker_containerd_namespace_refused(self):
        class Fake:
            def run(self, argv, **kwargs):
                return SimpleNamespace(returncode=0, stdout="moby\nk8s.io\n" if argv[0] == "ctr" else "")
        with patch.object(install.shutil, "which", return_value="/bin/fake"):
            with self.assertRaises(install.Refused):
                install.assert_no_workloads(Fake())

    def test_empty_engine_allowed(self):
        class Fake:
            def run(self, argv, **kwargs):
                return SimpleNamespace(returncode=0, stdout="bridge\nhost\nnone\n" if argv[:3] == ["docker", "network", "ls"] else "")
        with patch.object(install.shutil, "which", side_effect=lambda name: "/bin/docker" if name == "docker" else None):
            install.assert_no_workloads(Fake())

    def test_swarm_and_plugins_refused(self):
        for feature in ("swarm", "plugin"):
            class Fake:
                def run(self, argv, **kwargs):
                    value = ""
                    if feature == "swarm" and "{{.Swarm.LocalNodeState}}" in argv:
                        value = "active"
                    if feature == "plugin" and argv[:3] == ["docker", "plugin", "ls"]:
                        value = "plugin-id"
                    return SimpleNamespace(returncode=0, stdout=value)
            with patch.object(install.shutil, "which", side_effect=lambda name: "/bin/docker" if name == "docker" else None):
                with self.assertRaises(install.Refused):
                    install.assert_no_workloads(Fake())


class VerificationTests(unittest.TestCase):
    def exercise(self, fault=None):
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder)
            daemon = state / "daemon.json"
            daemon.write_text('{}\n')
            (state / "latest-install.json").write_text(json.dumps({"schema": 1, "stage": "complete",
                "daemon_sha256": hashlib.sha256(daemon.read_bytes()).hexdigest()}))
            calls, token, network, route_calls = [], [""], [False], [0]

            class Fake:
                def __init__(self, *args):
                    pass

                def run(self, argv, **kwargs):
                    calls.append(argv)
                    value, code = "", 0
                    if argv[:3] == ["docker", "info", "--format"]:
                        value = json.dumps({"ServerVersion": "29.test", "Driver": "overlayfs", "LoggingDriver": "local"})
                    elif argv[:3] == ["docker", "compose", "version"]:
                        value = "v2.test"
                    elif argv[:3] == ["docker", "buildx", "version"]:
                        value = "v0.test"
                    elif argv[0] == "ip":
                        route_calls[0] += 1
                        value = '[{"dst":"default","gateway":"10.10.20.1","dev":"ens18"}]'
                        if fault == "route_change" and route_calls[0] > 1:
                            value = '[{"dst":"default","gateway":"10.10.10.1","dev":"ens18"}]'
                    elif argv[:3] == ["docker", "image", "inspect"]:
                        if "{{json .RepoDigests}}" in argv:
                            value = json.dumps([argv[-1].split(":")[0] + "@sha256:" + "a" * 64])
                        elif "{{.Id}}" in argv:
                            if token[0]:
                                value = "sha256:" + "b" * 64
                            else:
                                code = 1
                        else:
                            value = token[0]
                    elif argv[:2] == ["docker", "run"]:
                        name = argv[argv.index("--name") + 1]
                        if name.endswith("-hello"):
                            value = "Hello from Docker!"
                        elif name.endswith("-https"):
                            if fault == "interruption":
                                raise KeyboardInterrupt("simulated interruption")
                            value = "200 1256 0" if fault != "tls_failure" else "200 1256 60"
                    elif argv[:2] == ["docker", "compose"] and "--project-name" in argv:
                        if "up" in argv:
                            network[0] = True
                        if "ps" in argv:
                            value = "service-id"
                        if "down" in argv:
                            if fault == "cleanup_failure":
                                code = 1
                            else:
                                network[0] = False
                    elif argv[:2] == ["docker", "inspect"]:
                        value = json.dumps({"Type": "local", "Config": {"max-size": "10m", "max-file": "3"}})
                    elif argv[:3] == ["docker", "buildx", "build"]:
                        token[0] = argv[argv.index("--label") + 1].split("=", 1)[1]
                        if fault == "build_timeout_after_image":
                            raise verify.Refused("simulated build CLI timeout after image creation")
                    elif argv[:3] == ["docker", "container", "inspect"]:
                        code = 1
                    elif argv[:3] == ["docker", "network", "ls"]:
                        value = "network-id" if network[0] else ""
                    return SimpleNamespace(returncode=code, stdout=value, stderr="")

            def private(path):
                path = Path(path)
                path.mkdir(mode=0o700, parents=True, exist_ok=True)
                return path

            def mapped_path(value):
                return daemon if str(value) == "/etc/docker/daemon.json" else Path(value)

            args = SimpleNamespace(state_dir=str(state), render_device=None)
            with patch.object(verify, "Commands", Fake), patch.object(verify, "root_free", return_value=6 * 1024 ** 3), \
                 patch.object(verify, "Path", side_effect=mapped_path), patch.object(verify.helpers, "require_root"), \
                 patch.object(verify.helpers, "read_os_release", return_value=("26.04", "resolute")), \
                 patch.object(verify.helpers, "allowed_state_directory", return_value=state), \
                 patch.object(verify.helpers, "private_directory", side_effect=private):
                try:
                    success = verify.verify(args)
                except (verify.Refused, KeyboardInterrupt):
                    success = False
            return success, json.loads((state / "latest-verify.json").read_text()), calls

    def test_success_and_scoped_cleanup(self):
        success, result, calls = self.exercise()
        self.assertTrue(success)
        self.assertEqual(result["status"], "passed")
        self.assertTrue(result["cleanup_passed"])
        self.assertEqual(result["checks"]["https"]["bytes"], 1256)
        for argv in calls:
            self.assertNotIn("prune", argv)
            self.assertNotIn("--privileged", argv)
            self.assertNotIn("--publish", argv)
        self.assertTrue(any("down" in argv for argv in calls))

    def test_tls_failure_still_cleans(self):
        success, result, calls = self.exercise("tls_failure")
        self.assertFalse(success)
        self.assertEqual(result["status"], "failed")
        self.assertTrue(result["cleanup_passed"])

    def test_interruption_still_cleans(self):
        success, result, calls = self.exercise("interruption")
        self.assertFalse(success)
        self.assertTrue(result["cleanup_passed"])

    def test_route_change_fails(self):
        success, result, calls = self.exercise("route_change")
        self.assertFalse(success)
        self.assertEqual(result["status"], "failed")
        self.assertTrue(result["cleanup_passed"])

    def test_build_timeout_cleans_its_unique_image_tag(self):
        success, result, calls = self.exercise("build_timeout_after_image")
        self.assertFalse(success)
        self.assertTrue(result["cleanup_passed"])
        self.assertTrue(any(argv[:3] == ["docker", "image", "rm"] for argv in calls))

    def test_cleanup_failure_is_never_success(self):
        success, result, calls = self.exercise("cleanup_failure")
        self.assertFalse(success)
        self.assertFalse(result["cleanup_passed"])
        self.assertIn("remaining_test_objects", result["cleanup_errors"])


if __name__ == "__main__":
    unittest.main()
