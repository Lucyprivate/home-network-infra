#!/usr/bin/env python3
"""Offline fixtures only: no SSH connections, live router writes or downloads."""
import copy
import contextlib
import datetime as dt
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import signal
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("backup_pull", HERE / "backup-pull.py")
bp = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bp)


def name(day=1):
    when = dt.datetime(2000, 1, 1) + dt.timedelta(days=day - 1)
    return "vzdump-qemu-100-" + when.strftime("%Y_%m_%d-03_30_00") + ".vma.zst"


def metadata(day=1, body=b"complete compressed fixture"):
    return {"name": name(day), "bytes": len(body), "sha256": hashlib.sha256(body).hexdigest(),
            "stamp": [1, day, len(body), 100, 100], "log_stamp": [1, 100 + day, 400, 100, 100]}


class FakeRunner:
    def __init__(self, day=1, body=b"complete compressed fixture", transfer_body=None, fail=False):
        self.body = body
        self.meta = metadata(day, body)
        self.transfer_body = transfer_body if transfer_body is not None else body
        self.fail = fail
        self.transfers = 0

    def discover(self):
        return copy.deepcopy(self.meta)

    def transfer(self, meta, handle):
        self.transfers += 1
        handle.write(self.transfer_body)
        if self.fail:
            raise bp.PullError("injected transfer failure")


class StoreFixtures(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="vm100-pull-offline-")
        self.root = Path(self.temp.name)
        self.destination = self.root / "private"
        self.destination.mkdir(mode=0o700)

    def tearDown(self):
        self.temp.cleanup()

    def run_pull(self, runner=None):
        # Free-space fixtures do not depend on the test host's disk fullness.
        with patch.object(bp.Store, "available", return_value=20 * 1024**3):
            return bp.pull(runner or FakeRunner(), self.destination)

    def manifest(self):
        return json.loads((self.destination / bp.MANIFEST).read_text())

    def assert_no_parts(self):
        self.assertEqual(list(self.destination.glob("*.part")), [])
        self.assertEqual([x for x in self.destination.iterdir() if x.name.endswith(".part")], [])

    def test_success_has_private_payload_manifest_and_exact_digest(self):
        runner = FakeRunner()
        result = self.run_pull(runner)
        self.assertEqual(result["event"], "copied")
        self.assertEqual((self.destination / name()).read_bytes(), runner.body)
        self.assertEqual(stat.S_IMODE((self.destination / name()).stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((self.destination / bp.MANIFEST).stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((self.destination / bp.LOCK).stat().st_mode), 0o600)
        self.assertEqual(self.manifest()["tool"], bp.TOOL)
        self.assertEqual(self.manifest()["entries"][0]["sha256"], hashlib.sha256(runner.body).hexdigest())
        self.assert_no_parts()

    def test_duplicate_hash_does_not_transfer(self):
        first = FakeRunner()
        self.run_pull(first)
        old_inode = (self.destination / name()).stat().st_ino
        second = FakeRunner()
        self.assertEqual(self.run_pull(second)["event"], "unchanged")
        self.assertEqual(second.transfers, 0)
        self.assertEqual((self.destination / name()).stat().st_ino, old_inode)

    def test_local_same_size_corruption_is_not_silently_replaced(self):
        runner = FakeRunner(body=b"aaaa")
        self.run_pull(runner)
        (self.destination / name()).write_bytes(b"bbbb")
        next_runner = FakeRunner(body=b"aaaa")
        with self.assertRaises(bp.PullError):
            self.run_pull(next_runner)
        self.assertEqual(next_runner.transfers, 0)
        self.assertEqual((self.destination / name()).read_bytes(), b"bbbb")

    def test_remote_immutable_backup_changed_hash_preserves_copy(self):
        self.run_pull(FakeRunner(body=b"aaaa"))
        next_runner = FakeRunner(body=b"bbbb")
        with self.assertRaises(bp.PullError):
            self.run_pull(next_runner)
        self.assertEqual((self.destination / name()).read_bytes(), b"aaaa")

    def test_bad_transfer_checksum_removes_own_temp_preserves_existing(self):
        self.run_pull(FakeRunner(day=1))
        before = (self.destination / bp.MANIFEST).read_bytes()
        with self.assertRaises(bp.PullError):
            self.run_pull(FakeRunner(day=2, body=b"good", transfer_body=b"evil"))
        self.assertEqual((self.destination / bp.MANIFEST).read_bytes(), before)
        self.assertFalse((self.destination / name(2)).exists())
        self.assertTrue((self.destination / name(1)).exists())
        self.assert_no_parts()

    def test_short_transfer_is_rejected(self):
        with self.assertRaises(bp.PullError):
            self.run_pull(FakeRunner(body=b"long complete payload", transfer_body=b"short"))
        self.assertFalse((self.destination / name()).exists())
        self.assert_no_parts()

    def test_interrupted_transfer_preserves_existing_and_removes_own_temp(self):
        self.run_pull(FakeRunner(day=1))
        unrelated = self.destination / ".vm100-pull-foreign.part"
        unrelated.write_text("foreign partial file")
        with self.assertRaises(bp.PullError):
            self.run_pull(FakeRunner(day=2, fail=True))
        self.assertTrue((self.destination / name(1)).exists())
        self.assertEqual(unrelated.read_text(), "foreign partial file")
        self.assertEqual([p.name for p in self.destination.iterdir() if p.name.endswith(".part")], [unrelated.name])

    def test_keep_newest_fourteen_owned_only(self):
        foreign = self.destination / name(100)
        foreign.write_text("foreign VM100 archive")
        unrelated = self.destination / "vzdump-qemu-150-2000_01_01-03_30_00.vma.zst"
        unrelated.write_text("foreign service host VM archive")
        link = self.destination / "unowned-link"
        link.symlink_to(unrelated)
        for day in range(1, 18):
            self.run_pull(FakeRunner(day=day, body=("payload-" + str(day)).encode()))
        owned = self.manifest()["entries"]
        self.assertEqual(len(owned), 14)
        self.assertEqual({x["name"] for x in owned}, {name(x) for x in range(4, 18)})
        for day in range(1, 4):
            self.assertFalse((self.destination / name(day)).exists())
        self.assertEqual(foreign.read_text(), "foreign VM100 archive")
        self.assertEqual(unrelated.read_text(), "foreign service host VM archive")
        self.assertTrue(link.is_symlink())

    def test_foreign_destination_name_not_adopted_or_overwritten(self):
        target = self.destination / name()
        target.write_bytes(FakeRunner().body)
        target.chmod(0o600)
        inode = target.stat().st_ino
        with self.assertRaises(bp.PullError):
            self.run_pull()
        self.assertEqual(target.stat().st_ino, inode)
        self.assertFalse((self.destination / bp.MANIFEST).exists())

    def test_destination_symlink_refused(self):
        link = self.root / "link"
        link.symlink_to(self.destination, target_is_directory=True)
        with self.assertRaises(bp.PullError):
            bp.Store(link)

    def test_public_destination_refused_without_chmod(self):
        self.destination.chmod(0o755)
        with self.assertRaises(bp.PullError):
            self.run_pull()
        self.assertEqual(stat.S_IMODE(self.destination.stat().st_mode), 0o755)

    def test_foreign_empty_lock_is_preserved(self):
        lock = self.destination / bp.LOCK
        lock.write_bytes(b"")
        lock.chmod(0o600)
        with self.assertRaises(bp.PullError):
            self.run_pull()
        self.assertEqual(lock.read_bytes(), b"")

    def test_manifest_symlink_never_followed(self):
        victim = self.root / "victim"
        victim.write_text("untouched")
        (self.destination / bp.MANIFEST).symlink_to(victim)
        with self.assertRaises(OSError):
            self.run_pull()
        self.assertEqual(victim.read_text(), "untouched")

    def test_damaged_manifest_retains_all_data(self):
        self.run_pull()
        manifest = self.destination / bp.MANIFEST
        manifest.write_text("{interrupted JSON")
        with self.assertRaises(bp.PullError):
            self.run_pull(FakeRunner(day=2))
        self.assertTrue((self.destination / name()).exists())
        self.assertEqual(manifest.read_text(), "{interrupted JSON")

    def test_unowned_manifest_marker_refused(self):
        manifest = self.destination / bp.MANIFEST
        manifest.write_text(json.dumps({"schema": 1, "tool": "someone-else", "entries": [], "updated_at": "now"}))
        manifest.chmod(0o600)
        original = manifest.read_bytes()
        with self.assertRaises(bp.PullError):
            self.run_pull()
        self.assertEqual(manifest.read_bytes(), original)

    def test_managed_file_replaced_by_symlink_is_preserved(self):
        self.run_pull()
        victim = self.root / "foreign"
        victim.write_text("untouched")
        target = self.destination / name()
        target.unlink()
        target.symlink_to(victim)
        with self.assertRaises(OSError):
            self.run_pull(FakeRunner(day=2))
        self.assertTrue(target.is_symlink())
        self.assertEqual(victim.read_text(), "untouched")

    def test_managed_file_with_hard_link_cannot_be_pruned(self):
        self.run_pull()
        os.link(self.destination / name(), self.root / "foreign-hardlink")
        with self.assertRaises(bp.PullError):
            self.run_pull(FakeRunner(day=2))
        self.assertTrue((self.destination / name()).exists())

    def test_managed_copy_permissions_not_relaxed_or_silently_fixed(self):
        self.run_pull()
        target = self.destination / name()
        target.chmod(0o644)
        with self.assertRaises(bp.PullError):
            self.run_pull()
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o644)

    def test_crash_after_owned_unlink_reconciles_missing_record(self):
        self.run_pull()
        (self.destination / name()).unlink()
        result = self.run_pull(FakeRunner(day=2))
        self.assertEqual(result["event"], "copied")
        self.assertEqual([x["name"] for x in self.manifest()["entries"]], [name(2)])

    def test_manifest_save_failure_keeps_existing_copies(self):
        self.run_pull(FakeRunner(day=1))
        previous = (self.destination / bp.MANIFEST).read_bytes()
        with patch.object(bp.Store, "save_manifest", side_effect=bp.PullError("injected durable-save failure")):
            with self.assertRaises(bp.PullError):
                self.run_pull(FakeRunner(day=2))
        self.assertTrue((self.destination / name(1)).exists())
        self.assertTrue((self.destination / name(2)).exists())
        self.assertEqual((self.destination / bp.MANIFEST).read_bytes(), previous)
        self.assert_no_parts()

    def test_backup_reserve_is_required_before_transfer(self):
        runner = FakeRunner()
        with patch.object(bp.Store, "available", return_value=bp.MIN_FREE_BYTES + runner.meta["bytes"] - 1):
            with self.assertRaises(bp.PullError):
                bp.pull(runner, self.destination)
        self.assertEqual(runner.transfers, 0)

    def test_minimum_free_space_applies_even_for_duplicate(self):
        self.run_pull()
        with patch.object(bp.Store, "available", return_value=bp.MIN_FREE_BYTES - 1):
            with self.assertRaises(bp.PullError):
                bp.pull(FakeRunner(), self.destination)

    def test_concurrent_store_refused_without_overwriting_lock(self):
        store = bp.Store(self.destination)
        before = (self.destination / bp.LOCK).read_bytes()
        try:
            with self.assertRaises(bp.PullError):
                bp.Store(self.destination)
        finally:
            store.close()
        self.assertEqual((self.destination / bp.LOCK).read_bytes(), before)

    def test_ctrl_c_and_sigterm_run_cleanup_and_restore_handlers(self):
        self.run_pull(FakeRunner(day=1))
        previous_manifest = (self.destination / bp.MANIFEST).read_bytes()
        for sig in (signal.SIGINT, signal.SIGTERM):
            runner = FakeRunner(day=2)
            original_transfer = runner.transfer

            def interrupt_transfer(meta, handle):
                original_transfer(meta, handle)
                signal.raise_signal(sig)

            runner.transfer = interrupt_transfer
            before_handler = signal.getsignal(sig)
            with self.subTest(signal=sig), patch.object(bp, "SSHRunner", return_value=runner), \
                    patch.object(bp.Store, "available", return_value=20 * 1024**3), \
                    contextlib.redirect_stderr(io.StringIO()):
                status = bp.main(["--ssh-config", str(self.root / "unused-config"),
                                  "--destination", str(self.destination)])
            self.assertEqual(status, 128 + sig)
            self.assertEqual(signal.getsignal(sig), before_handler)
            self.assertEqual((self.destination / bp.MANIFEST).read_bytes(), previous_manifest)
            self.assertTrue((self.destination / name(1)).exists())
            self.assertFalse((self.destination / name(2)).exists())
            self.assert_no_parts()

    def test_sigterm_kills_actual_local_transfer_child_and_cleans_partial(self):
        self.run_pull(FakeRunner(day=1))
        config = self.root / "ssh-config"
        config.write_text("Host pve-uplink\n    HostName example.invalid\n")
        config.chmod(0o600)
        runner = bp.SSHRunner(config, "pve-uplink")
        runner.discover = lambda: metadata(day=2)
        # This child is a local Python fixture, never SSH. It emits a partial
        # payload, sends the same SIGTERM as systemd stop, then would sleep unless
        # transfer() finally kills and reaps it.
        runner.command = [sys.executable, "-c", "import os,signal,sys,time; "
                          "sys.stdin.buffer.read(); sys.stdout.buffer.write(b'partial'); "
                          "sys.stdout.buffer.flush(); os.kill(os.getppid(),signal.SIGTERM); time.sleep(60)"]
        children = []
        real_popen = bp.subprocess.Popen

        def recording_popen(*args, **kwargs):
            child = real_popen(*args, **kwargs)
            children.append(child)
            return child

        previous_handler = signal.getsignal(signal.SIGTERM)
        with patch.object(bp, "SSHRunner", return_value=runner), \
                patch.object(bp.Store, "available", return_value=20 * 1024**3), \
                patch.object(bp.subprocess, "Popen", side_effect=recording_popen), \
                contextlib.redirect_stderr(io.StringIO()):
            status = bp.main(["--ssh-config", str(config), "--destination", str(self.destination)])
        self.assertEqual(status, 143)
        self.assertEqual(len(children), 1)
        self.assertIsNotNone(children[0].returncode)
        self.assertLess(children[0].returncode, 0)
        self.assertEqual(signal.getsignal(signal.SIGTERM), previous_handler)
        self.assertTrue((self.destination / name(1)).exists())
        self.assertFalse((self.destination / name(2)).exists())
        self.assert_no_parts()


class MetadataFixtures(unittest.TestCase):
    def test_rejects_other_vms_traversal_invalid_dates_and_suffixes(self):
        for bad in ["../" + name(), name().replace("qemu-100-", "qemu-150-"),
                    name().replace("2000_01_01", "2000_02_30"), name() + ".part",
                    name().replace("03_30_00", "25_30_00"), "/" + name(),
                    name().replace("qemu-100-", "qemu-1000-")]:
            with self.subTest(bad=bad):
                self.assertFalse(bp.valid_name(bad))

    def test_six_gib_size_limit_and_schema_boundary(self):
        for field, value in [("bytes", 0), ("bytes", True), ("bytes", bp.MAX_BYTES + 1),
                             ("sha256", "a" * 63), ("sha256", "../bad"), ("stamp", [1, 2]),
                             ("log_stamp", [True, 2, 3, 4, 5])]:
            candidate = metadata()
            candidate[field] = value
            with self.subTest(field=field, value=value):
                with self.assertRaises(bp.PullError):
                    bp.validate_metadata(candidate)
        candidate = metadata()
        candidate["unexpected"] = "unused"
        with self.assertRaises(bp.PullError):
            bp.validate_metadata(candidate)

    def test_backup_name_and_digest_are_only_log_payload(self):
        expected = {"event": "copied", "file": name(), "bytes": 4, "sha256": hashlib.sha256(b"test").hexdigest()}
        self.assertEqual(set(expected), {"event", "file", "bytes", "sha256"})

    def test_ssh_host_is_fixed_and_hostkey_checks_cannot_be_relaxed(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "ssh.conf"
            config.write_text("Host pve-uplink\n    HostName example.invalid\n")
            config.chmod(0o600)
            runner = bp.SSHRunner(config, "pve-uplink")
            self.assertIn("StrictHostKeyChecking=yes", runner.command)
            self.assertIn("BatchMode=yes", runner.command)
            self.assertIn("ControlMaster=no", runner.command)
            self.assertEqual(runner.command[-3:], ["pve-uplink", "python3", "-"])
            with self.assertRaises(bp.PullError):
                bp.SSHRunner(config, "other-host")
            config.chmod(0o666)
            with self.assertRaises(bp.PullError):
                bp.SSHRunner(config, "pve-uplink")


class RemoteReadonlyFixtures(unittest.TestCase):
    def setUp(self):
        self.ns = {}
        exec(compile(bp.REMOTE_PROGRAM, "remote_fixture", "exec"), self.ns)
        self.ns["being_written"] = lambda _s: False
        self.temp = tempfile.TemporaryDirectory(prefix="vm100-remote-offline-")
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def add(self, day=1, complete=True, failure=False, content=b"fixture"):
        backup = self.root / name(day)
        backup.write_bytes(content)
        log = self.root / (name(day)[:-8] + ".log")
        text = "2000-01-01 INFO: Starting Backup of VM 100 (qemu)\n"
        if failure:
            text += "2000-01-01 ERROR: backup failed\n"
        if complete:
            text += "2000-01-01 INFO: Finished Backup of VM 100 (00:00:07)\n"
        log.write_text(text)
        return backup, log

    def test_missing_finished_or_error_log_is_not_completed(self):
        for complete, failure in [(False, False), (True, True)]:
            backup, log = self.add(complete=complete, failure=failure)
            with self.assertRaises(ValueError):
                self.ns["discover"](str(self.root))
            backup.unlink()
            log.unlink()

    def test_latest_complete_selected_over_newer_unfinished(self):
        self.add(day=1)
        self.add(day=2, complete=False)
        self.add(day=3)
        self.add(day=4, failure=True)
        result = self.ns["discover"](str(self.root))
        self.assertEqual(result["name"], name(3))
        self.assertEqual(result["sha256"], hashlib.sha256(b"fixture").hexdigest())
        bp.validate_metadata(result)

    def test_writer_is_refused_even_with_complete_log(self):
        self.add()
        self.ns["being_written"] = lambda _s: True
        with self.assertRaises(ValueError):
            self.ns["discover"](str(self.root))

    def test_remote_backup_symlink_not_followed(self):
        backup, _log = self.add()
        backup.unlink()
        victim = self.root / "foreign"
        victim.write_text("private")
        backup.symlink_to(victim)
        with self.assertRaises(ValueError):
            self.ns["discover"](str(self.root))
        self.assertEqual(victim.read_text(), "private")

    def test_remote_log_symlink_not_followed(self):
        _backup, log = self.add()
        victim = self.root / "foreign-log"
        log.rename(victim)
        log.symlink_to(victim)
        with self.assertRaises(ValueError):
            self.ns["discover"](str(self.root))

    def test_remote_copy_identity_changed_before_transfer_is_refused(self):
        backup, _log = self.add()
        meta = self.ns["discover"](str(self.root))
        backup.write_bytes(b"replacement changed after discovery")
        with self.assertRaises(ValueError):
            self.ns["copy"](meta, str(self.root))

    def test_complete_log_exact_vm_and_order(self):
        parser = self.ns["complete_log"]
        self.assertTrue(parser("INFO: Starting Backup of VM 100 (qemu)\nINFO: Finished Backup of VM 100 (00:00:07)"))
        self.assertFalse(parser("INFO: Starting Backup of VM 1000 (qemu)\nINFO: Finished Backup of VM 1000 (00:00:07)"))
        self.assertFalse(parser("INFO: Finished Backup of VM 100 (00:00:07)\nINFO: Starting Backup of VM 100 (qemu)"))
        self.assertFalse(parser("INFO: Starting Backup of VM 100 (qemu)\nTASK ERROR: failure\nINFO: Finished Backup of VM 100 (00:00:07)"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
