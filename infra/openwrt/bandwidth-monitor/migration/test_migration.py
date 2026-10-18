#!/usr/bin/env python3
"""Offline filesystem and command-failure tests; never connects to a router."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "nlbw-persist"
BACKUP = "/root/bandwidth-monitor-offline/nlbwmon"

MOCK = r'''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
root = Path(os.environ["BWM_TEST_ROOT"])
state_path = root / "state.json"
state = json.loads(state_path.read_text())
cmd = Path(sys.argv[0]).name
args = sys.argv[1:]
def save(): state_path.write_text(json.dumps(state))
def dbdir(): return root / state["options"]["database_directory"].lstrip("/")
def dbbytes(): return json.dumps({"rx": state["rx"]}).encode()
def commit():
    dbdir().mkdir(parents=True, exist_ok=True)
    (dbdir() / "20000101.db.gz").write_bytes(dbbytes())
if cmd == "uci":
    if args and args[0] == "-q": args = args[1:]
    verb = args[0]
    if verb == "get":
        key = args[1]
        if key == "system.@system[0].timezone": print("UTC0")
        elif key == "nlbwmon.@nlbwmon[1]": sys.exit(1)
        else:
            key = key.rsplit(".", 1)[-1]
            if key not in state["options"]: sys.exit(1)
            print(state["options"][key])
    elif verb == "changes":
        if state.get("pending"): print("uncommitted")
    elif verb in ("set", "add_list"):
        key, val = args[1].split("=", 1)
        state["options"][key.rsplit(".", 1)[-1]] = val
        save()
    elif verb == "delete":
        state["options"].pop(args[1].rsplit(".", 1)[-1], None); save()
    elif verb == "commit":
        (root / "etc/config/nlbwmon").write_text(json.dumps(state["options"]))
    elif verb == "revert":
        # Original configuration is installed after this call; the daemon start
        # below then reloads that file, as real uci/procd does.
        pass
elif cmd == "nlbw":
    if not state["running"]: sys.exit(1)
    action = args[args.index("-c") + 1]
    if action == "commit":
        if state.get("commit_fail"): sys.exit(7)
        commit()
        print("malformed response" if state.get("commit_bad_reply") else "0 ok")
    elif action == "list": print("2000-01-01")
    elif action == "json":
        print(json.dumps({"columns": ["mac", "ip", "conns", "rx_bytes", "rx_pkts", "tx_bytes", "tx_pkts"],
            "data": [["private", "10.10.20.127", 5, state["rx"], 7, 40, 2]]}))
elif cmd == "pidof":
    if state["running"]: print("42")
    else: sys.exit(1)
elif cmd == "nlbwmon":
    state["options"] = json.loads((root / "etc/config/nlbwmon").read_text())
    if args[0] == "stop":
        state["stops"] += 1
        if not state.get("stop_stuck"):
            commit(); state["running"] = False
            if not state.get("stale_cache"):
                (root / "tmp/0.db").unlink(missing_ok=True)
    elif args[0] == "start":
        state["starts"] += 1
        state["running"] = True
        path = dbdir() / "20000101.db.gz"
        state["rx"] = json.loads(path.read_text())["rx"]
        (root / "tmp/0.db").write_text("running cache")
    save()
elif cmd == "ucode":
    before, after = Path(args[-2]), Path(args[-1])
    a = json.loads((before / "2000-01-01.json").read_text())["data"][0][3]
    b = json.loads((after / "2000-01-01.json").read_text())["data"][0][3]
    if state.get("verify_fail"):
        state["verify_fail"] = False; state["rx"] += 50; save(); sys.exit(1)
    if b < a: sys.exit(1)
    print('{"verified":true}')
elif cmd == "sleep": pass
elif cmd == "cp":
    import shutil
    paths = [arg for arg in args if not arg.startswith("-")]
    if state.get("copy_fail") and "database.before" in paths[-1]: sys.exit(9)
    shutil.copy2(paths[-2], paths[-1])
'''


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="bwm-migration-", dir="/tmp")
        self.root = Path(self.temp.name)
        for dirname in ("etc/config", "etc/init.d", "etc/nlbwmon", "var/lib/nlbwmon", "tmp", "proc", "bin"):
            (self.root / dirname).mkdir(parents=True, exist_ok=True)
        self.state = {
            "options": {"database_directory": "/var/lib/nlbwmon", "commit_interval": "1h", "refresh_interval": "30s", "local_network": "lan"},
            "running": True, "rx": 100, "stops": 0, "starts": 0,
        }
        self.write_state()
        (self.root / "etc/config/nlbwmon").write_text(json.dumps(self.state["options"]))
        (self.root / "etc/sysupgrade.conf").write_text("# Existing configuration\n/etc/other/\n")
        (self.root / "etc/nlbwmon/devices.conf").write_text("")
        (self.root / "var/lib/nlbwmon/20000101.db.gz").write_text('{"rx": 100}')
        (self.root / "proc/mounts").write_text("/dev/root / ext4 rw,noatime 0 0\ntmpfs /tmp tmpfs rw 0 0\n")
        (self.root / "tmp/0.db").write_text("running cache")
        for cmd in ("uci", "nlbw", "pidof", "ucode", "sleep", "cp"):
            path = self.root / "bin" / cmd
            path.write_text(MOCK); path.chmod(0o755)
        service = self.root / "etc/init.d/nlbwmon"
        service.write_text(MOCK); service.chmod(0o755)
        self.env = os.environ | {
            "BWM_TEST_MODE": "1", "BWM_TEST_ROOT": str(self.root),
            "PATH": str(self.root / "bin") + ":" + os.environ["PATH"],
        }
        self.backup = self.root / BACKUP.lstrip("/")

    def tearDown(self):
        self.temp.cleanup()

    def write_state(self):
        (self.root / "state.json").write_text(json.dumps(self.state))

    def read_state(self):
        self.state = json.loads((self.root / "state.json").read_text())
        return self.state

    def run_action(self, action="migrate", success=True):
        result = subprocess.run(["sh", str(SCRIPT), action, "--backup", BACKUP], env=self.env, text=True, capture_output=True, timeout=15)
        if success:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def test_migration_preserves_bytes_and_original_keep_entries(self):
        self.run_action()
        self.assertEqual((self.backup / "status").read_text().strip(), "MIGRATED")
        self.assertEqual((self.root / "etc/nlbwmon/20000101.db.gz").read_bytes(), (self.backup / "database.before/20000101.db.gz").read_bytes())
        state = self.read_state()
        self.assertTrue(state["running"])
        self.assertEqual(state["options"]["database_directory"], "/etc/nlbwmon")
        self.assertEqual(state["options"]["database_generations"], "12")
        self.assertEqual(state["options"]["netlink_buffer_size"], "524288")
        self.assertEqual(state["options"]["database_prealloc"], "0")
        keep = (self.root / "etc/sysupgrade.conf").read_text()
        self.assertIn("/etc/other/", keep)
        self.assertEqual(keep.count("/etc/nlbwmon/"), 1)
        self.assertEqual(keep.count("/etc/proxy-usage/"), 1)
        self.assertEqual(self.backup.stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.backup / "config.before").stat().st_mode & 0o777, 0o600)

    def test_rollback_preserves_newer_live_statistics_and_is_idempotent(self):
        self.run_action()
        self.read_state(); self.state["rx"] = 321; self.write_state()
        self.run_action("rollback")
        state = self.read_state()
        self.assertEqual(state["rx"], 321)
        self.assertEqual(state["options"]["database_directory"], "/var/lib/nlbwmon")
        self.assertEqual(json.loads((self.backup / "latest-before-rollback/20000101.db.gz").read_text())["rx"], 321)
        self.run_action("rollback")

    def test_commit_failure_never_stops_service(self):
        self.state["commit_fail"] = True; self.write_state()
        self.run_action(success=False)
        state = self.read_state()
        self.assertTrue(state["running"])
        self.assertEqual(state["stops"], 0)
        self.assertEqual((self.backup / "status").read_text().strip(), "ABORTED_BEFORE_STOP")

    def test_commit_requires_explicit_success_response(self):
        self.state["commit_bad_reply"] = True; self.write_state()
        self.run_action(success=False)
        self.assertTrue(self.read_state()["running"])
        self.assertEqual(self.state["stops"], 0)

    def test_conflicting_target_is_preserved_and_old_service_recovers(self):
        conflicting = self.root / "etc/nlbwmon/20000101.db.gz"
        conflicting.write_text("unrelated history")
        self.run_action(success=False)
        self.assertEqual(conflicting.read_text(), "unrelated history")
        self.assertTrue(self.read_state()["running"])
        self.assertEqual((self.backup / "status").read_text().strip(), "ROLLED_BACK")

    def test_copy_failure_recovers_without_switching_database(self):
        self.state["copy_fail"] = True; self.write_state()
        self.run_action(success=False)
        state = self.read_state()
        self.assertTrue(state["running"])
        self.assertEqual(state["options"]["database_directory"], "/var/lib/nlbwmon")

    def test_missing_normal_stop_does_not_force_stop(self):
        self.state["stop_stuck"] = True; self.write_state()
        self.run_action(success=False)
        self.assertTrue(self.read_state()["running"])
        self.assertEqual((self.backup / "status").read_text().strip(), "RECOVERY_REQUIRED")
        self.assertNotIn("kill", SCRIPT.read_text())

    def test_stale_cache_pauses_instead_of_loading_ambiguous_statistics(self):
        self.state["stale_cache"] = True; self.write_state()
        self.run_action(success=False)
        self.assertFalse(self.read_state()["running"])
        self.assertEqual((self.backup / "status").read_text().strip(), "RECOVERY_REQUIRED")

    def test_nonpersistent_mount_refused_before_service_stop(self):
        with (self.root / "proc/mounts").open("a") as handle:
            handle.write("tmpfs /etc/nlbwmon tmpfs rw 0 0\n")
        self.run_action(success=False)
        self.assertTrue(self.read_state()["running"])
        self.assertFalse(self.backup.exists())

    def test_pending_uci_changes_refused(self):
        self.state["pending"] = True; self.write_state()
        self.run_action(success=False)
        self.assertEqual(self.read_state()["stops"], 0)

    def test_validation_failure_recovers_latest_not_original_bytes(self):
        self.state["verify_fail"] = True; self.write_state()
        self.run_action(success=False)
        state = self.read_state()
        self.assertTrue(state["running"])
        self.assertEqual(state["rx"], 150)
        self.assertEqual(state["options"]["database_directory"], "/var/lib/nlbwmon")

    def test_keep_list_concurrent_edit_preserved_during_rollback(self):
        self.run_action()
        keep = self.root / "etc/sysupgrade.conf"
        keep.write_text(keep.read_text() + "/etc/later/\n")
        result = self.run_action("rollback")
        self.assertIn("/etc/later/", keep.read_text())
        self.assertIn("preserved for inspection", result.stderr)

    def test_foreign_backup_path_refused(self):
        result = subprocess.run(["sh", str(SCRIPT), "migrate", "--backup", "/etc/config"], env=self.env, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.read_state()["stops"], 0)


if __name__ == "__main__":
    unittest.main()
