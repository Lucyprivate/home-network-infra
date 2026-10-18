#!/usr/bin/env python3
"""Behavioral tests execute the real shell controller with isolated commands."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest

HERE = Path(__file__).resolve().parent
CONTROLLER = HERE / "vpn-egress"
SHELL = [shutil.which("busybox"), "sh"] if shutil.which("busybox") else ["/bin/sh"]
FAKE = r'''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
p=Path(os.environ['FAKE_DIR']); name=Path(sys.argv[0]).name; a=sys.argv[1:]
def read(n,default):
 try:return json.loads((p/n).read_text())
 except FileNotFoundError:return default
def save(n,v):(p/n).write_text(json.dumps(v))
def log(v):
 with (p/'calls').open('a') as f:f.write(json.dumps(v)+'\n')
log([name]+a)
if name=='id':print('0');sys.exit()
if name=='uci':
 print('203.0.113.84' if a[-1].endswith('google_ipv4') else '203.0.113.82');sys.exit()
if name=='dnsmasq':sys.exit(1 if (p/'dns-fail').exists() else 0)
if name=='curl':
 assert '--insecure' not in a and '-k' not in a
 assert a[a.index('--proxy')+1]=='' and a[a.index('--noproxy')+1]=='*'
 assert a[a.index('--interface')+1]=='wg_exit'
 assert '--resolve' in a and a[a.index('--max-time')+1]=='8'
 mode=(p/'probe-mode').read_text() if (p/'probe-mode').exists() else 'pass'
 if mode=='fail':sys.exit(28)
 cf='www.cloudflare.com' in a[-1]
 target=Path(a[a.index('--output')+1]); target.write_text('h=www.cloudflare.com\nip='+('198.51.100.7' if mode=='wrong-exit' else '198.51.100.10')+'\n' if cf else '')
 print('200' if cf else '204',end='');sys.exit()
if name=='conntrack':
 if '-L' in a:
  if (p/'conntrack-list-timeout').exists():sys.exit(124)
  print((p/'conntrack-list').read_text() if (p/'conntrack-list').exists() else '')
 elif '-D' in a:
  with (p/'deletions').open('a') as f:f.write(json.dumps(a)+'\n')
 else:sys.exit(2)
 sys.exit()
if name=='ip':
 if a==['-o','-4','address','show']:
  print('2: eth0 inet 10.10.10.2/24 brd 10.10.10.255 scope global eth0\n3: br-lan inet 10.10.20.1/24 brd 10.10.20.255 scope global br-lan\n4: wg_exit inet 10.200.0.2/30 scope global wg_exit');sys.exit()
 if a[:3]==['-4','rule','show']:
  rules=read('rules',{})
  for k in sorted(rules,key=int):print(k+': '+rules[k])
  sys.exit()
 if a[:3]==['-4','rule','add']:
  rules=read('rules',{}); pref=a[a.index('pref')+1]; vals=a[5:]
  if pref in rules:sys.exit(2)
  if vals[0]=='to':vals=['from','all']+vals
  if vals[0]=='lookup':vals=['from','all']+vals
  rules[pref]=' '.join(vals).replace('/32','');save('rules',rules);sys.exit()
 if a[:3]==['-4','rule','del']:
  rules=read('rules',{});rules.pop(a[a.index('pref')+1],None);save('rules',rules);sys.exit()
 if a[:4]==['-4','route','show','table']:
  print('\n'.join(read('routes',[])));sys.exit()
 if a[:3]==['-4','route','replace']:
  routes=read('routes',[])
  if a[3]=='unreachable':new='unreachable default proto 186 metric 42760'; prefix='unreachable'
  else:
   if (p/'interface-missing').exists():sys.exit(2)
   new='default dev wg_exit proto 186 src 10.200.0.2 metric 10';prefix='default'
  routes=[r for r in routes if not r.startswith(prefix)];routes.append(new);save('routes',routes);sys.exit()
 print('unexpected ip call',a,file=sys.stderr);sys.exit(9)
sys.exit(10)
'''


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="vpn-egress-tests-")
        self.path = Path(self.tmp.name)
        self.bin = self.path / "bin"
        self.bin.mkdir()
        for name in ("ip", "uci", "id", "conntrack", "curl", "dnsmasq"):
            (self.bin / name).write_text(FAKE)
            (self.bin / name).chmod(0o700)
        # The router ships BusyBox flock, whose API has no -w. Keep every
        # behavioral test on that smaller flag surface while using real locks.
        (self.bin / "flock").write_text("#!/bin/sh\n"
            "case \"$1\" in -n|-u) exec " + shutil.which("flock") + " \"$@\" ;;\n"
            "*) echo 'BusyBox flock: unsupported flag' >&2; exit 90 ;; esac\n")
        (self.bin / "flock").chmod(0o700)
        self.env = os.environ | {
            "PATH": str(self.bin) + ":" + os.environ["PATH"],
            "FAKE_DIR": str(self.path),
            "VPE_STORE": str(self.path / "store"),
            "VPE_RUN": str(self.path / "run"),
            "VPE_DNSMASQ": str(self.bin / "dnsmasq"),
            "VPE_ID": str(self.bin / "id"),
            "VPE_IP": str(self.bin / "ip"),
            "VPE_UCI": str(self.bin / "uci"),
            "VPE_CURL": str(self.bin / "curl"),
            "VPE_CONNTRACK": str(self.bin / "conntrack"),
            "VPE_FLOCK": str(self.bin / "flock"),
            "VPE_INTERVAL": "1",
        }

    def tearDown(self):
        self.tmp.cleanup()

    def run_cli(self, *args, ok=True):
        r = subprocess.run([*SHELL, str(CONTROLLER), *args], env=self.env,
                           capture_output=True, text=True, timeout=15)
        if ok:
            self.assertEqual(r.returncode, 0, r.stderr)
        else:
            self.assertNotEqual(r.returncode, 0)
        return r

    def data(self, name, default):
        p = self.path / name
        return json.loads(p.read_text()) if p.exists() else default

    def status(self):
        return json.loads(self.run_cli("status").stdout)

    def calls(self):
        return [json.loads(x) for x in (self.path / "calls").read_text().splitlines()]

    def test_resume_checks_exit_and_installs_ordered_rules(self):
        self.run_cli("resume")
        s = self.status()
        self.assertEqual(s["mode"], "WG_ACTIVE")
        self.assertEqual(s["transport"], "wireguard")
        rules = self.data("rules", {})
        self.assertEqual(rules["19990"], "from 10.200.0.2 lookup 200")
        self.assertEqual(rules["20014"], "from all to 198.51.100.10 lookup main")
        self.assertEqual(rules["20100"], "from all lookup 200")
        self.assertEqual(len(rules), 17)
        self.assertIn("unreachable default proto 186 metric 42760", self.data("routes", []))
        self.assertEqual((self.path / "run/status.json").stat().st_mode & 0o777, 0o600)

    def test_resume_is_idempotent(self):
        self.run_cli("resume")
        before = self.data("rules", {})
        self.run_cli("resume")
        self.assertEqual(before, self.data("rules", {}))

    def test_wrong_exit_refuses_resume_even_other_probe_succeeds(self):
        (self.path / "probe-mode").write_text("wrong-exit")
        self.run_cli("resume", ok=False)
        self.assertEqual(self.status()["mode"], "DIRECT_LATCHED")
        self.assertNotIn("20100", self.data("rules", {}))

    def test_direct_leaves_only_protected_probe_route(self):
        self.run_cli("resume")
        self.run_cli("direct")
        self.assertEqual(self.data("rules", {}), {"19990": "from 10.200.0.2 lookup 200"})
        self.assertEqual(self.status()["transport"], "direct")
        self.assertEqual(self.status()["endpoint"]["port"], 51820)
        rule_deletions = [a for a in self.calls() if a[:4] == ["ip", "-4", "rule", "del"]]
        self.assertTrue(rule_deletions)
        self.assertTrue(all("lookup" in a for a in rule_deletions))

    def test_foreign_reserved_rule_not_deleted(self):
        (self.path / "rules").write_text(json.dumps({"20100": "from all lookup 300"}))
        self.run_cli("direct", ok=False)
        self.assertEqual(self.data("rules", {})["20100"], "from all lookup 300")

    def test_failed_direct_preserves_actual_transport_truth(self):
        self.run_cli("resume")
        rules = self.data("rules", {})
        rules["20000"] = "from all to 203.0.113.1 lookup 300"
        (self.path / "rules").write_text(json.dumps(rules))
        self.run_cli("direct", ok=False)
        s = self.status()
        self.assertEqual(s["mode"], "DIRECT_LATCHED")
        self.assertEqual(s["transport"], "wireguard")
        self.assertTrue(s["production_routing"])
        self.assertFalse(s["routing_consistent"])
        self.assertFalse(s["tunnel_healthy"])

    def test_conntrack_list_timeout_still_restarts_dns(self):
        (self.path / "conntrack-list-timeout").touch()
        self.run_cli("resume", ok=False)
        self.assertEqual(self.status()["mode"], "DIRECT_LATCHED")
        self.assertTrue(any(a == ["dnsmasq", "restart"] for a in self.calls()))
        self.assertFalse(list((self.path / "run").glob("conntrack.*")))
        self.assertFalse(list((self.path / "run").glob("addresses.*")))

    def test_conntrack_pair_cap_still_restarts_dns(self):
        (self.path / "conntrack-list").write_text("\n".join(
            f"udp 17 20 src=10.10.20.112 dst=8.8.{i // 256}.{i % 256} sport=1 dport=53"
            for i in range(513)))
        # Fast fake keeps 512 deletions inside the eight-second cleanup bound,
        # proving the count cap separately from an elapsed-time stop.
        counter = self.path / "delete-count"
        fake_ct = self.bin / "conntrack-fast"
        fake_ct.write_text("#!/bin/sh\n"
            "if [ \"$1\" = -L ]; then cat \"$FAKE_DIR/conntrack-list\"; exit 0; fi\n"
            "printf 'x\\n' >> \"$FAKE_DIR/delete-count\"\n")
        fake_ct.chmod(0o700)
        self.env["VPE_CONNTRACK"] = str(fake_ct)
        self.run_cli("resume", ok=False)
        self.assertEqual(self.status()["mode"], "DIRECT_LATCHED")
        self.assertEqual(len(counter.read_text().splitlines()), 1024)
        self.assertGreaterEqual(sum(a == ["dnsmasq", "restart"] for a in self.calls()), 2)

    def test_conntrack_deadline_still_restarts_dns(self):
        self.run_cli("resume")
        (self.path / "conntrack-list").write_text("\n".join(
            f"udp 17 20 src=10.10.20.112 dst=8.9.0.{i} sport=1 dport=53"
            for i in range(1, 101)))
        fake_ct = self.bin / "conntrack-slow"
        fake_ct.write_text("#!/bin/sh\n"
            "if [ \"$1\" = -L ]; then cat \"$FAKE_DIR/conntrack-list\"; exit 0; fi\n"
            "sleep 0.3\nprintf 'x\\n' >> \"$FAKE_DIR/delete-count\"\n")
        fake_ct.chmod(0o700)
        self.env["VPE_CONNTRACK"] = str(fake_ct)
        start = time.monotonic()
        self.run_cli("direct", ok=False)
        self.assertLess(time.monotonic() - start, 11)
        self.assertLess(len((self.path / "delete-count").read_text().splitlines()), 100)
        self.assertEqual(self.status()["mode"], "DIRECT_LATCHED")
        self.assertEqual(sum(a == ["dnsmasq", "restart"] for a in self.calls()), 2)

    def test_foreign_table_not_modified(self):
        (self.path / "routes").write_text(json.dumps(["default via 10.10.10.1 dev eth0"]))
        self.run_cli("resume", ok=False)
        self.assertEqual(self.data("routes", []), ["default via 10.10.10.1 dev eth0"])

    def test_protocol_alias_bgp_normalized_without_replacing_foreign_routes(self):
        (self.path / "routes").write_text(json.dumps([
            "unreachable default proto bgp metric 42760 ",
            "default dev wg_exit proto bgp scope link src 10.200.0.2 metric 10 linkdown",
        ]))
        self.run_cli("resume")
        self.assertEqual(self.status()["mode"], "WG_ACTIVE")

    def test_missing_interface_leaves_unreachable_and_direct(self):
        (self.path / "interface-missing").touch()
        self.run_cli("resume", ok=False)
        self.assertEqual(self.status()["mode"], "DIRECT_LATCHED")
        self.assertEqual(self.data("routes", []), ["unreachable default proto 186 metric 42760"])

    def test_conntrack_cleanup_is_scoped_and_management_preserved(self):
        fixture = "\n".join([
            "udp 17 20 src=10.10.20.112 dst=8.8.8.8 sport=1234 dport=53 src=8.8.8.8 dst=10.200.0.2 sport=53 dport=1234",
            "tcp 6 50 src=10.10.20.127 dst=10.10.10.10 sport=40000 dport=22 src=10.10.10.10 dst=10.10.20.127",
            "udp 17 20 src=10.10.10.2 dst=198.51.100.10 sport=5555 dport=51820 src=198.51.100.10 dst=10.10.10.2",
            "udp 17 20 src=10.200.0.2 dst=1.1.1.1 sport=4567 dport=123 src=1.1.1.1 dst=10.200.0.2",
            # Deliberate public-address boundary fixture: it is outside 192.0.0.0/24.
            # Replacing it with a documentation block would bypass this case.
            "tcp 6 50 src=10.10.20.112 dst=192.0.80.1 sport=1 dport=443 src=192.0.80.1 dst=10.200.0.2",
            "tcp 6 50 src=203.0.113.5 dst=8.8.4.4 sport=1 dport=443 src=8.8.4.4 dst=203.0.113.5",
            # These LAN-origin flows must never be selected for public cleanup:
            # documentation, multicast, and private management destinations.
            "tcp 6 50 src=10.10.20.112 dst=192.0.2.30 sport=1 dport=443 src=192.0.2.30 dst=10.200.0.2",
            "udp 17 20 src=10.10.20.112 dst=224.0.0.1 sport=1 dport=5353",
            "tcp 6 50 src=10.10.20.112 dst=10.10.10.10 sport=1 dport=8006",
        ])
        (self.path / "conntrack-list").write_text(fixture)
        self.run_cli("resume")
        deletes = [json.loads(x) for x in (self.path / "deletions").read_text().splitlines()]
        self.assertEqual(len(deletes), 3)
        self.assertEqual({x[x.index("--orig-dst") + 1] for x in deletes}, {"8.8.8.8", "1.1.1.1", "192.0.80.1"})
        self.assertTrue(all("-F" not in x for x in deletes))

    def test_status_read_only_and_credentials_absent(self):
        self.run_cli("resume")
        files = [self.path / "store/state", self.path / "run/status.json", self.path / "run/health"]
        before = [(p.read_bytes(), p.stat().st_mtime_ns) for p in files]
        s = self.status()
        self.assertNotIn("private", json.dumps(s))
        self.assertEqual(before, [(p.read_bytes(), p.stat().st_mtime_ns) for p in files])

    def test_dns_restart_failure_reverts_activation(self):
        (self.path / "dns-fail").touch()
        self.run_cli("resume", ok=False)
        self.assertEqual(self.status()["mode"], "DIRECT_LATCHED")
        self.assertNotIn("20100", self.data("rules", {}))

    def test_watch_three_failures_latches_and_does_not_auto_resume(self):
        self.run_cli("resume")
        proc = subprocess.Popen([*SHELL, str(CONTROLLER), "watch"], env=self.env,
                                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 5
            # Allow service restart's successful guarded resume to finish.
            time.sleep(1)
            (self.path / "probe-mode").write_text("fail")
            while time.monotonic() < deadline and self.status()["mode"] != "DIRECT_LATCHED":
                time.sleep(0.1)
            self.assertEqual(self.status()["mode"], "DIRECT_LATCHED")
            (self.path / "probe-mode").write_text("pass")
            time.sleep(1.2)
            self.assertEqual(self.status()["mode"], "DIRECT_LATCHED")
        finally:
            proc.terminate()
            proc.communicate(timeout=5)

    def test_missing_timeout_refused_before_any_mutation(self):
        self.env["VPE_TIMEOUT"] = str(self.bin / "absent-timeout")
        r = self.run_cli("resume", ok=False)
        self.assertIn("runtime preflight failed", r.stderr)
        self.assertFalse((self.path / "store").exists())
        self.assertFalse((self.path / "run").exists())
        self.assertFalse((self.path / "rules").exists())
        self.assertFalse((self.path / "routes").exists())

    def test_bad_arguments_and_symlink_paths_refused(self):
        self.run_cli("resume", "extra", ok=False)
        (self.path / "run").symlink_to(self.bin, target_is_directory=True)
        self.run_cli("direct", ok=False)


if __name__ == "__main__":
    unittest.main(verbosity=2)
