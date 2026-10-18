#!/usr/bin/env python3
"""Run the actual helper under BusyBox ash; all service/controller calls isolated."""
import fcntl
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest

HERE = Path(__file__).resolve().parent
HELPER = HERE / "vpn-egress-webctl"
ASH = [shutil.which("busybox"), "sh"]
BOOT = "01234567-0123-4123-8123-0123456789ab"
UUID = "12345678-1234-4234-8234-123456789abc"
FAKE = r'''#!/usr/bin/env python3
import json,os,re,subprocess,sys,time
from pathlib import Path
p=Path(os.environ['WEB_TEST']); n=Path(sys.argv[0]).name; a=sys.argv[1:]
def log(v):
 with (p/'calls').open('a') as f:f.write(json.dumps(v)+'\n')
if n=='id':print('1' if (p/'not-root').exists() else '0');sys.exit()
if n=='stat':
 v=subprocess.check_output(['/usr/bin/stat']+a,text=True).strip()
 if a[:2]==['-c','%u:%a']:v='0:'+v.split(':')[1]
 print(v);sys.exit()
if n=='jsonfilter':
 try:
  d=json.loads(a[a.index('-s')+1]); sel=a[a.index('-e')+1]
  if sel!='@':
   for quoted,key,index in re.findall(r'\["([^"]+)"\]|\.([a-zA-Z_]+)|\[([0-9]+)\]',sel):
    d=d[int(index)] if index else d[quoted or key]
  if isinstance(d,(dict,list)):print(json.dumps(d))
  elif isinstance(d,bool):print('true' if d else 'false')
  elif d is None:print('null')
  else:print(d)
 except (ValueError,KeyError,IndexError,TypeError):sys.exit(1)
 sys.exit()
if n=='timeout':
 assert a[0]=='-k' and a[1] in ('1','5')
 if a[2]=='1' and (p/'bad-timeout').exists():sys.exit(2)
 if a[2]=='75' and (p/'timed-out').exists():sys.exit(124)
 os.execv(a[3],a[3:])
if n=='ubus':
 log([n]+a)
 assert a[:3]==['-S','call','service']
 if a[3]=='list':
  if (p/'bad-query').exists():print('not json');sys.exit()
  if (p/'query-fail').exists():sys.exit(1)
  print((p/'service').read_text() if (p/'service').exists() else '{}');sys.exit()
 assert a[3]=='add'
 d=json.loads(a[4]); inst=d['instances']['operation']
 assert set(d)=={'name','instances'} and d['name']=='vpn-egress-web'
 assert set(inst)=={'command','stdout','stderr','term_timeout'}
 assert inst['command'][1]=='worker' and inst['command'][2] in ('direct','resume')
 if (p/'launch-fail').exists():sys.exit(1)
 if (p/'launch-invalid').exists():print('{"error":"failed"}');sys.exit()
 if (p/'launch-unregistered').exists():print('{}');sys.exit()
 inst['running']=True
 (p/'service').write_text(json.dumps({'vpn-egress-web':{'instances':{'operation':inst}}}))
 if not (p/'launch-empty').exists():print('{}')
 sys.exit()
if n=='controller':
 log([n]+a); assert len(a)==1 and a[0] in ('direct','resume')
 if (p/'slow').exists():time.sleep(1)
 print('secret controller output must never reach API')
 sys.exit(1 if (p/'controller-fail').exists() else 0)
sys.exit(99)
'''


class WebctlTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="vpn-webctl-")
        self.root = Path(self.tmp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for name in ("id", "stat", "jsonfilter", "timeout", "ubus", "controller"):
            f = self.bin / name
            f.write_text(FAKE)
            f.chmod(0o700)
        self.self = self.bin / "webctl"
        self.self.write_text("#!/bin/sh\nexec /usr/bin/busybox sh " + str(HELPER) + ' "$@"\n')
        self.self.chmod(0o700)
        self.boot = self.root / "boot"
        self.boot.write_text(BOOT)
        self.uuid = self.root / "uuid"
        self.uuid.write_text(UUID)
        self.run = self.root / "run"
        self.env = os.environ | {"WEB_TEST":str(self.root), "VPEWEB_RUN":str(self.run),
            "VPEWEB_SELF":str(self.self), "VPEWEB_BOOT_FILE":str(self.boot),
            "VPEWEB_UUID_FILE":str(self.uuid), "VPEWEB_FLOCK":shutil.which("flock")}
        for var,name in (("ID","id"),("STAT","stat"),("JSON","jsonfilter"),
                         ("TIMEOUT","timeout"),("UBUS","ubus"),("CONTROLLER","controller")):
            self.env["VPEWEB_"+var]=str(self.bin/name)

    def tearDown(self): self.tmp.cleanup()

    def call(self,*args,ok=True):
        p=subprocess.run(ASH+[str(HELPER),*args],env=self.env,text=True,capture_output=True,timeout=15)
        if ok:self.assertEqual(p.returncode,0,p.stdout+p.stderr)
        else:self.assertNotEqual(p.returncode,0,p.stdout+p.stderr)
        return json.loads(p.stdout)

    def raw(self,*args):
        return subprocess.run(ASH+[str(HELPER),*args],env=self.env,text=True,capture_output=True,timeout=15)

    def calls(self):
        return [json.loads(s) for s in (self.root/'calls').read_text().splitlines()] if (self.root/'calls').exists() else []

    def state(self): return json.loads((self.run/'operation.json').read_text())
    def set_state(self,d): (self.run/'operation.json').write_text(json.dumps(d))
    def service_gone(self): (self.root/'service').write_text('{}')

    def test_status_absent_does_not_create_any_runtime_files(self):
        out=self.call('status'); self.assertFalse(out['operation']['running'])
        self.assertEqual(out['operation']['result'],'none'); self.assertFalse(self.run.exists())

    def test_submit_only_reserves_and_adds_fixed_procd_worker(self):
        out=self.call('submit','resume'); self.assertTrue(out['accepted'])
        self.assertEqual(out['operation']['id'],UUID); self.assertEqual(out['operation']['result'],'pending')
        self.assertEqual(self.run.stat().st_mode&0o777,0o700)
        self.assertEqual((self.run/'operation.json').stat().st_mode&0o777,0o600)
        self.assertFalse(any(c[0]=='controller' for c in self.calls()))

    def test_both_actions_finish_and_hide_controller_output(self):
        for action in ('direct','resume'):
            self.call('submit',action)
            p=self.raw('worker',action,UUID); self.assertEqual(p.returncode,0,p.stderr)
            self.assertNotIn('secret',p.stdout+p.stderr)
            s=self.state(); self.assertEqual(s['result'],'success'); self.assertEqual(s['exit_code'],0)
            self.assertFalse(s['running']); self.service_gone()

    def test_duplicate_submit_does_not_overwrite_running_job(self):
        self.call('submit','resume'); before=(self.run/'operation.json').read_bytes()
        self.assertIn('error',self.call('submit','direct',ok=False))
        self.assertEqual((self.run/'operation.json').read_bytes(),before)
        self.assertEqual(sum(c[0]=='ubus' and c[4]=='add' for c in self.calls()),1)

    def test_finished_instance_can_be_replaced(self):
        self.call('submit','resume'); self.raw('worker','resume',UUID); self.service_gone()
        self.uuid.write_text('abcdefab-abcd-4bcd-8bcd-abcdefabcdef')
        out=self.call('submit','direct'); self.assertNotEqual(out['operation']['id'],UUID)

    def test_recent_pending_blocks_even_when_procd_not_yet_running(self):
        self.call('submit','resume'); self.service_gone()
        self.call('submit','direct',ok=False); self.assertEqual(self.state()['action'],'resume')

    def test_stale_pending_is_interrupted_readonly(self):
        self.call('submit','resume'); self.service_gone(); d=self.state(); d['started_epoch']-=10; self.set_state(d)
        before=(self.run/'operation.json').read_bytes(); metadata=(self.run/'operation.json').stat().st_mtime_ns
        out=self.call('status'); self.assertEqual(out['operation']['result'],'interrupted')
        self.assertEqual((self.run/'operation.json').read_bytes(),before)
        self.assertEqual((self.run/'operation.json').stat().st_mtime_ns,metadata)
        self.call('submit','direct')

    def test_reboot_identity_marks_interrupted_without_write(self):
        self.call('submit','resume'); d=self.state(); d['boot_id']='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'; self.set_state(d)
        before=(self.run/'operation.json').read_bytes()
        self.assertEqual(self.call('status')['operation']['result'],'interrupted')
        self.assertEqual((self.run/'operation.json').read_bytes(),before)

    def test_timeout_and_controller_failure_are_recorded(self):
        for marker,result,code in [('controller-fail','failed',1),('timed-out','timed_out',124)]:
            self.call('submit','resume'); (self.root/marker).touch()
            p=self.raw('worker','resume',UUID); self.assertEqual(p.returncode,0,p.stderr)
            self.assertEqual(self.state()['result'],result); self.assertEqual(self.state()['exit_code'],code)
            (self.root/marker).unlink(); self.service_gone()

    def test_failed_or_invalid_launch_marks_failed(self):
        for marker in ('launch-fail','launch-invalid','launch-unregistered'):
            (self.root/marker).touch(); self.call('submit','resume',ok=False)
            self.assertEqual(self.state()['result'],'failed'); self.assertFalse(self.state()['running'])
            (self.root/marker).unlink()

    def test_empty_procd_ack_requires_registered_fixed_command(self):
        (self.root/'launch-empty').touch()
        self.assertTrue(self.call('submit','resume')['accepted'])

    def test_invalid_actions_ids_extra_args_are_rejected_before_mutations(self):
        for args in [('submit','reboot'),('submit','resume;touch /tmp/x'),('submit','resume','extra'),
                     ('worker','direct','../../bad'),('status','extra'),('watch',)]:
            self.call(*args,ok=False)
        self.assertFalse(self.run.exists()); self.assertFalse(self.calls())

    def test_nonroot_and_incompatible_timeout_rejected_before_state_creation(self):
        for marker in ('not-root','bad-timeout'):
            (self.root/marker).touch(); self.call('submit','resume',ok=False)
            self.assertFalse(self.run.exists()); (self.root/marker).unlink()

    def test_corrupt_state_is_retained_and_blocks_all_operations(self):
        self.call('submit','resume'); (self.run/'operation.json').write_text('{broken')
        self.call('status',ok=False); self.call('submit','direct',ok=False)
        self.assertEqual((self.run/'operation.json').read_text(),'{broken')

    def test_symlinks_and_insecure_modes_rejected(self):
        target=self.root/'target'; target.mkdir()
        self.run.symlink_to(target); self.call('status',ok=False); self.run.unlink()
        self.call('submit','resume'); f=self.run/'operation.json'; original=f.read_bytes(); f.unlink()
        t=self.root/'state-target'; t.write_bytes(original); t.chmod(0o600); f.symlink_to(t)
        self.call('status',ok=False); self.assertEqual(t.read_bytes(),original)
        f.unlink(); f.write_bytes(original); f.chmod(0o644); self.call('status',ok=False)

    def test_worker_identity_must_match_reservation(self):
        self.call('submit','resume')
        self.assertNotEqual(self.raw('worker','direct',UUID).returncode,0)
        self.assertNotEqual(self.raw('worker','resume','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa').returncode,0)
        self.assertFalse(any(c[0]=='controller' for c in self.calls()))

    def test_concurrent_duplicate_worker_executes_controller_only_once(self):
        self.call('submit','resume'); (self.root/'slow').touch()
        p=subprocess.Popen(ASH+[str(HELPER),'worker','resume',UUID],env=self.env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        time.sleep(.35)
        other=self.raw('worker','resume',UUID); self.assertNotEqual(other.returncode,0)
        p.communicate(timeout=10); self.assertEqual(p.returncode,0)
        self.assertEqual(sum(c[0]=='controller' for c in self.calls()),1)

    def test_queue_lock_busy_rejected_without_replacing_state(self):
        self.call('submit','resume'); before=(self.run/'operation.json').read_bytes()
        with (self.run/'queue.lock').open() as fd:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            self.call('submit','direct',ok=False)
        self.assertEqual((self.run/'operation.json').read_bytes(),before)

    def test_orphaned_child_execution_lock_prevents_new_action(self):
        self.call('submit','resume'); self.service_gone()
        d=self.state(); d['started_epoch']-=10; self.set_state(d)
        before=(self.run/'operation.json').read_bytes()
        with (self.run/'execution.lock').open() as fd:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            self.call('submit','direct',ok=False)
        self.assertEqual((self.run/'operation.json').read_bytes(),before)

    def test_worker_term_records_interrupted(self):
        self.call('submit','resume'); (self.root/'slow').touch()
        p=subprocess.Popen(ASH+[str(HELPER),'worker','resume',UUID],env=self.env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        deadline=time.monotonic()+5
        while time.monotonic()<deadline and not any(c[0]=='controller' for c in self.calls()):time.sleep(.05)
        p.terminate(); p.communicate(timeout=10)
        self.assertNotEqual(p.returncode,0)
        self.assertEqual(self.state()['result'],'interrupted'); self.assertFalse(self.state()['running'])

    def test_invalid_service_query_fails_closed(self):
        for marker in ('bad-query','query-fail'):
            (self.root/marker).touch(); self.call('submit','resume',ok=False)
            self.assertFalse((self.run/'operation.json').exists()); (self.root/marker).unlink()

    def test_status_never_runs_controller(self):
        self.call('submit','resume'); before=(self.run/'operation.json').read_bytes()
        self.call('status'); self.call('status')
        self.assertEqual((self.run/'operation.json').read_bytes(),before)
        self.assertFalse(any(c[0]=='controller' for c in self.calls()))


if __name__=='__main__':
    import hashlib
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(WebctlTests)
    names=[t.id().split('.')[-1] for t in suite]
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    report={'suite':'BusyBox ash helper behavioral tests','passed':result.testsRun-len(result.failures)-len(result.errors),
            'total':result.testsRun,'success':result.wasSuccessful(),'tests':names,
            'helper_sha256':hashlib.sha256(HELPER.read_bytes()).hexdigest()}
    (HERE/'webctl-test-results.json').write_text(json.dumps(report,indent=2)+'\n')
    raise SystemExit(0 if result.wasSuccessful() else 1)
