import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
spec=importlib.util.spec_from_file_location('hook',Path(__file__).with_name('openwrt-backup-hook.py'))
hook=importlib.util.module_from_spec(spec);spec.loader.exec_module(hook)
class BackupHookTest(unittest.TestCase):
    def test_guest_failure_aborts(self):
        for out in ['{"exited":true,"exitcode":1}', '{"exited":false,"pid":1}', '{}', 'not-json']:
            with self.subTest(out=out), self.assertRaises((RuntimeError,ValueError)):
                hook.ensure_completed(SimpleNamespace(returncode=0,stdout=out))
        with self.assertRaises(RuntimeError):hook.ensure_completed(SimpleNamespace(returncode=1,stdout='{}'))
    def test_actual_proxmox_integer_exited_flag(self):
        hook.ensure_completed(SimpleNamespace(returncode=0,stdout='{"exited":1,"exitcode":0}'))
        with self.assertRaises(RuntimeError):hook.ensure_completed(SimpleNamespace(returncode=0,stdout='{"exited":"1","exitcode":0}'))
    def test_vm100_running_and_success(self):
        calls=[]
        def fake(args,**kw):
            calls.append(args)
            return SimpleNamespace(returncode=0,stdout='status: running\n' if len(calls)==1 else '{"exited":true,"exitcode":0}')
        hook.run(['backup-start','snapshot','100'],command=fake)
        self.assertEqual(len(calls),2)
        self.assertEqual(calls[1][1:4],['guest','exec','100'])
    def test_stopped_guest_is_not_started(self):
        calls=[]
        def fake(args,**kw):calls.append(args);return SimpleNamespace(returncode=0,stdout='status: stopped\n')
        hook.run(['backup-start','snapshot','100'],command=fake)
        self.assertEqual(len(calls),1)
    def test_other_vm_and_stop_mode_refused(self):
        for args in [['backup-start','snapshot','150'],['backup-start','stop','100'],['bad','snapshot','100']]:
            with self.assertRaises(RuntimeError):hook.run(args)
    def test_artifact_path_escape_refused(self):
        for p in ['/etc/shadow','/var/lib/vz/dump/../shadow','/var/lib/vz/dump/vzdump-qemu-150-2000_01_12-03_30_00.vma.zst']:
            with self.assertRaises(RuntimeError):hook.restrict_artifact(p,'.vma.zst')
if __name__=='__main__':unittest.main()
