#!/usr/bin/env python3
"""Local BusyBox ash / UCI / fw4 / procd mocks; no SSH or real firewall calls."""
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time

HERE = Path(__file__).resolve().parent
SOURCE = HERE / 'openwrt-admin-switch'
MOCK = r'''#!/usr/bin/env python3
import json, os, signal, subprocess, sys, time
from pathlib import Path
base=Path(os.environ['ADMIN_MOCK']); db=base/'db.json'; events=base/'events'
name=Path(sys.argv[0]).name; args=sys.argv[1:]
def data(): return json.loads(db.read_text())
def put(d):
    p=base/('db.'+str(os.getpid())); p.write_text(json.dumps(d)); p.replace(db)
def event(v):
    with events.open('a') as f: f.write(v+'\n')
def cfg(path):
    lines=path.read_text().splitlines()
    for line in lines:
        if line.startswith('#MOCKDATA '): return json.loads(line[10:])
    return {}
def write_cfg(path,v): path.write_text("# retained fixture firewall; IPSec and other rules preserved\n#MOCKDATA "+json.dumps(v,sort_keys=True)+"\n")
active=base/'config/firewall'; d=data(); v=cfg(active)
if name in ['fw4','nft','firewall']:
    try: os.fstat(9); event('ERROR:bounded_child_inherited_transaction_lock')
    except OSError: pass
if name=='uci':
    directory=active.parent; delta=base/'default-delta'; override=base/'default-override'; i=0
    while i < len(args) and args[i].startswith('-'):
        if args[i] in ['-c','-P','-C']:
            if args[i]=='-c': directory=Path(args[i+1])
            elif args[i]=='-P': delta=Path(args[i+1])
            elif args[i]=='-C': override=Path(args[i+1])
            i+=2
        else: i+=1
    action=args[i]; rest=args[i+1:]; path=directory/'firewall'; v=cfg(path)
    if (override/'firewall').exists(): v.update(cfg(override/'firewall'))
    delta_file=delta/'firewall'
    saved=json.loads(delta_file.read_text()) if delta_file.exists() else {}
    v.update(saved)
    if action=='changes':
        if rest: print(d.get('firewall_changes',''),end='')
        else: print(d.get('all_changes',''),end='')
    elif action=='get':
        if rest[0] not in v: sys.exit(1)
        print(v[rest[0]])
    elif action=='show':
        for k,value in v.items(): print(k+"='"+str(value)+"'")
    elif action=='set':
        if d.get('candidate_set_fail'): sys.exit(1)
        key,value=rest[0].split('=',1); saved[key]=value
        delta.mkdir(exist_ok=True); delta_file.write_text(json.dumps(saved))
        event('candidate_set:'+key)
    elif action=='commit':
        # Models the observed target: return 0 but leave private deltas intact.
        event('candidate_commit_no_materialization')
    elif action=='export':
        event('candidate_export')
        if d.get('export_unchanged'): print(path.read_text(),end='')
        else:
            if d.get('export_drop_family'): v.pop('firewall.codex_upstream_admin.family',None)
            print('# retained fixture firewall; IPSec and other rules preserved\n#MOCKDATA '+json.dumps(v,sort_keys=True))
    else: sys.exit(2)
elif name=='fw4':
    candidate='firewall.codex_upstream_admin' in v
    event('check:'+('candidate' if candidate else 'baseline'))
    if candidate and not (base/'run/worker').exists(): event('ERROR:no_worker_before_active_change'); sys.exit(1)
    if d.get('check_candidate_fail') and candidate: sys.exit(1)
    if d.get('check_restore_fail') and not candidate: sys.exit(1)
    if d.get('hang_candidate') and candidate:
        p=subprocess.Popen([sys.executable,'-c','import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)'])
        (base/'bounded-grandchild').write_text(str(p.pid))
        while True: time.sleep(1)
elif name=='firewall':
    candidate='firewall.codex_upstream_admin' in v
    event('reload:'+('candidate' if candidate else 'baseline'))
    if candidate and d.get('reload_candidate_fail'): sys.exit(1)
    if not candidate and d.get('reload_restore_fail'): sys.exit(1)
    d['runtime_admin']=candidate; put(d)
elif name=='nft':
    line='ip saddr 10.10.10.0/24 tcp dport { 22, 443 } counter packets 0 bytes 0 accept comment "!fw4: Allow upstream HTTPS and SSH" # handle 123'
    if d.get('bad_source'): line=line.replace('10.10.10.0/24','0.0.0.0/0')
    if d.get('extra_port'): line=line.replace('22, 443','22, 80, 443')
    if d.get('duplicate'): line=line+'\n'+line
    if d.get('meta_ipv4'): line='meta nfproto ipv4 '+line
    if args[-1]=='input':
        print('table inet fw4 { chain input {')
        print('type filter hook input priority filter; policy drop;')
        if not d.get('no_input_jump'): print('iifname "eth0" jump input_wan comment "!fw4: Handle wan IPv4/IPv6 input traffic" # handle 33')
        print('} }')
    else:
        print('table inet fw4 { chain input_wan {')
        print('ip protocol esp accept comment "!fw4: retained IPSec" # handle 5')
        if d.get('runtime_admin'): print(line)
        print('} }')
elif name=='codex-upstream-admin':
    event('init:'+args[0])
    if args[0]=='enable': d['enabled']=True; put(d)
    elif args[0]=='disable': d['enabled']=False; put(d)
    elif args[0]=='start':
        if d.get('start_fail'): sys.exit(1)
        old=d.get('worker_pid')
        if old:
            try: os.kill(old,0); sys.exit(0)
            except ProcessLookupError: pass
        script=base/'switch'
        if subprocess.run(['busybox','ash',str(script),'_needs-watch'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode: sys.exit(0)
        p=subprocess.Popen(['busybox','ash',str(script),'watch'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env=os.environ,start_new_session=True)
        d=data(); d['worker_pid']=p.pid; put(d)
        (base/'worker-pids').open('a').write(str(p.pid)+'\n')
    elif args[0]=='stop':
        pid=d.get('worker_pid')
        if pid:
            try: os.kill(pid,signal.SIGTERM)
            except ProcessLookupError: pass
        d['worker_pid']=None; put(d)
    elif args[0]=='enabled': sys.exit(0 if d.get('enabled') else 1)
    else: sys.exit(2)
elif name=='ucode':
    path=Path(args[-1]); s=path.stat()
    if 'sprintf' in args[1]: print(oct(s.st_mode & 0o777)[2:])
    else: print(s.st_uid)
else: sys.exit(2)
'''

BASE_RULES = {
    'firewall.defaults': 'defaults',
    'firewall.defaults.input': 'REJECT',
    'firewall.ipsec': 'rule',
    'firewall.ipsec.name': 'retained IPSec',
    'firewall.ipsec.src': 'wan',
    'firewall.ipsec.dest': 'lan',
    'firewall.ipsec.proto': 'esp',
    'firewall.ipsec.target': 'ACCEPT',
}


class Fixture:
    def __init__(self, parent, **flags):
        self.base = Path(tempfile.mkdtemp(prefix='admin-mock-', dir=parent))
        b=self.base
        (b/'bin').mkdir(); (b/'config').mkdir()
        (b/'default-delta').mkdir(); (b/'default-override').mkdir()
        (b/'default-delta/sentinel').write_text('unrelated default delta directory file preserved\n')
        (b/'default-override/sentinel').write_text('unrelated default override directory file preserved\n')
        self.config=b/'config/firewall'
        self.config.write_text('# retained fixture firewall; IPSec and other rules preserved\n#MOCKDATA '+json.dumps(BASE_RULES,sort_keys=True)+'\n')
        self.before=self.config.read_bytes()
        self.config.chmod(0o600)
        (b/'boot').write_text('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\n')
        (b/'uptime').write_text('100.00 0.00\n')
        (b/'db.json').write_text(json.dumps({'runtime_admin':False,**flags}))
        source=SOURCE.read_text()
        values={'STORE':str(b/'store'),'RUN':str(b/'run'),'CONFIG':str(self.config),
                'INIT':str(b/'bin/codex-upstream-admin'),'FIREWALL_INIT':str(b/'bin/firewall'),
                'SELF':str(b/'switch'),'BOOT_FILE':str(b/'boot'),'UPTIME_FILE':str(b/'uptime'),
                'ROOT_UID':str(os.getuid())}
        lines=[]
        for line in source.splitlines():
            key=line.split('=',1)[0]
            lines.append(key+'='+values[key] if key in values else line)
        (b/'switch').write_text('\n'.join(lines)+'\n')
        mock=b/'bin/mock'; mock.write_text(MOCK); mock.chmod(0o755)
        for name in ['uci','fw4','firewall','nft','codex-upstream-admin','ucode']:
            (b/'bin'/name).symlink_to(mock)
        self.env=os.environ|{'PATH':str(b/'bin')+':'+os.environ['PATH'],'ADMIN_MOCK':str(b),
            'SSH_CONNECTION':'fe80::1234 22000 fe80::5678 22'}

    def call(self, action, expected=0, session=None):
        env=self.env if session is None else self.env|{'SSH_CONNECTION':session}
        p=subprocess.run(['busybox','ash',str(self.base/'switch'),action],env=env,capture_output=True,text=True,timeout=45)
        assert p.returncode==expected,(action,p.returncode,p.stdout,p.stderr, self.events())
        return p

    def data(self): return json.loads((self.base/'db.json').read_text())
    def change(self,**fields):
        d=self.data(); d.update(fields)
        tmp=self.base/'db-change'; tmp.write_text(json.dumps(d)); tmp.replace(self.base/'db.json')
    def phase(self):
        path=self.base/'store/state'
        if not path.exists(): return 'initial'
        return dict(line.split('=',1) for line in path.read_text().splitlines())['phase']
    def events(self):
        path=self.base/'events'
        return path.read_text().splitlines() if path.exists() else []
    def wait(self,predicate,timeout=8):
        until=time.monotonic()+timeout
        while time.monotonic()<until:
            if predicate(): return
            time.sleep(.1)
        raise AssertionError((self.phase(),self.events()))
    def cleanup(self):
        path=self.base/'worker-pids'
        if path.exists():
            for line in path.read_text().splitlines():
                try: os.kill(int(line),signal.SIGTERM)
                except ProcessLookupError: pass


def main():
    passed=[]; fixtures=[]
    with tempfile.TemporaryDirectory(prefix='admin-tests-',dir=HERE) as parent:
      def f(**flags):
        x=Fixture(parent,**flags); fixtures.append(x); return x
      try:
        x=f(); x.call('stage')
        assert x.phase()=='pending' and x.data()['enabled']
        assert x.events().index('init:start') < x.events().index('check:candidate')
        assert 'ERROR:no_worker_before_active_change' not in x.events()
        active=json.loads(x.config.read_text().split('#MOCKDATA ',1)[1])
        for key,value in BASE_RULES.items(): assert active[key]==value
        added={k:v for k,v in active.items() if k not in BASE_RULES}
        assert len(added)==8 and 'firewall.codex_upstream_admin.dest' not in added
        assert added['firewall.codex_upstream_admin.dest_port']=='22 443'
        assert 'candidate_export' in x.events() and 'candidate_commit_no_materialization' not in x.events()
        assert (x.base/'default-delta/sentinel').read_text()=='unrelated default delta directory file preserved\n'
        assert (x.base/'default-override/sentinel').read_text()=='unrelated default override directory file preserved\n'
        assert (x.base/'store/state').stat().st_mode & 0o777==0o600
        tx=next((x.base/'store/transactions').iterdir())
        assert (tx/'firewall.before').read_bytes()==x.before
        assert (tx/'firewall.before').stat().st_mode & 0o777==0o600
        assert (tx/'candidate/firewall').read_bytes()!=x.before
        assert (tx/'delta/firewall').exists() and not (tx/'delta-empty/firewall').exists()
        x.call('confirm',1)
        assert x.phase()=='pending' and x.data()['enabled']
        x.call('confirm',session='fe80::1234 22001 fe80::5678 22')
        assert x.phase()=='confirmed' and not x.data()['enabled']
        assert x.data()['runtime_admin']
        passed.append('timer-before-change; exact one INPUT rule; preserves IPSec; private backup; new SSH required; confirmed service disabled')

        for failure in ['export_unchanged','export_drop_family']:
            x=f(**{failure:True}); x.call('stage',1)
            assert x.phase()=='initial' and x.config.read_bytes()==x.before
            assert 'init:start' not in x.events() and 'init:enable' not in x.events()
            passed.append(f'{failure}: byte materialization and empty-delta parse gates reject before arming')

        x=f(all_changes="homeproxy.config.main_node='other'\n"); x.call('stage',1)
        assert x.config.read_bytes()==x.before and x.phase()=='initial'
        passed.append('rejects uncommitted UCI changes before arming or mutation')

        x=f(); payload=BASE_RULES|{'firewall.codex_upstream_admin':'rule'}
        x.config.write_text('#MOCKDATA '+json.dumps(payload)+'\n'); before=x.config.read_bytes()
        x.call('stage',1); assert x.config.read_bytes()==before and x.phase()=='initial'
        passed.append('rejects named section collision')

        x=f(); payload=BASE_RULES|{'firewall.other':'rule','firewall.other.name':'Allow upstream HTTPS and SSH'}
        x.config.write_text('#MOCKDATA '+json.dumps(payload)+'\n'); before=x.config.read_bytes()
        x.call('stage',1); assert x.config.read_bytes()==before and x.phase()=='initial'
        passed.append('rejects other section using same rule name')

        x=f(runtime_admin=True); x.call('stage',1)
        assert x.config.read_bytes()==x.before and x.phase()=='initial'
        passed.append('rejects existing runtime comment collision')

        x=f(start_fail=True); x.call('stage',1)
        assert x.config.read_bytes()==x.before and x.phase()=='rolled_back'
        assert not any(v=='check:candidate' for v in x.events())
        passed.append('worker start failure never installs candidate')

        for failure in ['check_candidate_fail','reload_candidate_fail']:
            x=f(**{failure:True}); x.call('stage',1)
            assert x.config.read_bytes()==x.before and x.phase()=='rolled_back' and not x.data()['enabled']
            passed.append(f'{failure}: active config restored and service disabled only after verification')

        x=f(); x.call('stage'); x.call('rollback')
        assert x.config.read_bytes()==x.before and x.phase()=='rolled_back' and not x.data()['runtime_admin']
        passed.append('manual rollback restores byte-exact baseline and runtime rule absence')

        x=f(); x.call('stage'); (x.base/'uptime').write_text('401.00 0.00\n')
        x.wait(lambda:x.phase()=='rolled_back')
        x.wait(lambda:not x.data()['enabled'])
        assert x.config.read_bytes()==x.before
        passed.append('monotonic 300-second deadline restores without client connection')

        x=f(); x.call('stage'); (x.base/'boot').write_text('ffffffff-bbbb-cccc-dddd-eeeeeeeeeeee\n')
        x.wait(lambda:x.phase()=='rolled_back')
        assert x.config.read_bytes()==x.before
        passed.append('boot ID change restores immediately without waiting old uptime deadline')

        x=f(); x.call('stage'); x.change(reload_restore_fail=True); x.call('rollback',1)
        assert x.phase()=='rollback_pending' and x.data()['enabled']
        x.change(reload_restore_fail=False)
        x.wait(lambda:x.phase()=='rolled_back')
        x.wait(lambda:not x.data()['enabled'])
        passed.append('restore reload failure stays pending; independent watcher retries to success')

        for failure in ['bad_source','extra_port','no_input_jump','duplicate']:
            x=f(); x.call('stage'); x.change(**{failure:True})
            x.call('confirm',1,session='fe80::1234 22001 fe80::5678 22')
            assert x.phase()=='pending' and x.data()['enabled']
            x.change(**{failure:False}); x.call('rollback')
            passed.append(f'confirmation rejects runtime {failure} and keeps timer')

        x=f(meta_ipv4=True); x.call('stage'); x.call('confirm',session='10.10.10.50 22001 10.10.10.100 22')
        assert x.phase()=='confirmed'
        passed.append('explicit meta nfproto ipv4 runtime rendering accepted with exact same restriction')

        scoped='fe80::200%br-lan 56172 fe80::300%br-lan 22'
        x=f(); x.env['SSH_CONNECTION']=scoped; x.call('stage')
        x.call('confirm',1)
        x.call('confirm',session=scoped.replace(' 56172 ', ' 56173 '))
        assert x.phase()=='confirmed'
        passed.append('exact scoped IPv6 br-lan SSH tuple accepted; same tuple still rejected')

        for invalid in [scoped+'\n',scoped.replace('%br-lan','%br;lan',1),
                        scoped.replace('%br-lan','%br$(id)',1),
                        scoped.replace('%br-lan','%br%lan',1)]:
            x=f(); x.env['SSH_CONNECTION']=invalid; x.call('stage',1)
            assert x.phase()=='initial' and x.config.read_bytes()==x.before
        passed.append('SSH scoped-zone newline, semicolon, command substitution and duplicate percent rejected')

        x=f(); x.call('stage')
        x.config.write_text(x.config.read_text()+'# unrelated concurrent edit\n')
        changed=x.config.read_bytes(); x.call('rollback',1)
        assert x.phase()=='rollback_pending' and x.config.read_bytes()==changed and x.data()['enabled']
        passed.append('unknown concurrent firewall file change not silently clobbered; pending watchdog retained')

        x=f(hang_candidate=True)
        p=x.base/'switch'; p.write_text(p.read_text().replace('bounded() { limited 20 ', 'bounded() { limited 1 '))
        x.call('stage',1)
        assert x.phase()=='rolled_back' and x.config.read_bytes()==x.before
        pid=int((x.base/'bounded-grandchild').read_text())
        stat=Path(f'/proc/{pid}/stat')
        assert not stat.exists() or stat.read_text().split(') ',1)[1].split()[0]=='Z'
        assert 'ERROR:bounded_child_inherited_transaction_lock' not in x.events()
        passed.append('setsid timeout TERM/KILL removes TERM-ignoring grandchild; bounded children close transaction FD9')

        init=(HERE/'openwrt-admin-switch.init').read_text()
        assert '_needs-watch' in init and 'respawn 3600 5 0' in init
        for path in [SOURCE,HERE/'openwrt-admin-switch.init']:
            subprocess.run(['busybox','ash','-n',str(path)],check=True)
        passed.append('BusyBox ash syntax and procd conditional start/respawn policy')
      finally:
        for x in fixtures: x.cleanup()
        time.sleep(.2)
    result={'scope':'LOCAL_MOCKS_ONLY_NO_SSH_NO_REAL_FIREWALL','passed':len(passed),'cases':passed}
    (HERE/'openwrt-admin-test-results.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(result,ensure_ascii=False,indent=2))


if __name__=='__main__': main()
