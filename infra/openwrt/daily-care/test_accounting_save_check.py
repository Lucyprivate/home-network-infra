#!/usr/bin/env python3
"""Exercise the exact read-only gate using synthetic fs data and real ucode.

No fixtures are written to OpenWrt. The installed pure accounting model is
imported read-only; fs calls from the gate are replaced by in-memory fixtures.
"""
import argparse
import json
from pathlib import Path
import shlex
import subprocess

SHIM = r'''
import { new_state } from '/usr/share/proxy-usage/model.uc';
let fixture;
function clone(v) { return json(sprintf('%J',v)); }
function reset() {
 let d=new_state(800,'2000-01');d.mode='proxy';d.saved_at=1100;d.updated_at=1100;
 let r=clone(d);r.updated_at=1101;
 fixture={data:{
  '/etc/proxy-usage/state.json':d,
  '/var/run/proxy-usage/runtime.json':r,
  '/var/run/proxy-usage/status.json':{schema:1,service:'running',updated_at:1101}
 },stat:{},raw:{}};
}
function lstat(p) {
 if(fixture.stat[p]!=null)return fixture.stat[p];
 if(p=='/etc/proxy-usage'||p=='/var/run/proxy-usage')return {type:'directory',uid:0,mode:448};
 if(!(p in fixture.data)&&!(p in fixture.raw))return null;
 return {type:'file',uid:0,mode:384,nlink:1,size:100,inode:p=='/etc/proxy-usage/state.json'?8:9};
}
function readfile(p) { return p in fixture.raw ? fixture.raw[p] : sprintf('%J',fixture.data[p]); }
reset();
'''

TESTS = r'''
let tests=[];
function okay(args) { try {return saved_currently(args || ['1000','7']);} catch(e){return false;} }
function expect(name,result){if(!result)die('FAILED '+name);push(tests,name);}
expect('fresh durable save and matching running runtime accepted',okay());
reset();fixture.data['/etc/proxy-usage/state.json'].saved_at=999;
expect('nonempty stale durable file rejected',!okay());
reset();fixture.data['/var/run/proxy-usage/runtime.json'].updated_at=999;
expect('stale runtime rejected',!okay());
reset();fixture.data['/var/run/proxy-usage/status.json'].service='stopped';
expect('not running snapshot rejected',!okay());
reset();fixture.raw['/etc/proxy-usage/state.json']='{broken';
expect('malformed durable JSON rejected',!okay());
reset();fixture.data['/etc/proxy-usage/state.json'].lifetime.upload_bytes=-1;
expect('invalid durable schema rejected',!okay());
reset();fixture.data['/var/run/proxy-usage/runtime.json'].lifetime.download_bytes=-1;
expect('invalid runtime schema rejected',!okay());
reset();expect('unchanged durable inode rejected',!okay(['1000','8']));
reset();fixture.data['/var/run/proxy-usage/runtime.json'].saved_at=1099;
expect('runtime preceding durable save rejected',!okay());
reset();fixture.data['/var/run/proxy-usage/runtime.json'].since=801;
expect('unrelated runtime identity rejected',!okay());
reset();fixture.data['/var/run/proxy-usage/status.json'].updated_at=1100;
expect('runtime and published status mismatch rejected',!okay());
reset();fixture.stat['/etc/proxy-usage/state.json']={type:'symlink',uid:0,mode:384,nlink:1,size:100,inode:8};
expect('symlink durable file rejected',!okay());
reset();fixture.stat['/var/run/proxy-usage/runtime.json']={type:'file',uid:1000,mode:384,nlink:1,size:100,inode:9};
expect('non-root runtime file rejected',!okay());
reset();fixture.stat['/var/run/proxy-usage/status.json']={type:'file',uid:0,mode:420,nlink:1,size:100,inode:9};
expect('non-private status file rejected',!okay());
reset();fixture.stat['/etc/proxy-usage']={type:'directory',uid:0,mode:493};
expect('non-private parent directory rejected',!okay());
reset();fixture.stat['/etc/proxy-usage/state.json']={type:'file',uid:0,mode:384,nlink:2,size:100,inode:8};
expect('hard-linked durable state rejected',!okay());
reset();delete fixture.data['/etc/proxy-usage/state.json'];
expect('missing durable state rejected',!okay());
reset();expect('caller-supplied filename is never accepted',!okay(['/etc/shadow','7']));
expect('invalid inode argument rejected',!okay(['1000','not-an-inode']));
expect('unexpected argument count rejected',!okay(['1000']));
print(sprintf('%J\n',{ok:true,passed:length(tests),tests:tests}));
'''

def run(source, args):
    loader = 'import {readfile} from "fs"; let fn=loadstring(readfile("/dev/stdin")); fn();'
    command = ['ssh', '-F', args.ssh_config, args.host, 'ucode -e ' + shlex.quote(loader)]
    return subprocess.run(command, input=source, text=True, capture_output=True, timeout=30)

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--ssh-config',default='outputs/pve-access.conf')
    parser.add_argument('--host',default='openwrt-wan')
    args=parser.parse_args()
    source=Path(__file__).with_name('accounting-save-check.uc').read_text()
    source=source.replace("import { lstat, readfile } from 'fs';", '')
    declarations=source.split('try { exit(saved_currently(ARGV) ? 0 : 1); }',1)[0]
    result=run(SHIM+declarations+TESTS,args)
    if result.returncode:
        raise SystemExit(result.stderr or 'accounting freshness tests failed')
    report=json.loads(result.stdout)
    if not report.get('ok') or report.get('passed',0)<20:
        raise SystemExit('incomplete tests')
    # Exercise the helper's exact final 0/1 exit path with no payload output.
    for name, setup, expected in (
        ('entrypoint success is silent and returns zero',"global.ARGV=['1000','7'];",0),
        ('entrypoint stale save is silent and returns one',"fixture.data['/etc/proxy-usage/state.json'].saved_at=999;global.ARGV=['1000','7'];",1),
        ('entrypoint malformed JSON is silent and returns one',"fixture.raw['/etc/proxy-usage/state.json']='{bad';global.ARGV=['1000','7'];",1),
    ):
        result=run(SHIM+setup+source,args)
        if result.returncode!=expected or result.stdout or result.stderr:
            raise SystemExit('failed: '+name)
        report['tests'].append(name);report['passed']+=1
    print(json.dumps(report,ensure_ascii=False,indent=2))

if __name__=='__main__':
    main()
