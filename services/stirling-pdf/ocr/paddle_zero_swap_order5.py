"""UNEXECUTED order-v5 quad release helper: Stirling-only scoped zero-swap policy.

The dedicated slice enforces zero swap before container creation. The post-start
scope property mirrors that parent policy for inspection; it supplies no startup
window guarantee by itself. Default status is read-only. No Docker lifecycle,
global systemd reload, other container, network or memory/CPU mutation is used.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time
import uuid

ROOT=Path('/srv/stirling-pdf')
LAB='/usr/local/share/stirling-paddle-order2-lab'
SLICE='stirling-pdf.slice'
PARENT_CGROUP='/stirling.slice/stirling-pdf.slice'
IMAGE='ghcr.io/stirling-tools/stirling-pdf:3.1.0@sha256:b5b9e400c086e5334a4947a0d7cd589808f743f29267d7f41c18200cf4bc48b4'
OWNER='ServiceHostStirlingPaddleOrder5ZeroSwap20000101'
MEMORY=1536*1024*1024
SLICE_UNIT=b'''[Unit]
Description=Stirling-PDF private zero-swap container parent

[Slice]
MemoryAccounting=yes
MemorySwapMax=0
'''


class Refused(RuntimeError):pass


def command(argv,timeout=5):
    value=subprocess.run(argv,capture_output=True,text=True,timeout=timeout)
    if value.returncode:raise Refused('Fixed owned-cgroup query failed')
    return value.stdout


def properties(unit):
    return dict(line.split('=',1) for line in command(['systemctl','show',unit,
        '-p','Id','-p','ActiveState','-p','ControlGroup','-p','MemoryMax',
        '-p','MemorySwapMax','-p','FragmentPath','-p','DropInPaths']).splitlines() if '=' in line)


def read_owned(path,maximum=1024*1024):
    path=Path(path)
    for parent in (path.parent,*path.parent.parents):
        s=parent.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022:raise Refused('Untrusted owned-file ancestor')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        s=os.fstat(f.fileno())
        if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1 or s.st_uid!=0 or s.st_mode&0o022 or not 0<s.st_size<=maximum:raise Refused('Untrusted bounded owned file')
        data=f.read(maximum+1);after=os.fstat(f.fileno())
        if len(data)!=s.st_size or (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns):raise Refused('Owned file changed while reading')
        return data


def validate_compose(value):
    try:
        s=value['services']['stirling']
        expected={'type':'bind','source':str(ROOT/'local/paddle-order5-runtime'),'target':LAB,
                  'read_only':True,'bind':{'create_host_path':False}}
        if (set(value['services'])!={'stirling'} or s['image']!=IMAGE or
                s['container_name']!='stirling-pdf' or s['restart']!='no' or
                s['cgroup_parent']!=SLICE or s['mem_limit']!='1536m' or
                s['memswap_limit']!='1536m' or type(s['cpus']) not in (int,float) or s['cpus']!=1 or
                [m for m in s['volumes'] if m.get('target')==LAB]!=[expected]):
            raise Refused('Fixed Stirling parent/resource/runtime binding differs')
    except (KeyError,TypeError):raise Refused('Invalid fixed Compose structure') from None


def validate_parent(props,kernel):
    if (props.get('Id')!=SLICE or props.get('ActiveState')!='active' or
            props.get('ControlGroup')!=PARENT_CGROUP or props.get('MemorySwapMax')!='0' or
            props.get('FragmentPath')!='/etc/systemd/system/'+SLICE or
            props.get('DropInPaths','').strip() or kernel!='0'):
        raise Refused('Owned pre-start parent is not active with exact zero swap')


def parent_state():
    if read_owned(Path('/etc/systemd/system')/SLICE)!=SLICE_UNIT:raise Refused('Private slice source differs')
    validate_compose(json.loads(read_owned(ROOT/'compose.yaml')))
    p=properties(SLICE)
    cg=Path('/sys/fs/cgroup')/PARENT_CGROUP.lstrip('/')
    for directory in (cg,*cg.parents):
        s=directory.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0:raise Refused('Invalid private cgroup hierarchy')
    kernel=(cg/'memory.swap.max').read_text().strip();validate_parent(p,kernel)
    return {'slice':SLICE,'cgroup':PARENT_CGROUP,'manager_swap_max':p['MemorySwapMax'],'kernel_swap_max':kernel}


def validate_container(value):
    try:
        cid,pid=value['Id'],value['State']['Pid'];c=value['Config'];h=value['HostConfig'];labels=c['Labels']
        if not isinstance(cid,str) or not re.fullmatch('[0-9a-f]{64}',cid) or type(pid) is not int or pid<=1:raise Refused('Invalid live container identity')
        expected={'io.codex.owner':'ServiceHostStirlingPDF20000101','com.docker.compose.project':'stirling-pdf',
                  'com.docker.compose.service':'stirling','com.docker.compose.project.working_dir':str(ROOT),
                  'com.docker.compose.project.config_files':str(ROOT/'compose.yaml')}
        if (value['State']['Running'] is not True or value['State']['OOMKilled'] is not False or c['Image']!=IMAGE or
                any(labels.get(k)!=v for k,v in expected.items()) or h['CgroupParent']!=SLICE or
                type(h['Memory']) is not int or h['Memory']!=MEMORY or h['MemorySwap']!=MEMORY or
                type(h['NanoCpus']) is not int or h['NanoCpus']!=1_000_000_000):raise Refused('Container is outside the fixed owned parent/resources')
        return cid,pid
    except (KeyError,TypeError):raise Refused('Incomplete owned container metadata') from None


def validate_membership(cid,pid,group,members):
    wanted=PARENT_CGROUP+'/docker-'+cid+'.scope'
    if group!=wanted or str(pid) not in members:raise Refused('Owned process is outside the zero-swap parent')
    return wanted


def container_state(value):
    cid,pid=validate_container(value);process=Path('/proc')/str(pid)
    before=process.joinpath('stat').read_text().rsplit(')',1)[1].split()[19]
    groups=process.joinpath('cgroup').read_text().splitlines()
    if len(groups)!=1 or not groups[0].startswith('0::/'):raise Refused('Expected unified owned cgroup')
    group=groups[0][3:];cg=Path('/sys/fs/cgroup')/group.lstrip('/')
    validate_membership(cid,pid,group,cg.joinpath('cgroup.procs').read_text().split())
    limits={name:cg.joinpath(name).read_text().strip() for name in ('memory.max','memory.swap.max','memory.swap.current','cpu.max')}
    if limits['memory.max']!=str(MEMORY) or limits['cpu.max']!='100000 100000' or not limits['memory.swap.current'].isdigit():raise Refused('Actual owned memory/CPU limits differ')
    unit='docker-'+cid+'.scope';props=properties(unit)
    if props.get('Id')!=unit or props.get('ActiveState')!='active' or props.get('ControlGroup')!=group or props.get('MemoryMax')!=str(MEMORY):raise Refused('Owned scope manager identity differs')
    if before!=process.joinpath('stat').read_text().rsplit(')',1)[1].split()[19] or groups!=process.joinpath('cgroup').read_text().splitlines():raise Refused('Container process changed during verification')
    return {'container_id':cid,'pid':pid,'starttime':before,'unit':unit,'cgroup':group,
            'limits':limits,'properties':props}


def inspect_running():
    # A stopped or absent fixed name is a normal short startup transition.
    v=subprocess.run(['docker','inspect','stirling-pdf'],capture_output=True,text=True,timeout=5)
    if v.returncode:
        if v.returncode==1 and not v.stdout.strip() and 'no such object: stirling-pdf' in v.stderr.lower():return None
        raise Refused('Fixed Docker inspect failed')
    rows=json.loads(v.stdout)
    if type(rows) is not list or len(rows)!=1:raise Refused('Ambiguous fixed container')
    item=rows[0]
    if item.get('Config',{}).get('Labels',{}).get('io.codex.owner')!='ServiceHostStirlingPDF20000101':raise Refused('Foreign fixed container name')
    return item if item.get('State',{}).get('Running') is True else None


def write_new(path,data):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    with os.fdopen(fd,'wb') as f:os.fchmod(f.fileno(),0o600);f.write(data);f.flush();os.fsync(f.fileno())
    descriptor=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(descriptor)
    finally:os.close(descriptor)


def enforce(wait_seconds):
    if os.geteuid()!=0:raise Refused('VM root is required for scoped enforcement')
    parent=parent_state();end=time.monotonic()+wait_seconds;item=None
    while time.monotonic()<end:
        item=inspect_running()
        if item is not None:break
        time.sleep(.2)
    if item is None:raise Refused('Owned container did not become running within startup budget')
    before=container_state(item);parent_state()
    # The slice is the no-startup-window guarantee, even if the leaf says max.
    initial={'schema':1,'owner':OWNER,'phase':'PREPARED','utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
             'parent':parent,'before':before,'memory_cpu_unchanged':True,'global_reload_used':False}
    data=(json.dumps(initial,sort_keys=True)+'\n').encode()
    for p in (ROOT/'runtime',ROOT):
        s=p.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022:raise Refused('Untrusted runtime receipt directory')
    receipt=ROOT/'runtime'/('paddle-order5-zero-swap-'+before['container_id'][:16]+'-'+uuid.uuid4().hex+'.json')
    write_new(receipt,data)
    if before['properties'].get('MemorySwapMax')!='0' or before['limits']['memory.swap.max']!='0':
        # Fresh PID/start/cgroup recheck immediately before the sole policy write.
        fresh=inspect_running()
        if fresh is None or container_state(fresh)!=before:raise Refused('Owned scope changed before policy write')
        command(['systemctl','set-property','--runtime',before['unit'],'MemorySwapMax=0'])
    after_item=inspect_running()
    if after_item is None:raise Refused('Owned scope disappeared after policy write')
    after=container_state(after_item);parent_state()
    if any(after[k]!=before[k] for k in ('container_id','pid','starttime','unit','cgroup')) or after['limits']['memory.max']!=before['limits']['memory.max'] or after['limits']['cpu.max']!=before['limits']['cpu.max'] or after['limits']['memory.swap.max']!='0' or after['properties'].get('MemorySwapMax')!='0':raise Refused('Scoped zero-swap readback failed')
    initial.update(phase='APPLIED',after=after,existing_swapped_pages_may_remain=True)
    if read_owned(receipt)!=data:raise Refused('Prepared private receipt changed')
    temporary=receipt.with_name('.zero-swap-'+uuid.uuid4().hex);write_new(temporary,(json.dumps(initial,sort_keys=True)+'\n').encode());os.replace(temporary,receipt)
    descriptor=os.open(receipt.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(descriptor)
    finally:os.close(descriptor)
    return {'result':'OWNED_PARENT_AND_SCOPE_ZERO_SWAP','container_id':after['container_id'],
            'parent_kernel_swap_max':'0','scope_kernel_swap_max':'0','scope_manager_swap_max':'0',
            'existing_swap_bytes':int(after['limits']['memory.swap.current']),'memory_cpu_unchanged':True}


def main():
    p=argparse.ArgumentParser(description=__doc__);actions=p.add_mutually_exclusive_group()
    actions.add_argument('--check-parent',action='store_true');actions.add_argument('--scope-enforce',action='store_true')
    p.add_argument('--wait-seconds',type=int,default=40);a=p.parse_args()
    try:
        if not 1<=a.wait_seconds<=40:raise Refused('Startup wait is outside the fixed bound')
        value=enforce(a.wait_seconds) if a.scope_enforce else {'result':'PARENT_ZERO_SWAP_VERIFIED','readonly':True,**parent_state()}
        print(json.dumps(value,sort_keys=True));return 0
    except Exception as e:
        print(json.dumps({'result':'REFUSED','error_type':type(e).__name__,'raw_error_emitted':False}));return 1


if __name__=='__main__':raise SystemExit(main())
