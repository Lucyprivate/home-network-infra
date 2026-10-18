#!/usr/bin/env python3
"""VM100 vzdump hook: persist accounting before an online snapshot."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys

GUEST_PREPARE = r'''set -eu
umask 077
PREPARE_START=$(date +%s)
PREPARE_INODE=$(/usr/bin/ucode -e 'import {lstat} from "fs"; let s=lstat("/etc/proxy-usage/state.json"); if(s?.type != "file") exit(1); printf("%d",s.inode);')
nlbw -c commit | grep -Fqx '0 ok'
/etc/init.d/proxy-usage restart
CHECKED=0
for ATTEMPT in 0 1 2 3 4 5 6 7 8 9; do
    if /usr/bin/ucode -e '// SPDX-License-Identifier: MIT
// Read-only backup preparation gate. ARGV: start epoch, pre-save state inode.
// No data is printed. Zero means this preparation produced a durable save and
// a matching healthy running monitor snapshot; all other results mean retry.
'"'"'use strict'"'"';
import { lstat, readfile } from '"'"'fs'"'"';
import { valid_state } from '"'"'/usr/share/proxy-usage/model.uc'"'"';

function decimal(v) {
	if (type(v) != '"'"'string'"'"' || !match(v, /^[0-9]{1,16}$/)) return null;
	let n = +v;
	return type(n) == '"'"'int'"'"' && n > 0 && n <= 9007199254740991 ? n : null;
}

function private_directory(path) {
	let s = lstat(path);
	return s?.type == '"'"'directory'"'"' && s.uid == 0 && s.mode == 448;
}

function private_json(path) {
	let s = lstat(path);
	if (s?.type != '"'"'file'"'"' || s.uid != 0 || s.mode != 384 || s.nlink != 1 ||
	    s.size < 2 || s.size > 262144) return null;
	let text = readfile(path);
	if (text == null) return null;
	let value = json(text);
	return { value: value, inode: s.inode };
}

function saved_currently(args) {
	if (type(args) != '"'"'array'"'"' || length(args) != 2) return false;
	let start = decimal(args[0]), before_inode = decimal(args[1]);
	if (start == null || before_inode == null ||
	    !private_directory('"'"'/etc/proxy-usage'"'"') || !private_directory('"'"'/var/run/proxy-usage'"'"')) return false;
	let durable = private_json('"'"'/etc/proxy-usage/state.json'"'"');
	let runtime = private_json('"'"'/var/run/proxy-usage/runtime.json'"'"');
	let status = private_json('"'"'/var/run/proxy-usage/status.json'"'"');
	if (!durable || !runtime || !status || durable.inode == before_inode ||
	    !valid_state(durable.value) || !valid_state(runtime.value)) return false;
	let d = durable.value, r = runtime.value, s = status.value;
	return d.saved_at >= start && r.updated_at >= start && r.saved_at >= d.saved_at &&
		r.since == d.since && s.schema == 1 && s.service == '"'"'running'"'"' &&
		s.updated_at == r.updated_at;
}

try { exit(saved_currently(ARGV) ? 0 : 1); }
catch (e) { exit(1); }
' -- "$PREPARE_START" "$PREPARE_INODE"; then
        CHECKED=1
        break
    fi
    sleep 1
done
test "$CHECKED" = 1
mkdir -p /root/openwrt-recovery
chmod 700 /root/openwrt-recovery
sysupgrade -b /root/openwrt-recovery/.config-current.tar.gz.tmp
chmod 600 /root/openwrt-recovery/.config-current.tar.gz.tmp
mv /root/openwrt-recovery/.config-current.tar.gz.tmp /root/openwrt-recovery/config-current.tar.gz
ubus call system board > /root/openwrt-recovery/board.json
apk list --installed > /root/openwrt-recovery/packages.txt
chmod 600 /root/openwrt-recovery/board.json /root/openwrt-recovery/packages.txt
'''

def ensure_completed(result):
    if result.returncode:
        raise RuntimeError('guest preparation command failed')
    data = json.loads(result.stdout)
    if type(data.get('exited')) not in (bool, int) or data.get('exited') != 1 or data.get('exitcode') != 0:
        raise RuntimeError('guest preparation did not finish successfully')

def restrict_artifact(raw, suffix):
    path = Path(raw)
    pattern = r'vzdump-qemu-100-\d{4}_\d{2}_\d{2}-\d{2}_\d{2}_\d{2}' + re.escape(suffix)
    if path.parent != Path('/var/lib/vz/dump') or not re.fullmatch(pattern, path.name):
        raise RuntimeError('unexpected backup artifact path')
    if path.is_symlink() or not path.is_file():
        raise RuntimeError('backup artifact is not a regular owned-path file')
    path.chmod(0o600)

def run(argv, env=os.environ, command=subprocess.run):
    if not argv:
        raise RuntimeError('missing vzdump phase')
    phase = argv[0]
    if phase in {'job-init','job-start','job-end','job-abort'}:
        return
    if len(argv) != 3 or argv[2] != '100':
        raise RuntimeError('hook is restricted to VM100')
    mode = argv[1]
    if phase == 'backup-start':
        if mode != 'snapshot':
            raise RuntimeError('hook requires the configured snapshot mode')
        state = command(['/usr/sbin/qm','status','100'], capture_output=True, text=True, timeout=15)
        if state.returncode:
            raise RuntimeError('cannot establish VM100 status')
        if state.stdout.strip() == 'status: stopped':
            print('HOOK: VM100 stopped; backing up existing durable state')
            return
        if state.stdout.strip() != 'status: running':
            raise RuntimeError('unexpected VM100 state')
        result = command(['/usr/sbin/qm','guest','exec','100','--timeout','45','--synchronous','1','--','/bin/sh','-c',GUEST_PREPARE], capture_output=True, text=True, timeout=60)
        ensure_completed(result)
        print('HOOK: VM100 accounting and private configuration snapshot saved')
    elif phase == 'backup-end':
        restrict_artifact(env['TARGET'], '.vma.zst')
    elif phase == 'log-end':
        restrict_artifact(env['LOGFILE'], '.log')
    elif phase in {'backup-abort','pre-stop','pre-restart','post-restart'}:
        return
    else:
        raise RuntimeError('unknown vzdump phase')

if __name__ == '__main__':
    try:
        run(sys.argv[1:])
    except (RuntimeError, ValueError, KeyError, subprocess.TimeoutExpired, OSError) as e:
        print('HOOK: preparation/artifact verification failed: ' + str(e), file=sys.stderr)
        sys.exit(1)
