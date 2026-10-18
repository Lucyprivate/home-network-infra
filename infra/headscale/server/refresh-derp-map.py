#!/usr/bin/python
"""Manual official public DERP map refresh; CentOS 7 Python 2.7 compatible.

No daemon, timer, configuration edit, service signal or restart is performed.
The local file uses YAML integer region keys with JSON flow-map values. This
matches Headscale's map[int]*DERPRegion loader without a YAML dependency.
"""
from __future__ import print_function
import hashlib
import grp
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time

URL = 'https://controlplane.tailscale.com/derpmap/default'
MAP = '/etc/headscale/derp-public.yaml'
CONFIG = '/etc/headscale/config.yaml'
OWNER_DIR = '/var/lib/home-network-derp-map'
OWNER = OWNER_DIR + '/owner.json'
MAX_BYTES = 2097152


def sha(data):
    return hashlib.sha256(data).hexdigest()


def lower_keys(value):
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            normalized = key.lower()
            if normalized in result:
                raise ValueError('Duplicate case-insensitive DERP field')
            result[normalized] = lower_keys(item)
        return result
    if isinstance(value, list):
        return [lower_keys(item) for item in value]
    return value


def validate(data):
    if not data or len(data) > MAX_BYTES:
        raise ValueError('DERP map size is invalid')
    text = data.decode('utf-8')
    if text.lstrip().startswith('{'):
        value = lower_keys(json.loads(text))
    else:
        lines = text.splitlines()
        if not lines or lines[0] != 'regions:':
            raise ValueError('Local DERP map must start with regions:')
        regions = {}
        for line in lines[1:]:
            match = re.match(r'^  ([1-9][0-9]*): (\{.*\})$', line)
            if not match or match.group(1) in regions:
                raise ValueError('Invalid or duplicate local integer region key')
            regions[match.group(1)] = json.loads(match.group(2))
        value = lower_keys({'regions': regions})
    regions = value.get('regions')
    if not isinstance(regions, dict) or not 1 <= len(regions) <= 200:
        raise ValueError('Public DERP regions are missing or excessive')
    nodes = 0
    for key, region in regions.items():
        region_id = int(key)
        if region_id <= 0 or region_id == 999 or region.get('regionid') != region_id:
            raise ValueError('Region ID is invalid or collides with embedded 999')
        if not region.get('regioncode') or not region.get('regionname'):
            raise ValueError('Region identity is incomplete')
        entries = region.get('nodes')
        if not isinstance(entries, list) or not entries:
            raise ValueError('Region has no relay nodes')
        for node in entries:
            host = node.get('hostname', '')
            if node.get('regionid') != region_id or not node.get('name') or not host:
                raise ValueError('DERP node identity is incomplete')
            if len(host) > 253 or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-' for c in host):
                raise ValueError('DERP hostname is malformed')
            if not 1 <= int(node.get('derpport', 443) or 443) <= 65535:
                raise ValueError('DERP port is invalid')
            nodes += 1
    rows = ['regions:']
    for key in sorted(regions, key=lambda item: int(item)):
        rows.append('  ' + str(int(key)) + ': ' + json.dumps(regions[key], sort_keys=True, separators=(',', ':')))
    rendered = ('\n'.join(rows) + '\n').encode('utf-8')
    return rendered, {'regions': len(regions), 'nodes': nodes,
                      'sha256': sha(rendered), 'upstream_sha256': sha(data)}


def read_file(path, private=False):
    metadata = os.lstat(path)
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or
            metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) & 0o022 or
            private and stat.S_IMODE(metadata.st_mode) != 0o600):
        raise ValueError('Unsafe owned file: ' + path)
    with open(path, 'rb') as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError('Owned file exceeds size limit')
    return data, metadata


def atomic(path, data, mode, uid=0, gid=0):
    fd, temp = tempfile.mkstemp(prefix='.derp-map-', dir=os.path.dirname(path))
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chown(temp, uid, gid)
        os.chmod(temp, mode)
        os.rename(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def current():
    data, meta = read_file(MAP)
    rendered, info = validate(data)
    # Python 2/3 may serialize floats or whitespace differently. Validate the
    # structure, but bind ownership to the installed bytes without rewriting.
    info['sha256'] = sha(data)
    info.pop('upstream_sha256', None)
    config, config_meta = read_file(CONFIG)
    tool, tool_meta = read_file(os.path.abspath(__file__))
    headscale_gid = grp.getgrnam('headscale').gr_gid
    if (meta.st_gid != headscale_gid or stat.S_IMODE(meta.st_mode) != 0o640 or
            config_meta.st_gid != headscale_gid or stat.S_IMODE(config_meta.st_mode) != 0o640 or
            tool_meta.st_gid != 0 or stat.S_IMODE(tool_meta.st_mode) != 0o700):
        raise ValueError('Installed DERP map/config/tool ownership or mode differs')
    info.update(config_sha256=sha(config), tool_sha256=sha(tool),
                map_path=MAP, config_path=CONFIG)
    return data, meta, info


def owner_directory():
    if not os.path.exists(OWNER_DIR):
        os.mkdir(OWNER_DIR, 0o700)
    info = os.lstat(OWNER_DIR)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('Private DERP receipt directory is not root-owned 0700')


def owned(info):
    raw, unused = read_file(OWNER, private=True)
    receipt = json.loads(raw.decode('utf-8'))
    if receipt.get('schema') != 1 or receipt.get('state') != 'ACTIVE':
        raise ValueError('DERP receipt is not active')
    for key in ('sha256', 'config_sha256', 'tool_sha256', 'map_path', 'config_path'):
        if receipt.get(key) != info[key]:
            raise ValueError('DERP receipt mismatch: ' + key)
    if receipt.get('current_map_sha256') != info['sha256']:
        raise ValueError('DERP current map ownership mismatch')
    return raw, receipt


def main():
    action = sys.argv[1] if len(sys.argv) == 2 else 'check'
    if os.geteuid() != 0:
        raise ValueError('Run as root')
    old_map, meta, info = current()
    if action == 'init-receipt':
        owner_directory()
        if os.path.lexists(OWNER):
            raise ValueError('Refusing to replace an existing DERP receipt')
        info.update(schema=1, state='ACTIVE', source=URL,
                    initial_map_sha256=info['sha256'], current_map_sha256=info['sha256'],
                    initialized_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()))
        backup = OWNER_DIR + '/config.yaml'
        info['config_before_sha256'] = sha(read_file(backup, private=True)[0]) if os.path.exists(backup) else None
        atomic(OWNER, (json.dumps(info, indent=2, sort_keys=True) + '\n').encode(), 0o600)
        print(json.dumps({'state': 'ACTIVE', 'regions': info['regions'], 'nodes': info['nodes'], 'sha256': info['sha256']}))
        return
    old_owner, receipt = owned(info)
    if action == 'check':
        print(json.dumps({'state': 'ACTIVE', 'regions': info['regions'], 'nodes': info['nodes'], 'sha256': info['sha256'], 'read_only': True}))
        return
    if action == 'restore':
        backup, unused = read_file(OWNER_DIR + '/config.yaml', private=True)
        if not receipt.get('config_before_sha256') or sha(backup) != receipt['config_before_sha256']:
            raise ValueError('Original config backup does not match this overlay')
        unused, config_meta = read_file(CONFIG)
        # Existing service behavior remains unchanged until its owner reloads
        # or restarts it. Extra map/tool files are removed only after all exact
        # current ownership hashes and the original backup have been checked.
        atomic(CONFIG, backup, stat.S_IMODE(config_meta.st_mode), config_meta.st_uid, config_meta.st_gid)
        os.unlink(MAP)
        os.unlink(os.path.abspath(__file__))
        receipt.update(state='RESTORED', restored_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()))
        atomic(OWNER, (json.dumps(receipt, sort_keys=True, indent=2) + '\n').encode(), 0o600)
        print(json.dumps({'state': 'RESTORED', 'service_restarted': False, 'backup_retained': OWNER_DIR}))
        return
    if action != 'refresh':
        raise ValueError('Usage: refresh-derp-map.py check|refresh|init-receipt|restore')
    with tempfile.TemporaryFile() as errors:
        process = subprocess.Popen(['curl', '--fail', '--location', '--silent', '--show-error',
            '--connect-timeout', '10', '--max-time', '30', '--max-filesize', str(MAX_BYTES), URL],
            stdout=subprocess.PIPE, stderr=errors)
        # Older CentOS curl cannot enforce --max-filesize on chunked responses.
        # Bound the actual bytes read independently, then stop this own curl.
        chunks, used = [], 0
        while True:
            chunk = process.stdout.read(min(65536, MAX_BYTES + 1 - used))
            if not chunk:
                break
            chunks.append(chunk)
            used += len(chunk)
            if used > MAX_BYTES:
                process.terminate()
                process.communicate()
                raise ValueError('Official map exceeds 2 MiB; installed map preserved')
        data = b''.join(chunks)
        process.communicate()
        if process.returncode:
            raise ValueError('Official map fetch failed; installed map preserved')
    new_map, refreshed = validate(data)
    # Recheck all owned bytes after the fetch; never overwrite concurrent edits.
    now_map, unused, now_info = current()
    now_owner, unused = owned(now_info)
    if now_map != old_map or now_owner != old_owner:
        raise ValueError('Owned files changed during download; refusing replacement')
    receipt.update(refreshed)
    receipt['current_map_sha256'] = refreshed['sha256']
    receipt['refreshed_utc'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    new_owner = (json.dumps(receipt, indent=2, sort_keys=True) + '\n').encode()
    try:
        atomic(MAP, new_map, stat.S_IMODE(meta.st_mode), meta.st_uid, meta.st_gid)
        atomic(OWNER, new_owner, 0o600)
    except Exception:
        atomic(MAP, old_map, stat.S_IMODE(meta.st_mode), meta.st_uid, meta.st_gid)
        atomic(OWNER, old_owner, 0o600)
        raise
    print(json.dumps({'state': 'REFRESHED', 'regions': refreshed['regions'], 'nodes': refreshed['nodes'],
                      'sha256': refreshed['sha256'], 'service_restarted': False,
                      'loaded_by_existing_headscale_derp_refresh_within': '3h'}))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('REFUSED: ' + str(error), file=sys.stderr)
        sys.exit(1)
