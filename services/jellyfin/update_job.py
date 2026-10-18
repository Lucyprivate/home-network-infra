"""VM root wrapper: one 900-second budget for update and native refresh."""
import argparse
import fcntl
import json
import os
import pathlib
import subprocess
import sys
import time

B = pathlib.Path('/srv/jellyfin')
L = B / 'livetv'
T = B / 'tools/livetv'
LOCK = pathlib.Path('/run/jf-live-update.lock')
PYTHON = 'python:3.13-slim@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f'
JOB_SECONDS = 900
CLEANUP_SECONDS = 2


def docker_command(mode):
    return ['docker', 'run', '--rm', '--pull', 'never', '--name', 'jf-live-update',
            '--network', 'jfmedia_media', '--ip', '172.28.40.5', '--dns', '10.10.10.1',
            '--user', '10003:10002', '--memory', '384m', '--memory-swap', '384m',
            '--cpus', '0.5', '--pids-limit', '64', '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges:true', '--read-only',
            '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m', '-e', 'TZ=Etc/UTC',
            '-e', 'HTTP_PROXY=', '-e', 'HTTPS_PROXY=', '-e', 'ALL_PROXY=',
            '-v', str(T / 'updater.py') + ':/app/updater.py:ro',
            '-v', str(T / 'channels.json') + ':/app/channels.json:ro',
            '-v', str(L) + ':/data', PYTHON, 'python', '-B', '/app/updater.py',
            '--root', '/data', '--mode', mode]


def run_update(mode):
    deadline = time.monotonic() + JOB_SECONDS

    def remaining(cap=None, reserve=CLEANUP_SECONDS):
        value = deadline - time.monotonic() - reserve
        if value <= 0:
            raise subprocess.TimeoutExpired('live-update-deadline', JOB_SECONDS)
        return min(cap, value) if cap is not None else value

    try:
        guard = subprocess.run(['python3', str(T / 'network_guard.py'), '--status'],
                               capture_output=True, text=True, timeout=remaining(15))
    except subprocess.TimeoutExpired:
        print('Direct-route guard exceeded the job deadline.')
        return 124
    if guard.returncode:
        print('Direct-route guard is not ready.')
        return 1
    try:
        result = subprocess.run(docker_command(mode), timeout=remaining())
    except subprocess.TimeoutExpired:
        # The CLI is already killed. A graceful container stop exceeds this budget.
        try:
            subprocess.run(['docker', 'kill', '--signal', 'KILL', 'jf-live-update'],
                           capture_output=True, timeout=remaining(CLEANUP_SECONDS, reserve=0))
        except (subprocess.TimeoutExpired, OSError):
            pass
        print('Live TV update reached its hard deadline; container kill requested. Current valid files are retained.')
        return 124
    if result.returncode:
        return result.returncode
    requested = (L / 'credentials/jellyfin-updater.json').is_file()
    if requested:
        try:
            refresh = subprocess.run(['python3', str(T / 'configure_jellyfin.py'), '--refresh'],
                                     capture_output=True, text=True, timeout=remaining(60))
        except subprocess.TimeoutExpired:
            print('Files updated; native guide refresh reached the job deadline.')
            return 124
        receipt = L / 'runtime/last-refresh.json'
        receipt.write_text(refresh.stdout)
        receipt.chmod(0o600)
        if refresh.returncode:
            print('Files updated; native guide refresh failed.')
            return 1
    print(json.dumps({'status': 'updated', 'mode': mode, 'guide_refresh_requested': requested}))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=['full', 'epg'], required=True)
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        print('Live TV update wrapper requires root.')
        return 1
    with LOCK.open('w') as lock:
        os.fchmod(lock.fileno(), 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print('Another Live TV update is running.')
            return 75
        return run_update(args.mode)


if __name__ == '__main__':
    sys.exit(main())
