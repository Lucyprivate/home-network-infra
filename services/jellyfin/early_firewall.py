#!/usr/bin/env python3
"""Install only the owned nft guard before Docker may restore containers.

No interface, address, route, bridge, Docker API, or network-online dependency
is needed. The normal guard configures route table 152 after Docker starts.
Stopping this oneshot leaves the firewall present; rollback removes it through
network_guard --remove only after this deployment's containers are stopped.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import stat
import sys

import network_guard as guard

EXPECTED_TABLE = 'jf_livetv_guard'


def private_directory(path):
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
        raise RuntimeError('Early firewall state directory must be root-owned mode 700')


def apply_firewall(check_only=False):
    if guard.FIREWALL != EXPECTED_TABLE:
        raise RuntimeError('Unexpected firewall ownership scope')
    identity = guard.validate_firewall()
    if identity is None and not check_only:
        # At boot the normal guard waits for Docker, so its lock is available.
        # During online installation the guard holds this lock for its lifetime;
        # the exact-owned existing table above is simply verified, without
        # waiting for that lock. Only missing-table creation needs serialization.
        descriptor = os.open(guard.LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(descriptor, 'a') as lock:
            info = os.fstat(lock.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1:
                raise RuntimeError('Early firewall guard lock must be a real root-owned private file')
            os.fchmod(lock.fileno(), 0o600)
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            guard.ensure_firewall()
            identity = guard.validate_firewall()
    if identity is None:
        raise RuntimeError('Owned early firewall is absent; Docker must stay stopped')
    return {'status': 'EARLY_FIREWALL_READY', 'table': EXPECTED_TABLE,
            'identity': identity, 'routes_configured': False,
            'docker_or_interfaces_required': False, 'check_only': check_only}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='Verify only; do not create a table or state directories.')
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        raise SystemExit('Run the early firewall as VM root')
    os.umask(0o077)
    try:
        if args.check:
            result = apply_firewall(check_only=True)
        else:
            private_directory(guard.RUNTIME)
            result = apply_firewall()
    except Exception as error:
        # Failure propagates to Requires=/After= on docker.service; never
        # replace/delete a conflicting table or continue to route setup.
        print('Early firewall refused: ' + str(error), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
