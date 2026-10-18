#!/usr/bin/env python3
"""Run fixture-only tests. No live installer, daemon or network is started."""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PORTABLE = [
    ['-m', 'unittest', 'discover', '-s', 'tests', '-v'],
    ['infra/tests/test_control_plane.py'],
    ['services/home-tools/test_network_guard.py'],
    ['services/tests/test_service_contracts.py'],
]
POSIX = [
    'infra/pve/reference/ports/test_port_reorder.py',
    'infra/pve/reference/uplink/test_uplink.py',
    'infra/pve/reference/router-ready/test_downstream_test.py',
    'infra/pve/reference/router-ready/test_readiness.py',
    'infra/pve/reference/router-ready/test_openwrt_admin.py',
    'infra/ubuntu-service-host/test_docker_setup.py',
    'infra/openwrt/daily-care/test_backup_hook.py',
    'infra/openwrt/daily-care/test_backup_pull.py',
    'infra/openwrt/wireguard/controller/test_controller.py',
    'infra/openwrt/wireguard/luci/backend/test_webctl.py',
]


def main():
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
    commands = [[sys.executable, '-B', *args] for args in PORTABLE]
    if os.name == 'posix':
        commands += [[sys.executable, '-B', path] for path in POSIX]
    node = os.environ.get('NODE_BINARY') or shutil.which('node')
    if not node:
        raise RuntimeError('Node.js is required for UI fixture tests')
    commands += [[node, path] for path in (
        'infra/openwrt/wireguard/luci/ui/test_view.js',
        'infra/openwrt/bandwidth-monitor/ui/test_view.js')]
    failures = []
    for command in commands:
        result = subprocess.run(command, cwd=ROOT, env=env, timeout=180)
        if result.returncode:
            failures.append(command[-1])
    print(json.dumps({'passed': not failures, 'failed_groups': failures, 'command_groups': len(commands),
                      'posix_groups_run': len(POSIX) if os.name == 'posix' else 0,
                      'live_deployment_performed': False}))
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
