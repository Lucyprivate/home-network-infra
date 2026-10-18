#!/usr/bin/env python3
"""Run the pure actual ucode model tests on an installed OpenWrt interpreter.

Remote command is read-only, contains no live endpoint or credentials and does
not upload files. Optional --local-ucode uses an existing local interpreter.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import subprocess

def sources():
    here = Path(__file__).resolve().parent
    tests = (here / 'tests.uc').read_text()
    model_tests, nft_tests = tests.split('function expr(output)', 1)
    report = "print(sprintf('%J\\n',{ok:true,passed:length(results),tests:results}));"
    helpers = """let results=[]; function check(n,b){if(!b)die('FAILED '+n);push(results,n);}
function cp(v){return json(sprintf('%J',v));}
let e={schema:1,node_id:'abc123',label:'Test native H2',wan:'eth0',address:'198.51.100.2',port:443};
let bad;
"""
    # Keep independent test groups, executed via stdin/loadstring so Dropbear's
    # command-size limit is irrelevant and no remote temporary files are needed.
    model = (here / 'model.uc').read_text().replace('export function', 'function')
    nft = (here / 'nft.uc').read_text().replace('export function', 'function')
    collector = (here / 'collector.uc').read_text()
    # The actual collector functions run against mocked fs; fixed main routine
    # is excluded so the test cannot touch a table, configuration or filesystem.
    declarations = collector.split('directory(STORE); directory(RUN);', 1)[0]
    declarations = '\n'.join(line for line in declarations.splitlines()
                             if not line.startswith('import ') and not line.startswith('#!'))
    declarations = declarations.replace('system(', 'fake_system(')
    atomic = (model + nft + (here / 'atomic-tests.uc').read_text() + declarations +
              (here / 'atomic-assertions.uc').read_text())
    return [
        (here / 'model.uc').read_text().replace('export function', 'function') + model_tests + report,
        (here / 'nft.uc').read_text().replace('export function', 'function') + helpers + 'function expr(output)' + nft_tests,
        atomic,
    ]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--local-ucode')
    parser.add_argument('--ssh-config', default='outputs/pve-access.conf')
    parser.add_argument('--host', default='openwrt-wan')
    parser.add_argument('--installed-compile', action='store_true',
                        help='Also verify byte-identical installed modules and compile actual imports read-only')
    args = parser.parse_args()
    parsed = {'ok': True, 'passed': 0, 'tests': []}
    for src in sources():
        loader = 'ucode -e ' + shlex.quote('import {readfile} from "fs"; let fn=loadstring(readfile("/dev/stdin")); fn();')
        command = ([args.local_ucode, '-e', src] if args.local_ucode else
                   ['ssh', '-F', args.ssh_config, args.host, loader])
        result = subprocess.run(command, input=None if args.local_ucode else src,
                                text=True, capture_output=True, timeout=30)
        if result.returncode:
            raise SystemExit(result.stderr or 'ucode tests failed')
        group = json.loads(result.stdout)
        if not group.get('ok'):
            raise SystemExit('test group failed')
        parsed['passed'] += group['passed']
        parsed['tests'] += group['tests']
    if parsed['passed'] < 30:
        raise SystemExit('incomplete test output')
    if args.installed_compile:
        if args.local_ucode:
            raise SystemExit('--installed-compile needs the OpenWrt SSH target')
        here = Path(__file__).resolve().parent
        names = ('model.uc', 'nft.uc', 'collector.uc')
        paths = ' '.join('/usr/share/proxy-usage/' + name for name in names)
        command = ['ssh', '-F', args.ssh_config, args.host,
                   'ucode -c -o /dev/null /usr/share/proxy-usage/collector.uc && sha256sum ' + paths]
        result = subprocess.run(command, text=True, capture_output=True, timeout=30)
        if result.returncode:
            raise SystemExit(result.stderr or 'actual installed module compile failed')
        hashes = {line.split()[1]: line.split()[0] for line in result.stdout.splitlines()}
        for name in names:
            expected = hashlib.sha256((here / name).read_bytes()).hexdigest()
            if hashes.get('/usr/share/proxy-usage/' + name) != expected:
                raise SystemExit('Installed source differs: ' + name)
            parsed['tests'].append('actual installed source hash matches ' + name)
            parsed['passed'] += 1
        parsed['tests'].append('actual installed module exports and imports compile')
        parsed['passed'] += 1
    print(json.dumps(parsed, ensure_ascii=False, indent=2))

if __name__ == '__main__':
    main()
