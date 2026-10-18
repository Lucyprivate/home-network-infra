#!/usr/bin/env python3
"""Validate security boundaries locally and execute RPC tests in actual ucode.

--remote-ucode uses the already authorized SSH connection, executes code only,
and writes no OpenWrt files/configuration. Runtime filesystem reads are mocked.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess

BASE = Path(__file__).resolve().parent
RPC = BASE / "rpcd/luci.proxy-usage"
VIEW = BASE / "view/proxy.js"


def fixture():
    count = dict(upload_bytes=8192, download_bytes=4096, upload_packets=8, download_packets=4)
    return dict(schema=1, service="running", label="vpn-exit", mode="proxy",
                coverage=dict(state="complete", gaps=0, last_gap=None, since=946684800),
                updated_at=946685100, saved_at=946684800, interval_seconds=30,
                rates=dict(upload_bps=12.5, download_bps=4, upload_pps=1, download_pps=0.5),
                lifetime=count, months=[dict(period="2000-01", gaps=0, **count)],
                current_period="2000-01", note="Tunnel totals include protocol overhead.")


def runtime_program(source):
    source = source.replace("import { lstat, readfile } from 'fs';", """
let MOCK_FILE = null, MOCK_STAT = null, MOCK_DIR = {type:'directory', uid:0, mode:448};
function lstat(path) { if (path == '/var/run/proxy-usage') return MOCK_DIR; if (path != '/var/run/proxy-usage/status.json') die('unexpected path'); return MOCK_STAT; }
function readfile(path) { if (path != '/var/run/proxy-usage/status.json') die('unexpected path'); return MOCK_FILE; }
""")
    source = source.replace("return { 'luci.proxy-usage': methods };", "const exposed = { 'luci.proxy-usage': methods };")
    source += "\nconst F = " + json.dumps(fixture(), ensure_ascii=False) + ";\n"
    source += """
let checks = 0;
function expect(value, message) { checks++; if (!value) die(message); }
function clone(value) { return json(sprintf('%J', value)); }
function load(value) { MOCK_FILE = sprintf('%J', value); MOCK_STAT = { type:'file', uid:0, mode:384, size:length(MOCK_FILE) }; }
load(F);
let s = methods.status.call({args:{}});
expect(s.label == F.label && s.lifetime.upload_bytes == 8192, 'valid snapshot failed');
expect(length(keys(exposed)) == 1 && length(keys(methods)) == 3, 'exposed method surface');
expect(methods.periods.call({args:{}}).periods[0] == '2000-01', 'period enumeration');
let extra = clone(F); extra.password='SECRET'; extra.server='ENDPOINT'; extra.lifetime.token='SECRET'; extra.coverage.key='SECRET'; extra.months[0].credential='SECRET';
load(extra); s = methods.status.call({args:{path:'/etc/homeproxy',command:'id'}});
expect(index(sprintf('%J', s), 'SECRET') < 0 && index(sprintf('%J', s), 'ENDPOINT') < 0, 'extra fields leaked');
expect(length(keys(s.lifetime)) == 4 && length(keys(s.coverage)) == 4, 'nested whitelist failed');
let wg = clone(F); wg.transport='wireguard'; wg.egress_mode='WG_ACTIVE'; load(wg);
expect(methods.status.call({}).transport=='wireguard'&&methods.status.call({}).egress_mode=='WG_ACTIVE', 'WireGuard status metadata lost');
let wgexp=methods.export.call({args:{format:'json',period:'all'}});
expect(json(wgexp.content).transport=='wireguard'&&json(wgexp.content).lifetime.upload_bytes==8192, 'WireGuard export lost history or transport');
wg.mode='direct';wg.egress_mode='DIRECT_LATCHED';load(wg);
expect(methods.status.call({}).mode=='direct'&&methods.status.call({}).transport=='wireguard', 'direct latched WireGuard accounting hidden');
wg.transport='arbitrary';load(wg);expect(methods.status.call({}).error!=null,'unapproved transport accepted');
load(F);
let e = methods.export.call({args:{format:'json',period:'2000-01'}});
expect(e.filename == 'proxy-usage-2000-01.json' && json(e.content).months[0].period == '2000-01', 'JSON export failed');
e = methods.export.call({args:{format:'csv',period:'all'}});
expect(index(e.content, 'upload_bytes') >= 0 && index(e.content, 'lifetime') >= 0, 'CSV export failed');
expect(methods.export.call({args:{format:'csv',period:'1999-12'}}).error != null, 'missing month accepted');
for (let bad in ['../../etc/shadow', '2000-13', '2000-00', '2000-01;id', '', null, 7])
    expect(methods.export.call({args:{format:'json',period:bad}}).error != null, 'bad period accepted');
for (let bad in ['../../etc/shadow', 'sh', 'json;id', '', null, 7])
    expect(methods.export.call({args:{format:bad,period:'all'}}).error != null, 'bad format accepted');
for (let field in ['upload_bytes','download_bytes','upload_packets','download_packets']) {
    let bad = clone(F); bad.lifetime[field] = -1; load(bad);
    expect(methods.status.call({}).error != null, 'negative counter accepted');
}
let bad = clone(F); bad.lifetime.upload_bytes = 9007199254740992; load(bad);
expect(methods.status.call({}).error != null, 'unsafe JSON integer accepted');
bad=clone(F); push(bad.months, clone(bad.months[0])); load(bad);
expect(methods.status.call({}).error != null, 'duplicate months accepted');
bad=clone(F); bad.months[0].period='2000-13'; load(bad);
expect(methods.status.call({}).error != null, 'bad source month accepted');
bad=clone(F); bad.mode='direct'; bad.coverage.state='paused'; load(bad);
expect(methods.status.call({}).mode == 'direct', 'direct mode hidden');
bad=clone(F); bad.mode='paused'; bad.coverage.state='gap'; bad.coverage.gaps=1; bad.coverage.last_gap={at:946685100,reason:'counter_reset'}; load(bad);
expect(methods.status.call({}).coverage.last_gap.reason == 'counter_reset', 'gap missing');
MOCK_STAT={type:'link',uid:0,mode:384,size:1};
expect(methods.status.call({}).error != null, 'symlink accepted');
MOCK_STAT={type:'file',uid:0,mode:384,size:65537};
expect(methods.status.call({}).error != null, 'oversize snapshot accepted');
MOCK_STAT={type:'file',uid:0,mode:384,size:1}; MOCK_FILE='{broken';
expect(methods.status.call({}).error != null, 'corrupt snapshot accepted');
MOCK_STAT=null;
expect(methods.status.call({}).error != null, 'missing snapshot accepted');
load(F); MOCK_STAT.mode=420;
expect(methods.status.call({}).error != null, 'nonprivate snapshot accepted');
load(F); MOCK_STAT.uid=1000;
expect(methods.status.call({}).error != null, 'nonroot snapshot accepted');
load(F); MOCK_DIR.mode=493;
expect(methods.status.call({}).error != null, 'nonprivate directory accepted');
MOCK_DIR.mode=448;
expect(csv_cell('=SUM(1,2)') == '\"\\\'=SUM(1,2)\"', 'CSV formula guard missing');
expect(csv_cell('a\"b') == '\"a\"\"b\"', 'CSV quote escaping failed');
printf('%J\\n', {runtime_checks:checks, result:'passed'});
"""
    return source


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--remote-ucode", action="store_true")
    parser.add_argument("--ssh-config", default="outputs/pve-access.conf")
    args = parser.parse_args()
    source = RPC.read_text()
    assert "import { lstat, readfile } from 'fs';" in source
    for forbidden in ["system(", "popen(", "writefile(", "open(", "cursor(", "connect("]:
        assert forbidden not in source, f"forbidden RPC operation {forbidden}"
    assert source.count("'/var/run/proxy-usage/status.json'") == 1
    acl = json.loads((BASE / "acl/luci-app-proxy-usage.json").read_text())
    grant = acl["luci-app-proxy-usage"]
    assert set(grant) == {"description", "read"}
    assert grant["read"] == {"ubus": {"luci.proxy-usage": ["status", "periods", "export"]}}
    menu = json.loads((BASE / "menu/luci-app-proxy-usage.json").read_text())
    assert set(menu) == {"admin/services/nlbw/proxy"}
    assert menu["admin/services/nlbw/proxy"]["order"] == 15
    assert menu["admin/services/nlbw/proxy"]["title"] == "Node Usage"
    javascript = VIEW.read_text()
    assert not re.search(r"[\u3400-\u4dbf\u4e00-\u9fff]", javascript), "Chinese UI text found"
    assert "toLocaleString('en-GB'" in javascript and "zh-HK" not in javascript
    assert "innerHTML" not in javascript and "document.createTextNode" in javascript
    assert "fs.exec" not in javascript and "handleSave: null" in javascript
    node = subprocess.run(["node", "-e", "new Function(require('fs').readFileSync(process.argv[1], 'utf8'));", str(VIEW)], capture_output=True, text=True)
    if node.returncode:
        raise SystemExit(node.stderr)
    result = {"local_security_checks": "passed", "javascript_syntax": "passed", "english_ui_scan": "passed"}
    view = subprocess.run(["node", str(BASE / "test_view.js")], capture_output=True, text=True)
    if view.returncode:
        raise SystemExit(view.stderr)
    result["view_runtime"] = json.loads(view.stdout)
    if args.remote_ucode:
        for operation in ["ucode -c -o /dev/null -e ", "ucode -e "]:
            code = source if " -c " in operation else runtime_program(source)
            # Dropbear rejects long command packets; source travels on stdin.
            # The remote command is fixed and shell expansion remains quoted.
            remote = operation + '"$(cat)"'
            proc = subprocess.run(["ssh", "-F", args.ssh_config, "openwrt-wan", remote], input=code, text=True, capture_output=True)
            if proc.returncode:
                raise SystemExit(proc.stderr or proc.stdout)
            if proc.stdout.strip():
                result["rpc_runtime"] = json.loads(proc.stdout)
        result["rpc_ucode_syntax"] = "passed"
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
