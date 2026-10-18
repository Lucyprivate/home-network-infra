#!/usr/bin/ucode
// SPDX-License-Identifier: MIT
// Router-local accounting only. Never calls HomeProxy, guard or network controls.
'use strict';
import * as fs from 'fs';
import * as uloop from 'uloop';
import { cursor } from 'uci';
import { valid_endpoint, new_state, valid_state, advance, public_status } from '/usr/share/proxy-usage/model.uc';
import { nft_script, inspect_table } from '/usr/share/proxy-usage/nft.uc';

const STORE = '/etc/proxy-usage';
const RUN = '/var/run/proxy-usage';
const BOOT = trim(fs.readfile('/proc/sys/kernel/random/boot_id') || '');
const VPN_DIR = '/var/run/vpn-egress';
const VPN_STATUS = VPN_DIR + '/status.json';
// This approved endpoint is public transport metadata, never a peer credential.
const WIREGUARD = {schema: 1, node_id: 'wireguard_us', label: 'vpn-exit',
	address: '198.51.100.10', port: 51820, wan: 'eth0'};
let stopping = false, state, endpoint, registered_endpoint, timer, fresh_table = false;

function log_error(reason) { fs.stderr.write('proxy-usage: ' + reason + '\n'); }
function directory(path) {
	let s = fs.lstat(path);
	if (!s || s.type != 'directory' || s.uid != 0 || s.mode != 448) die('unsafe statistics directory');
}
function file_safe(path, optional) {
	let s = fs.lstat(path);
	if (!s) { if (optional) return null; die('missing statistics file'); }
	if (s.type != 'file' || s.uid != 0 || s.mode != 384 || s.nlink != 1 || s.size > 262144) die('unsafe statistics file');
	return s;
}
function load(path, optional) {
	if (!file_safe(path, optional)) return null;
	let s = fs.readfile(path);
	if (s == null) die('cannot read statistics file');
	try { return json(s); } catch (e) { die('corrupt statistics file; original retained'); }
}
function write_atomic(path, value, raw) {
	file_safe(path, true); file_safe(path + '.new', true);
	let f = fs.open(path + '.new', 'w', 384);
	if (!f) die('cannot open statistics temporary file');
	let data = raw ? value : sprintf('%J\n', value);
	let written = f.write(data), flushed = f.flush(), closed = f.close();
	if (written != length(data) || !flushed || !closed) die('statistics write failed');
	if (!fs.chmod(path + '.new', 384) || !fs.rename(path + '.new', path)) die('statistics atomic rename failed');
}
function period(at) {
	let t = localtime(at);
	return sprintf('%04d-%02d', t.year, t.mon);
}
function command(cmd) {
	let f = fs.popen(cmd, 'r');
	if (!f) return null;
	let text = f.read('all'), rc = f.close();
	if (rc != 0 || text == null || length(text) > 262144) return null;
	try { return json(text); } catch (e) { return null; }
}
function controller_mode() {
	let dir = fs.lstat(VPN_DIR), installed = fs.lstat('/etc/init.d/vpn-egress');
	if (!dir && !installed) return null; // Original HomeProxy behavior for rollback.
	let st = fs.lstat(VPN_STATUS);
	if (!dir || dir.type != 'directory' || dir.uid != 0 || dir.mode != 448 ||
	    !st || st.type != 'file' || st.uid != 0 || st.mode != 384 || st.nlink != 1 || st.size > 16384)
		return {mode: 'paused', reason: 'vpn_status_unavailable'};
	if (type(st.mtime) != 'int' || time() - st.mtime > 95 || st.mtime > time() + 5)
		return {mode: 'paused', reason: 'vpn_status_stale'};
	let v;
	try { v = json(fs.readfile(VPN_STATUS) || 'null'); }
	catch (e) { return {mode: 'paused', reason: 'vpn_status_invalid'}; }
	// Never label a failed direct transition as direct while production still
	// catches public traffic. Explicit contradictions pause accounting/status.
	if (v?.routing_consistent === false ||
	    (v?.mode == 'DIRECT_LATCHED' && v.production_routing === true) ||
	    (v?.mode == 'WG_ACTIVE' && v.production_routing === false))
		return {mode: 'paused', reason: 'vpn_routing_inconsistent'};
	if ((v?.routing_consistent != null && type(v.routing_consistent) != 'bool') ||
	    (v?.production_routing != null && type(v.production_routing) != 'bool'))
		return {mode: 'paused', reason: 'vpn_routing_status_invalid'};
	if (v?.schema != 1 || v.node_label != WIREGUARD.label ||
	    v.endpoint?.address != WIREGUARD.address || v.endpoint?.port != WIREGUARD.port ||
	    v.endpoint?.protocol != 'udp' || v.expected_exit_ipv4 != WIREGUARD.address ||
	    index(['WG_ACTIVE', 'DIRECT_LATCHED'], v.mode) < 0 ||
	    v.transport != (v.mode == 'WG_ACTIVE' ? 'wireguard' : 'direct') ||
	    type(v.tunnel_healthy) != 'bool')
		return {mode: 'paused', reason: 'unsupported_or_changed_vpn_endpoint'};
	return {mode: v.mode == 'WG_ACTIVE' ? 'proxy' : 'direct', transport: 'wireguard',
		egress_mode: v.mode, accounting_endpoint: WIREGUARD};
}
function active_mode() {
	let vpn = controller_mode();
	if (vpn) return vpn;
	let u = cursor();
	let main = u.get('homeproxy', 'config', 'main_node');
	if (main == 'nil' || main == null || main == '') return { mode: 'direct', transport: 'hysteria2', egress_mode: 'DIRECT_LATCHED' };
	if (main != registered_endpoint.node_id || u.get('homeproxy', 'config', 'main_udp_node') != 'same')
		return { mode: 'paused', reason: 'node_identity_changed' };
	let cfg;
	try { cfg = json(fs.readfile('/var/run/homeproxy/sing-box-c.json') || 'null'); }
	catch (e) { return { mode: 'paused', reason: 'proxy_config_unavailable' }; }
	let found = [];
	for (let o in cfg?.outbounds || []) if (o.tag == 'main-out') push(found, o);
	if (length(found) != 1 || found[0].type != 'hysteria2' ||
	    found[0].server != registered_endpoint.address || found[0].server_port != registered_endpoint.port ||
	    found[0].server_ports != null || found[0].hop_interval != null)
		return { mode: 'paused', reason: 'unsupported_or_changed_endpoint' };
	return { mode: 'proxy', transport: 'hysteria2', egress_mode: 'HOMEPROXY_ACTIVE' };
}
function table_exists() {
	let all = command('/usr/sbin/nft -j list tables 2>/dev/null');
	if (!all || type(all.nftables) != 'array') return null;
	for (let row in all.nftables) if (row.table?.family == 'inet' && row.table?.name == 'proxy_usage') return true;
	return false;
}
function publish(service) {
	write_atomic(RUN + '/runtime.json', state);
	write_atomic(RUN + '/status.json', public_status(state, endpoint.label, service));
}
function save() {
	let previous = state.saved_at;
	state.saved_at = time();
	try {
		write_atomic(STORE + '/state.json', state);
		if (system('/bin/sync', 10000) != 0) die('statistics sync failed');
	} catch (e) { state.saved_at = previous; die('statistics durable save failed'); }
}
function create_counters(replace_owned) {
	let uuid = trim(fs.readfile('/proc/sys/kernel/random/uuid') || '');
	if (!match(uuid, /^[0-9a-f-]{36}$/)) return null;
	// nft applies this complete batch atomically. A failed check leaves old rules.
	let batch = (replace_owned ? 'delete table inet proxy_usage\n' : '') + nft_script(endpoint, uuid);
	write_atomic(RUN + '/rules.nft', batch, true);
	if (system('/usr/sbin/nft -c -f /var/run/proxy-usage/rules.nft >/dev/null 2>&1', 3000) != 0 ||
	    system('/usr/sbin/nft -f /var/run/proxy-usage/rules.nft >/dev/null 2>&1', 3000) != 0) return null;
	fresh_table = !replace_owned;
	let doc = command('/usr/sbin/nft -j -a list table inet proxy_usage 2>/dev/null');
	return inspect_table(doc, endpoint);
}
function read_counters(now, current_period) {
	let doc = command('/usr/sbin/nft -j -a list table inet proxy_usage 2>/dev/null');
	if (doc) {
		let current = inspect_table(doc, endpoint);
		if (current) return current;
		// Only switch between the two explicitly approved counter-only shapes.
		let previous = inspect_table(doc, registered_endpoint) || inspect_table(doc, WIREGUARD);
		if (!previous) return null;
		// Final old delta is committed before replacement; a crash cannot replay it.
		advance(state, {at: now, period: current_period, mode: state.mode,
			boot_id: BOOT, identity: previous.identity, totals: previous.totals});
		save(); publish('running');
		return create_counters(true);
	}
	if (table_exists() !== false) return null;
	return create_counters(false);
}
function sample() {
	let now = time(), mode = active_mode();
	endpoint = mode.accounting_endpoint || registered_endpoint;
	let counters = mode.mode == 'paused' ? null : read_counters(now, period(now));
	// Additive metadata leaves the schema-1 accounting state rollback compatible.
	state.transport = mode.transport || state.transport || 'hysteria2';
	state.egress_mode = mode.egress_mode || null;
	advance(state, { at: now, period: period(now), mode: mode.mode,
		reason: mode.reason || (counters ? null : 'counter_unavailable_or_foreign_table'),
		boot_id: BOOT, identity: counters?.identity, totals: counters?.totals, fresh: fresh_table });
	fresh_table = false;
	if (state.saved_at == 0 || now - state.saved_at >= 3600) save();
	publish(stopping ? 'stopped' : 'running');
}
function finish() {
	if (stopping) return;
	stopping = true;
	try { sample(); save(); publish('stopped'); }
	catch (e) { log_error('final save failed; original durable state retained'); }
	uloop.end();
}

directory(STORE); directory(RUN);
endpoint = load(STORE + '/endpoint.json');
registered_endpoint = endpoint;
if (!valid_endpoint(endpoint) || !match(BOOT, /^[0-9a-f-]{36}$/)) die('invalid approved endpoint or boot identity');
state = load(STORE + '/state.json', true);
if (state != null && !valid_state(state)) die('invalid durable statistics; original retained');
let runtime = load(RUN + '/runtime.json', true);
if (runtime != null && !valid_state(runtime)) die('invalid runtime statistics; original retained');
if (runtime && runtime.checkpoint?.boot_id == BOOT && (!state ||
	(runtime.since == state.since && runtime.updated_at >= state.updated_at && runtime.saved_at >= state.saved_at))) state = runtime;
if (!state) {
	if (fs.lstat(STORE + '/state.json.new')) die('interrupted first save; inspect temporary statistics');
	state = new_state(time(), period(time()));
}
uloop.init();
let term = uloop.signal(15, finish), intr = uloop.signal(2, finish);
try { sample(); }
catch (e) { log_error('initial sample failed; no proxy changes'); exit(1); }
timer = uloop.timer(30000, function() {
	try { sample(); }
	catch (e) { log_error('sample/save failed; no proxy changes'); try { publish('error'); } catch (ignored) {} }
	if (!stopping) timer.set(30000);
});
uloop.run(); uloop.done();
