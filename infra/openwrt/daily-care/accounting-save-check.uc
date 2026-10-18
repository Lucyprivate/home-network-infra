// SPDX-License-Identifier: MIT
// Read-only backup preparation gate. ARGV: start epoch, pre-save state inode.
// No data is printed. Zero means this preparation produced a durable save and
// a matching healthy running monitor snapshot; all other results mean retry.
'use strict';
import { lstat, readfile } from 'fs';
import { valid_state } from '/usr/share/proxy-usage/model.uc';

function decimal(v) {
	if (type(v) != 'string' || !match(v, /^[0-9]{1,16}$/)) return null;
	let n = +v;
	return type(n) == 'int' && n > 0 && n <= 9007199254740991 ? n : null;
}

function private_directory(path) {
	let s = lstat(path);
	return s?.type == 'directory' && s.uid == 0 && s.mode == 448;
}

function private_json(path) {
	let s = lstat(path);
	if (s?.type != 'file' || s.uid != 0 || s.mode != 384 || s.nlink != 1 ||
	    s.size < 2 || s.size > 262144) return null;
	let text = readfile(path);
	if (text == null) return null;
	let value = json(text);
	return { value: value, inode: s.inode };
}

function saved_currently(args) {
	if (type(args) != 'array' || length(args) != 2) return false;
	let start = decimal(args[0]), before_inode = decimal(args[1]);
	if (start == null || before_inode == null ||
	    !private_directory('/etc/proxy-usage') || !private_directory('/var/run/proxy-usage')) return false;
	let durable = private_json('/etc/proxy-usage/state.json');
	let runtime = private_json('/var/run/proxy-usage/runtime.json');
	let status = private_json('/var/run/proxy-usage/status.json');
	if (!durable || !runtime || !status || durable.inode == before_inode ||
	    !valid_state(durable.value) || !valid_state(runtime.value)) return false;
	let d = durable.value, r = runtime.value, s = status.value;
	return d.saved_at >= start && r.updated_at >= start && r.saved_at >= d.saved_at &&
		r.since == d.since && s.schema == 1 && s.service == 'running' &&
		s.updated_at == r.updated_at;
}

try { exit(saved_currently(ARGV) ? 0 : 1); }
catch (e) { exit(1); }
