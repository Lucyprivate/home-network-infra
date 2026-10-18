// SPDX-License-Identifier: MIT
'use strict';

export function nft_script(e, uuid) {
	// "create", rather than declarative "table", prevents accidentally merging
	// into a foreign table that appeared after the preceding existence check.
	return sprintf('create table inet proxy_usage { comment "proxy-usage-v1:%s"; }\nadd counter inet proxy_usage upload {}\nadd counter inet proxy_usage download {}\nadd chain inet proxy_usage output { type filter hook output priority 10; policy accept; }\nadd chain inet proxy_usage input { type filter hook input priority 10; policy accept; }\nadd rule inet proxy_usage output oifname "eth0" ip daddr %s udp dport %d counter name upload\nadd rule inet proxy_usage input iifname "eth0" ip saddr %s udp sport %d counter name download\n', uuid, e.address, e.port, e.address, e.port);
};

function equal(a, b) {
	if (type(a) != type(b)) return false;
	if (type(a) == 'array') {
		if (length(a) != length(b)) return false;
		for (let i = 0; i < length(a); i++) if (!equal(a[i], b[i])) return false;
		return true;
	}
	if (type(a) == 'object') {
		if (length(keys(a)) != length(keys(b))) return false;
		for (let k, v in a) if (!(k in b) || !equal(v, b[k])) return false;
		return true;
	}
	return a == b;
}

function expressions(e, output) {
	return [
		{ match: { op: '==', left: { meta: { key: output ? 'oifname' : 'iifname' } }, right: 'eth0' } },
		{ match: { op: '==', left: { payload: { protocol: 'ip', field: output ? 'daddr' : 'saddr' } }, right: e.address } },
		{ match: { op: '==', left: { payload: { protocol: 'udp', field: output ? 'dport' : 'sport' } }, right: e.port } },
		{ counter: output ? 'upload' : 'download' }
	];
}

function keys_valid(object, allowed) {
	for (let k in keys(object)) if (index(allowed, k) < 0) return false;
	return true;
}

// A foreign or modified table is never deleted or adopted. Only this exact
// counter-only shape is accepted, including handles identifying the objects.
export function inspect_table(doc, e) {
	if (type(doc) != 'object' || type(doc.nftables) != 'array') return null;
	let table = null, chains = {}, counters = {}, rules = {};
	for (let row in doc.nftables) {
		if (type(row) != 'object' || length(keys(row)) != 1) return null;
		let k = keys(row)[0], v = row[k];
		if (k == 'metainfo') continue;
		if (type(v) != 'object' || v.family != 'inet') return null;
		if (k == 'table') {
			if (table || !keys_valid(v, ['family','name','handle','comment']) || v.name != 'proxy_usage' || !match(v.comment || '', /^proxy-usage-v1:[0-9a-f-]{36}$/) || type(v.handle) != 'int') return null;
			table = v; continue;
		}
		if (v.table != 'proxy_usage') return null;
		if (k == 'chain') {
			if (!keys_valid(v, ['family','table','name','handle','type','hook','prio','policy']) || index(['input', 'output'], v.name) < 0 || chains[v.name] || v.type != 'filter' ||
			    v.hook != v.name || v.prio != 10 || v.policy != 'accept' || type(v.handle) != 'int') return null;
			chains[v.name] = v;
		} else if (k == 'counter') {
			if (!keys_valid(v, ['family','table','name','handle','bytes','packets']) || index(['upload', 'download'], v.name) < 0 || counters[v.name] ||
			    type(v.handle) != 'int' || type(v.bytes) != 'int' || type(v.packets) != 'int' ||
			    v.bytes < 0 || v.packets < 0 || v.bytes > 9007199254740991 || v.packets > 9007199254740991) return null;
			counters[v.name] = v;
		} else if (k == 'rule') {
			if (!keys_valid(v, ['family','table','chain','handle','expr']) || index(['input', 'output'], v.chain) < 0 || rules[v.chain] ||
			    !equal(v.expr, expressions(e, v.chain == 'output'))) return null;
			rules[v.chain] = v;
		} else return null;
	}
	if (!table || length(keys(chains)) != 2 || length(keys(counters)) != 2 || length(keys(rules)) != 2) return null;
	return { identity: sprintf('%s:%d:%d:%d', table.comment, table.handle, counters.upload.handle, counters.download.handle),
		totals: { upload_bytes: counters.upload.bytes, download_bytes: counters.download.bytes,
			upload_packets: counters.upload.packets, download_packets: counters.download.packets } };
};
