// SPDX-License-Identifier: MIT
// Pure accounting model. No files, commands, credentials or proxy controls.
'use strict';

const FIELDS = ['upload_bytes', 'download_bytes', 'upload_packets', 'download_packets'];
const MAX = 9007199254740991;

export function zero_totals() {
	return { upload_bytes: 0, download_bytes: 0, upload_packets: 0, download_packets: 0 };
};

function integer(v) { return type(v) == 'int' && v >= 0 && v <= MAX; }

export function valid_totals(v) {
	if (type(v) != 'object') return false;
	for (let k in FIELDS) if (!integer(v[k])) return false;
	return true;
};

export function valid_endpoint(e) {
	if (type(e) != 'object' || e.schema != 1 || e.wan != 'eth0' ||
	    type(e.node_id) != 'string' || !match(e.node_id, /^[a-zA-Z0-9_]{1,80}$/) ||
	    type(e.label) != 'string' || !length(e.label) || length(e.label) > 256 ||
	    type(e.address) != 'string' || !match(e.address, /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) ||
	    !integer(e.port) || e.port < 1 || e.port > 65535) return false;
	let octets = split(e.address, '.');
	for (let n in octets) if (+n > 255 || sprintf('%d', +n) != n) return false;
	return +octets[0] > 0 && +octets[0] < 224 && +octets[0] != 127;
};

function period_valid(p) { return type(p) == 'string' && !!match(p, /^20[0-9]{2}-(0[1-9]|1[0-2])$/); }

export function new_state(at, period) {
	return { schema: 1, since: at, updated_at: at, saved_at: 0, current_period: period,
		mode: 'paused', lifetime: zero_totals(), months: [], checkpoint: null,
		coverage: { gaps: 0, last_gap: null, active_gap: null },
		rates: { upload_bps: 0, download_bps: 0, upload_pps: 0, download_pps: 0 } };
};

export function valid_state(s) {
	if (type(s) != 'object' || s.schema != 1 || !integer(s.since) || !integer(s.updated_at) ||
	    !integer(s.saved_at) || !period_valid(s.current_period) || !valid_totals(s.lifetime) ||
	    index(['proxy', 'direct', 'paused'], s.mode) < 0 || type(s.months) != 'array' || length(s.months) > 12 ||
	    type(s.coverage) != 'object' || !integer(s.coverage.gaps) || type(s.rates) != 'object') return false;
	let seen = {};
	let sum = zero_totals();
	for (let m in s.months) {
		if (!period_valid(m.period) || seen[m.period] || !valid_totals(m) || !integer(m.gaps)) return false;
		seen[m.period] = true;
		for (let k in FIELDS) { sum[k] += m[k]; if (sum[k] > s.lifetime[k]) return false; }
	}
	for (let k in ['upload_bps', 'download_bps', 'upload_pps', 'download_pps'])
		if (type(s.rates[k]) != 'double' && type(s.rates[k]) != 'int' || s.rates[k] < 0 || s.rates[k] > MAX) return false;
	if (s.coverage.last_gap != null && (type(s.coverage.last_gap) != 'object' ||
	    !integer(s.coverage.last_gap.at) || type(s.coverage.last_gap.reason) != 'string')) return false;
	if (s.coverage.active_gap != null && type(s.coverage.active_gap) != 'string') return false;
	if (s.checkpoint != null && (type(s.checkpoint) != 'object' || !integer(s.checkpoint.at) ||
	    !period_valid(s.checkpoint.period) || type(s.checkpoint.boot_id) != 'string' ||
	    type(s.checkpoint.identity) != 'string' || !valid_totals(s.checkpoint.totals))) return false;
	return true;
};

function month(s, period) {
	for (let m in s.months) if (m.period == period) return m;
	let m = zero_totals(); m.period = period; m.gaps = 0;
	push(s.months, m);
	sort(s.months, (a, b) => a.period == b.period ? 0 : a.period > b.period ? -1 : 1);
	while (length(s.months) > 12) pop(s.months);
	return m;
}

function gap(s, at, reason) {
	if (s.coverage.active_gap != reason) {
		s.coverage.gaps++;
		s.coverage.last_gap = { at: at, reason: reason };
		month(s, s.current_period).gaps++;
	}
	s.coverage.active_gap = reason;
}

// A valid counter sample is recoverable across graceful service restarts.
// Kernel counter loss, changed identity and unknown intervals are never fabricated.
export function advance(s, x) {
	if (!valid_state(s) || !integer(x.at) || !period_valid(x.period) ||
	    index(['proxy', 'direct', 'paused'], x.mode) < 0) die('invalid accounting state/sample');
	s.current_period = x.period; month(s, x.period);
	s.rates = { upload_bps: 0, download_bps: 0, upload_pps: 0, download_pps: 0 };
	let previous_mode = s.mode;
	s.mode = x.mode;
	if (x.mode == 'paused' || !valid_totals(x.totals) || type(x.identity) != 'string' || type(x.boot_id) != 'string') {
		gap(s, x.at, x.reason || 'counter_unavailable');
		s.checkpoint = null; s.updated_at = x.at; return s;
	}
	let cp = s.checkpoint;
	if (cp && cp.at == x.at && cp.boot_id == x.boot_id && cp.identity == x.identity) {
		let identical = true;
		for (let k in FIELDS) if (cp.totals[k] != x.totals[k]) identical = false;
		if (identical) { s.updated_at = x.at; return s; }
	}
	let reason = null, delta = zero_totals();
	if (!cp) {
		// A newly created table begins at zero. Count activity since installation,
		// but never backfill raw counters after an interrupted/paused interval.
		if (x.fresh && s.updated_at == s.since && s.coverage.gaps == 0) delta = x.totals;
		else if (previous_mode != 'paused' || s.coverage.gaps == 0) reason = 'checkpoint_missing';
	} else if (cp.boot_id != x.boot_id) reason = 'boot_changed';
	else if (cp.identity != x.identity) reason = 'counter_identity_changed';
	else {
		for (let k in FIELDS) if (x.totals[k] < cp.totals[k]) reason = 'counter_reverted';
		if (!reason) {
			for (let k in FIELDS) delta[k] = x.totals[k] - cp.totals[k];
			if (x.at < cp.at) reason = 'clock_reverted';
			else if (x.at - cp.at > 45) reason = 'sampling_interrupted';
			else if (x.period != cp.period) reason = 'month_boundary_interval';
		}
	}
	if (reason) gap(s, x.at, reason);
	else s.coverage.active_gap = null;
	for (let k in FIELDS) {
		if (s.lifetime[k] > MAX - delta[k]) die('accounting integer limit');
		s.lifetime[k] += delta[k];
		// Interval crossing midnight is assigned to the previous month, explicitly
		// marked as a coverage gap (at most one sample interval).
		month(s, reason == 'month_boundary_interval' ? cp.period : x.period)[k] += delta[k];
	}
	if (cp && !reason && x.mode == 'proxy' && x.at > cp.at) {
		let seconds = x.at - cp.at;
		s.rates = { upload_bps: delta.upload_bytes / seconds, download_bps: delta.download_bytes / seconds,
			upload_pps: delta.upload_packets / seconds, download_pps: delta.download_packets / seconds };
	}
	s.checkpoint = { at: x.at, period: x.period, boot_id: x.boot_id, identity: x.identity, totals: x.totals };
	s.updated_at = x.at;
	return s;
};

export function public_status(s, label, service) {
	return { schema: 1, service: service, label: label, mode: s.mode,
		transport: s.transport || 'hysteria2', egress_mode: s.egress_mode || (s.mode == 'proxy' ? 'HOMEPROXY_ACTIVE' : s.mode == 'direct' ? 'DIRECT_LATCHED' : null),
		coverage: { state: s.mode == 'paused' ? 'paused' : s.coverage.gaps ? 'gap' : 'complete',
			gaps: s.coverage.gaps, last_gap: s.coverage.last_gap, since: s.since },
		updated_at: s.updated_at, saved_at: s.saved_at, interval_seconds: 30,
		save_seconds: 3600, history_months: 12, rates: s.rates, lifetime: s.lifetime,
		months: s.months, current_period: s.current_period,
		note: 'Counts router-local node UDP traffic, tunnel probes and protocol overhead from enablement; provider billing may differ.' };
};
