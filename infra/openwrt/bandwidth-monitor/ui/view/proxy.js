'use strict';
'require view';
'require rpc';
'require poll';
'require ui';
'require dom';

const getStatus = rpc.declare({object: 'luci.proxy-usage', method: 'status', expect: {'': {}}});
const getPeriods = rpc.declare({object: 'luci.proxy-usage', method: 'periods', expect: {'': {}}});
const getExport = rpc.declare({object: 'luci.proxy-usage', method: 'export', params: ['format', 'period'], expect: {'': {}}});

function text(value) {
	return document.createTextNode(value == null ? '—' : String(value));
}

function bytes(value) {
	let n = Number(value), unit = 0;
	const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'];
	if (!Number.isFinite(n) || n < 0)
		return '—';
	while (n >= 1024 && unit < units.length - 1) { n /= 1024; unit++; }
	return n.toFixed(unit ? 2 : 0) + ' ' + units[unit];
}

function date(value) {
	if (!value)
		return 'Not yet recorded';
	return new Date(value * 1000).toLocaleString('en-GB', {timeZone: 'UTC', hour12: false}) + ' UTC';
}

function quantity(value) {
	return Number(value || 0).toLocaleString('en-GB');
}

function line(label, value) {
	return E('div', {'class': 'cbi-value'}, [
		E('label', {'class': 'cbi-value-title'}, [text(label)]),
		E('div', {'class': 'cbi-value-field'}, [text(value)])
	]);
}

return view.extend({
	load: function() { return Promise.all([getStatus(), getPeriods()]); },

	handleDownload: function(format) {
		const period = this.selector.value;
		return getExport(format, period).then(function(res) {
			if (res.error || typeof res.content !== 'string')
				throw new Error(res.error || 'Export data is unavailable');
			if (!/^proxy-usage-(all|\d{4}-(0[1-9]|1[0-2]))\.(json|csv)$/.test(res.filename))
				throw new Error('Invalid export filename');
			const blob = new Blob([format === 'csv' ? '\ufeff' : '', res.content], {type: res.mime});
			const url = window.URL.createObjectURL(blob);
			const link = E('a', {href: url, download: res.filename, style: 'display:none'});
			document.body.appendChild(link);
			link.click();
			link.remove();
			window.URL.revokeObjectURL(url);
		}).catch(function(err) { ui.addNotification(null, E('p', [text('Export failed: ' + err.message)]), 'error'); });
	},

	updatePeriods: function(s) {
		const selected = this.selector.value;
		const choices = [E('option', {value: 'all'}, ['All retained months'])];
		(s.months || []).slice().sort(function(a, b) { return b.period.localeCompare(a.period); }).forEach(function(m) {
			choices.push(E('option', {value: m.period}, [text(m.period)]));
		});
		dom.content(this.selector, choices);
		this.selector.value = selected === 'all' || (s.months || []).some(function(m) { return m.period === selected; }) ? selected : 'all';
	},

	update: function(s) {
		if (s.error || s.schema !== 1) {
			this.latest = null;
			dom.content(this.summary, [E('p', {'class': 'alert-message warning'}, [text(s.error || 'Invalid statistics format')])]);
			dom.content(this.table, []);
			this.downloadButtons.forEach(function(button) { button.disabled = true; });
			return;
		}
		this.downloadButtons.forEach(function(button) { button.disabled = false; });
		const mode = s.mode === 'proxy' && s.egress_mode === 'WG_ACTIVE' ? 'WireGuard active' :
			{proxy: 'Proxy active', direct: 'Direct', paused: 'Node statistics paused'}[s.mode] || 'Unknown';
		const transport = {wireguard: 'WireGuard', hysteria2: 'Hysteria2'}[s.transport] || 'Hysteria2';
		const coverage = {complete: 'Covered', gap: 'Statistics gaps detected', paused: 'Coverage paused'}[s.coverage.state] || 'Unknown';
		const service = {running: 'running', stopped: 'stopped', error: 'error'}[s.service] || 'unknown';
		const age = Math.max(0, Date.now() / 1000 - s.updated_at);
		const statusText = age > 90 ? mode.replace(' active', '') + ' (last recorded); current service status is unconfirmed' : mode + ' / Service ' + service;
		const current = (s.months || []).find(function(m) { return m.period === s.current_period; });
		let details = [
			line('Node', s.label), line('Status', statusText), line('Monitored transport', transport),
			line('Coverage', coverage + '; total gaps: ' + quantity(s.coverage.gaps)),
			line('Statistics start', date(s.coverage.since)),
			line('Last update', date(s.updated_at) + (age > 90 ? ' (not updated for more than 90 seconds)' : '')),
			line('Last saved', date(s.saved_at)),
			line('30-second average upload / download', bytes(s.rates.upload_bps) + '/s / ' + bytes(s.rates.download_bps) + '/s'),
			line('30-second average packet rates', Number(s.rates.upload_pps).toFixed(2) + ' / ' + Number(s.rates.download_pps).toFixed(2) + ' packets/s (up / down)'),
			line('This month upload / download', current ? bytes(current.upload_bytes) + ' / ' + bytes(current.download_bytes) : 'Not yet recorded'),
			line('Lifetime upload / download', bytes(s.lifetime.upload_bytes) + ' / ' + bytes(s.lifetime.download_bytes)),
			line('Lifetime packet counts (up / down)', quantity(s.lifetime.upload_packets) + ' / ' + quantity(s.lifetime.download_packets))
		];
		if (s.coverage.last_gap)
			details.push(line('Last statistics gap', date(s.coverage.last_gap.at) + '; ' + s.coverage.last_gap.reason));
		if (s.note)
			details.push(E('p', {'class': 'alert-message notice'}, [text(s.note)]));
		dom.content(this.summary, details);
		this.updatePeriods(s);
		const chosen = this.selector.value;
		const rows = (s.months || []).slice().sort(function(a, b) { return b.period.localeCompare(a.period); }).filter(function(m) { return chosen === 'all' || chosen === m.period; }).map(function(m) {
			return E('tr', {'class': 'tr'}, [m.period, bytes(m.upload_bytes), bytes(m.download_bytes), quantity(m.upload_packets), quantity(m.download_packets), quantity(m.gaps)].map(function(value) {
				return E('td', {'class': 'td'}, [text(value)]);
			}));
		});
		dom.content(this.table, [E('tr', {'class': 'tr table-titles'}, ['Month (UTC)', 'Upload', 'Download', 'Uploaded packets', 'Downloaded packets', 'Statistics gaps'].map(function(label) {
			return E('th', {'class': 'th'}, [text(label)]);
		}))].concat(rows.length ? rows : [E('tr', {'class': 'tr'}, [E('td', {colspan: 6, 'class': 'td'}, ['No records yet'])])]));
		this.latest = s;
	},

	render: function(data) {
		this.summary = E('div', {'class': 'cbi-section'});
		this.table = E('table', {'class': 'table'});
		this.selector = E('select', {'class': 'cbi-input-select', change: L.bind(function() { if (this.latest) this.update(this.latest); }, this)});
		this.downloadButtons = ['json', 'csv'].map(L.bind(function(format) {
			return E('button', {'class': 'cbi-button cbi-button-neutral', click: ui.createHandlerFn(this, 'handleDownload', format)}, ['Export ' + format.toUpperCase()]);
		}, this));
		const node = E('div', [
			E('h2', ['Node Usage']),
			E('p', ['Sampled every 30 seconds, saved every hour, with 12 months of history. Counts only the router\'s local tunnel traffic to the current node, including connections, health probes and protocol overhead. Your provider\'s billing dashboard remains authoritative.']),
			E('p', ['Totals start when monitoring is enabled. An unexpected power loss may lose approximately one hour of unsaved traffic. Service restarts, missing counters or interrupted sampling are reported as statistics gaps.']),
			this.summary,
			E('div', {'class': 'cbi-section'}, [E('h3', ['Monthly usage']), E('p', [this.selector, ' ', this.downloadButtons[0], ' ', this.downloadButtons[1]]), this.table])
		]);
		this.update(data[0]);
		poll.add(L.bind(function() {
			return getStatus().then(L.bind(this.update, this)).catch(L.bind(function(err) {
				this.update({error: 'Unable to read statistics: ' + err.message});
			}, this));
		}, this), 30);
		return node;
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
