'use strict';
'require view';
'require rpc';
'require poll';
'require ui';
'require dom';

const getStatus = rpc.declare({object: 'luci.vpn-egress', method: 'status', expect: {'': {}}});
const control = rpc.declare({object: 'luci.vpn-egress', method: 'control', params: ['action'], expect: {'': {}}});

function text(value) {
	return document.createTextNode(value == null || value === '' ? '\u2014' : String(value));
}

function bytes(value) {
	if (value == null || value === '')
		return '\u2014';
	let n = Number(value), unit = 0;
	const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
	if (!Number.isFinite(n) || n < 0)
		return '\u2014';
	while (n >= 1024 && unit < units.length - 1) { n /= 1024; unit++; }
	return n.toFixed(unit ? 2 : 0) + ' ' + units[unit];
}

function date(value) {
	if (!value)
		return 'Not yet recorded';
	const d = typeof value === 'number' ? new Date(value * 1000) : new Date(value);
	if (!Number.isFinite(d.getTime()))
		return 'Not available';
	return d.toLocaleString('en-GB', {timeZone: 'UTC', hour12: false}) + ' UTC';
}

function line(label, value) {
	return E('div', {'class': 'cbi-value'}, [
		E('label', {'class': 'cbi-value-title'}, [text(label)]),
		E('div', {'class': 'cbi-value-field'}, [text(value)])
	]);
}

function hasWriteAccess() {
	return typeof L.hasViewPermission === 'function' && L.hasViewPermission();
}

function health(c, service) {
	if (!service.running)
		return 'Controller stopped; health unconfirmed';
	if (!c.last_health_utc)
		return 'Not yet checked';
	const checked = new Date(c.last_health_utc).getTime();
	if (!Number.isFinite(checked))
		return 'Not yet checked';
	const age = Date.now() - checked;
	if (age > 95000)
		return 'Health check is stale';
	if (age < -5000)
		return 'Health check time is unconfirmed';
	return c.tunnel_healthy === true ? 'Healthy' : 'Not confirmed healthy';
}

return view.extend({
	load: function() { return getStatus().catch(function(err) { return {error: err.message}; }); },

	updateButtons: function() {
		const busy = this.pending || !!(this.latest && this.latest.operation && this.latest.operation.running);
		const disabled = !hasWriteAccess() || !this.latest || busy;
		this.resumeButton.disabled = disabled;
		this.directButton.disabled = disabled;
	},

	update: function(s) {
		if (!s || s.error || s.schema !== 1 || !s.controller || !s.tunnel || !s.service || !s.operation) {
			this.latest = null;
			dom.content(this.summary, [E('p', {'class': 'alert-message warning'}, [text('Unable to read WireGuard status: ' + (s && s.error || 'Invalid status response'))])]);
			this.updateButtons();
			return;
		}
		this.latest = s;
		const c = s.controller, t = s.tunnel, op = s.operation;
		const mode = c.mode === 'WG_ACTIVE' && c.production_routing === true && c.routing_consistent === true ? 'WireGuard active' :
			c.mode === 'DIRECT_LATCHED' && c.production_routing === false && c.routing_consistent === true ? 'Direct connection (manual recovery required)' : 'Routing state needs attention';
		const details = [
			line('Current egress mode', mode),
			line('Current transport', {wireguard: 'WireGuard', direct: 'Direct'}[c.transport] || 'Unknown'),
			line('Expected WireGuard public IPv4', c.expected_exit_ipv4),
			line('WireGuard remote endpoint', c.endpoint && c.endpoint.address && c.endpoint.port ? c.endpoint.address + ':' + c.endpoint.port + ' / UDP' : '\u2014'),
			line('Tunnel health', health(c, s.service)),
			line('Last health check', date(c.last_health_utc)),
			line('Consecutive failed health checks', Number.isInteger(c.failures) && c.failures >= 0 ? c.failures : '\u2014'),
			line('Controller reason', c.reason),
			line('Controller state updated', date(c.updated_utc)),
			line('Controller service', (s.service.running ? 'Running' : 'Stopped') + ' / ' + (s.service.enabled ? 'Starts at boot' : 'Boot startup disabled')),
			line('WireGuard interface', 'wg_exit / ' + (t.up ? 'Up' : 'Down')),
			line('Tunnel address / MTU', (t.address || '\u2014') + ' / ' + (t.mtu || '\u2014')),
			line('Peer count', Number.isInteger(t.peer_count) && t.peer_count >= 0 ? t.peer_count : '\u2014'),
			line('Last WireGuard handshake', date(t.last_handshake)),
			line('Tunnel received / sent', bytes(t.rx_bytes) + ' / ' + bytes(t.tx_bytes)),
			line('Latest operation', op.running ? (op.action || 'Switch') + ' in progress' : (op.action || 'None'))
		];
		if (op.started_utc)
			details.push(line('Operation started', date(op.started_utc)));
		if (op.completed_utc)
			details.push(line('Operation completed', date(op.completed_utc)));
		if (typeof op.result === 'string' && op.result)
			details.push(line('Operation result', op.result));
		if (typeof op.result === 'object' && op.result && typeof op.result.message === 'string')
			details.push(line('Operation result', op.result.message));
		details.push(line('Page refreshed', date(Date.now() / 1000)));
		dom.content(this.summary, details);
		this.updateButtons();
	},

	refresh: function() {
		return getStatus().then(L.bind(this.update, this)).catch(L.bind(function(err) {
			this.update({error: err.message});
		}, this));
	},

	runAction: function(action) {
		if ((action !== 'direct' && action !== 'resume') || !hasWriteAccess() || !this.latest || this.pending || this.latest.operation.running)
			return Promise.resolve();
		this.pending = true;
		this.updateButtons();
		return control(action).then(L.bind(function(res) {
			if (!res || res.error || res.accepted !== true)
				throw new Error(res && res.error || 'The operation was not accepted');
			ui.addNotification(null, E('p', [text('The egress switch has started. Status will update automatically.')]), 'info');
		}, this)).catch(function(err) {
			ui.addNotification(null, E('p', [text('Egress switch failed: ' + err.message)]), 'error');
		}).then(L.bind(function() {
			this.pending = false;
			return this.refresh();
		}, this));
	},

	confirmAction: function(action) {
		if ((action !== 'direct' && action !== 'resume') || !hasWriteAccess() || !this.latest || this.pending || this.latest.operation.running)
			return;
		const resume = action === 'resume';
		ui.showModal(resume ? 'Use WireGuard' : 'Use Direct Connection', [
			E('p', [resume ?
				'Validate the WireGuard tunnel, then route public IPv4 traffic from downstream devices and this router through the configured VPS. If validation fails, the controller locks public traffic to a direct connection using your home public IP.' :
				'Route public IPv4 traffic through your home Internet connection. Websites will see your home public IP. This mode stays active until you manually restore WireGuard.']),
			E('p', ['Existing public Internet connections may disconnect and need to reconnect. Local management addresses remain directly reachable.']),
			E('div', {'class': 'right'}, [
				E('button', {'class': 'cbi-button cbi-button-neutral', click: ui.hideModal}, ['Cancel']),
				' ',
				E('button', {'class': 'cbi-button cbi-button-action important', click: L.bind(function() {
					ui.hideModal();
					return this.runAction(action);
				}, this)}, [resume ? 'Validate and use WireGuard' : 'Use Direct Connection'])
			])
		]);
	},

	render: function(data) {
		this.pending = false;
		this.summary = E('div', {'class': 'cbi-section'});
		this.resumeButton = E('button', {'class': 'cbi-button cbi-button-apply', click: ui.createHandlerFn(this, 'confirmAction', 'resume')}, ['Use WireGuard']);
		this.directButton = E('button', {'class': 'cbi-button cbi-button-neutral', click: ui.createHandlerFn(this, 'confirmAction', 'direct')}, ['Use Direct Connection']);
		const node = E('div', [
			E('h2', ['WireGuard Egress']),
			E('p', ['Manage the existing WireGuard egress controller. Public IPv4 uses the VPS while WireGuard is active. After three failed health checks, the controller switches to a direct connection; restoring WireGuard requires the button below.']),
			E('p', ['The expected public IPv4 is configuration information, not a live public-IP lookup. Private management traffic remains direct. IPv6 is disabled.']),
			this.summary,
			E('div', {'class': 'cbi-section'}, [this.resumeButton, ' ', this.directButton]),
			!hasWriteAccess() ? E('p', {'class': 'alert-message notice'}, ['Read-only access: your LuCI account cannot change the egress mode.']) : '',
			E('p', [E('a', {href: L.url('admin/status/wireguard')}, ['View native WireGuard status']), ' / ', E('a', {href: L.url('admin/network/network')}, ['View interface settings']), ' / ', E('a', {href: L.url('admin/services/nlbw/proxy')}, ['View node usage'])]),
			E('p', ['Use these egress controls for normal switching. Bringing the interface down in Network settings is not a replacement for selecting a direct connection. Tunnel byte counters are current-interface counters; persistent monthly usage is available on Node Usage.'])
		]);
		this.update(data);
		poll.add(L.bind(this.refresh, this), 5);
		return node;
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
