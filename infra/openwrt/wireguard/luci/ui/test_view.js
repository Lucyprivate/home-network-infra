'use strict';
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const source = fs.readFileSync(path.join(__dirname, 'view/egress.js'), 'utf8');
const fixture = {
  schema: 1,
  controller: {mode:'WG_ACTIVE', transport:'wireguard', production_routing:true, routing_consistent:true,
    expected_exit_ipv4:'198.51.100.10', tunnel_healthy:true, failures:0,
    last_health_utc:new Date().toISOString().replace(/\.\d{3}Z$/,'Z'), updated_utc:'2000-01-15T14:59:00Z', reason:'manual_resume'},
  tunnel: {up:true, address:'10.200.0.2/30', mtu:1380, listen_port:51820, peer_count:1,
    last_handshake:946684800, rx_bytes:4096, tx_bytes:2048},
  operation: {running:false, action:null, result:null},
  service: {enabled:true, running:true}
};
let calls, notifications, modal, writable, status, response, polling, deferred, checks = 0;

function check(value, message) { assert(value, message); checks++; }
function node(tag, attributes, children) {
  if (Array.isArray(attributes) || typeof attributes === 'string') { children = attributes; attributes = {}; }
  return {tag, attributes:attributes || {}, children:[].concat(children || [])};
}
function allText(v) {
  if (!v) return '';
  if (typeof v === 'string') return v;
  return v.tag === '#text' ? v.value : (v.children || []).map(allText).join(' ');
}
function find(v, predicate, result = []) {
  if (v && typeof v === 'object') {
    if (predicate(v)) result.push(v);
    (v.children || []).forEach(n => find(n, predicate, result));
  }
  return result;
}
function makePage() {
  calls = []; notifications = []; modal = null; writable = true; status = structuredClone(fixture);
  response = {accepted:true}; polling = null; deferred = null;
  return new Function('view','rpc','poll','ui','dom','L','E','document', source)(
    {extend(v) { return v; }},
    {declare(options) { return (...args) => {
      calls.push({method:options.method, args});
      return options.method === 'status' ? Promise.resolve(status) : deferred || Promise.resolve(response);
    }; }},
    {add(fn, seconds) { polling = {fn, seconds}; }},
    {
      createHandlerFn(receiver, method, ...args) { return receiver[method].bind(receiver, ...args); },
      addNotification(_, text, level) { notifications.push({text:allText(text), level}); },
      showModal(title, contents) { modal = {title, contents}; },
      hideModal() { modal = null; }
    },
    {content(target, contents) { target.children = contents; }},
    {bind(fn, receiver, ...args) { return fn.bind(receiver, ...args); },
      hasViewPermission() { return writable; }, url(p) { return '/cgi-bin/luci/' + p; }},
    node,
    {createTextNode(value) { return {tag:'#text',value}; }}
  );
}

async function test() {
  const page = makePage();
  const loaded = await page.load();
  const root = page.render(loaded);
  check(calls.length === 1 && calls[0].method === 'status', 'load is read-only');
  check(polling.seconds === 5, 'bounded five-second polling');
  check(allText(root).includes('WireGuard Egress'));
  check(allText(root).includes('WireGuard active'));
  check(allText(root).includes('Tunnel health Healthy'), 'fresh successful check from a running controller is healthy');
  check(allText(root).includes('Expected WireGuard public IPv4 198.51.100.10'));
  check(allText(root).includes('not a live public-IP lookup'), 'expected address is not claimed to be measured');
  check(allText(root).includes('4.00 KiB / 2.00 KiB'));
  check(allText(root).includes('UTC'));
  check(!page.resumeButton.disabled && !page.directButton.disabled);
  check(find(root, v => v.tag === 'a').map(v => v.attributes.href).includes('/cgi-bin/luci/admin/network/network'));
  check(find(root, v => v.tag === 'a').map(v => v.attributes.href).includes('/cgi-bin/luci/admin/status/wireguard'));
  check(page.handleSave === null && page.handleSaveApply === null && page.handleReset === null, 'no implicit UCI apply');
  page.update({...status,controller:{...status.controller,last_health_utc:null}});
  check(allText(page.summary).includes('Tunnel health Not yet checked'), 'missing health timestamp is never healthy');
  check(!page.resumeButton.disabled && !page.directButton.disabled, 'recovery controls remain available without a health result');
  page.update({...status,controller:{...status.controller,last_health_utc:new Date(Date.now()-96000).toISOString()}});
  check(allText(page.summary).includes('Tunnel health Health check is stale'), 'old success is not current health');
  page.update({...status,service:{...status.service,running:false}});
  check(allText(page.summary).includes('Tunnel health Controller stopped; health unconfirmed'), 'stopped watcher cannot claim healthy');
  check(!page.resumeButton.disabled && !page.directButton.disabled, 'recovery controls remain available when controller is stopped');
  page.update(status);
  page.confirmAction('direct');
  check(modal.title === 'Use Direct Connection');
  check(allText({children:modal.contents}).includes('home public IP'));
  check(calls.filter(v => v.method === 'control').length === 0, 'opening confirmation does not write');
  const confirm = find({children:modal.contents}, v => v.tag === 'button').at(-1);
  await confirm.attributes.click();
  check(calls.filter(v => v.method === 'control').length === 1);
  check(calls.filter(v => v.method === 'control')[0].args[0] === 'direct');
  check(notifications[0].level === 'info');
  check(modal === null, 'confirmation closes before operation');
  page.confirmAction('resume');
  check(allText({children:modal.contents}).includes('locks public traffic to a direct connection using your home public IP'));
  check(find({children:modal.contents}, v => v.tag === 'button').at(-1).children[0] === 'Validate and use WireGuard');
  const beforeInvalid = calls.length;
  await page.runAction('restart'); page.confirmAction('restart');
  check(calls.length === beforeInvalid, 'unsupported action is never sent');
  const dangerous = '<img src=x onerror=alert(1)>';
  page.update({...status, controller:{...status.controller,reason:dangerous}});
  check(allText(page.summary).includes(dangerous));
  check(find(page.summary, v => v.tag === 'img').length === 0, 'backend strings are rendered as text');
  page.update({...status,controller:{...status.controller,mode:'DIRECT_LATCHED',production_routing:false,tunnel_healthy:false}});
  check(allText(page.summary).includes('Direct connection (manual recovery required)'));
  page.update({...status,controller:{...status.controller,routing_consistent:false}});
  check(allText(page.summary).includes('Routing state needs attention'), 'inconsistency never looks active');
  page.update({...status,operation:{running:true,action:'resume',started_utc:'2000-01-15T15:00:00Z'}});
  check(page.resumeButton.disabled && page.directButton.disabled);
  const beforeBusy = calls.length;
  await page.runAction('direct'); page.confirmAction('direct');
  check(calls.length === beforeBusy, 'pending backend operation prevents another request');
  page.update({error:'Backend unavailable'});
  check(page.resumeButton.disabled && page.directButton.disabled && page.latest === null);
  check(!allText(page.summary).includes('WireGuard active'), 'stale active state is cleared after failure');
  page.update({...status,tunnel:{...status.tunnel,last_handshake:0,rx_bytes:-1,tx_bytes:'bad'}});
  check(allText(page.summary).includes('Last WireGuard handshake Not yet recorded'));
  check(allText(page.summary).includes('Tunnel received / sent \u2014 / \u2014'));
  page.update({...status,tunnel:{...status.tunnel,rx_bytes:null,tx_bytes:null}});
  check(allText(page.summary).includes('Tunnel received / sent \u2014 / \u2014'), 'unavailable counters are not displayed as zero');
  writable = false;
  page.update(status);
  check(page.resumeButton.disabled && page.directButton.disabled);
  const beforeReadOnly = calls.length;
  await page.runAction('resume'); page.confirmAction('direct');
  check(calls.length === beforeReadOnly, 'read-only account cannot invoke control');
  const readonly = page.render(status);
  check(allText(readonly).includes('Read-only access:'));
  writable = true; page.update(status);
  response = {error: 'Permission denied'};
  await page.runAction('resume');
  check(notifications.at(-1).level === 'error' && notifications.at(-1).text.includes('Permission denied'));
  response = {accepted:true};
  let release;
  deferred = new Promise(resolve => { release = resolve; });
  const pendingAction = page.runAction('resume');
  check(page.resumeButton.disabled && page.directButton.disabled && page.pending);
  const controls = calls.filter(v => v.method === 'control').length;
  await page.runAction('direct');
  check(calls.filter(v => v.method === 'control').length === controls, 'double click cannot send duplicate control');
  release({accepted:true}); await pendingAction; deferred = null;
  check(!page.pending && !page.directButton.disabled, 'pending flag clears after completion');
  check(!/[\u3400-\u9fff]/u.test(source), 'view is English-only');
  const menu = JSON.parse(fs.readFileSync(path.join(__dirname,'menu/luci-app-vpn-egress.json'),'utf8'));
  const acl = JSON.parse(fs.readFileSync(path.join(__dirname,'acl/luci-app-vpn-egress.json'),'utf8'));
  check(menu['admin/services/vpn-egress'].action.path === 'vpn-egress/egress');
  check(JSON.stringify(acl['luci-app-vpn-egress'].read.ubus) === JSON.stringify({'luci.vpn-egress':['status']}));
  check(JSON.stringify(acl['luci-app-vpn-egress'].write.ubus) === JSON.stringify({'luci.vpn-egress':['control']}));
  check(!Object.hasOwn(acl['luci-app-vpn-egress'].read,'file') && !Object.hasOwn(acl['luci-app-vpn-egress'].read,'uci') &&
    !Object.hasOwn(acl['luci-app-vpn-egress'].write,'file') && !Object.hasOwn(acl['luci-app-vpn-egress'].write,'uci'), 'ACL cannot read keys or write UCI');
  console.log(JSON.stringify({schema:1,view_checks:checks,result:'passed'}));
}
test().catch(e => { console.error(e); process.exit(1); });
