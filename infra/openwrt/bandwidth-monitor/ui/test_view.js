/* SPDX-License-Identifier: MIT */
'use strict';
const assert = require('assert');
const fs = require('fs');
const path = require('path');

let calls = [], notifications = [], downloads = 0, pollInterval = null;
let response = {filename: 'proxy-usage-all.json', content: '{}', mime: 'application/json'};
const fixture = {
  schema: 1, label: '<img src=x onerror=alert(1)>', mode: 'proxy', service: 'running',
  coverage: {state: 'complete', gaps: 0, since: 1, last_gap: null},
  updated_at: Date.now()/1000, saved_at: 1,
  rates: {upload_bps: 2048, download_bps: 4096, upload_pps: 1, download_pps: 2},
  lifetime: {upload_bytes: 4096, download_bytes: 8192, upload_packets: 4, download_packets: 8},
  months: [
    {period: '2000-01', upload_bytes: 2048, download_bytes: 4096, upload_packets: 2, download_packets: 4, gaps: 0},
    {period: '1999-12', upload_bytes: 2048, download_bytes: 4096, upload_packets: 2, download_packets: 4, gaps: 1}
  ], current_period: '2000-01', note: 'Protocol overhead is included.'
};

function node(tag, attributes, children) {
  if (Array.isArray(attributes) || typeof attributes === 'string') { children = attributes; attributes = {}; }
  return {
    tag, attributes: attributes || {}, children: [].concat(children || []), value: '',
    click() { downloads++; }, remove() {}
  };
}
const document = {
  createTextNode(value) { return {tag: '#text', value}; },
  body: {appendChild() {}}
};
const dom = {content(target, children) { target.children = children; }};
const rpc = {
  declare(options) { return function(...args) {
    calls.push({method: options.method, args});
    return Promise.resolve(options.method === 'status' ? fixture : options.method === 'periods' ? {periods:['2000-01','1999-12']} : response);
  }; }
};
const ui = {
  createHandlerFn(receiver, method, ...args) { return receiver[method].bind(receiver, ...args); },
  addNotification(_, text) { notifications.push(text); }
};
const poll = {add(fn, interval) { pollInterval = interval; }};
const L = {bind(fn, receiver, ...args) { return fn.bind(receiver, ...args); }};
const window = {URL: {createObjectURL() { return 'blob:test'; }, revokeObjectURL() {}}};
const source = fs.readFileSync(path.join(__dirname, 'view/proxy.js'), 'utf8');
const page = new Function('view','rpc','poll','ui','dom','L','E','document','window', source)(
  {extend(v) { return v; }}, rpc, poll, ui, dom, L, node, document, window
);

function allText(v) {
  if (!v) return '';
  if (typeof v === 'string') return v;
  return v.tag === '#text' ? v.value : (v.children || []).map(allText).join(' ');
}

async function test() {
  const loaded = await page.load();
  assert.deepStrictEqual(calls.slice(0,2).map(v => v.method), ['status','periods']);
  page.render(loaded);
  assert.strictEqual(pollInterval, 30);
  assert(allText(page.summary).includes(fixture.label));
  assert(allText(page.summary).includes('2.00 KiB/s'));
  assert.strictEqual(page.selector.children[1].attributes.value, '2000-01');
  assert.strictEqual(page.table.children.length, 3);
  assert.strictEqual(page.summary.children[0].children[1].children[0].tag, '#text');
  page.selector.value = '1999-12'; page.update(fixture);
  assert.strictEqual(page.selector.value, '1999-12');
  assert.strictEqual(page.table.children.length, 2);
  assert(allText(page.table).includes('1999-12'));
  const direct = {...fixture, mode:'direct', coverage:{...fixture.coverage,state:'paused'}};
  page.update(direct); assert(allText(page.summary).includes('Direct'));
  page.update({...fixture, transport:'wireguard', egress_mode:'WG_ACTIVE'});
  assert(allText(page.summary).includes('WireGuard active'));
  assert(allText(page.summary).includes('Monitored transport WireGuard'));
  page.update({...direct, transport:'wireguard', egress_mode:'DIRECT_LATCHED'});
  assert(allText(page.summary).includes('Direct'));
  assert(allText(page.summary).includes('Monitored transport WireGuard'));
  assert.strictEqual(page.table.children.length,2);
  page.update({...fixture, updated_at:Date.now()/1000-200});
  assert(allText(page.summary).includes('more than 90 seconds'));
  assert(allText(page.summary).includes('current service status is unconfirmed'));
  page.update({error:'Statistics unavailable'});
  assert(page.downloadButtons.every(v => v.disabled));
  assert.strictEqual(page.latest, null);
  page.update(fixture);
  assert(page.downloadButtons.every(v => !v.disabled));
  page.selector.value = 'all'; await page.handleDownload('json');
  assert.strictEqual(downloads, 1);
  assert.deepStrictEqual(calls.at(-1), {method:'export',args:['json','all']});
  response={filename:'../../etc/shadow',content:'not used',mime:'application/json'};
  await page.handleDownload('json');
  assert.strictEqual(downloads, 1);
  assert.strictEqual(notifications.length, 1);
  response={error:'Invalid export selection'};
  await page.handleDownload('csv');
  assert.strictEqual(downloads, 1);
  assert.strictEqual(notifications.length, 2);
  assert.strictEqual(page.handleSave, null);
  assert.strictEqual(page.handleSaveApply, null);
  assert.strictEqual(page.handleReset, null);
  console.log(JSON.stringify({view_checks:30,result:'passed'}));
}
test().catch(e => {console.error(e);process.exit(1);});
