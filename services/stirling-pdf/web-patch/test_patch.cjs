'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const p = __dirname + require('node:path').sep;
const original = fs.readFileSync(p + 'refresh-function-original.js', 'utf8');
const patched = fs.readFileSync(p + 'refresh-function-patched.js', 'utf8');
let checks = 0;
const seen = [];

function mount(source, cfg, result, failure) {
  const calls = [];
  let deps;
  const folders = {
    pullFromServer: async () => {calls.push('server'); if (failure === 'server') throw Error('server exploded'); return result;},
    refresh: async () => {calls.push('local'); if (failure === 'local') throw Error('local exploded');},
    setError: e => calls.push(['error', e]),
  };
  const files = {
    refresh: async () => calls.push('files'),
    bumpDiskRevision: () => calls.push('disk'),
  };
  const t = (key, fallback) => fallback;
  const ctx = {
    A: () => ({t}),
    ot: () => folders,
    ft: () => files,
    Ze: () => ({config: cfg}),
    u: {
      useState: () => [false, x => calls.push(['loading', x])],
      useCallback: (cb, d) => {deps = d; return cb;},
    },
  };
  vm.createContext(ctx);
  vm.runInContext(source + '; this.hook = Qg;', ctx);
  return {run: ctx.hook().refresh, calls, deps: () => deps};
}
async function test(name, fn) {
  await fn();
  checks++;
  seen.push(name);
}

(async () => {
  for (const config of [undefined, {}, {storageEnabled: false}, {storageEnabled: 'true'}, {storageEnabled: 1}]) {
    await test('disabled storage local refresh ' + JSON.stringify(config), async () => {
      const m = mount(patched, config, {ok: false, reason: 'client'});
      await m.run();
      assert.deepEqual(m.calls, [['loading', true], ['error', null], 'local', 'disk', 'files', ['loading', false]]);
      assert.equal(m.deps().at(-1), false);
    });
  }
  for (const result of [{ok:true}, {ok:false, reason:'endpoint-missing'}, {ok:false,reason:'network'}, {ok:false,reason:'server'}, {ok:false,reason:'client'}]) {
    await test('enabled retains existing server branch ' + JSON.stringify(result), async () => {
      const before = mount(original, {storageEnabled:true}, result);
      const after = mount(patched, {storageEnabled:true}, result);
      await before.run(); await after.run();
      assert.deepEqual(after.calls, before.calls);
      assert.equal(after.calls.includes('local'), false);
      assert.equal(after.deps().at(-1), true);
    });
  }
  await test('server throw releases loading unchanged', async () => {
    const a = mount(patched, {storageEnabled:true}, null, 'server');
    await assert.rejects(a.run, /server exploded/);
    assert.deepEqual(a.calls, [['loading',true], 'server', ['loading',false]]);
  });
  await test('local throw releases loading without false success', async () => {
    const a = mount(patched, {storageEnabled:false}, null, 'local');
    await assert.rejects(a.run, /local exploded/);
    assert.deepEqual(a.calls, [['loading',true], ['error',null], 'local', ['loading',false]]);
  });
  const main = fs.readFileSync(p + 'patched.js', 'utf8');
  const surface = main.match(/x=(\[b,E,\.\.\.\(r\?\.accountId\?\[C\]:\[\]\)\]),T=/)?.[1];
  assert.ok(surface, 'exact real patched surface expression');
  for (const config of [undefined, {}, {accountId:null}, {accountId:''}, {accountId:'real-test-account'}]) {
    await test('processor real account identity ' + JSON.stringify(config), async () => {
      const context = {b:'reader',E:'editor',C:'processor',r:config};
      vm.createContext(context);
      const values = Array.from(vm.runInContext(surface, context));
      assert.deepEqual(values, config?.accountId ? ['reader','editor','processor'] : ['reader','editor']);
    });
  }
  await test('refresh actual label cannot be overridden by old translation key', () => {
    const landing = fs.readFileSync(p + 'patched-landing.js', 'utf8');
    assert.ok(landing.includes('label:"Refresh files",onClick:()=>{p()},'));
    assert.ok(!landing.includes('label:i("filesPage.refresh","Refresh"),onClick:()=>{p()},'));
  });
  const report = {passed:true, checks, tests:seen, scope:'Pure mocks exercise exact extracted production Qg function and exact production QuickNav visibility expression. No VM deployment.'};
  fs.writeFileSync(p + 'logic-verification.json', JSON.stringify(report, null, 2) + '\n');
  console.log(JSON.stringify(report, null, 2));
})().catch(e => { console.error(e); process.exitCode=1; });
