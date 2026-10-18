// Pure ucode tests run with the installed interpreter. No remote writes.
let results = [];
function check(name, okay) { if (!okay) die('FAILED ' + name); push(results, name); }
function cp(v) { return json(sprintf('%J', v)); }
function counts(n) { return {upload_bytes:n,download_bytes:n*2,upload_packets:n/10,download_packets:n/5}; }
function sample(s, at, n, extra) {
	let x = {at:at,period:'2000-01',mode:'proxy',identity:'c1',boot_id:'boot1',totals:counts(n)};
	for (let k, v in extra || {}) x[k] = v;
	return advance(s, x);
}
function initial() { let s=new_state(100,'2000-01'); sample(s,100,0,{fresh:true}); return s; }

let e={schema:1,node_id:'abc123',label:'Test native H2',wan:'eth0',address:'198.51.100.2',port:443};
check('approved endpoint', valid_endpoint(e));
for (let address in ['198.51.100.999', '0198.51.100.44', '127.0.0.1', '224.0.0.1', '198.51.100.44; reboot']) {
	let bad=cp(e);bad.address=address;check('bad endpoint '+address,!valid_endpoint(bad));
}
let s=initial(); sample(s,130,100);
check('count bytes and packets',s.lifetime.upload_bytes==100&&s.lifetime.download_bytes==200&&s.lifetime.upload_packets==10);
check('30 second average rate',s.rates.upload_bps==100/30);
let before=cp(s); sample(s,130,100);
check('duplicate checkpoint is idempotent',s.lifetime.upload_bytes==100&&s.coverage.gaps==0);
sample(s,130,110);
check('same-second final delta has no false gap or division by zero',s.lifetime.upload_bytes==110&&s.coverage.gaps==0&&s.rates.upload_bps==0);
s=cp(s); sample(s,160,200);
check('restart no double counting',s.lifetime.upload_bytes==200);
sample(s,300,500);
check('sampling gap retains recoverable bytes',s.lifetime.upload_bytes==500&&s.coverage.last_gap.reason=='sampling_interrupted'&&s.rates.upload_bps==0);
sample(s,330,600);
check('gap remains historical',s.coverage.gaps==1&&s.coverage.active_gap==null);
sample(s,360,10);
check('counter rollback never subtracts',s.lifetime.upload_bytes==600&&s.coverage.last_gap.reason=='counter_reverted');
sample(s,390,20);
check('counter rollback recovers from fresh checkpoint',s.lifetime.upload_bytes==610);
sample(s,420,500,{identity:'new'});
check('changed counter identity skips unknowable raw count',s.lifetime.upload_bytes==610&&s.coverage.last_gap.reason=='counter_identity_changed');
sample(s,450,20,{boot_id:'boot2'});
check('reboot marks loss without fabricated backfill',s.lifetime.upload_bytes==610&&s.coverage.last_gap.reason=='boot_changed');
s=initial(); sample(s,130,100,{mode:'direct'});
check('direct mode visible without changing counters',s.mode=='direct'&&s.rates.upload_bps==0&&s.lifetime.upload_bytes==100);
sample(s,160,200,{mode:'paused',reason:'node_identity_changed'});
check('changed node pauses and preserves history',s.lifetime.upload_bytes==100&&s.mode=='paused'&&s.checkpoint==null);
sample(s,190,500);
check('resuming does not attribute paused traffic',s.lifetime.upload_bytes==100);
sample(s,220,600);
check('resumed accounting tracks new delta',s.lifetime.upload_bytes==200);
s=initial();sample(s,130,100);sample(s,160,200,{period:'2000-02'});
check('month boundary keeps monthly and lifetime consistency',s.months[0].period=='2000-02'&&s.months[0].upload_bytes==0&&s.months[1].upload_bytes==200&&s.lifetime.upload_bytes==200&&s.coverage.last_gap.reason=='month_boundary_interval');
for (let i=0;i<13;i++) sample(s,200+i*30,300+i*100,{period:sprintf('2027-%02d',1+(i%12))});
check('at most 12 monthly records',length(s.months)==12);
check('valid accumulated state',valid_state(s));
let bad=cp(s);bad.lifetime.upload_bytes=-1;check('reject corrupt negative state',!valid_state(bad));
bad=cp(s);bad.months[0].upload_bytes=9007199254740991;check('reject impossible monthly totals',!valid_state(bad));
bad=cp(s);bad.months[0].period='../../etc/config/homeproxy';check('reject untrusted period',!valid_state(bad));
check('public status has no endpoint or checkpoint',public_status(s,e.label,'running').address==null&&public_status(s,e.label,'running').checkpoint==null);

function expr(output) {
	return [{match:{op:'==',left:{meta:{key:output?'oifname':'iifname'}},right:'eth0'}},
		{match:{op:'==',left:{payload:{protocol:'ip',field:output?'daddr':'saddr'}},right:e.address}},
		{match:{op:'==',left:{payload:{protocol:'udp',field:output?'dport':'sport'}},right:e.port}},
		{counter:output?'upload':'download'}];
}
let doc={nftables:[{metainfo:{}},{table:{family:'inet',name:'proxy_usage',handle:10,comment:'proxy-usage-v1:11111111-1111-1111-1111-111111111111'}}]};
for (let direction in ['input','output']) push(doc.nftables,{chain:{family:'inet',table:'proxy_usage',name:direction,handle:direction=='input'?1:2,type:'filter',hook:direction,prio:10,policy:'accept'}});
for (let name in ['upload','download']) push(doc.nftables,{counter:{family:'inet',table:'proxy_usage',name:name,handle:name=='upload'?3:4,bytes:100,packets:10}});
for (let direction in ['input','output']) push(doc.nftables,{rule:{family:'inet',table:'proxy_usage',chain:direction,handle:direction=='input'?5:6,expr:expr(direction=='output')}});
check('exact counter-only nft table accepted',inspect_table(doc,e)!=null);
bad=cp(doc);bad.nftables[1].table.comment='foreign';check('foreign table refused',inspect_table(bad,e)==null);
bad=cp(doc);bad.nftables[1].table.flags=['dormant'];check('dormant or extra table flags refused',inspect_table(bad,e)==null);
bad=cp(doc);push(bad.nftables[6].rule.expr,{drop:null});check('filter action refused',inspect_table(bad,e)==null);
bad=cp(doc);bad.nftables[2].chain.prio=0;check('wrong chain priority refused',inspect_table(bad,e)==null);
bad=cp(doc);bad.nftables[6].rule.expr[0].match.right='br-lan';check('forward/device mismatch refused',inspect_table(bad,e)==null);
bad=cp(doc);push(bad.nftables,{set:{family:'inet',table:'proxy_usage',name:'other'}});check('extra nft object refused',inspect_table(bad,e)==null);
bad=cp(doc);bad.nftables[4].counter.handle=99;check('counter handles form identity',inspect_table(doc,e).identity!=inspect_table(bad,e).identity);
let rules=nft_script(e,'11111111-1111-1111-1111-111111111111');
check('rules have no forwarding/filter/mark verbs',!match(rules,/hook forward|drop|reject|jump|goto|meta mark|snat|dnat/));
print(sprintf('%J\n',{ok:true,passed:length(results),tests:results}));
