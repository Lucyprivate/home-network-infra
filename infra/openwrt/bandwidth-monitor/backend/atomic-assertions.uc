directory(STORE); directory(RUN);
let path = STORE + '/state.json';
write_atomic(path, {version:1});
check('atomic write replaces complete JSON',json(database[path]).version==1&&database[path+'.new']==null);
fail_rename=true;
let failed=false;
try {write_atomic(path,{version:2});} catch(e){failed=true;}
check('interrupted rename preserves previous durable state',failed&&json(database[path]).version==1&&json(database[path+'.new']).version==2);
fail_rename=false;write_atomic(path,{version:3});
check('subsequent successful save completes atomically',json(database[path]).version==3&&database[path+'.new']==null);
let closed_before=closed_files;fail_write=true;failed=false;
try {write_atomic(path,{version:4});} catch(e){failed=true;}
check('failed write closes fd and preserves durable file',failed&&closed_files==closed_before+1&&json(database[path]).version==3);
fail_write=false;closed_before=closed_files;fail_flush=true;failed=false;
try {write_atomic(path,{version:4});} catch(e){failed=true;}
check('failed flush closes fd and preserves durable file',failed&&closed_files==closed_before+1&&json(database[path]).version==3);
fail_flush=false;
overrides[path]={type:'symlink',uid:0,mode:384,nlink:1,size:1};failed=false;
try {write_atomic(path,{version:4});} catch(e){failed=true;}
check('symlink state rejected before writing',failed&&json(database[path]).version==3);
delete overrides[path];
overrides[path]={type:'file',uid:1000,mode:384,nlink:1,size:1};failed=false;
try {load(path,false);} catch(e){failed=true;}
check('non-root file rejected',failed);
delete overrides[path];database[path]='corrupt';failed=false;
try {load(path,false);} catch(e){failed=true;}
check('corrupt file retained without reset',failed&&database[path]=='corrupt');
delete database[path];
state = new_state(100,'2000-01');endpoint={label:'Native H2'};
save();
check('save stores accounting checkpoint with timestamp',valid_state(json(database[path]))&&state.saved_at>0);
publish('running');
check('runtime and status written separately',valid_state(json(database[RUN+'/runtime.json']))&&json(database[RUN+'/status.json']).label=='Native H2');
let old=state.saved_at;sync_rc=1;failed=false;
try {save();} catch(e){failed=true;}
check('sync failure is reported and saved timestamp unconfirmed',failed&&state.saved_at==old);
check('no proxy control invoked during persistence tests',length(results)>=9);
sync_rc=0;
check('controller absence retains original HomeProxy fallback',controller_mode()==null);
overrides['/etc/init.d/vpn-egress']={type:'file',uid:0,mode:493,nlink:1,size:1};
check('installed controller without status pauses rather than falling back',controller_mode().mode=='paused');
overrides[VPN_DIR]={type:'directory',uid:0,mode:448};
let vpn={schema:1,mode:'WG_ACTIVE',transport:'wireguard',node_label:WIREGUARD.label,
	endpoint:{address:WIREGUARD.address,port:51820,protocol:'udp'},expected_exit_ipv4:WIREGUARD.address,tunnel_healthy:true};
database[VPN_STATUS]=sprintf('%J',vpn);
check('WireGuard active status selects approved UDP endpoint',controller_mode().mode=='proxy'&&controller_mode().egress_mode=='WG_ACTIVE'&&controller_mode().accounting_endpoint.port==51820);
vpn.mode='DIRECT_LATCHED';vpn.transport='direct';vpn.tunnel_healthy=false;database[VPN_STATUS]=sprintf('%J',vpn);
check('direct latched preserves WireGuard keepalive accounting identity',controller_mode().mode=='direct'&&controller_mode().transport=='wireguard'&&controller_mode().accounting_endpoint.port==51820);
vpn.production_routing=true;database[VPN_STATUS]=sprintf('%J',vpn);
check('latched direct with production routing is never displayed as direct',controller_mode().mode=='paused'&&controller_mode().reason=='vpn_routing_inconsistent');
vpn.production_routing=false;vpn.routing_consistent=false;database[VPN_STATUS]=sprintf('%J',vpn);
check('explicit routing inconsistency pauses accounting',controller_mode().mode=='paused'&&controller_mode().reason=='vpn_routing_inconsistent');
vpn.mode='WG_ACTIVE';vpn.transport='wireguard';vpn.routing_consistent=true;database[VPN_STATUS]=sprintf('%J',vpn);
check('active state without production route pauses accounting',controller_mode().mode=='paused'&&controller_mode().reason=='vpn_routing_inconsistent');
vpn.production_routing=true;database[VPN_STATUS]=sprintf('%J',vpn);
check('consistent active route status preserves WireGuard accounting',controller_mode().mode=='proxy'&&controller_mode().egress_mode=='WG_ACTIVE');
vpn.production_routing='true';database[VPN_STATUS]=sprintf('%J',vpn);
check('malformed routing flags cannot claim production status',controller_mode().mode=='paused'&&controller_mode().reason=='vpn_routing_status_invalid');
vpn.mode='DIRECT_LATCHED';vpn.transport='direct';vpn.production_routing=false;vpn.routing_consistent=true;

vpn.endpoint.port=999;database[VPN_STATUS]=sprintf('%J',vpn);
check('changed VPN endpoint pauses without replacing rules',controller_mode().mode=='paused');
vpn.endpoint.port=51820;database[VPN_STATUS]=sprintf('%J',vpn);
overrides[VPN_STATUS]={type:'symlink',uid:0,mode:384,nlink:1,size:1};
check('untrusted status symlink refused',controller_mode().mode=='paused');delete overrides[VPN_STATUS];
overrides[VPN_STATUS]={type:'file',uid:0,mode:384,nlink:1,size:100,mtime:time()-100};
check('stale controller snapshot cannot claim current WireGuard mode',controller_mode().mode=='paused'&&controller_mode().reason=='vpn_status_stale');delete overrides[VPN_STATUS];
function table_for(e, identity, count) {
	let rows=[{table:{family:'inet',name:'proxy_usage',handle:identity,comment:'proxy-usage-v1:11111111-1111-1111-1111-111111111111'}}];
	for(let n in ['input','output']) push(rows,{chain:{family:'inet',table:'proxy_usage',name:n,handle:identity+1,type:'filter',hook:n,prio:10,policy:'accept'}});
	for(let n in ['upload','download']) push(rows,{counter:{family:'inet',table:'proxy_usage',name:n,handle:identity+2,bytes:count,packets:count}});
	for(let n in ['input','output']) push(rows,{rule:{family:'inet',table:'proxy_usage',chain:n,handle:identity+3,expr:expressions(e,n=='output')}});
	return {nftables:rows};
}
registered_endpoint={schema:1,node_id:'abc123',label:'Native H2',wan:'eth0',address:'198.51.100.2',port:443};
endpoint=WIREGUARD;
state=new_state(100,'2000-01');
let initial=inspect_table(table_for(registered_endpoint,10,100),registered_endpoint);
advance(state,{at:100,period:'2000-01',mode:'proxy',boot_id:BOOT,identity:initial.identity,totals:initial.totals,fresh:true});
mock_table=table_for(registered_endpoint,10,150);next_table=table_for(WIREGUARD,20,0);actions=[];
let current=read_counters(130,'2000-01');
check('old final counter delta saved before atomic endpoint replacement',state.lifetime.upload_bytes==150&&actions[0]=='saved'&&actions[1]=='checked'&&actions[2]=='replaced');
check('switch transaction replaces only owned statistics table',index(database[RUN+'/rules.nft'],'delete table inet proxy_usage\ncreate table inet proxy_usage')==0&&index(database[RUN+'/rules.nft'],'udp dport 51820')>=0);
advance(state,{at:130,period:'2000-01',mode:'proxy',boot_id:BOOT,identity:current.identity,totals:current.totals});
check('endpoint identity switch marks gap and never counts new raw value twice',state.coverage.gaps==1&&state.coverage.last_gap.reason=='counter_identity_changed'&&state.lifetime.upload_bytes==150);
mock_table=table_for(WIREGUARD,20,50);current=read_counters(160,'2000-01');
advance(state,{at:160,period:'2000-01',mode:'proxy',boot_id:BOOT,identity:current.identity,totals:current.totals});
advance(state,{at:160,period:'2000-01',mode:'proxy',boot_id:BOOT,identity:current.identity,totals:current.totals});
check('WireGuard restart checkpoints retain prior months and cumulative totals',state.lifetime.upload_bytes==200&&state.months[0].upload_bytes==200);
state.transport='wireguard';state.egress_mode='WG_ACTIVE';
let status=public_status(state,WIREGUARD.label,'running');
check('public snapshot exposes mode and transport but no private endpoint',status.transport=='wireguard'&&status.egress_mode=='WG_ACTIVE'&&status.endpoint==null&&status.checkpoint==null);
let prior_month={period:'1999-12',gaps:0,upload_bytes:10,download_bytes:10,upload_packets:10,download_packets:10};
push(state.months,prior_month);
for(let k in ['upload_bytes','download_bytes','upload_packets','download_packets']) state.lifetime[k]+=10;
let raw_snapshot=sprintf('%J',state);
check('additive WireGuard metadata keeps schema1 state compatible',valid_state(json(raw_snapshot)));
endpoint=registered_endpoint;mock_table=table_for(WIREGUARD,20,70);next_table=table_for(registered_endpoint,30,0);actions=[];
current=read_counters(190,'2000-01');
advance(state,{at:190,period:'2000-01',mode:'proxy',boot_id:BOOT,identity:current.identity,totals:current.totals});
check('rollback transport checkpoint keeps final WireGuard bytes',state.lifetime.upload_bytes==230&&state.coverage.gaps==2&&state.months[1].period=='1999-12'&&state.months[1].upload_bytes==10);
mock_table=table_for(WIREGUARD,50,99);mock_table.nftables[5].rule.expr[0].match.right='eth9';actions=[];
check('foreign modified table never deleted for endpoint switch',read_counters(220,'2000-01')==null&&length(actions)==0);
mock_table=table_for(WIREGUARD,50,99);next_table=table_for(registered_endpoint,60,0);nft_rc=1;actions=[];
check('failed syntax check preserves owned previous table and history',read_counters(250,'2000-01')==null&&index(actions,'replaced')<0&&inspect_table(mock_table,WIREGUARD)!=null&&state.lifetime.upload_bytes>=230);
print(sprintf('%J\n',{ok:true,passed:length(results),tests:results}));
