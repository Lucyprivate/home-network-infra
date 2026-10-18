import json,subprocess
from pathlib import Path
B=Path(__file__).resolve().parent
source='\n'.join(x for x in (B/'luci.vpn-egress').read_text().splitlines() if not x.startswith(('import ','#!')))
source=source.rsplit("return {'luci.vpn-egress':methods};",1)[0]
mock='''let responses={},calls=[],enabled=true;function init_enabled(n){return enabled;}
function popen(c){push(calls,c);let v=responses[c];if(v==null)return null;return {read:function(n){return substr(v.text,0,n);},close:function(){return v.rc??0;}};}
let tests=[];function check(n,b){if(!b)die('FAILED '+n);push(tests,n);}
function copy(v){return json(sprintf('%J',v));}
'''
fixtures='''
let base={schema:1,mode:'WG_ACTIVE',transport:'wireguard',tunnel_healthy:true,production_routing:true,routing_consistent:true,failures:0,reason:'healthy',expected_exit_ipv4:'198.51.100.10',endpoint:{address:'198.51.100.10',port:51820,protocol:'udp'},last_health_utc:'2000-01-15T16:00:00Z',updated_utc:'2000-01-15T15:33:03Z',private_key:'DO_NOT_EXPOSE',password:'DO_NOT_EXPOSE'};
let none={running:false,action:null,result:'none',started_utc:null,completed_utc:null,private_key:'DO_NOT_EXPOSE'};
let key='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'+'=';
function set(name,value){responses[COMMANDS[name]]={text:type(value)=='string'?value:sprintf('%J',value)};}
function reset(){responses={};calls=[];set('controller',base);set('operation',{operation:none});set('address',[{ifname:'wg_exit',flags:['UP','POINTOPOINT'],mtu:1380,addr_info:[{family:'inet',local:'10.200.0.2',prefixlen:30}]}]);set('handshakes',key+'\\t1234\\n');set('transfer',key+'\\t123\\t456\\n');set('listen','60000');set('service',{'vpn-egress':{instances:{instance1:{running:true,command:['/usr/sbin/vpn-egress','watch']}}}});}
reset();let s=status();check('complete live-shaped status',s.schema==1&&s.controller.mode=='WG_ACTIVE'&&s.tunnel.up&&s.tunnel.peer_count==1&&s.tunnel.rx_bytes==123&&s.tunnel.tx_bytes==456&&s.tunnel.last_handshake==1234&&s.service.running&&s.service.enabled);
check('status omits credentials and peer keys',index(sprintf('%J',s),'DO_NOT_EXPOSE')<0&&index(sprintf('%J',s),key)<0);
check('status invokes only fixed local commands',length(calls)==7&&length(filter(calls,c=>index(values(COMMANDS),c)<0))==0);
reset();let bad=copy(base);bad.tunnel_healthy='true';set('controller',bad);check('malformed health boolean refused',status().error!=null);
reset();bad=copy(base);bad.expected_exit_ipv4='198.51.100.3';set('controller',bad);check('unexpected endpoint identity refused',status().error!=null);
reset();bad=copy(base);bad.reason='healthy\\n<script>';set('controller',bad);check('control characters in reason refused',status().error!=null);
reset();bad=copy(base);bad.updated_utc='invalid';set('controller',bad);check('invalid controller time refused',status().error!=null);
reset();bad=copy(base);bad.updated_utc='';bad.last_health_utc='';set('controller',bad);s=status();check('boot without runtime health remains recoverable',s.controller.last_health_utc==null&&s.controller.updated_utc==null);
reset();bad=copy(none);bad.running='false';set('operation',{operation:bad});check('malformed operation shape refused',status().error!=null);
reset();bad=copy(none);bad.running=true;bad.action='direct';set('operation',{operation:bad});check('running without pending result refused',status().error!=null);
reset();delete responses[COMMANDS.address];s=status();check('missing interface is safely down',s.tunnel.up==false&&s.tunnel.rx_bytes==null);
reset();set('transfer',key+'\\t123\\t456\\n'+key+'\\t789\\t12\\n');check('duplicate peer rows do not count twice',status().tunnel.rx_bytes==null);
reset();set('transfer',key+'\\t9007199254740992\\t1\\n');check('unsafe JS integer counters refused',status().tunnel.rx_bytes==null);
reset();set('handshakes','malformed-key\\t1234');check('invalid public key rows refused',status().tunnel.rx_bytes==null);
reset();set('handshakes','');set('transfer','');s=status();check('empty peer list never invents handshake',s.tunnel.peer_count==0&&s.tunnel.last_handshake==null);
reset();responses[COMMANDS.controller].rc=1;check('failed executable never accepted as status',status().error!=null);
reset();set('controller',sprintf('%33000s','x'));check('oversized output rejected',status().error!=null);
for(let action in [null,{},[],1,'DIRECT','resume;reboot','direct\\nreboot','../direct','']){reset();let r=methods.control.call({args:{action}});check('invalid action rejected without execution '+sprintf('%J',action),r.error=='Unsupported action'&&length(calls)==0);}
for(let action in ['direct','resume']){reset();let op={running:true,action,result:'pending',started_utc:'2000-01-15T16:00:00Z',completed_utc:null,token:'DO_NOT_EXPOSE'};set(action,{accepted:true,operation:op});let r=methods.control.call({args:{action}});check('fixed allowed action dispatch '+action,r.accepted&&r.operation.running&&length(calls)==1&&calls[0]==COMMANDS[action]&&index(sprintf('%J',r),'DO_NOT_EXPOSE')<0);}
reset();set('direct',{error:'An egress operation is already running'});responses[COMMANDS.direct].rc=1;check('fixed helper rc1 busy JSON remains visible',methods.control.call({args:{action:'direct'}}).error=='An egress operation is already running');
reset();set('direct',{error:'An operation is already running'});check('busy operation reported safely',methods.control.call({args:{action:'direct'}}).error=='An operation is already running');
reset();set('direct',{error:'private /etc/config/root credential'});check('untrusted raw execution error not disclosed',methods.control.call({args:{action:'direct'}}).error=='Unable to start operation');
reset();set('resume',{accepted:true,operation:{running:true,action:'direct',result:'pending',started_utc:null,completed_utc:null}});check('mismatched worker action not accepted',methods.control.call({args:{action:'resume'}}).accepted!=true);
print(sprintf('%J\\n',{passed:length(tests),tests}));
'''
program=mock+source+fixtures
ucode=B.parents[3]/'wifi/tooling/build/ucode'
# B=.../work/wireguard-egress/luci/backend
ucode=B.parents[2]/'wifi/tooling/build/ucode'
p=subprocess.run([str(ucode),'-e',program],capture_output=True,text=True,timeout=20)
if p.returncode:raise SystemExit(p.stderr)
result=json.loads(p.stdout);(B/'rpc-test-results.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
