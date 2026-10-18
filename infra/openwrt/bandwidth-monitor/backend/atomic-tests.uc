// Exercises the collector's actual file/save functions with an in-memory fs.
let results = [];
function check(name, okay) { if (!okay) die('FAILED ' + name); push(results, name); }
let database = {}, overrides = {}, fail_rename = false, sync_rc = 0;
let fail_write = false, fail_flush = false, closed_files = 0;
let mock_table = null, next_table = null, actions = [], nft_rc = 0;
let fs = {
	lstat: function(path) {
		if (overrides[path]) return overrides[path];
		if (path == '/etc/proxy-usage' || path == '/var/run/proxy-usage') return {type:'directory',uid:0,mode:448};
		if (!(path in database)) return null;
		return {type:'file',uid:0,mode:384,nlink:1,size:length(database[path]),mtime:time()};
	},
	readfile: function(path) { return path == '/proc/sys/kernel/random/boot_id' || path == '/proc/sys/kernel/random/uuid' ? '11111111-1111-1111-1111-111111111111' : database[path]; },
	popen: function(cmd, mode) {
		if (cmd != '/usr/sbin/nft -j -a list table inet proxy_usage 2>/dev/null') die('unexpected command in accounting test');
		return {read:function(){return sprintf('%J',mock_table);},close:function(){return 0;}};
	},
	open: function(path, mode, permissions) {
		database[path]='';
		return {write:function(data){database[path]=data;return fail_write ? 0 : length(data);},flush:function(){return !fail_flush;},close:function(){closed_files++;return true;}};
	},
	chmod: function(){return true;},
	rename: function(a,b){if(fail_rename)return false;database[b]=database[a];delete database[a];return true;},
	stderr: {write:function(){} }
};
function fake_system(command, timeout) {
	if(command == '/bin/sync') { push(actions,'saved'); return sync_rc; }
	if(command == '/usr/sbin/nft -c -f /var/run/proxy-usage/rules.nft >/dev/null 2>&1') {push(actions,'checked');return nft_rc;}
	if(command == '/usr/sbin/nft -f /var/run/proxy-usage/rules.nft >/dev/null 2>&1') {push(actions,'replaced');mock_table=next_table;return nft_rc;}
	die('unexpected command in filesystem test');
}
function cursor() {return {get:function(conf,section,key){return key=='main_node'?'abc123':'same';}};}
// Collector declarations are inserted below this line by run-tests.py.
