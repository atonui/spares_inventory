const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const {loadPageScripts}=require('./helpers/frontend.cjs');
const plain=v=>JSON.parse(JSON.stringify(v));
const blank={startDate:'',endDate:'',action:'',targetUserId:'',status:''};
const actorless={id:1,user_id:null,username:null,created_at:'2026-10-12T09:00:00Z',action:'LOGIN_FAILED',resource_type:null,resource_id:0,status:'FAILED',ip_address:null,error_message:null,details:'{"reason":"bad password"}'};
class FixedDate extends Date{constructor(...args){super(...(args.length?args:['2026-10-14T02:00:00Z']));}static now(){return new FixedDate().getTime();}}
function setup({prompt=()=> '90',confirm=()=>true,fetch}={}){
 const timers=[],alerts=[];const c=vm.createContext({Date:FixedDate,Intl,Headers,FormData,URLSearchParams,prompt,confirm,fetch,alert:m=>alerts.push(m),console:{log(){},error(){}},setTimeout(callback,delay){timers.push({callback,delay});},localStorage:{removeItem(){}},window:{location:{}}});loadPageScripts('index.html',c);const a=c.inventoryApp();c.app=a;a.currentUser={id:7,role:'superadmin'};return {a,c,timers,alerts};
}
const response=(status,data,headers={})=>new Response(JSON.stringify(data),{status,headers:{'Content-Type':'application/json',...headers}});
test('activity log uses the shared heading and retains its filters, actions, and audit details',()=>{
 const source=fs.readFileSync('static/index.html','utf8');
 const start=source.indexOf('<section x-show="showLogsPanel"');
 const end=source.indexOf('<section x-show="showMovementsPanel"',start);
 assert.ok(start>=0&&end>start,'Missing Activity Log panel');
 const panel=source.slice(start,end);
 assert.match(panel,/aria-labelledby="audit-heading"/,'Panel should retain its accessible title reference');
 assert.match(panel,/class="inventory-panel-heading"/,'Panel should use the shared heading layout');
 assert.match(panel,/class="inventory-panel-heading-content"/,'Title and explanatory copy should use the shared content wrapper');
 assert.match(panel,/<h3 id="audit-heading" class="inventory-panel-title">Activity log<\/h3>/,'Title should use the shared heading style');
 assert.match(panel,/<p class="inventory-panel-meta">Stock changes include recorded balances and linked movements\. Older entries retain their original details; missing historical balances cannot be reconstructed here\.<\/p>/,'Audit guidance should remain visible');
 assert.match(panel,/<form class="replenishment-toolbar" @submit\.prevent="loadActivityLogs\(\)">/,'Log filter form should remain in place');
 for(const input of ['logFilters.startDate','logFilters.endDate','logFilters.action','logFilters.status'])assert.ok(panel.includes(`x-model="${input}"`),`Missing ${input} filter`);
 assert.match(panel,/aria-label="Refresh log"/,'Refresh action should remain available');
 assert.match(panel,/@click="exportActivityLogsCSV\(\)"/,'CSV export should remain available');
 for(const state of ['x-show="loading"','x-show="!loading && !activityLogs.length && !error"','x-show="activityLogs.length"'])assert.ok(panel.includes(state),`Missing state ${state}`);
 assert.match(panel,/x-for="log in activityLogs"/,'Audit entries should remain rendered');
 assert.match(panel,/View recorded details/,'Recorded detail disclosure should remain available');
 assert.match(panel,/Raw record/,'Raw record disclosure should remain available');
});
for(const full of [false,true])test('logs preserve '+(full?'full encoded':'empty')+' query, limit, callback and loading',async()=>{
 const {a}=setup();a.error='old';if(full)a.logFilters={startDate:'2026-10-01',endDate:'2026-10-14',action:'A & B',targetUserId:'7',status:'FAILED'};const context={timezone:'Africa/Nairobi',timezone_revision:1};
 a.apiCall=async(path,opts,callback)=>{assert.equal(a.loading,true);assert.equal(a.error,'');assert.equal(path,full?'/logs/activity?start_date=2026-10-01&end_date=2026-10-14&action=A+%26+B&target_user_id=7&status=FAILED&limit=200':'/logs/activity?limit=200');assert.deepEqual(plain(opts),{});callback(context);return [actorless];};await a.loadActivityLogs();assert.equal(a.activityTimeContext,context);assert.equal(a.activityLogs[0],actorless);assert.equal(a.loading,false);
});
test('falsy target zero is omitted and failed logs clear rows while preserving context',async()=>{
 const {a}=setup();a.logFilters.targetUserId=0;const context={timezone:'UTC',timezone_revision:1};a.activityTimeContext=context;a.activityLogs=[actorless];a.apiCall=async(path)=>{assert.equal(path,'/logs/activity?limit=200');throw Error('offline');};await a.loadActivityLogs();assert.equal(a.activityLogs.length,0);assert.equal(a.activityTimeContext,context);assert.equal(a.error,'Failed to load activity logs: offline');assert.equal(a.loading,false);
});
test('actual activity navigation/form bindings and filter reset retain unreturned pending reload',async()=>{
 const {a,c}=setup();const source=fs.readFileSync('static/index.html','utf8');const button=[...source.matchAll(/@click(?:\.prevent)?="([^"]*)"/g)].map(m=>m[1]).find(e=>e==="openPanel('showLogsPanel'); loadActivityLogs()");assert.ok(button);assert.ok(source.includes('@submit.prevent="loadActivityLogs()"'));let calls=0;a.loadActivityLogs=()=>{calls++;};vm.runInContext('with(app){'+button+'}',c);assert.equal(a.showLogsPanel,true);assert.equal(calls,1);vm.runInContext('with(app){loadActivityLogs()}',c);assert.equal(calls,2);
 let release;const pending=new Promise(resolve=>release=resolve);a.logFilters.action='test';const old=a.logFilters;a.loadActivityLogs=()=>pending;assert.equal(a.clearLogFilters(),undefined);assert.notEqual(a.logFilters,old);assert.deepEqual(plain(a.logFilters),blank);release();await pending;
});
for(const fail of [false,true])test('stats '+(fail?'failure retains data/modal':'uses only date filters and opens modal'),async()=>{
 const {a}=setup();const old={count:9};a.activityStats=old;a.logFilters={startDate:'2026-10-01',endDate:'2026-10-14',action:'ignored',targetUserId:'7',status:'FAILED'};a.apiCall=async(path)=>{assert.equal(path,'/logs/activity/stats?start_date=2026-10-01&end_date=2026-10-14');if(fail)throw Error('offline');return {count:0};};await a.loadActivityStats();assert.equal(a.loading,false);assert.equal(a.showStatsModal,!fail);if(fail){assert.equal(a.activityStats,old);assert.equal(a.error,'Failed to load activity stats: offline');}else assert.equal(a.activityStats.count,0);
});
test('details preserve row reference and independent arrays/stats/filters',()=>{
 const {a}=setup();a.showLogDetails(actorless);assert.equal(a.selectedLog,actorless);assert.equal(a.showLogDetailsModal,true);a.activityLogs.push(actorless);a.activityStats.count=1;a.logFilters.action='changed';const {a:b}=setup();assert.equal(b.activityLogs.length,0);assert.deepEqual(plain(b.activityStats),{});assert.deepEqual(plain(b.logFilters),blank);assert.equal(b.selectedLog,null);
});
for(const metadata of [{timezone:'Africa/Nairobi',timezone_revision:1},{timezone:'invalid',timezone_revision:1},null])test('real metadata validation and CSV retain activity context '+JSON.stringify(metadata),async()=>{
 const {a}=setup({fetch:async(url,opts)=>{assert.equal(url,'/api/logs/activity?limit=200');assert.equal(opts.credentials,'include');return response(200,[actorless],metadata?{'X-Report-Time-Context':JSON.stringify(metadata)}:{});}});a.timezoneContext={business_timezone:'America/New_York',display_timezone:'Asia/Kathmandu',revision:8};const movement={timezone:'UTC',timezone_revision:2};a.movementTimeContext=movement;await a.loadActivityLogs();const valid=metadata?.timezone==='Africa/Nairobi';assert.deepEqual(plain(a.activityTimeContext),valid?metadata:null);assert.equal(a.movementTimeContext,movement);assert.equal(a.activityLogs[0].user_id,null);
 a.downloadCSV=function(headers,rows,name){assert.equal(this,a);assert.deepEqual(plain(headers),['Date/Time ('+(valid?'Africa/Nairobi':'Unknown')+')','User','Action','Resource Type','Resource ID','Status','IP Address','Error Message','Details']);assert.deepEqual(plain(rows),[[valid?'2026-10-12 12:00:00 UTC+03:00':'Unknown',null,'LOGIN_FAILED','-','-','FAILED','-','-','{\n  "reason": "bad password"\n}']]);assert.equal(name,'activity_logs_2026-10-14.csv');};a.exportActivityLogsCSV();
});
for(const answer of [null,''])test('cleanup prompt cancellation '+JSON.stringify(answer)+' preserves feedback/loading',async()=>{
 const prompts=[];const {a,timers}=setup({prompt(...args){prompts.push(args);return answer;},confirm(){assert.fail('no confirmation');}});a.error='old';a.successMessage='keep';a.apiCall=async()=>assert.fail('no write');await a.cleanupOldLogs();assert.deepEqual(prompts,[['Delete logs older than how many days?','90']]);assert.equal(a.error,'old');assert.equal(a.successMessage,'keep');assert.equal(a.loading,false);assert.equal(timers.length,0);
});
test('declined cleanup retains exact warning and performs no write',async()=>{
 const warnings=[];const {a,timers}=setup({confirm(m){warnings.push(m);return false;}});a.error='old';a.apiCall=async()=>assert.fail('no write');await a.cleanupOldLogs();assert.deepEqual(warnings,['Delete general logs older than 90 days? Stock audit evidence is retained. This cannot be undone.']);assert.equal(a.error,'old');assert.equal(timers.length,0);
});
for(const stage of ['success','write','reload','swallowed'])test('cleanup '+stage+' preserves raw query/feedback/timer behavior',async()=>{
 const {a,timers}=setup({prompt:()=> '90 & extra=1'});a.error='old error';a.successMessage='old success';const calls=[];
 a.apiCall=async(path,opts)=>{calls.push(path);if(opts?.method==='DELETE'){assert.equal(path,'/logs/activity/cleanup?days=90 & extra=1');assert.equal(a.loading,true);assert.equal(a.error,'old error');assert.equal(a.successMessage,'old success');if(stage==='write')throw Error('offline');return {deleted_count:0};}throw Error('reload offline');};
 if(stage!=='swallowed')a.loadActivityLogs=async function(){assert.equal(this,a);calls.push('reload');if(stage==='reload')throw Error('offline');};
 await a.cleanupOldLogs();assert.equal(a.loading,false);if(stage==='write'||stage==='reload'){assert.equal(a.error,'Failed to cleanup logs: offline');assert.equal(timers.length,0);assert.equal(a.successMessage,stage==='write'?'old success':'Deleted 0 old log entries');}else{assert.equal(a.successMessage,'Deleted 0 old log entries');assert.equal(a.error,stage==='swallowed'?'Failed to load activity logs: reload offline':'old error');assert.equal(timers[0].delay,5000);timers[0].callback();assert.equal(a.successMessage,'');}
 assert.deepEqual(calls,['/logs/activity/cleanup?days=90 & extra=1',...(stage==='write'?[]:[stage==='swallowed'?'/logs/activity?limit=200':'reload'])]);
});
for(const mode of ['initial','retry','permission','token','retry_rejected'])test('real cleanup CSRF write '+mode,async()=>{
 const calls=[];let writes=0;const {a,timers}=setup({fetch:async(url,opts)=>{assert.equal(opts.credentials,'include');calls.push(url);if(url==='/api/csrf-token')return response(mode==='token'?503:200,{csrf_token:'fresh'});assert.equal(url,'/api/logs/activity/cleanup?days=90');assert.equal(opts.method,'DELETE');assert.equal(opts.headers.get('Content-Type'),'application/json');writes++;if(mode==='permission')return response(403,{detail:'Admin required'});if(mode==='retry_rejected'||(mode==='retry'&&writes===1))return response(403,{detail:'Invalid CSRF token'});assert.equal(opts.headers.get('X-CSRF-Token'),'fresh');return response(200,{deleted_count:0});}});const user={id:7};a.currentUser=user;if(mode!=='initial'&&mode!=='token')a.csrfToken='old';a.loadActivityLogs=async()=>{};await a.cleanupOldLogs();assert.equal(a.currentUser,user);assert.equal(a.loading,false);assert.equal(writes,mode==='token'?0:mode==='retry'||mode==='retry_rejected'?2:1);assert.equal(calls.filter(u=>u==='/api/csrf-token').length,mode==='permission'?0:1);if(mode==='initial'||mode==='retry'){assert.equal(a.successMessage,'Deleted 0 old log entries');assert.equal(timers.length,1);}else{assert.match(a.error,/Failed to cleanup logs:/);assert.equal(timers.length,0);}
});
for(const mode of ['ok','error','network'])test('diagnostic direct fetch retains headers and alert '+mode,async()=>{
 const {a,alerts}=setup({fetch:async(url,opts)=>{assert.equal(url,'/api/logs/test');assert.deepEqual(plain(opts),{headers:{Authorization:'Bearer diagnostic-token','Content-Type':'application/json'}});if(mode==='network')throw Error('offline');return response(200,mode==='ok'?{status:'ok',table_exists:true,log_count:3,current_user:{name:'Tester'},can_view_logs:true}:{status:'error',error:'bad table'});}});a.token='diagnostic-token';await a.testLogging();assert.deepEqual(alerts,[mode==='ok'?'✅ Logging system OK!\n\nTable exists: true\nLog count: 3\nYou are: Tester\nCan view logs: true':mode==='error'?'❌ Error: bad table':'Test failed: offline']);
});
test('core navigation/logout retains activity and independent movement ownership',async()=>{
 const {a,c}=setup();a.showLogsPanel=true;a.openPanel('showInventoryPanel');assert.equal(a.showLogsPanel,false);a.activityTimeContext={timezone:'Africa/Nairobi',timezone_revision:1};a.movementTimeContext={timezone:'UTC',timezone_revision:2};a.apiCall=async()=>assert.fail('local logout must not request');await a.logout({localOnly:true});assert.equal(a.activityTimeContext,null);assert.equal(a.movementTimeContext,null);assert.equal(a.currentUser,null);assert.equal(c.window.location.href,'/static/index.html');
});
