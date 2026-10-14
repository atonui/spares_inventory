const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const plain=v=>JSON.parse(JSON.stringify(v));
const blank={startDate:'',endDate:'',action:'',targetUserId:'',status:''};
function setup(globals={}){const c=vm.createContext({URLSearchParams,...globals});vm.runInContext(fs.readFileSync('static/js/shared/features.js','utf8'),c);const file='static/js/inventory/activity-logs.js';assert.ok(fs.existsSync(file),'activity logs feature must exist');vm.runInContext(fs.readFileSync(file,'utf8'),c,{filename:file});return c;}
test('activity logs own exactly16 properties with independent arrays/stats/filters',()=>{
 const c=setup(),a=c.activityLogsFeature(),b=c.activityLogsFeature();assert.deepEqual(Object.keys(a).sort(),['activityTimeContext','showLogsPanel','showStatsModal','showLogDetailsModal','activityLogs','activityStats','selectedLog','logFilters','formatAuditDetails','loadActivityLogs','testLogging','loadActivityStats','clearLogFilters','showLogDetails','cleanupOldLogs','exportActivityLogsCSV'].sort());assert.deepEqual(plain(a.logFilters),blank);assert.equal(a.activityTimeContext,null);assert.equal(a.selectedLog,null);for(const key of ['showLogsPanel','showStatsModal','showLogDetailsModal'])assert.equal(a[key],false);a.activityLogs.push({id:1});a.activityStats.count=1;a.logFilters.action='test';assert.equal(b.activityLogs.length,0);assert.deepEqual(plain(b.activityStats),{});assert.deepEqual(plain(b.logFilters),blank);
});
test('activity loader retains composed API callback receiver',async()=>{
 const c=setup(),context={timezone:'Africa/Nairobi',timezone_revision:1};const a=c.composeInventoryFeatures({loading:false,error:'old',async apiCall(path,opts,callback){assert.equal(this,a);assert.equal(a.loading,true);assert.equal(a.error,'');assert.equal(path,'/logs/activity?limit=200');callback(context);return [{id:1,user_id:null}];}},c.activityLogsFeature());await a.loadActivityLogs();assert.equal(a.activityTimeContext,context);assert.equal(a.activityLogs[0].user_id,null);assert.equal(a.loading,false);
});
test('statistics provider and audit/export calls retain composed receiver',async()=>{
 const c=setup({formatStockAuditDetails:raw=>'formatted:'+raw});const a=c.composeInventoryFeatures({async apiCall(path){assert.equal(this,a);assert.equal(path,'/logs/activity/stats');return {count:1};},formatBusinessInstant(value,context){assert.equal(this,a);assert.equal(context,a.activityTimeContext);return 'date:'+value;},downloadCSV(headers,rows,name){assert.equal(this,a);assert.equal(headers[0],'Date/Time (Unknown)');assert.equal(rows[0][0],'date:instant');assert.equal(rows[0][8],'formatted:details');assert.match(name,/^activity_logs_\d{4}-\d{2}-\d{2}\.csv$/);}},c.activityLogsFeature());await a.loadActivityStats();assert.equal(a.showStatsModal,true);a.activityLogs=[{created_at:'instant',details:'details'}];a.exportActivityLogsCSV();
});
test('cleanup retains composed write/reload receiver and timer',async()=>{
 const c=setup({prompt:()=> '90',confirm:()=>true,setTimeout(fn,delay){assert.equal(delay,5000);}});const a=c.composeInventoryFeatures({loading:false,async apiCall(path,opts){assert.equal(this,a);assert.equal(path,'/logs/activity/cleanup?days=90');assert.equal(opts.method,'DELETE');return {deleted_count:0};}},c.activityLogsFeature());a.loadActivityLogs=async function(){assert.equal(this,a);};await a.cleanupOldLogs();assert.equal(a.successMessage,'Deleted 0 old log entries');assert.equal(a.loading,false);
});
