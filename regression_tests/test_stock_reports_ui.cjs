const {loadPageScripts} = require('./helpers/frontend.cjs');
const {test}=require('node:test');const assert=require('node:assert/strict');const vm=require('node:vm');
const fs=require('node:fs');const path=require('node:path');
const readStatic=name=>fs.readFileSync(path.join(__dirname,'..','static',name),'utf8');
function app(){const c={console,setTimeout:()=>{},URLSearchParams,Date,Intl};vm.createContext(c);loadPageScripts('index.html',c);const a=c.inventoryApp();a.timezoneContext={business_timezone:'Africa/Nairobi',display_timezone:'Africa/Nairobi',revision:1};a.currentUser={id:3,role:'engineer'};return a;}
const result={scope:'own',totals:{events:205,quantity:300,parts:2},rows:[{movement_id:1,quantity:3}],by_part:[],by_work_order:[],limit:100,offset:0};
test('report queries include exact selected filters and reset to first page',async()=>{const a=app();a.reportForm={allDates:false,start_date:'2026-10-01',end_date:'2026-10-05',part_id:'7',store_id:'8',engineer_id:'',work_order_number:' WO-10 '};a.reportOffset=100;a.apiCall=async(p)=>{assert.match(p,/work_order_number=WO-10/);assert.match(p,/part_id=7/);assert.match(p,/offset=0/);return result;};await a.loadConsumptionReport();assert.equal(a.consumptionReport.totals.quantity,300);assert.equal(a.reportOffset,0);});
test('work-order drilldown applies the same filters and performs only GET',async()=>{const a=app();a.reportForm.allDates=true;a.apiCall=async(p,o)=>{assert.equal(o,undefined);assert.match(p,/work_order_number=WO-20/);assert.doesNotMatch(p,/start_date/);return result;};await a.openWorkOrderReport('WO-20');assert.equal(a.reportForm.work_order_number,'WO-20');assert.equal(a.showReportsPanel,true);});
test('failed report clears stale totals and prevents exporting them',async()=>{const a=app();a.consumptionReport=result;a.apiCall=async()=>{throw Error('offline');};await a.loadConsumptionReport();assert.equal(a.consumptionReport,null);assert.match(a.reportError,/offline/);});
test('invalid date range makes no request',async()=>{const a=app();a.reportForm.start_date='2026-10-06';a.reportForm.end_date='2026-10-05';let sent=false;a.apiCall=async()=>{sent=true;};await a.loadConsumptionReport();assert.equal(sent,false);assert.match(a.reportError,/date/i);});
test('pagination preserves filters and full totals',async()=>{const a=app();a.consumptionReport=result;a.reportForm.allDates=true;a.apiCall=async(p)=>{assert.match(p,/offset=100/);return {...result,offset:100};};await a.loadConsumptionReport(100);assert.equal(a.reportOffset,100);assert.equal(a.consumptionReport.totals.events,205);});
test('editing filters marks displayed report stale until refreshed',()=>{const a=app();a.consumptionReport={...result,timezone_revision:7};a.reportDirty=false;a.markReportDirty();assert.equal(a.reportDirty,true);});
test('late response after changing users does not reveal previous user history',async()=>{const a=app();a.reportForm.allDates=true;let resolve;a.apiCall=()=>new Promise(r=>resolve=r);const pending=a.loadConsumptionReport();a.currentUser={id:4,role:'engineer'};resolve(result);await pending;assert.equal(a.consumptionReport,null);});
test('CSV downloads all applied filters without page limits',async()=>{let requested,clicked=false;const c={console,setTimeout:()=>{},URLSearchParams,Date,Intl,fetch:async(url,options)=>{requested=url;assert.equal(options.credentials,'include');return {ok:true,blob:async()=>({})};},URL:{createObjectURL:()=> 'blob:test',revokeObjectURL:()=>{}},document:{body:{appendChild:()=>{}},createElement:()=>({click:()=>{clicked=true;},remove:()=>{}})}};vm.createContext(c);loadPageScripts('index.html',c);const a=c.inventoryApp();a.timezoneContext={business_timezone:'Africa/Nairobi',display_timezone:'Africa/Nairobi',revision:1};a.currentUser={id:3,role:'engineer'};a.consumptionReport={...result,timezone_revision:7};a.reportDirty=false;a.reportAppliedQuery='work_order_number=WO-20';await a.exportConsumptionReport();assert.match(requested,/consumption.csv\?work_order_number=WO-20/);const query=new URLSearchParams(requested.split('?')[1]);assert.equal(query.get('expected_timezone_revision'),'7');assert.equal(query.has('limit'),false);assert.equal(query.has('offset'),false);assert.equal(clicked,true);a.reportDirty=true;clicked=false;await a.exportConsumptionReport();assert.equal(clicked,false);});
test('opening Reports through core navigation invokes the extracted feature',async()=>{const a=app();a.reportForm.allDates=true;let calls=0;a.apiCall=async p=>{assert.match(p,/reports\/consumption/);calls++;return result;};const original=a.loadConsumptionReport;let pending;a.loadConsumptionReport=function(...args){pending=original.apply(this,args);return pending;};a.openPanel('showReportsPanel');await pending;assert.equal(a.showReportsPanel,true);assert.equal(calls,1);assert.equal(a.consumptionReport.totals.quantity,300);});
test('logout invalidates a pending report without altering another app instance',async()=>{const c={console,Intl,Date,URLSearchParams,setTimeout:()=>{},localStorage:{removeItem(){}},window:{location:{href:''}}};vm.createContext(c);loadPageScripts('index.html',c);const a=c.inventoryApp(),b=c.inventoryApp();a.timezoneContext={business_timezone:'Africa/Nairobi'};a.currentUser={id:3};a.reportForm.allDates=true;let resolve;a.apiCall=()=>new Promise(r=>resolve=r);const pending=a.loadConsumptionReport();await a.logout({localOnly:true});resolve({...result,filter_options:{parts:[{id:1}],stores:[],engineers:[]}});await pending;assert.equal(a.consumptionReport,null);assert.equal(a.reportOptions.parts.length,0);assert.equal(a.reportBusy,false);assert.equal(a.reportRequest,2);assert.equal(b.reportRequest,0);assert.equal(b.reportOptions.parts.length,0);assert.equal(c.window.location.href,'/static/index.html');});

test('consumption report tables become labeled mobile cards without changing report actions',()=>{
 const html=readStatic('index.html');
 const start=html.indexOf('<section x-show="showReportsPanel"');
 const end=html.indexOf('<section x-show="showLogsPanel"',start);
 assert.ok(start>=0&&end>start,'Missing consumption reports panel');
 const tables=[...html.slice(start,end).matchAll(/<table\b([^>]*)>([\s\S]*?)<\/table>/g)];
 assert.equal(tables.length,3,'Expected parts, work order, and event report tables');
 const labels=tables.map(([,attrs,table])=>{
  assert.match(attrs,/class="consumption-report-table"/,'Consumption result table needs mobile styling');
  return [...table.matchAll(/<td\b[^>]*data-label="([^"]+)"/g)].map(([,label])=>label);
 });
 assert.deepEqual(labels,[
  ['Part number','Description','Quantity','Events'],
  ['Work order','Quantity','Events'],
  ['Time','Part','Quantity','Source store','Recorded by','Work order','Notes']
 ]);
 assert.match(tables[1][2],/@click="openWorkOrderReport\(w\.work_order\)"/,'Work order drilldown should remain available');
 const css=readStatic('mystyle.css');
 assert.match(css,/@media\s*\(max-width:\s*600px\)[\s\S]*?\.consumption-report-table\s*,\s*\.consumption-report-table\s+tbody\s*\{[^}]*display:\s*block/s,'Report tables should switch to a mobile card layout');
 assert.match(css,/\.consumption-report-table\s+td::before\s*\{[^}]*content:\s*attr\(data-label\)/s,'Mobile report values should retain field labels');
 assert.match(css,/\.report-table-wrap\s+table\.consumption-report-table\s*\{[^}]*min-width:\s*0/s,'Consumption report cards should not keep the wide-table minimum');
});
