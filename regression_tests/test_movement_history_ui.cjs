const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const {loadPageScripts}=require('./helpers/frontend.cjs');
const plain=v=>JSON.parse(JSON.stringify(v));
const blank={startDate:'',endDate:'',movementType:'',partId:'',storeId:''};
test('movement history navigation has a rendered panel with filters and rows',()=>{
 const html=fs.readFileSync('static/index.html','utf8');
 assert.match(html,/<section[^>]*x-show="showMovementsPanel"/);
 assert.match(html,/<section[^>]*class="controls movement-history-panel"/);
 assert.match(html,/x-model="movementFilters\.startDate"/);
 assert.match(html,/x-model="movementFilters\.endDate"/);
 assert.match(html,/x-model="movementFilters\.movementType"/);
 assert.match(html,/x-model="movementFilters\.partId"/);
 assert.match(html,/x-model="movementFilters\.storeId"/);
 assert.match(html,/x-for="movement in movements/);
 const css=fs.readFileSync('static/mystyle.css','utf8');
 const mobileCss=css.slice(css.indexOf('@media (max-width: 768px)'));
 assert.match(mobileCss,/\.movement-history-panel \.movement-history-toolbar input\[type="date"\]\s*\{[^}]*box-sizing:\s*border-box;[^}]*width:\s*100%;[^}]*min-width:\s*0;/);
});
const movement={id:1,created_at:'2026-10-12T09:00:00Z',movement_type:'TRANSFER',part_number:'P-1',quantity:0,from_store_name:null,to_store_name:'Site',work_order:null,created_by_name:'Engineer',transfer_status:'RECEIVED',completed_by_name:'Receiver',completed_at:'2026-10-12T10:00:00Z'};
class FixedDate extends Date{constructor(...args){super(...(args.length?args:['2026-10-14T02:00:00Z']));}static now(){return new FixedDate().getTime();}}
function setup({fetch,globals={}}={}){const c=vm.createContext({Date:FixedDate,Intl,Headers,FormData,URLSearchParams,fetch,console:{log(){},error(){}},setTimeout(){},localStorage:{removeItem(){}},window:{location:{}},...globals});loadPageScripts('index.html',c);const a=c.inventoryApp();c.app=a;a.currentUser={id:7,role:'superadmin',name:'Tester',email:'tester@example.test'};return {a,c};}
const response=(status,data,headers={})=>new Response(JSON.stringify(data),{status,headers:{'Content-Type':'application/json',...headers}});
for(const full of [false,true])test('movement '+(full?'encoded full':'blank')+' query has exact order/no added limit',async()=>{
 const {a}=setup();a.loading=true;a.error='keep error';a.successMessage='keep success';if(full)a.movementFilters={startDate:'2026-10-01',endDate:'2026-10-14',movementType:'A & B',partId:'7',storeId:'9'};const metadata={timezone:'Africa/Nairobi',timezone_revision:1};a.apiCall=async(path,opts,callback)=>{assert.equal(path,full?'/movements?start_date=2026-10-01&end_date=2026-10-14&movement_type=A+%26+B&part_id=7&store_id=9':'/movements');assert.deepEqual(plain(opts),{});callback(metadata);return [movement];};await a.loadMovements();assert.equal(a.movements[0],movement);assert.equal(a.movementTimeContext,metadata);assert.equal(a.loading,true);assert.equal(a.error,'keep error');assert.equal(a.successMessage,'keep success');
});
for(const id of [0,'0'])test('ID truthiness preserves '+JSON.stringify(id),async()=>{
 const {a}=setup();a.movementFilters.partId=id;a.movementFilters.storeId=id;a.apiCall=async(path)=>{assert.equal(path,id===0?'/movements':'/movements?part_id=0&store_id=0');return [];};await a.loadMovements();
});
test('movement rejection propagates retaining prior rows/context/loading/feedback',async()=>{
 const {a}=setup();const rows=[movement],context={timezone:'UTC',timezone_revision:2};a.movements=rows;a.movementTimeContext=context;a.loading=true;a.error='keep';a.apiCall=async()=>{throw Error('offline');};await assert.rejects(a.loadMovements(),/offline/);assert.equal(a.movements,rows);assert.equal(a.movementTimeContext,context);assert.equal(a.loading,true);assert.equal(a.error,'keep');
});
test('actual navigation/apply/clear/export buttons call shipped methods; reset allocates and does not return pending reload',async()=>{
 const {a,c}=setup();const expressions=[...fs.readFileSync('static/index.html','utf8').matchAll(/@click="([^"]*)"/g)].map(m=>m[1]);const nav="openPanel('showMovementsPanel'); loadMovements()";assert.ok(expressions.includes(nav));let calls=0;a.loadMovements=()=>{calls++;};vm.runInContext('with(app){'+nav+'}',c);assert.equal(a.showMovementsPanel,true);assert.equal(calls,1);assert.ok(expressions.includes('loadMovements()'));vm.runInContext('with(app){loadMovements()}',c);assert.equal(calls,2);assert.ok(expressions.includes('exportMovementsCSV()'));a.exportMovementsCSV=()=>{calls++;};vm.runInContext('with(app){exportMovementsCSV()}',c);assert.equal(calls,3);
 let release;const pending=new Promise(resolve=>release=resolve);a.loadMovements=()=>pending;a.movementFilters.partId=7;const old=a.movementFilters;assert.ok(expressions.includes('clearMovementFilters()'));assert.equal(a.clearMovementFilters(),undefined);assert.notEqual(a.movementFilters,old);assert.deepEqual(plain(a.movementFilters),blank);release();await pending;
});
test('toggle opening waits for load, closing performs no request',async()=>{
 const {a}=setup();let release,calls=0;const pending=new Promise(resolve=>release=resolve);a.loadMovements=()=>{calls++;return pending;};let finished=false;const result=a.toggleMovements().then(()=>finished=true);assert.equal(a.showMovementsPanel,true);await Promise.resolve();assert.equal(finished,false);release();await result;assert.equal(finished,true);await a.toggleMovements();assert.equal(a.showMovementsPanel,false);assert.equal(calls,1);
});
test('toggle rejection propagates and leaves the already-open panel open',async()=>{
 const {a}=setup();a.loadMovements=async()=>{throw Error('offline');};await assert.rejects(a.toggleMovements(),/offline/);assert.equal(a.showMovementsPanel,true);
});
test('recentActivity is a live first20 slice in existing order',()=>{
 const {a}=setup();a.movements=Array.from({length:25},(_,id)=>({id:25-id}));assert.deepEqual(Array.from(a.recentActivity,m=>m.id),Array.from({length:20},(_,i)=>25-i));const slice=a.recentActivity;assert.notEqual(slice,a.movements);slice.pop();assert.equal(a.movements.length,25);a.movements.unshift({id:99});assert.equal(a.recentActivity[0].id,99);
});
for(const metadata of [{timezone:'Africa/Nairobi',timezone_revision:1},{timezone:'invalid',timezone_revision:1},null])test('real metadata/CSV timestamp pairing '+JSON.stringify(metadata),async()=>{
 const {a}=setup({fetch:async(url,opts)=>{assert.equal(url,'/api/movements');assert.equal(opts.credentials,'include');return response(200,[movement,{...movement,id:2,transfer_status:null,completed_by_name:null,completed_at:null}],metadata?{'X-Report-Time-Context':JSON.stringify(metadata)}:{});}});const activity={timezone:'UTC',timezone_revision:2};a.activityTimeContext=activity;a.timezoneContext={business_timezone:'America/New_York',display_timezone:'Asia/Kathmandu',revision:3};await a.loadMovements();const valid=metadata?.timezone==='Africa/Nairobi';assert.deepEqual(plain(a.movementTimeContext),valid?metadata:null);assert.equal(a.activityTimeContext,activity);
 a.downloadCSV=function(headers,rows,name){assert.equal(this,a);const zone=valid?'Africa/Nairobi':'Unknown';assert.deepEqual(plain(headers),['Date/Time ('+zone+')','Type','Part Number','Quantity','From Store','To Store','Work Order','Created By','Transfer Status','Confirmed By','Confirmed At ('+zone+')']);assert.deepEqual(plain(rows),[[valid?'2026-10-12 12:00:00 UTC+03:00':'Unknown','TRANSFER','P-1',0,'-','Site','-','Engineer','RECEIVED','Receiver',valid?'2026-10-12 13:00:00 UTC+03:00':'Unknown'],[valid?'2026-10-12 12:00:00 UTC+03:00':'Unknown','TRANSFER','P-1',0,'-','Site','-','Engineer','','','']]);assert.equal(name,'movement_history_2026-10-14.csv');};a.exportMovementsCSV();
});
test('comprehensive export consumes composed movement rows/context with existing browser lifecycle',async()=>{
 let blob,revoked=false,clicked=false;const link={style:{},click(){clicked=true;}};const {a}=setup({globals:{Blob,URL:{createObjectURL(b){blob=b;return 'blob:report';},revokeObjectURL(url){assert.equal(url,'blob:report');revoked=true;}},document:{createElement(tag){assert.equal(tag,'a');return link;},body:{appendChild(el){assert.equal(el,link);},removeChild(el){assert.equal(el,link);}}}}});a.movementTimeContext={timezone:'Africa/Nairobi',timezone_revision:1};a.activityTimeContext={timezone:'UTC',timezone_revision:2};a.movements=[movement];a.exportComprehensiveReport();const text=await blob.text();assert.match(text,/Generated \(Africa\/Nairobi\): 2026-10-14 05:00:00 UTC\+03:00/);assert.ok(text.includes('"2026-10-12 12:00:00 UTC+03:00",TRANSFER,P-1,0,"-","Site","-","Engineer","RECEIVED","Receiver","2026-10-12 13:00:00 UTC+03:00"'));assert.equal(link.download,'comprehensive_report_2026-10-14.csv');assert.equal(clicked,true);assert.equal(revoked,true);
});
test('core startup/navigation/logout and independent state preserve movement ownership',async()=>{
 const {a,c}=setup();for(const name of ['loadTimezoneContext','loadStats','loadStores','loadParts','loadInventory','loadPendingTransfers','loadEquipment','loadEquipmentStats','loadCalibrationSettings','loadStoreTypes','loadUsers'])a[name]=async()=>{};a.apiCall=async(path)=>{assert.equal(path,'/movements');return [movement];};await a.loadAllData();assert.equal(a.movements[0],movement);a.showMovementsPanel=true;a.openPanel('showUsersPanel');assert.equal(a.showMovementsPanel,false);a.movementFilters.partId=7;const {a:b}=setup();assert.equal(b.movements.length,0);assert.deepEqual(plain(b.movementFilters),blank);a.movementTimeContext={timezone:'UTC',timezone_revision:1};await a.logout({localOnly:true});assert.equal(a.movementTimeContext,null);assert.equal(c.window.location.href,'/static/index.html');
});
