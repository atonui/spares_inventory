const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const {loadPageScripts}=require('./helpers/frontend.cjs');
const plain=v=>JSON.parse(JSON.stringify(v));
const equipmentBlank={equipment_name:'',make:'',model:'',serial_number:'',assigned_user_id:'',calibration_cert_number:'',calibration_authority:'',calibration_date:'',next_calibration_date:'',notes:''};
const calibrationBlank={calibration_cert_number:'',calibration_authority:'',calibration_date:'',next_calibration_date:'',notes:''};
const row={id:42,equipment_name:'Meter',make:'Maker',model:'Model',serial_number:'SN42',assigned_user_id:7,calibration_cert_number:null,calibration_authority:null,calibration_date:null,next_calibration_date:'2026-10-21',notes:null};
class FixedDate extends Date{constructor(...args){super(...(args.length?args:['2026-10-14T02:00:00Z']));}static now(){return new FixedDate().getTime();}}
function setup({confirm=()=>true,fetch,globals={}}={}){
 const timers=[];const c=vm.createContext({Date:FixedDate,Intl,Headers,FormData,URLSearchParams,fetch,confirm,console:{log(){},error(){}},setTimeout(callback,delay){timers.push({callback,delay});},...globals});
 loadPageScripts('index.html',c);const a=c.inventoryApp();c.app=a;a.currentUser={id:7,role:'superadmin'};a.timezoneContext={business_timezone:'Africa/Nairobi',display_timezone:'UTC',revision:1};return {a,c,timers};
}
const html=()=>fs.readFileSync('static/index.html','utf8');
const clicks=()=>[...html().matchAll(/@click="([^"]*)"/g)].map(m=>m[1]);
const response=(status,data)=>new Response(JSON.stringify(data),{status,headers:{'Content-Type':'application/json'}});
const cases={
 create:{method:'createEquipment',path:'/equipment',verb:'POST',message:'Equipment created successfully!',error:'Failed to create equipment: ',modal:'showEquipmentModal'},
 update:{method:'updateEquipment',path:'/equipment/42',verb:'PUT',message:'Equipment updated successfully!',error:'Failed to update equipment: ',modal:'showEquipmentModal'},
 delete:{method:'deleteEquipment',path:'/equipment/42',verb:'DELETE',message:'Equipment archived; history preserved.',error:'Failed to delete equipment: '},
 calibration:{method:'updateCalibration',path:'/equipment/42/calibrate',verb:'POST',message:'Calibration updated successfully!',error:'Failed to update calibration: ',modal:'showCalibrationModal'},
 transfer:{method:'transferEquipmentToUser',path:'/equipment/42/transfer',verb:'POST',message:'Equipment transferred successfully!',error:'Failed to transfer equipment: ',modal:'showTransferEquipmentModal'},
 setting:{method:'updateCalibrationReminderDays',path:'/settings/calibration-reminder-days?days=45',verb:'PUT',message:'Calibration reminder set to 45 days!',error:'Failed to update setting: ',modal:'showCalibrationSettingsModal'},
};
test('equipment row actions use an accessible compact menu with role-gated operations',()=>{
 const source=html();const start=source.indexOf('<!-- Equipment Management Panel -->');const end=source.indexOf('<!-- Inventory Panel -->',start);const panel=source.slice(start,end);
 const actions=panel.slice(panel.indexOf('<td data-label="Actions">'),panel.indexOf('</td>',panel.indexOf('<td data-label="Actions">')));
 const css=fs.readFileSync('static/mystyle.css','utf8');
 assert.match(actions,/<details class="stock-action-menu equipment-action-menu"/);
 assert.match(actions,/:aria-label="'Actions for ' \+ eq\.equipment_name"/);
 assert.match(actions,/<div class="stock-action-menu__items equipment-action-menu__items">/);
 for(const action of ['openCalibrationModal(eq)','openTransferEquipmentModal(eq)','viewEquipmentHistory(eq)','editEquipment(eq)','deleteEquipment(eq.id, eq.equipment_name)']) assert.ok(actions.includes(action),action);
 assert.equal((actions.match(/x-show="\['owner','admin'\]\.includes\(currentUser\?\.role\) \|\| eq\.assigned_user_id === currentUser\?\.id"/g)||[]).length,2);
 assert.equal((actions.match(/x-show="\['owner','admin'\]\.includes\(currentUser\?\.role\)"/g)||[]).length,2);
 assert.match(actions,/@click\.outside="\$el\.open = false"/);
 assert.match(actions,/@keydown\.escape\.stop\.prevent=/);
 assert.match(actions,/class="stock-action-item equipment-action-item--danger"/);
 assert.match(actions,/>Archive equipment<\/button>/);
 assert.doesNotMatch(actions,/style="background:\s*#dc3545/);
 assert.match(css,/\.equipment-action-item--danger\s*\{[^}]*color:\s*#991b1b/s);
});
test('equipment table keeps labeled fields visible in mobile cards',()=>{
 const source=html();const start=source.indexOf('<!-- Equipment Management Panel -->');const end=source.indexOf('<!-- Inventory Panel -->',start);const panel=source.slice(start,end);
 const css=fs.readFileSync('static/mystyle.css','utf8');
 assert.match(panel,/<div class="equipment-table-wrap" role="region" aria-label="Equipment records" tabindex="0">/);
 assert.match(panel,/<table class="stock-table equipment-table" aria-label="Equipment records">/);
 for(const label of ['Equipment Name','Make / model','Serial number','Assigned to','Last calibration','Next calibration','Status','Actions']) assert.ok(panel.includes(`data-label="${label}"`),label);
 assert.doesNotMatch(css,/\.equipment-table (?:th|td):nth-child\(\d+\)\s*\{\s*display:\s*none;/);
 assert.match(css,/\.equipment-table tr\s*\{[^}]*grid-template-columns:\s*minmax\(0,\s*1fr\)\s+minmax\(0,\s*1fr\)\s+44px/s);
 assert.match(css,/\.equipment-table td\[data-label="Assigned to"\]\s*\{\s*grid-area:\s*assigned;/);
 assert.match(css,/\.equipment-table td\[data-label="Next calibration"\]\s*\{\s*grid-area:\s*next;/);
 assert.match(css,/\.equipment-table \.stock-action-trigger\s*\{[^}]*min-height:\s*44px/s);
});
test('equipment panel uses the shared responsive heading and preserves summary/actions',()=>{
 const source=html();const start=source.indexOf('<!-- Equipment Management Panel -->');const end=source.indexOf('<!-- Store Types Management Panel',start);const panel=source.slice(start,end);
 const css=fs.readFileSync('static/mystyle.css','utf8');
 assert.ok(panel.includes('x-show="!loading && showEquipmentPanel"'));
 assert.ok(panel.includes('class="inventory-panel-heading"'));
 assert.ok(panel.includes('class="inventory-panel-heading-content"'));
 assert.ok(panel.includes('class="inventory-panel-title">Equipment Management</h3>'));
 assert.ok(panel.includes('class="inventory-panel-meta equipment-summary"'));
 for(const field of ['total_equipment','my_equipment','due_soon','overdue']) assert.ok(panel.includes(`equipmentStats.${field} || 0`),field);
 assert.ok(panel.includes('class="equipment-summary-due"'));
 assert.ok(panel.includes('class="equipment-summary-overdue"'));
 assert.match(css,/\.equipment-summary\s*\{[^}]*display:\s*flex;[^}]*flex-wrap:\s*wrap;/s);
 assert.ok(panel.includes('class="inventory-panel-actions"'));
 for(const action of ['downloadEquipmentTemplate()','exportEquipmentCSV()','showEquipmentModal = true','loadCalibrationSettings()','closeAllPanels()','openCalibrationModal(eq)','openTransferEquipmentModal(eq)','viewEquipmentHistory(eq)','x-for="eq in equipment"']) assert.ok(panel.includes(action),action);
 assert.equal((panel.match(/x-show="\['owner','admin'\]\.includes\(currentUser\?\.role\)"/g)||[]).length,4);
});
test('calibration table uses neutral rows and class-based status badges',()=>{
 const source=html();const start=source.indexOf('<!-- Equipment Management Panel -->');const end=source.indexOf('<!-- Store Types Management Panel',start);const panel=source.slice(start,end);
 const css=fs.readFileSync('static/mystyle.css','utf8');
 assert.match(panel,/<tr :class="getCalibrationStatus\(eq\)\.class">/);
 assert.match(panel,/<span class="wo-tag equipment-calibration-status" :class="'equipment-calibration-status--' \+ getCalibrationStatus\(eq\)\.status"\s+x-text="getCalibrationStatus\(eq\)\.text">/);
 const statusCell=panel.slice(panel.indexOf('<td data-label="Status">'),panel.indexOf('<td data-label="Actions">'));
 assert.doesNotMatch(statusCell,/:style=/,'Status colors should come from CSS classes');
 for(const status of ['overdue','urgent','soon','ok','none']) assert.match(css,new RegExp(`\\.equipment-calibration-status--${status}\\s*\\{`),status);
 for(const status of ['overdue','urgent','soon','ok']) assert.match(css,new RegExp(`\\.stock-table tr\\.${status}-cal\\s*\\{[^}]*border-left:\\s*4px solid`, 's'),`${status} row accent`);
});
function fill(a,op){a.editEquipment(row);if(op==='create')a.editingEquipment=null;if(op==='calibration')a.openCalibrationModal(row);if(op==='transfer')a.openTransferEquipmentModal(row);if(op==='setting'){a.calibrationReminderDays=45;a.showCalibrationSettingsModal=true;}}
function payload(a,op){
 if(op==='create'||op==='update'){const f=a.equipmentForm;return {equipment_name:f.equipment_name,make:f.make,model:f.model,serial_number:f.serial_number,assigned_user_id:7,calibration_cert_number:null,calibration_authority:null,calibration_date:null,next_calibration_date:'2026-10-21',notes:null};}
 if(op==='calibration')return plain(a.calibrationForm);
 if(op==='transfer')return {to_user_id:null,notes:null};
 return undefined;
}
function assertSaved(a,op){
 if(op==='create'||op==='update'){assert.deepEqual(plain(a.equipmentForm),equipmentBlank);assert.equal(a.showEquipmentModal,false);assert.equal(a.editingEquipment,null);}
 if(op==='calibration'){assert.deepEqual(plain(a.calibrationForm),calibrationBlank);assert.equal(a.selectedEquipment,null);assert.equal(a.showCalibrationModal,false);}
 if(op==='transfer'){assert.deepEqual(plain(a.transferEquipmentForm),{to_user_id:'',notes:''});assert.equal(a.selectedEquipment,null);assert.equal(a.showTransferEquipmentModal,false);}
 if(op==='setting'){assert.equal(a.showCalibrationSettingsModal,false);assert.equal(a.calibrationReminderDays,45);}
}
test('actual add/edit/cancel/submit/navigation bindings preserve equipment and shared-selection state',()=>{
 const {a,c}=setup();a.editEquipment(row);assert.equal(a.equipmentForm.calibration_cert_number,'');assert.equal(a.equipmentForm.notes,'');
 const add=clicks().find(e=>e.startsWith('editingEquipment = null; equipmentForm ='));assert.ok(add);vm.runInContext('with(app){'+add+'}',c);assert.deepEqual(plain(a.equipmentForm),equipmentBlank);assert.equal(a.editingEquipment,null);assert.equal(a.showEquipmentModal,true);
 const submit=[...html().matchAll(/@submit.prevent="([^"]*)"/g)].map(m=>m[1]).find(e=>e==='editingEquipment ? updateEquipment() : createEquipment()');assert.ok(submit);const calls=[];a.createEquipment=()=>calls.push('create');a.updateEquipment=()=>calls.push('update');vm.runInContext('with(app){'+submit+'}',c);a.editEquipment(row);vm.runInContext('with(app){'+submit+'}',c);assert.deepEqual(calls,['create','update']);
 for(const expression of ['showEquipmentModal = false; editingEquipment = null;','showCalibrationModal = false; selectedEquipment = null;','showTransferEquipmentModal = false; selectedEquipment = null;','showEquipmentHistoryModal = false; selectedEquipment = null;']){assert.ok(clicks().includes(expression));vm.runInContext('with(app){'+expression+'}',c);}
 a.openCalibrationModal(row);a.openTransferEquipmentModal({...row,id:43});assert.equal(a.selectedEquipment.id,43);assert.equal(a.showCalibrationModal,true);assert.deepEqual(plain(a.transferEquipmentForm),{to_user_id:'',notes:''});const form=a.calibrationForm;a.openPanel('showEquipmentPanel');assert.equal(a.showCalibrationModal,false);assert.equal(a.showTransferEquipmentModal,false);assert.equal(a.selectedEquipment.id,43);assert.equal(a.calibrationForm,form);
});
for(const [op,config] of Object.entries(cases))test(op+' preserves payload, reset-before-refresh and feedback timer',async()=>{
 const calls=[];const {a,timers}=setup({confirm(m){calls.push(m);return true;}});fill(a,op);const body=payload(a,op),user=a.currentUser;
 a.apiCall=async(path,opts)=>{assert.equal(a.loading,true);assert.equal(a.error,'');calls.push([path,opts.method,opts.body?JSON.parse(opts.body):undefined]);return {message:'ignored'};};
 a.loadEquipment=async()=>{assertSaved(a,op);assert.equal(timers.length,0);calls.push('equipment');};a.loadEquipmentStats=async()=>{assert.equal(timers.length,0);calls.push('stats');};
 await a[config.method](42,'Meter');assert.deepEqual(calls,[...(op==='delete'?['Archive equipment Meter? It will leave active lists, keep its history, and can be restored by an admin.']:[]),[config.path,config.verb,body],...(op==='setting'?[]:['equipment','stats'])]);assertSaved(a,op);assert.equal(a.currentUser,user);assert.equal(a.successMessage,config.message);assert.equal(a.loading,false);assert.equal(timers[0].delay,3000);timers[0].callback();assert.equal(a.successMessage,'');
});
for(const [op,config] of Object.entries(cases))for(const stage of (op==='setting'?['write']:['write','equipment','stats']))test(op+' failure at '+stage+' preserves pre-write or saved state',async()=>{
 const {a,timers}=setup();fill(a,op);const form=a.equipmentForm,cal=a.calibrationForm,transfer=a.transferEquipmentForm,selected=a.selectedEquipment;const calls=[];
 a.apiCall=async()=>{calls.push('write');if(stage==='write')throw Error('offline');return {};};a.loadEquipment=async()=>{calls.push('equipment');if(stage==='equipment')throw Error('offline');};a.loadEquipmentStats=async()=>{calls.push('stats');if(stage==='stats')throw Error('offline');};
 await a[config.method](42,'Meter');assert.equal(a.error,config.error+'offline');assert.equal(a.loading,false);assert.equal(timers.length,0);
 if(stage==='write'||op==='delete'){assert.equal(a.equipmentForm,form);assert.equal(a.calibrationForm,cal);assert.equal(a.transferEquipmentForm,transfer);assert.equal(a.selectedEquipment,selected);if(config.modal)assert.equal(a[config.modal],true);}else assertSaved(a,op);
 const order=['write','equipment','stats'];assert.deepEqual(calls,order.slice(0,order.indexOf(stage)+1));
});
test('declined archive retains selection, forms and feedback',async()=>{
 const {a,timers}=setup({confirm:()=>false});a.selectedEquipment=row;a.error='old';a.successMessage='keep';a.apiCall=async()=>assert.fail('no mutation');await a.deleteEquipment(42,'Meter');assert.equal(a.selectedEquipment,row);assert.equal(a.error,'old');assert.equal(a.successMessage,'keep');assert.equal(timers.length,0);
});
for(const op of ['create','update'])test(op+' retains populated optional fields and raw identity/date strings',async()=>{
 const {a}=setup();fill(a,op);a.equipmentForm={equipment_name:' Meter ',make:' Maker ',model:' Model ',serial_number:' SN ',assigned_user_id:'9',calibration_cert_number:' CERT ',calibration_authority:' Lab ',calibration_date:'2026-10-01',next_calibration_date:'2027-10-01',notes:' Notes '};let body;a.apiCall=async(p,o)=>{body=JSON.parse(o.body);return {};};a.loadEquipment=async()=>{};a.loadEquipmentStats=async()=>{};await a[cases[op].method]();assert.deepEqual(body,{equipment_name:' Meter ',make:' Maker ',model:' Model ',serial_number:' SN ',assigned_user_id:9,calibration_cert_number:' CERT ',calibration_authority:' Lab ',calibration_date:'2026-10-01',next_calibration_date:'2027-10-01',notes:' Notes '});
});
test('calibration opener uses actual business date and blanks unavailable timezone; transfer retains raw notes/integer target',async()=>{
 const {a}=setup();a.openCalibrationModal(row);assert.equal(a.calibrationForm.calibration_date,'2026-10-14');assert.equal(a.calibrationForm.next_calibration_date,'2026-10-21');a.timezoneContext=null;a.openCalibrationModal(row);assert.equal(a.calibrationForm.calibration_date,'');a.openTransferEquipmentModal(row);a.transferEquipmentForm={to_user_id:'9',notes:' untrimmed '};let body;a.apiCall=async(p,o)=>{body=JSON.parse(o.body);return {};};a.loadEquipment=async()=>{};a.loadEquipmentStats=async()=>{};await a.transferEquipmentToUser();assert.deepEqual(body,{to_user_id:9,notes:' untrimmed '});
});
for(const [method,field,prefix] of [['loadEquipment','equipment','Failed to load equipment: '],['loadEquipmentStats','equipmentStats','Failed to load equipment stats: '],['loadCalibrationSettings','calibrationReminderDays','Failed to load calibration settings: ']])test(method+' catches failure and retains prior data',async()=>{
 const {a}=setup();const prior=field==='calibrationReminderDays'?45:field==='equipment'?[row]:{count:1};a[field]=prior;a.apiCall=async()=>{throw Error('offline');};await a[method]();assert.equal(a[field],prior);assert.equal(a.error,prefix+'offline');
});
test('successful mutation preserves swallowed equipment refresh failure and schedules timer',async()=>{
 const {a,timers}=setup();fill(a,'update');a.equipment=[row];a.equipmentStats={count:1};a.apiCall=async(p,o)=>{if(o)return {};throw Error('offline');};await a.updateEquipment();assertSaved(a,'update');assert.equal(a.equipment[0],row);assert.equal(a.equipmentStats.count,1);assert.equal(a.error,'Failed to load equipment stats: offline');assert.equal(a.successMessage,'Equipment updated successfully!');assert.equal(timers[0].delay,3000);assert.equal(a.loading,false);
});
for(const fail of [false,true])test('history '+(fail?'failure retains old rows/modal and new selection':'success replaces rows and opens modal'),async()=>{
 const {a}=setup();const old=[{id:1}];a.equipmentHistory=old;a.apiCall=async(p)=>{assert.equal(p,'/equipment/42/history');assert.equal(a.selectedEquipment,row);assert.equal(a.loading,true);if(fail)throw Error('offline');return [{id:2}];};await a.viewEquipmentHistory(row);assert.equal(a.selectedEquipment,row);assert.equal(a.loading,false);if(fail){assert.equal(a.equipmentHistory,old);assert.equal(a.showEquipmentHistoryModal,false);assert.equal(a.error,'Failed to load equipment history: offline');}else{assert.equal(a.equipmentHistory[0].id,2);assert.equal(a.showEquipmentHistoryModal,true);}
});
test('real date status/getter boundaries remain live and threshold semantics distinct',()=>{
 const {a}=setup();const fixtures=[[null,'none','Not set'],['invalid','none','Unknown'],['2026-10-13','overdue','Overdue by 1 days'],['2026-10-14','urgent','Due in 0 days'],['2026-10-21','urgent','Due in 7 days'],['2026-10-22','soon','Due in 8 days'],['2026-11-13','soon','Due in 30 days'],['2026-11-14','ok','Due in 31 days']];
 for(const [date,status,text] of fixtures){const actual=a.getCalibrationStatus({next_calibration_date:date});assert.equal(actual.status,status);assert.equal(actual.text,text);}
 a.equipment=fixtures.map(([date],id)=>({id,next_calibration_date:date,assigned_user_id:id===3?7:'7'}));assert.equal(a.myEquipment.length,1);assert.deepEqual(Array.from(a.overdueEquipment,e=>e.id),[2]);a.calibrationReminderDays=7;assert.deepEqual(Array.from(a.dueSoonEquipment,e=>e.id),[3,4]);a.calibrationReminderDays=31;assert.equal(a.dueSoonEquipment.length,5);a.currentUser.id='7';assert.equal(a.myEquipment.length,7);a.timezoneContext=null;assert.equal(a.dueSoonEquipment.length,0);assert.equal(a.overdueEquipment.length,0);assert.equal(a.getCalibrationStatus({next_calibration_date:'2026-10-21'}).text,'Unknown');
});
for(const mode of ['initial','retry','permission','token','retry_rejected'])test('real equipment JSON/CSRF mutation '+mode,async()=>{
 let writes=0;const calls=[];const {a,timers}=setup({fetch:async(url,opts)=>{assert.equal(opts.credentials,'include');calls.push(url);if(url==='/api/csrf-token')return response(mode==='token'?503:200,{csrf_token:'fresh'});assert.equal(url,'/api/equipment/42/transfer');assert.equal(opts.headers.get('Content-Type'),'application/json');assert.deepEqual(JSON.parse(opts.body),{to_user_id:9,notes:' raw '});writes++;if(mode==='permission')return response(403,{detail:'Admin required'});if(mode==='retry_rejected'||(mode==='retry'&&writes===1))return response(403,{detail:'Invalid CSRF token'});assert.equal(opts.headers.get('X-CSRF-Token'),'fresh');return response(200,{});}});fill(a,'transfer');a.transferEquipmentForm={to_user_id:'9',notes:' raw '};const form=a.transferEquipmentForm;if(mode!=='initial'&&mode!=='token')a.csrfToken='old';a.loadEquipment=async()=>{};a.loadEquipmentStats=async()=>{};await a.transferEquipmentToUser();if(mode==='initial'||mode==='retry'){assertSaved(a,'transfer');assert.equal(timers.length,1);}else{assert.equal(a.transferEquipmentForm,form);assert.equal(a.selectedEquipment,row);assert.equal(timers.length,0);}assert.equal(writes,mode==='token'?0:mode==='retry'||mode==='retry_rejected'?2:1);assert.equal(calls.filter(u=>u==='/api/csrf-token').length,mode==='permission'?0:1);
});
test('equipment export preserves exact headers/row fallback/UTC filename and receiver',()=>{
 const {a}=setup();a.equipment=[{...row,days_until_calibration:0}];a.downloadCSV=function(headers,rows,name){assert.equal(this,a);assert.deepEqual(plain(headers),['Equipment Name','Make','Model','Serial Number','Assigned To','Calibration Cert','Calibration Authority','Calibration Date','Next Calibration','Days Until Due','Status']);assert.deepEqual(plain(rows),[['Meter','Maker','Model','SN42','Unassigned','-','-','-','2026-10-21','-','Due in 7 days']]);assert.equal(name,'equipment_2026-10-14.csv');};a.exportEquipmentCSV();
});
test('equipment template preserves exact CSV/Blob/URL/anchor lifecycle',async()=>{
 let blob,clicked=false;const anchor={click(){clicked=true;}};const {a}=setup({globals:{Blob,URL:{createObjectURL(b){blob=b;return 'blob:template';},revokeObjectURL(){assert.fail('no added revoke');}},document:{createElement(tag){assert.equal(tag,'a');return anchor;}}}});a.downloadEquipmentTemplate();assert.equal(blob.type,'text/csv');assert.equal(await blob.text(),'equipment_name,make,model,serial_number,assigned_user_email,calibration_cert_number,calibration_authority,calibration_date,next_calibration_date,notes\nSample Equipment,Sample Make,Sample Model,SN-12345,user@example.com,CERT-001,Lab Name,2024-01-01,2025-01-01,Sample notes');assert.equal(anchor.href,'blob:template');assert.equal(anchor.download,'equipment_import_template.csv');assert.equal(clicked,true);
});
test('core startup/dashboard invokes moved loaders and independent apps retain fresh equipment state',async()=>{
 const {a}=setup();const calls=[];for(const name of ['loadTimezoneContext','loadStats','loadStores','loadParts','loadInventory','loadMovements','loadPendingTransfers','loadEquipment','loadEquipmentStats','loadCalibrationSettings','loadStoreTypes','loadUsers'])a[name]=async function(){assert.equal(this,a);calls.push(name);};await a.loadAllData();assert.ok(calls.includes('loadEquipment'));assert.ok(calls.includes('loadEquipmentStats'));assert.ok(calls.includes('loadCalibrationSettings'));calls.length=0;await a.refreshDashboard();assert.deepEqual(calls,['loadStats','loadEquipmentStats']);a.equipment.push(row);a.calibrationForm.notes='changed';const {a:b}=setup();assert.equal(b.equipment.length,0);assert.equal(b.calibrationForm.notes,'');
});
test('blank equipment assignment becomes null while raw calibration form is submitted unchanged',async()=>{
 const {a}=setup();fill(a,'create');a.equipmentForm.assigned_user_id='';let body;a.apiCall=async(p,o)=>{body=JSON.parse(o.body);return {};};a.loadEquipment=async()=>{};a.loadEquipmentStats=async()=>{};await a.createEquipment();assert.equal(body.assigned_user_id,null);
 a.openCalibrationModal(row);a.calibrationForm={calibration_cert_number:' CERT ',calibration_authority:' Lab ',calibration_date:'2026-10-01',next_calibration_date:'2027-10-01',notes:' raw notes '};const expected=plain(a.calibrationForm);await a.updateCalibration();assert.deepEqual(body,expected);
});
test('actual calibration/transfer/settings submit expressions invoke existing methods',()=>{
 const {a,c}=setup();const expressions=[...html().matchAll(/@submit.prevent="([^"]*)"/g)].map(m=>m[1]);const calls=[];
 for(const name of ['updateCalibration','transferEquipmentToUser','updateCalibrationReminderDays']){assert.ok(expressions.includes(name+'()'));a[name]=()=>calls.push(name);vm.runInContext('with(app){'+name+'()}',c);}assert.deepEqual(calls,['updateCalibration','transferEquipmentToUser','updateCalibrationReminderDays']);
});
test('history failure preserves an already-open history modal and its previous rows',async()=>{
 const {a}=setup();a.showEquipmentHistoryModal=true;const prior=[{id:1}];a.equipmentHistory=prior;a.apiCall=async()=>{throw Error('offline');};await a.viewEquipmentHistory(row);assert.equal(a.showEquipmentHistoryModal,true);assert.equal(a.equipmentHistory,prior);assert.equal(a.selectedEquipment,row);
});
