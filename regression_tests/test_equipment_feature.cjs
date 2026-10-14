const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const plain=v=>JSON.parse(JSON.stringify(v));
function setup(globals={}){
 const c=vm.createContext(globals);vm.runInContext(fs.readFileSync('static/js/shared/features.js','utf8'),c);
 const file='static/js/inventory/equipment.js';assert.ok(fs.existsSync(file),'equipment feature must exist');vm.runInContext(fs.readFileSync(file,'utf8'),c,{filename:file});return c;
}
const states=['equipment','equipmentStats','equipmentForm','calibrationForm','transferEquipmentForm','editingEquipment','selectedEquipment','equipmentHistory','calibrationReminderDays','showEquipmentModal','showCalibrationModal','showTransferEquipmentModal','showEquipmentPanel','showEquipmentHistoryModal','showCalibrationSettingsModal'];
const methods=['loadEquipment','loadEquipmentStats','loadCalibrationSettings','createEquipment','editEquipment','updateEquipment','deleteEquipment','openCalibrationModal','updateCalibration','openTransferEquipmentModal','transferEquipmentToUser','viewEquipmentHistory','updateCalibrationReminderDays','getCalibrationStatus','exportEquipmentCSV','downloadEquipmentTemplate'];
test('equipment owns exactly34 properties with fresh defaults/getter descriptors',()=>{
 const c=setup(),a=c.equipmentFeature(),b=c.equipmentFeature();assert.deepEqual(Object.keys(a).sort(),[...states,...methods,'myEquipment','dueSoonEquipment','overdueEquipment'].sort());
 assert.equal(a.calibrationReminderDays,30);for(const key of ['editingEquipment','selectedEquipment'])assert.equal(a[key],null);
 for(const key of states.filter(k=>k.startsWith('show')))assert.equal(a[key],false);
 for(const key of ['equipment','equipmentHistory']){assert.deepEqual(plain(a[key]),[]);a[key].push({id:1});assert.equal(b[key].length,0);}
 for(const key of ['equipmentForm','calibrationForm','transferEquipmentForm','equipmentStats']){assert.notEqual(a[key],b[key]);for(const value of Object.values(a[key]))assert.equal(value,'');a[key].changed=true;assert.equal(b[key].changed,undefined);}
 for(const key of ['myEquipment','dueSoonEquipment','overdueEquipment'])assert.equal(typeof Object.getOwnPropertyDescriptor(a,key).get,'function');
});
for(const [name,path,result,field] of [['loadEquipment','/equipment?show_all=true',[{id:1}],'equipment'],['loadEquipmentStats','/equipment/statistics',{count:1},'equipmentStats'],['loadCalibrationSettings','/settings/calibration-reminder-days',{days:45},'calibrationReminderDays']])test(name+' uses composed API receiver',async()=>{
 const c=setup(),a=c.composeInventoryFeatures({async apiCall(p){assert.equal(this,a);assert.equal(p,path);return result;}},c.equipmentFeature());await a[name]();assert.deepEqual(plain(a[field]),field==='calibrationReminderDays'?45:result);
});
test('equipment derived views and CSV provider use composed core receiver',()=>{
 const c=setup({InventoryTime:{daysBetween(today,date){assert.equal(today,'2026-10-14');return date==='due'?0:-1;}}});
 const a=c.composeInventoryFeatures({currentUser:{id:7},businessToday(){assert.equal(this,a);return '2026-10-14';},downloadCSV(headers,rows,name){assert.equal(this,a);assert.equal(headers[0],'Equipment Name');assert.equal(rows.length,2);assert.match(name,/^equipment_\d{4}-\d{2}-\d{2}\.csv$/);}},c.equipmentFeature());
 a.equipment=[{assigned_user_id:7,next_calibration_date:'due'},{assigned_user_id:8,next_calibration_date:'overdue'}];assert.equal(a.myEquipment.length,1);assert.equal(a.dueSoonEquipment.length,1);assert.equal(a.overdueEquipment.length,1);a.currentUser.id=8;assert.equal(a.myEquipment[0].assigned_user_id,8);a.exportEquipmentCSV();
});
for(const op of ['createEquipment','updateEquipment','deleteEquipment','updateCalibration','transferEquipmentToUser','updateCalibrationReminderDays'])test(op+' retains composed API/refresh receivers',async()=>{
 const calls=[];const c=setup({confirm:()=>true,setTimeout(fn,delay){calls.push(['timer',delay]);}});
 const a=c.composeInventoryFeatures({loading:false,error:'',successMessage:'',async apiCall(path,opts){assert.equal(this,a);calls.push([path,opts.method]);return {};}},c.equipmentFeature());
 a.editingEquipment=42;a.selectedEquipment={id:42};a.loadEquipment=async function(){assert.equal(this,a);calls.push('equipment');};a.loadEquipmentStats=async function(){assert.equal(this,a);calls.push('stats');};
 await a[op](42,'Meter');assert.equal(calls.length,op==='updateCalibrationReminderDays'?2:4);assert.deepEqual(calls.at(-1),['timer',3000]);assert.equal(a.loading,false);
});
