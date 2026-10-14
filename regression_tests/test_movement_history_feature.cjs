const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const plain=v=>JSON.parse(JSON.stringify(v));
const blank={startDate:'',endDate:'',movementType:'',partId:'',storeId:''};
function setup(globals={}){const c=vm.createContext({URLSearchParams,...globals});vm.runInContext(fs.readFileSync('static/js/shared/features.js','utf8'),c);const file='static/js/inventory/movement-history.js';assert.ok(fs.existsSync(file),'movement history feature must exist');vm.runInContext(fs.readFileSync(file,'utf8'),c,{filename:file});return c;}
test('movement history owns exactly9 properties with independent state and live getter',()=>{
 const c=setup(),a=c.movementHistoryFeature(),b=c.movementHistoryFeature();assert.deepEqual(Object.keys(a).sort(),['movementTimeContext','showMovementsPanel','movements','movementFilters','loadMovements','clearMovementFilters','toggleMovements','exportMovementsCSV','recentActivity'].sort());assert.equal(a.movementTimeContext,null);assert.equal(a.showMovementsPanel,false);assert.deepEqual(plain(a.movementFilters),blank);assert.equal(typeof Object.getOwnPropertyDescriptor(a,'recentActivity').get,'function');a.movements.push({id:1});a.movementFilters.partId=7;assert.equal(a.recentActivity.length,1);assert.equal(b.movements.length,0);assert.deepEqual(plain(b.movementFilters),blank);
});
test('loader callback preserves composed API receiver and rows',async()=>{
 const c=setup(),context={timezone:'Africa/Nairobi',timezone_revision:1};const a=c.composeInventoryFeatures({async apiCall(path,opts,callback){assert.equal(this,a);assert.equal(path,'/movements');assert.deepEqual(plain(opts),{});callback(context);return [{id:1}];}},c.movementHistoryFeature());await a.loadMovements();assert.equal(a.movementTimeContext,context);assert.equal(a.movements[0].id,1);
});
test('export date and CSV providers use composed receiver',()=>{
 const context={timezone:'Africa/Nairobi',timezone_revision:1};const c=setup();const a=c.composeInventoryFeatures({formatBusinessInstant(value,metadata){assert.equal(this,a);assert.equal(metadata,context);return 'date:'+value;},downloadCSV(headers,rows,name){assert.equal(this,a);assert.equal(headers[0],'Date/Time (Africa/Nairobi)');assert.equal(headers[10],'Confirmed At (Africa/Nairobi)');assert.equal(rows[0][0],'date:created');assert.equal(rows[0][10],'date:completed');assert.match(name,/^movement_history_\d{4}-\d{2}-\d{2}\.csv$/);}},c.movementHistoryFeature());a.movementTimeContext=context;a.movements=[{created_at:'created',completed_at:'completed'}];a.exportMovementsCSV();
});
