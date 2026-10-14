const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const plain = value => JSON.parse(JSON.stringify(value));
const initial = {type_code:'',type_name:'',description:'',display_order:0,is_active:true};
const saved = {type_code:'',type_name:'',description:'',display_order:0};
function setup(globals = {}) {
    const c = vm.createContext(globals);
    vm.runInContext(fs.readFileSync('static/js/shared/features.js', 'utf8'), c);
    const filename = 'static/js/inventory/store-types-admin.js';
    assert.ok(fs.existsSync(filename), 'store types admin feature must exist');
    vm.runInContext(fs.readFileSync(filename, 'utf8'), c, {filename});
    return c;
}
test('store type administration owns exactly seven properties and independent forms', () => {
    const c = setup();
    const a = c.storeTypesAdminFeature(), b = c.storeTypesAdminFeature();
    assert.deepEqual(Object.keys(a).sort(), ['storeTypeForm', 'showStoreTypeModal', 'editingStoreType', 'createStoreType', 'editStoreType', 'updateStoreType', 'deleteStoreType'].sort());
    assert.deepEqual(plain(a.storeTypeForm), initial);
    assert.equal(a.showStoreTypeModal, false);
    assert.equal(a.editingStoreType, null);
    a.storeTypeForm.is_active = false; a.showStoreTypeModal = true; a.editingStoreType = 42;
    assert.deepEqual(plain(b.storeTypeForm), initial);
    assert.equal(b.showStoreTypeModal, false); assert.equal(b.editingStoreType, null);
});
test('edit replaces form and preserves inactive/order with blank description fallback',()=>{
 const c=setup(),a=c.composeInventoryFeatures({},c.storeTypesAdminFeature()),form=a.storeTypeForm;
 a.editStoreType({id:42,type_code:'custom',type_name:'Custom',description:null,display_order:-2,is_active:false});
 assert.notEqual(a.storeTypeForm,form);assert.deepEqual(plain(a.storeTypeForm),{type_code:'custom',type_name:'Custom',description:'',display_order:-2,is_active:false});assert.equal(a.editingStoreType,42);assert.equal(a.showStoreTypeModal,true);
});
for(const op of ['create','update','delete'])test(op+' uses composed providers in existing order',async()=>{
 const calls=[];let callback;const c=setup({confirm(m){assert.equal(m,"Are you sure you want to delete/deactivate store type 'Target'?");calls.push('confirm');return true;},setTimeout(fn,delay){calls.push(['timer',delay]);callback=fn;}});
 const a=c.composeInventoryFeatures({loading:false,error:'old',successMessage:'old',async apiCall(path,opts){assert.equal(this,a);assert.equal(a.loading,true);assert.equal(a.error,'');calls.push([path,opts.method,opts.body?JSON.parse(opts.body):null]);return {message:'Deactivated'};},async loadStoreTypes(){assert.equal(this,a);calls.push('types');},async loadStores(){assert.equal(this,a);calls.push('stores');}},c.storeTypesAdminFeature());
 a.storeTypeForm={type_code:'custom',type_name:'Target',description:' raw ',display_order:'3.9',is_active:false};a.editingStoreType=op==='create'?null:42;a.showStoreTypeModal=true;
 await a[op==='create'?'createStoreType':op==='update'?'updateStoreType':'deleteStoreType'](42,'Target');
 const payload=op==='delete'?null:{...(op==='create'?{type_code:'custom'}:{}),type_name:'Target',description:' raw ',display_order:3,...(op==='update'?{is_active:false}:{})};
 assert.deepEqual(calls,[...(op==='delete'?['confirm']:[]),[op==='create'?'/store-types':'/store-types/42',op==='create'?'POST':op==='update'?'PUT':'DELETE',payload],'types',...(op==='update'?['stores']:[]),['timer',3000]]);
 if(op!=='delete'){assert.deepEqual(plain(a.storeTypeForm),saved);assert.equal(a.showStoreTypeModal,false);assert.equal(a.editingStoreType,null);}assert.equal(a.loading,false);callback();assert.equal(a.successMessage,'');
});
