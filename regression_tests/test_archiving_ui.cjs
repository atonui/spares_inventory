const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
function app() {
    const prompts=[];
    const c={console,setTimeout:()=>{},confirm:message=>{prompts.push(message);return true;}};
    vm.createContext(c);vm.runInContext(fs.readFileSync('static/script.js','utf8'),c);
    const a=c.inventoryApp();a.currentUser={id:1,role:'admin'};
    for(const method of ['loadParts','loadStores','loadUsers','loadStats','loadInventory','loadArchivedRecords'])a[method]=async()=>{};
    return {a,prompts};
}
for(const kind of ['Part','Store','User'])test(`archive ${kind} describes history preservation`,async()=>{
    const {a,prompts}=app();
    a.apiCall=async()=>({message:'Record archived; history preserved'});
    await a['delete'+kind](42,'Example');
    assert.match(prompts[0],/archive/i);
    assert.match(a.successMessage,/archived/i);
});
test('restore uses the selected record type and refreshes active lists',async()=>{
    const {a}=app();const writes=[];let refreshes=0;
    a.loadParts=async()=>{refreshes++;};
    a.apiCall=async(path,options)=>{writes.push({path,method:options.method});return {message:'Restored'};};
    await a.restoreArchivedRecord({kind:'parts',id:42,label:'Example'});
    assert.deepEqual(writes,[{path:'/parts/42/restore',method:'POST'}]);
    assert.equal(refreshes,1);
});
test('superadmin initially receives the active user management list',async()=>{
    const c={console,setTimeout:()=>{}};
    vm.createContext(c);vm.runInContext(fs.readFileSync('static/script.js','utf8'),c);
    const a=c.inventoryApp();a.currentUser={id:2,role:'superadmin'};
    a.apiCall=async path=>path==='/users'?[{id:3,name:'Engineer'}]:[];
    await a.loadAllData();
    assert.equal(a.users[0]?.name,'Engineer');
});
