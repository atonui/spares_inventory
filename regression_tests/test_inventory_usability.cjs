const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
function app() {
    const c={console,setTimeout:()=>{}};vm.createContext(c);vm.runInContext(fs.readFileSync('static/script.js','utf8'),c);
    const a=c.inventoryApp();a.currentUser={id:3,role:'engineer'};
    a.stores=[{id:90,name:'Same Name'},{id:91,name:'Same Name'}];
    a.inventory=[
        {id:1,store_id:90,store_name:'Same Name',part_number:'110661103',description:'Drive Nut, Solid',quantity:10,work_order:null},
        {id:2,store_id:91,store_name:'Same Name',part_number:'110661203',description:'Drive Nut, Half',quantity:3,work_order:'WO-7'},
        {id:3,store_id:90,store_name:'Same Name',part_number:'411',description:null,quantity:2,work_order:null},
    ];return a;
}
test('search ignores surrounding spaces and matches description words in any order',()=>{
    const a=app();a.searchTerm='  solid   DRIVE ';a.filterInventory();
    assert.deepEqual(Array.from(a.filteredInventory,r=>r.id),[1]);
    a.searchTerm='110 661 103';a.filterInventory();assert.deepEqual(Array.from(a.filteredInventory,r=>r.id),[1]);
});
test('store filters never mix identically named stores',()=>{
    const a=app();a.storeFilter='91';a.filterInventory();
    assert.deepEqual(Array.from(a.filteredInventory,r=>r.id),[2]);
});
test('store details and CSV export use selected store identity',async()=>{
    const a=app();await a.viewStoreInventory(a.stores[1]);
    assert.deepEqual(Array.from(a.storeInventory,r=>r.id),[2]);
    let rows;a.downloadCSV=(_headers,data)=>{rows=data;};a.exportStoreInventoryCSV(91);
    assert.equal(rows.length,1);assert.equal(rows[0][0],'110661203');
});
test('background inventory refresh keeps current panel and navigation preserves filters',async()=>{
    const a=app();a.showInventoryPanel=false;a.showUsersPanel=true;a.searchTerm='drive';a.storeFilter='90';
    a.apiCall=async()=>a.inventory;await a.loadInventory();
    assert.equal(a.showUsersPanel,true);assert.equal(a.showInventoryPanel,false);
    a.openPanel('showInventoryPanel');assert.equal(a.searchTerm,'drive');assert.equal(a.storeFilter,'90');
});
test('clear filters restores all stock and archived navigation closes cleanly',()=>{
    const a=app();a.searchTerm='missing';a.storeFilter='90';a.showArchivedPanel=true;
    a.clearInventoryFilters();assert.equal(a.searchTerm,'');assert.equal(a.storeFilter,'');assert.equal(a.filteredInventory.length,3);
    assert.equal(a.showArchivedPanel,false);assert.equal(a.showInventoryPanel,true);
});
test('store search narrows only that store and does not change recorded balances',async()=>{
    const a=app();await a.viewStoreInventory(a.stores[0]);a.storeSearchTerm='411';
    assert.deepEqual(Array.from(a.filteredStoreInventory,r=>r.id),[3]);
    assert.equal(a.inventory[0].quantity,10);assert.equal(a.storeInventory.length,2);
});
test('failed refresh retains stock but exposes a failure state rather than empty stock',async()=>{
    const a=app();a.apiCall=async()=>{throw new Error('Network offline');};
    await a.loadInventory();assert.equal(a.inventory.length,3);assert.equal(a.inventoryLoadFailed,true);assert.match(a.error,/reload|retry/i);
    a.apiCall=async()=>[];await a.loadInventory();assert.equal(a.inventoryLoadFailed,false);assert.equal(a.inventory.length,0);
    assert.equal(a.error,'');
});
test('refresh recovery preserves unrelated errors',async()=>{
    const a=app();a.apiCall=async()=>{throw new Error('Network offline');};await a.loadInventory();
    a.error='Transfer needs physical receipt';a.apiCall=async()=>a.inventory;await a.loadInventory();
    assert.equal(a.error,'Transfer needs physical receipt');
});
test('store summaries report separate quantities for identical names',()=>{
    const a=app();let rows;a.getUserName=()=>'';a.downloadCSV=(_headers,data)=>{rows=data;};
    a.exportStoresCSV();assert.equal(rows[0][4],2);assert.equal(rows[0][5],12);assert.equal(rows[1][4],1);assert.equal(rows[1][5],3);
});
