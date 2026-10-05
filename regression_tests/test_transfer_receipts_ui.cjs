const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
function app(confirmResult=true) {
    const context={console,setTimeout:()=>{},confirm:()=>confirmResult};
    vm.createContext(context);
    vm.runInContext(fs.readFileSync('static/script.js','utf8'),context);
    const a=context.inventoryApp();
    for(const method of ['loadInventory','loadStats','loadMovements','loadPendingTransfers']) a[method]=async()=>{};
    return a;
}
test('receipt confirmation sends explicit acknowledgement once',async()=>{
    const a=app();const writes=[];
    a.apiCall=async(path,options)=>{writes.push({path,body:JSON.parse(options.body)});return {message:'Received'};};
    await a.confirmTransfer({id:42,quantity:4,part_number:'TEST',to_store_name:'Destination',can_receive:true},'receive');
    assert.deepEqual(writes,[{path:'/inventory/transfers/42/receive',body:{confirmed:true}}]);
});
test('declining physical return confirmation does not change stock',async()=>{
    const a=app(false);let writes=0;
    a.apiCall=async()=>{writes++;};
    await a.confirmTransfer({id:42,quantity:4,part_number:'TEST',from_store_name:'Sender',can_return:true},'return');
    assert.equal(writes,0);
});
test('dispatch describes in-transit stock and refreshes pending transfers',async()=>{
    const a=app();let refreshes=0;
    a.loadPendingTransfers=async()=>{refreshes++;};
    a.transferForm={inventory_id:1,to_store_id:2,quantity:4};
    a.apiCall=async()=>({message:'Dispatched; awaiting receipt'});
    await a.transferStock();
    assert.match(a.successMessage,/awaiting receipt/);
    assert.equal(refreshes,1);
});
