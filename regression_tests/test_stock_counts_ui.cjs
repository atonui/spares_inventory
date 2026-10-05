const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
function app() {
    const c={console,setTimeout:()=>{},confirm:()=>true};
    vm.createContext(c);vm.runInContext(fs.readFileSync('static/script.js','utf8'),c);
    const a=c.inventoryApp();a.currentUser={id:3,role:'engineer'};
    return a;
}
test('start count uses store ID, fresh sheet and leaves physical entries blank',async()=>{
    const a=app();a.apiCall=async path=>{
        assert.equal(path,'/inventory/count-sheet/975');
        return {sheet_token:'sheet',store_name:'Count Store',rows:[{inventory_id:975,quantity:10,work_order:null},{inventory_id:976,quantity:3,work_order:'COUNT-WO'}]};
    };
    await a.startStockCount({id:975,name:'Count Store'});
    assert.equal(a.stockCount.rows.length,2);
    assert.equal(a.stockCount.rows[0].counted_quantity,'');
    assert.equal(a.stockCount.rows[1].work_order,'COUNT-WO');
    assert.equal(a.stockCount.sheet_token,'sheet');
});
test('preview submits zero but skips blanks and writes no confirmation',async()=>{
    const a=app();a.stockCount={sheet_token:'sheet',rows:[{inventory_id:975,counted_quantity:'0',quantity:10,reason:'Empty shelf'},{inventory_id:976,counted_quantity:'',quantity:3,reason:''}]};
    const writes=[];a.apiCall=async(path,options)=>{writes.push({path,body:JSON.parse(options.body)});return {preview_token:'preview',rows:[{inventory_id:975,before_quantity:10,counted_quantity:0,difference:-10}]};};
    await a.previewStockCount();
    assert.equal(writes.length,1);
    assert.equal(writes[0].path,'/inventory/count-preview');
    assert.deepEqual(writes[0].body.rows,[{inventory_id:975,counted_quantity:0,reason:'Empty shelf'}]);
    assert.equal(a.stockCountPreview.preview_token,'preview');
});
test('invalid quantities and missing adjustment reasons never reach API',async()=>{
    for(const [quantity,reason] of [['-1','Bad'],['1.5','Bad'],['2','   '],['9007199254740992','Bad']]) {
        const a=app();a.stockCount={sheet_token:'sheet',rows:[{inventory_id:975,counted_quantity:quantity,quantity:10,reason}]};
        let writes=0;a.apiCall=async()=>{writes++;};
        await a.previewStockCount();assert.equal(writes,0);assert.ok(a.error);
    }
});
test('confirmation uses only signed preview and blocks duplicate clicks',async()=>{
    const a=app();a.stockCountPreview={preview_token:'preview',rows:[]};let writes=0;
    let resolve;a.apiCall=async(path,options)=>{
        writes++;assert.equal(path,'/inventory/count-confirm');
        assert.deepEqual(JSON.parse(options.body),{preview_token:'preview',confirmed:true});
        await new Promise(r=>{resolve=r;});return {changed:1,unchanged:0};
    };
    a.loadInventory=async()=>{};a.loadStats=async()=>{};
    const first=a.confirmStockCount();await a.confirmStockCount();resolve();await first;
    assert.equal(writes,1);assert.equal(a.stockCountPreview,null);assert.equal(a.stockCount,null);
});
test('editing a preview requires a new preview before confirmation',()=>{
    const a=app();a.stockCount={rows:[{inventory_id:975,counted_quantity:'8'}]};a.stockCountPreview={preview_token:'old'};
    a.editStockCount();assert.equal(a.stockCountPreview,null);assert.equal(a.stockCount.rows[0].counted_quantity,'8');
});
test('failed confirmation retains count entries and displays server error',async()=>{
    const a=app();a.stockCount={rows:[{inventory_id:975,counted_quantity:'8'}]};a.stockCountPreview={preview_token:'preview'};
    a.apiCall=async()=>{throw new Error('Stock changed; restart count');};
    await a.confirmStockCount();
    assert.match(a.error,/Stock changed/);assert.equal(a.stockCount.rows[0].counted_quantity,'8');
});
test('restart asks before replacing entered counts with fresh balances',async()=>{
    const c={console,setTimeout:()=>{},confirm:()=>false};vm.createContext(c);vm.runInContext(fs.readFileSync('static/script.js','utf8'),c);
    const a=c.inventoryApp();a.stockCount={store_id:975,rows:[{counted_quantity:'8'}]};let reads=0;
    a.apiCall=async()=>{reads++;return {rows:[],sheet_token:'fresh'};};
    await a.restartStockCount();assert.equal(reads,0);assert.equal(a.stockCount.rows[0].counted_quantity,'8');
    c.confirm=()=>true;await a.restartStockCount();assert.equal(reads,1);assert.equal(a.stockCount.sheet_token,'fresh');
});
test('count dialog keeps keyboard focus inside and restores the opening button',()=>{
    const a=app();const focused=[];
    const first={offsetParent:{},focus:()=>focused.push('first')};
    const last={offsetParent:{},focus:()=>focused.push('last')};
    const dialog={querySelectorAll:()=>[first,last],ownerDocument:{activeElement:last}};
    let prevented=0;
    a.trapStockCountFocus({shiftKey:false,preventDefault:()=>prevented++},dialog);
    assert.deepEqual(focused,['first']);assert.equal(prevented,1);
    dialog.ownerDocument.activeElement=first;
    a.trapStockCountFocus({shiftKey:true,preventDefault:()=>prevented++},dialog);
    assert.deepEqual(focused,['first','last']);
    a.stockCount={rows:[]};a.stockCountTrigger={focus:()=>focused.push('trigger')};
    a.cancelStockCount();assert.equal(focused.at(-1),'trigger');
});
test('refresh failure after committed confirmation is reported as saved',async()=>{
    const a=app();a.stockCount={rows:[]};a.stockCountPreview={preview_token:'preview'};
    a.apiCall=async()=>({changed:1,unchanged:0});a.loadInventory=async()=>{throw new Error('Network offline');};a.loadStats=async()=>{};
    await a.confirmStockCount();
    assert.match(a.successMessage,/saved/);assert.doesNotMatch(a.error,/not saved/i);assert.match(a.error,/refresh|reload/i);
    assert.equal(a.stockCountPreview,null);
});
test('preview and edit refocus the dialog after rendering and saved counts refocus an enabled opener',async()=>{
    const a=app();const ticks=[];let dialogFocus=0,openerFocus=0;
    a.$nextTick=callback=>ticks.push(callback);a.$refs={stockCountDialog:{focus:()=>dialogFocus++}};
    a.stockCount={sheet_token:'sheet',rows:[{inventory_id:975,quantity:10,counted_quantity:'8',reason:'Missing'}]};
    a.apiCall=async()=>({preview_token:'preview',rows:[]});
    await a.previewStockCount();ticks.splice(0).forEach(fn=>fn());assert.equal(dialogFocus,1);
    a.editStockCount();ticks.splice(0).forEach(fn=>fn());assert.equal(dialogFocus,2);
    a.stockCountPreview={preview_token:'preview'};
    a.stockCountTrigger={focus:()=>{assert.equal(a.stockCountBusy,false);openerFocus++;}};
    a.apiCall=async()=>({changed:1,unchanged:0});a.loadInventory=async()=>{};a.loadStats=async()=>{};
    await a.confirmStockCount();assert.equal(openerFocus,0);
    ticks.splice(0).forEach(fn=>fn());assert.equal(openerFocus,1);
});
