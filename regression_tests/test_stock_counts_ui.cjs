const {loadPageScripts} = require('./helpers/frontend.cjs');
const {test}=require('node:test');
const assert=require('node:assert/strict');
const vm=require('node:vm');
function app() {
    const c={console,setTimeout:()=>{},confirm:()=>true};
    vm.createContext(c);loadPageScripts('index.html',c);
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
    const c={console,setTimeout:()=>{},confirm:()=>false};vm.createContext(c);loadPageScripts('index.html',c);
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

test('saved count refreshes selected store by ID before restoring focus', async () => {
    const a = app(), order = [], ticks = [];
    a.stockCount = {rows:[]}; a.stockCountPreview = {preview_token:'preview'};
    a.selectedStore = {id:7, name:'Same name'};
    a.$nextTick = callback => ticks.push(callback);
    a.stockCountTrigger = {focus(){assert.equal(a.stockCountBusy,false);order.push('focus');}};
    a.apiCall = async () => {order.push('confirm'); return {changed:1,unchanged:0};};
    a.loadInventory = async () => {order.push('inventory');a.inventory=[{id:1,store_id:7,store_name:'Same name'},{id:2,store_id:8,store_name:'Same name'}];};
    a.loadStats = async () => {order.push('stats');};
    await a.confirmStockCount();
    assert.deepEqual(order,['confirm','inventory','stats']);
    assert.equal(a.storeInventory.length,1); assert.equal(a.storeInventory[0].id,1);
    ticks.splice(0).forEach(fn=>fn());assert.deepEqual(order,['confirm','inventory','stats','focus']);
});

test('failed count write retains preview and refocuses the dialog without refreshing', async () => {
    const a = app(), ticks = []; let focus = 0, refreshes = 0;
    const sheet = {rows:[]}, preview = {preview_token:'preview'};
    a.stockCount = sheet; a.stockCountPreview = preview;
    a.$nextTick = callback => ticks.push(callback); a.$refs = {stockCountDialog:{focus(){focus++;}}};
    a.apiCall = async () => {throw Error('stale preview');};
    a.loadInventory = async () => {refreshes++;};
    await a.confirmStockCount();
    assert.equal(a.stockCount,sheet); assert.equal(a.stockCountPreview,preview);
    assert.equal(refreshes,0);assert.match(a.error,/Count not saved: stale preview/);
    ticks.splice(0).forEach(fn=>fn());assert.equal(focus,1);assert.equal(a.stockCountBusy,false);
});

test('refresh failure after a saved count closes the count and restores the opener', async () => {
    const a = app(), ticks = []; let focus = 0;
    a.stockCount = {rows:[]}; a.stockCountPreview = {preview_token:'preview'};
    a.$nextTick = callback => ticks.push(callback);a.stockCountTrigger = {focus(){assert.equal(a.stockCountBusy,false);focus++;}};
    a.apiCall = async () => ({changed:1,unchanged:0});
    a.loadInventory = async () => {throw Error('offline');};
    await a.confirmStockCount();
    assert.equal(a.stockCount,null);assert.equal(a.stockCountPreview,null);
    assert.match(a.error,/Stock count saved, but refresh failed.*offline/);
    ticks.splice(0).forEach(fn=>fn());assert.equal(focus,1);
});

test('composed count state and opener references belong to each application', () => {
    const a = app(), b = app();
    a.stockCount = {rows:[]};a.stockCountPreview = {preview_token:'fixture'};
    a.stockCountBusy = true;a.stockCountTrigger = {focus(){}};
    assert.equal(b.stockCount,null);assert.equal(b.stockCountPreview,null);
    assert.equal(b.stockCountBusy,false);assert.equal(b.stockCountTrigger,null);
});

test('declined physical count confirmation makes no write and retains preview', async () => {
    const c = {console, setTimeout:()=>{}, confirm:()=>false};
    vm.createContext(c);loadPageScripts('index.html',c);
    const a = c.inventoryApp(), preview = {preview_token:'preview'};
    a.stockCountPreview = preview;let writes = 0;
    a.apiCall = async () => {writes++;};
    await a.confirmStockCount();
    assert.equal(writes,0);assert.equal(a.stockCountPreview,preview);assert.equal(a.stockCountBusy,false);
});

test('empty count focus trap prevents default and focuses the dialog', () => {
    const a = app();let focused = 0, prevented = 0;
    const dialog = {querySelectorAll:()=>[], focus(){focused++;}};
    a.trapStockCountFocus({preventDefault(){prevented++;}},dialog);
    assert.equal(prevented,1);assert.equal(focused,1);
});
