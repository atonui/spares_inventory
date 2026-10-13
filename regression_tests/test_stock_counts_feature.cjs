const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
function setup() {
    const c = vm.createContext({confirm:()=>true});
    for (const file of ['static/js/shared/features.js','static/js/inventory/stock-counts.js']) {
        vm.runInContext(fs.readFileSync(file,'utf8'),c);
    }
    return c;
}
const owned = ['stockCount','stockCountPreview','stockCountBusy','stockCountTrigger','startStockCount','previewStockCount','editStockCount','focusStockCountDialog','restoreStockCountFocus','restartStockCount','cancelStockCount','trapStockCountFocus','confirmStockCount'].sort();
test('counts have one owner and independent instance state', () => {
    const c=setup(),a=c.stockCountsFeature(),b=c.stockCountsFeature();
    assert.deepEqual(Object.keys(a).sort(),owned);
    assert.equal(a.stockCount,null);assert.equal(a.stockCountBusy,false);
    a.stockCount={rows:[]};a.stockCountPreview={preview_token:'fixture'};a.stockCountBusy=true;a.stockCountTrigger={focus(){}};
    assert.equal(b.stockCount,null);assert.equal(b.stockCountPreview,null);assert.equal(b.stockCountBusy,false);assert.equal(b.stockCountTrigger,null);
});
test('composed sheet and preview retain exact fields, zero and blank handling', async () => {
    const c=setup(),calls=[];
    const a=c.composeInventoryFeatures({error:'',async apiCall(path,options){
        assert.equal(this,a);calls.push(path);
        if(!options)return {sheet_token:'sheet',rows:[{inventory_id:1,quantity:3},{inventory_id:2,quantity:1}]};
        assert.deepEqual(JSON.parse(options.body),{sheet_token:'sheet',rows:[{inventory_id:1,counted_quantity:0,reason:'Empty'}]});
        return {preview_token:'preview',rows:[]};
    }},c.stockCountsFeature());
    await a.startStockCount({id:7});assert.equal(a.stockCount.rows[0].counted_quantity,'');
    a.stockCount.rows[0].counted_quantity='0';a.stockCount.rows[0].reason='Empty';
    await a.previewStockCount();assert.deepEqual(calls,['/inventory/count-sheet/7','/inventory/count-preview']);assert.equal(a.stockCountPreview.preview_token,'preview');
});
test('focus uses composed Alpine refs and restores an opener after busy clears', async () => {
    const c=setup(),ticks=[];let dialogFocus=0,openerFocus=0;
    const a=c.composeInventoryFeatures({error:'',successMessage:'',selectedStore:null,inventory:[],
        $nextTick(fn){assert.equal(this,a);ticks.push(fn);},$refs:{stockCountDialog:{focus(){dialogFocus++;}}},
        async apiCall(){assert.equal(this,a);return {changed:1,unchanged:0};},async loadInventory(){},async loadStats(){}
    },c.stockCountsFeature());
    a.stockCount={rows:[]};a.focusStockCountDialog();assert.equal(dialogFocus,0);ticks.splice(0).forEach(fn=>fn());assert.equal(dialogFocus,1);
    a.stockCountPreview={preview_token:'preview'};a.stockCountTrigger={focus(){assert.equal(a.stockCountBusy,false);openerFocus++;}};
    await a.confirmStockCount();assert.equal(openerFocus,0);assert.equal(a.stockCountBusy,false);
    ticks.splice(0).forEach(fn=>fn());assert.equal(openerFocus,1);assert.equal(a.stockCountTrigger,null);
});
