const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

function app() {
    const context = {console, setTimeout:()=>{}, Number, Map, Set};
    vm.createContext(context);
    vm.runInContext(fs.readFileSync('static/script.js','utf8'),context);
    const a=context.inventoryApp();
    a.parts=[{id:900,part_number:'CSV-A',description:'A'}];
    a.inventory=[];
    a.selectedStore={id:90,name:'Test'};
    a.loadInventory=async()=>{};
    a.loadParts=async()=>{};
    a.apiCall=async(path)=>path==='/inventory' ? a.inventory : a.parts;
    return a;
}

test('a valid import waits for preview confirmation even with no conflicts',async()=>{
    const a=app();let calls=0;a.apiCall=async(path,options)=>{if(options) calls++;return a.inventory;};
    await a.importPartsToStore({target:{files:[{text:async()=> 'part_number,quantity\nCSV-A,4'}],value:'file'}},90);
    assert.equal(calls,0);
    assert.equal(a.showDuplicateResolutionModal,true);
});

for(const qty of ['4abc','1.5','-1','9007199254740992']) {
    test(`rejects malformed quantity ${qty} before writes`,async()=>{
        const a=app();let calls=0;a.apiCall=async(path,options)=>{if(options) calls++;return a.inventory;};
        await a.importPartsToStore({target:{files:[{text:async()=> `part_number,quantity\nCSV-A,${qty}`}],value:'file'}},90);
        assert.equal(calls,0);
        assert.ok(a.error);
        assert.equal(a.showDuplicateResolutionModal,false);
    });
}

test('duplicate CSV rows require an explicit decision',async()=>{
    const a=app();let calls=0;a.apiCall=async(path,options)=>{if(options) calls++;return a.inventory;};
    await a.importPartsToStore({target:{files:[{text:async()=> 'part_number,quantity\nCSV-A,4\nCSV-A,4'}],value:'file'}},90);
    await a.processDuplicateResolution();
    assert.equal(calls,0);
    assert.ok(a.error);
});

test('preview updates when duplicate resolution changes',async()=>{
    const a=app();
    a.inventory=[{id:1,part_number:'CSV-A',store_id:90,store_name:'Test',quantity:7,work_order:null}];
    await a.importPartsToStore({target:{files:[{text:async()=> 'part_number,quantity\nCSV-A,4\nCSV-A,6'}],value:'file'}},90);
    a.csvDuplicates[0].action='first';
    const row=a.getImportPreview()[0];
    assert.equal(row.quantity,4);
    assert.equal(row.currentQuantity,7);
    assert.equal(row.action,'replace');
});

test('same store names do not mix their balances',async()=>{
    const a=app();
    a.inventory=[{id:1,part_number:'CSV-A',store_id:91,store_name:'Test',quantity:7,work_order:null}];
    await a.importPartsToStore({target:{files:[{text:async()=> 'part_number,quantity\nCSV-A,4'}],value:'file'}},90);
    assert.equal(a.getImportPreview()[0].currentQuantity,null);
    assert.equal(a.getImportPreview()[0].action,'create');
});

test('confirmation sends one batch with the previewed balances',async()=>{
    const a=app();const requests=[];
    a.loadStats=async()=>{};
    a.inventory=[{id:1,part_number:'CSV-A',store_id:90,quantity:7,work_order:null}];
    a.apiCall=async(path,options)=>{
        if(!options) return a.inventory;
        requests.push({path,body:JSON.parse(options.body)});
        return {added:0,updated:1,unchanged:0};
    };
    await a.importPartsToStore({target:{files:[{text:async()=> 'part_number,quantity\n"CSV-A","4"'}],value:'file'}},90);
    assert.equal(requests.length,0);
    await a.processDuplicateResolution();
    assert.deepEqual(requests,[{path:'/inventory/import-balances',body:{store_id:90,rows:[{part_number:'CSV-A',quantity:4,expected_quantity:7}]}}]);
});

test('failed stock refresh blocks the import preview',async()=>{
    const a=app();a.apiCall=async()=>{throw new Error('Network failure');};
    await a.importPartsToStore({target:{files:[{text:async()=> 'part_number,quantity\nCSV-A,4'}],value:'file'}},90);
    assert.equal(a.showDuplicateResolutionModal,false);
    assert.ok(a.error);
});
