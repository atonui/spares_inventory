const {loadPageScripts} = require('./helpers/frontend.cjs');
const {test} = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');

function app() {
    const context = {console, setTimeout:()=>{}, Number, Map, Set};
    vm.createContext(context);
    loadPageScripts('index.html',context);
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

function input(csv) {
    return {target: {files: [{text: async () => csv}], value: 'selected.csv'}};
}

test('BOM and quoted headers preserve a zero quantity and reset the file input', async () => {
    const a = app();
    const event = input('\uFEFF"part_number","quantity"\r\n"CSV-A","0"\r\n');
    await a.importPartsToStore(event, 90);
    assert.equal(a.error, '');
    assert.equal(a.showDuplicateResolutionModal, true);
    assert.equal(a.getImportPreview()[0].quantity, 0);
    assert.equal(event.target.value, '');
});

for (const count of [1000, 1001]) {
    test(`stock CSV ${count} rows ${count === 1000 ? 'opens preview' : 'is rejected'}`, async () => {
        const a = app();
        const event = input('part_number,quantity\n' + Array(count).fill('CSV-A,1').join('\n'));
        await a.importPartsToStore(event, 90);
        assert.equal(a.showDuplicateResolutionModal, count === 1000);
        if (count === 1000) {
            assert.equal(a.pendingImportData.parsedRows.length, 1000);
            assert.equal(a.csvDuplicates[0].action, '');
        } else {
            assert.equal(a.pendingImportData, null);
            assert.match(a.error, /Maximum 1,000 stock rows/);
        }
        assert.equal(event.target.value, '');
        assert.equal(a.loading, false);
    });
}

for (const [csv, message] of [
    ['part_number,quantity\nCSV-A,4,extra', /expected exactly two CSV columns/],
    ['part_number,quantity\nUNKNOWN,4', /Part UNKNOWN not found in catalog/],
]) {
    test(`invalid stock CSV clears an earlier preview: ${message.source}`, async () => {
        const a = app();
        await a.importPartsToStore(input('part_number,quantity\nCSV-A,4'), 90);
        assert.equal(a.showDuplicateResolutionModal, true);
        const event = input(csv);
        await a.importPartsToStore(event, 90);
        assert.equal(a.showDuplicateResolutionModal, false);
        assert.equal(a.pendingImportData, null);
        assert.equal(a.csvDuplicates.length, 0);
        assert.equal(a.storeConflicts.length, 0);
        assert.match(a.error, message);
        assert.equal(event.target.value, '');
    });
}

test('work-order balances are excluded but duplicate existing stock blocks preview', async () => {
    const a = app();
    a.inventory = [
        {part_number: 'CSV-A', store_id: 90, quantity: 9, work_order: 'WO-1'},
        {part_number: 'CSV-A', store_id: 90, quantity: 7, work_order: null},
    ];
    await a.importPartsToStore(input('part_number,quantity\nCSV-A,4'), 90);
    assert.equal(a.showDuplicateResolutionModal, true);
    assert.equal(a.getImportPreview()[0].currentQuantity, 7);
    a.inventory.push({part_number: 'CSV-A', store_id: 90, quantity: 2, work_order: null});
    await a.importPartsToStore(input('part_number,quantity\nCSV-A,4'), 90);
    assert.equal(a.pendingImportData, null);
    assert.equal(a.showDuplicateResolutionModal, false);
    assert.match(a.error, /Duplicate stock for CSV-A/);
});

test('first, tally and skip choices update the shipped preview summary', async () => {
    const a = app();
    a.inventory = [{part_number: 'CSV-A', store_id: 90, quantity: 7}];
    await a.importPartsToStore(input('part_number,quantity\nCSV-A,4\nCSV-A,6'), 90);
    a.setAllCsvDuplicates('first');
    assert.equal(a.getImportPreview()[0].quantity, 4);
    assert.equal(a.getResolutionSummary().willUpdate, 1);
    a.setAllCsvDuplicates('tally');
    assert.equal(a.getImportPreview()[0].quantity, 10);
    a.setAllActions('skip');
    assert.equal(a.getResolutionSummary().willSkip, 1);
    assert.equal(a.getResolutionSummary().willUpdate, 0);
    a.cancelDuplicateResolution();
    assert.equal(a.showDuplicateResolutionModal, false);
    assert.equal(a.pendingImportData, null);
    assert.equal(a.csvDuplicates.length, 0);
    assert.equal(a.storeConflicts.length, 0);
});

for (const [csv, action, message] of [
    ['part_number,quantity\nCSV-A,9007199254740991\nCSV-A,1', 'tally', /Combined quantity is too large/],
    ['part_number,quantity\nCSV-A,4\nCSV-A,6', 'skip', /No rows selected for import/],
]) {
    test(`invalid confirmation prevents writes: ${message.source}`, async () => {
        const a = app();
        let writes = 0;
        a.apiCall = async (path, options) => {
            if (options) writes++;
            return a.inventory;
        };
        await a.importPartsToStore(input(csv), 90);
        a.setAllCsvDuplicates(action);
        await a.processDuplicateResolution();
        assert.equal(writes, 0);
        assert.match(a.error, message);
        assert.equal(a.showDuplicateResolutionModal, true);
        assert.equal(a.loading, false);
    });
}

test('shared loading prevents a second import and confirmation while a file is being read', async () => {
    const a = app();
    let release;
    const first = {target: {files: [{text: () => new Promise(resolve => { release = resolve; })}], value: 'first'}};
    const pending = a.importPartsToStore(first, 90);
    assert.equal(a.loading, true);
    let reads = 0;
    const second = {target: {files: [{text: async () => { reads++; return ''; }}], value: 'second'}};
    await a.importPartsToStore(second, 91);
    await a.processDuplicateResolution();
    assert.equal(reads, 0);
    assert.equal(a.error, '');
    assert.equal(second.target.value, 'second');
    release('part_number,quantity\nCSV-A,4');
    await pending;
    assert.equal(a.pendingImportData.storeId, 90);
    assert.equal(a.loading, false);
    assert.equal(first.target.value, '');
});

test('confirmation sends one batch and refreshes selected stock by ID before statistics', async () => {
    const a = app();
    const calls = [];
    let release;
    a.inventory = [{part_number: 'CSV-A', store_id: 90, quantity: 7}];
    a.apiCall = async (path, options) => {
        if (!options) return a.inventory;
        calls.push({path, body: JSON.parse(options.body)});
        return new Promise(resolve => { release = resolve; });
    };
    a.loadInventory = async () => {
        assert.equal(a.pendingImportData, null);
        assert.equal(a.showDuplicateResolutionModal, false);
        calls.push('inventory');
        a.inventory = [
            {part_number: 'CSV-A', store_id: 90, store_name: 'Test', quantity: 4},
            {part_number: 'CSV-A', store_id: 91, store_name: 'Test', quantity: 8},
        ];
    };
    a.loadStats = async () => {
        assert.equal(a.storeInventory.length, 1);
        assert.equal(a.storeInventory[0].store_id, 90);
        calls.push('stats');
    };
    await a.importPartsToStore(input('part_number,quantity\nCSV-A,4'), 90);
    const pending = a.processDuplicateResolution();
    assert.equal(a.loading, true);
    await a.processDuplicateResolution();
    assert.equal(calls.length, 1);
    release({added: 0, updated: 1, unchanged: 0});
    await pending;
    assert.deepEqual(calls, [
        {path: '/inventory/import-balances', body: {store_id: 90, rows: [
            {part_number: 'CSV-A', quantity: 4, expected_quantity: 7},
        ]}},
        'inventory', 'stats',
    ]);
    assert.equal(a.successMessage, 'Import saved: 0 created, 1 updated, 0 unchanged.');
    assert.equal(a.loading, false);
});

test('failed writes retain preview and release shared loading for retry', async () => {
    const a = app();
    await a.importPartsToStore(input('part_number,quantity\nCSV-A,4'), 90);
    const preview = a.pendingImportData;
    a.apiCall = async () => { throw new Error('Stale quantity'); };
    await a.processDuplicateResolution();
    assert.equal(a.pendingImportData, preview);
    assert.equal(a.showDuplicateResolutionModal, true);
    assert.equal(a.error, 'Import not saved: Stale quantity');
    assert.equal(a.loading, false);
});

test('refresh failure after saving preserves the existing cleared preview and error text', async () => {
    const a = app();
    await a.importPartsToStore(input('part_number,quantity\nCSV-A,4'), 90);
    a.apiCall = async () => ({added: 1, updated: 0, unchanged: 0});
    a.loadInventory = async () => { throw new Error('Refresh failed'); };
    let stats = 0;
    a.loadStats = async () => { stats++; };
    await a.processDuplicateResolution();
    assert.equal(a.pendingImportData, null);
    assert.equal(a.showDuplicateResolutionModal, false);
    assert.equal(a.successMessage, 'Import saved: 1 created, 0 updated, 0 unchanged.');
    assert.equal(a.error, 'Import not saved: Refresh failed');
    assert.equal(stats, 0);
    assert.equal(a.loading, false);
});

test('shipped applications keep import state independent', async () => {
    const first = app();
    const second = app();
    await first.importPartsToStore(input('part_number,quantity\nCSV-A,4\nCSV-A,6'), 90);
    first.csvDuplicates[0].action = 'tally';
    assert.equal(second.pendingImportData, null);
    assert.equal(second.showDuplicateResolutionModal, false);
    assert.equal(second.csvDuplicates.length, 0);
    assert.equal(second.storeConflicts.length, 0);
});
