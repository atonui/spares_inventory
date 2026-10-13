const {loadPageScripts} = require('./helpers/frontend.cjs');
const {test}=require('node:test');
const assert=require('node:assert/strict');
const vm=require('node:vm');
function app(confirmResult=true) {
    const context={console,setTimeout:()=>{},confirm:()=>confirmResult};
    vm.createContext(context);
    loadPageScripts('index.html',context);
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

function receiptApp(confirmFn = () => true) {
    const context = vm.createContext({console, setTimeout: () => {}, confirm: confirmFn});
    loadPageScripts('index.html', context);
    return context.inventoryApp();
}
const receipt = {id: 42, quantity: 4, part_number: 'TEST', to_store_name: 'Destination', from_store_name: 'Sender', can_receive: true, can_return: true};

for (const action of ['receive', 'return']) {
    test(`successful ${action} asks for physical confirmation and refreshes in order`, async () => {
        const calls = [];
        const a = receiptApp(message => { calls.push(['confirm', message]); return true; });
        a.selectedStore = {id: 7, name: 'Same name'};
        a.apiCall = async (path, options) => {
            if (options) {
                assert.equal(options.method, 'POST');
                calls.push(['write', path, JSON.parse(options.body)]);
                return {message: 'Completed'};
            }
            assert.equal(path, '/inventory/transfers');
            calls.push('transfers');
            return [{id: 43}];
        };
        a.loadInventory = async () => {
            calls.push('inventory');
            a.inventory = [{store_id: 7, store_name: 'Same name', quantity: 4}, {store_id: 8, store_name: 'Same name', quantity: 8}];
        };
        a.loadMovements = async () => {
            assert.equal(a.storeInventory.length, 1);
            assert.equal(a.storeInventory[0].store_id, 7);
            calls.push('movements');
        };
        a.loadStats = async () => { calls.push('stats'); };
        await a.confirmTransfer(receipt, action);
        assert.deepEqual(calls, [
            ['confirm', action === 'receive'
                ? 'Confirm physical receipt of all 4 x TEST at Destination?'
                : 'Confirm all 4 x TEST have physically returned to Sender? Source stock will be restored.'],
            ['write', `/inventory/transfers/42/${action}`, {confirmed: true}],
            'transfers', 'inventory', 'movements', 'stats',
        ]);
        assert.equal(a.pendingTransfers[0].id, 43);
        assert.equal(a.successMessage, 'Completed');
        assert.equal(a.error, '');
        assert.equal(a.loading, false);
    });
}

for (const action of ['receive', 'return']) {
    test(`denied ${action} permission prevents prompts and writes`, async () => {
        let prompts = 0;
        let writes = 0;
        const a = receiptApp(() => { prompts++; return true; });
        a.error = 'keep error';
        a.successMessage = 'keep success';
        a.pendingTransfers = [{id: 42}];
        const rows = a.pendingTransfers;
        a.apiCall = async () => { writes++; };
        await a.confirmTransfer({...receipt, can_receive: false, can_return: false}, action);
        assert.equal(prompts, 0);
        assert.equal(writes, 0);
        assert.equal(a.pendingTransfers, rows);
        assert.equal(a.error, 'keep error');
        assert.equal(a.successMessage, 'keep success');
        assert.equal(a.loading, false);
    });
    test(`declined ${action} prompt preserves state and prevents writes`, async () => {
        let prompts = 0;
        const a = receiptApp(() => { prompts++; return false; });
        a.error = 'keep error';
        a.successMessage = 'keep success';
        const rows = a.pendingTransfers;
        let writes = 0;
        a.apiCall = async () => { writes++; };
        await a.confirmTransfer(receipt, action);
        assert.equal(prompts, 1);
        assert.equal(writes, 0);
        assert.equal(a.pendingTransfers, rows);
        assert.equal(a.error, 'keep error');
        assert.equal(a.successMessage, 'keep success');
        assert.equal(a.loading, false);
    });
}

test('pending confirmation POST blocks a second confirmation and releases loading after failure', async () => {
    let prompts = 0;
    let writes = 0;
    let rejectWrite;
    const a = receiptApp(() => { prompts++; return true; });
    a.pendingTransfers = [{id: 42}];
    const rows = a.pendingTransfers;
    a.successMessage = 'prior success';
    a.apiCall = async () => {
        writes++;
        return new Promise((resolve, reject) => { rejectWrite = reject; });
    };
    const pending = a.confirmTransfer(receipt, 'receive');
    assert.equal(a.loading, true);
    await a.confirmTransfer(receipt, 'return');
    assert.equal(prompts, 1);
    assert.equal(writes, 1);
    rejectWrite(new Error('stale transfer'));
    await pending;
    assert.equal(a.pendingTransfers, rows);
    assert.equal(a.error, 'Confirmation failed: stale transfer');
    assert.equal(a.successMessage, 'prior success');
    assert.equal(a.loading, false);
});

for (const stage of ['transfers', 'stats']) {
    test(`explicit refresh failure at ${stage} preserves current rows and error wording`, async () => {
        const a = receiptApp();
        const calls = [];
        const oldRows = [{id: 42}];
        const newRows = [{id: 43}];
        a.pendingTransfers = oldRows;
        a.apiCall = async path => {
            assert.equal(path, '/inventory/transfers');
            assert.equal(a.error, '');
            calls.push('transfers');
            if (stage === 'transfers') throw new Error('read failed');
            return newRows;
        };
        a.loadStats = async () => { calls.push('stats'); throw new Error('read failed'); };
        a.error = 'old error';
        a.successMessage = 'keep success';
        await a.refreshTransfers();
        assert.equal(a.pendingTransfers, stage === 'transfers' ? oldRows : newRows);
        assert.deepEqual(calls, stage === 'transfers' ? ['transfers'] : ['transfers', 'stats']);
        assert.equal(a.error, 'Failed to refresh transfers: read failed');
        assert.equal(a.successMessage, 'keep success');
        assert.equal(a.loading, false);
    });
}

for (const stage of ['transfers', 'inventory', 'movements', 'stats']) {
    test(`confirmation refresh rejection at ${stage} preserves success and stops later refreshes`, async () => {
        const a = receiptApp();
        const calls = [];
        const oldRows = [{id: 42}];
        const newRows = [{id: 43}];
        a.pendingTransfers = oldRows;
        a.apiCall = async (path, options) => {
            if (options) { calls.push('write'); return {message: 'Received'}; }
            calls.push('transfers');
            if (stage === 'transfers') throw new Error('refresh failed');
            return newRows;
        };
        for (const [method, name] of [['loadInventory', 'inventory'], ['loadMovements', 'movements'], ['loadStats', 'stats']]) {
            a[method] = async () => {
                calls.push(name);
                if (stage === name) throw new Error('refresh failed');
            };
        }
        await a.confirmTransfer(receipt, 'receive');
        const order = ['write', 'transfers', 'inventory', 'movements', 'stats'];
        assert.deepEqual(calls, order.slice(0, order.indexOf(stage) + 1));
        assert.equal(a.pendingTransfers, stage === 'transfers' ? oldRows : newRows);
        assert.equal(a.successMessage, 'Received');
        assert.equal(a.error, 'Confirmation failed: refresh failed');
        assert.equal(a.loading, false);
    });
}

test('confirmation retains the real inventory refresh loading and swallowed-error semantics', async () => {
    const a = receiptApp();
    const calls = [];
    a.apiCall = async (path, options) => {
        if (options) { calls.push('write'); return {message: 'Received'}; }
        if (path === '/inventory/transfers') { calls.push('transfers'); return []; }
        assert.equal(path, '/inventory');
        calls.push('inventory');
        throw new Error('inventory unavailable');
    };
    a.loadMovements = async () => {
        assert.equal(a.loading, false);
        assert.equal(a.inventoryLoadFailed, true);
        calls.push('movements');
    };
    a.loadStats = async () => { calls.push('stats'); };
    await a.confirmTransfer(receipt, 'receive');
    assert.deepEqual(calls, ['write', 'transfers', 'inventory', 'movements', 'stats']);
    assert.equal(a.successMessage, 'Received');
    assert.equal(a.error, 'Inventory could not refresh. Retry or reload the page: inventory unavailable');
    assert.equal(a.loading, false);
});

test('core dispatch uses the real composed pending-transfer loader', async () => {
    const a = receiptApp();
    const calls = [];
    a.transferForm = {inventory_id: 1, to_store_id: 7, quantity: 4};
    a.apiCall = async (path, options) => {
        calls.push(path);
        if (options) {
            assert.equal(path, '/inventory/transfer');
            assert.deepEqual(JSON.parse(options.body), {inventory_id: 1, to_store_id: 7, quantity: 4});
            return {message: 'Dispatched; awaiting receipt'};
        }
        assert.equal(path, '/inventory/transfers');
        return [{id: 42}];
    };
    a.loadInventory = async () => { calls.push('inventory'); };
    a.loadStats = async () => { calls.push('stats'); };
    await a.transferStock();
    assert.deepEqual(calls, ['/inventory/transfer', 'inventory', 'stats', '/inventory/transfers']);
    assert.equal(a.pendingTransfers[0].id, 42);
});

test('core startup uses the real composed pending-transfer loader', async () => {
    const a = receiptApp();
    const calls = [];
    for (const method of ['loadTimezoneContext', 'loadStats', 'loadStores', 'loadParts', 'loadInventory', 'loadMovements', 'loadEquipment', 'loadEquipmentStats', 'loadCalibrationSettings', 'loadStoreTypes', 'loadUsers']) {
        a[method] = async () => {};
    }
    a.apiCall = async path => { calls.push(path); return [{id: 42}]; };
    await a.loadAllData();
    assert.deepEqual(calls, ['/inventory/transfers']);
    assert.equal(a.pendingTransfers[0].id, 42);
    assert.equal(a.loading, false);
});

test('shipped application pending-transfer arrays are independent', () => {
    const first = receiptApp();
    const second = receiptApp();
    first.pendingTransfers.push({id: 42});
    assert.equal(second.pendingTransfers.length, 0);
});
