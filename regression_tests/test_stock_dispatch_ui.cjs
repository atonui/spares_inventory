const {test} = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const {loadPageScripts} = require('./helpers/frontend.cjs');
const plain = value => JSON.parse(JSON.stringify(value));

function setup() {
    const timers = [];
    const c = vm.createContext({
        console,
        setTimeout(callback, delay) { timers.push({callback, delay}); },
        confirm() { throw new Error('Receipt prompt must be blocked while dispatch is busy'); },
    });
    loadPageScripts('index.html', c);
    return {app: c.inventoryApp(), timers};
}

for (const replenishment of [false, true]) {
    test(`${replenishment ? 'replenishment' : 'ordinary'} dispatch preserves payload and success lifecycle`, async () => {
        const {app: a, timers} = setup();
        const calls = [];
        a.transferForm = {inventory_id: '30', to_store_id: '10', quantity: '2', replenishment, max_quantity: 2};
        a.showTransferModal = true;
        a.error = 'old error';
        a.successMessage = 'old success';
        a.apiCall = async (path, options) => {
            if (options) {
                assert.equal(a.loading, true);
                assert.equal(a.error, '');
                assert.equal(a.successMessage, '');
                calls.push(['write', path, options.method, JSON.parse(options.body)]);
                return {message: 'Dispatched; awaiting receipt'};
            }
            assert.equal(path, '/inventory/transfers');
            assert.equal(timers.length, 0);
            calls.push('transfers');
            return [{id: 42}];
        };
        a.loadInventory = async () => {
            assert.equal(a.showTransferModal, false);
            assert.deepEqual(plain(a.transferForm), {inventory_id: '', to_store_id: '', quantity: ''});
            assert.equal(a.successMessage, 'Dispatched; awaiting receipt');
            assert.equal(timers.length, 0);
            calls.push('inventory');
        };
        a.loadStats = async () => { assert.equal(timers.length, 0); calls.push('stats'); };
        await a.transferStock();
        assert.deepEqual(calls, [
            ['write', '/inventory/transfer', 'POST', {inventory_id: 30, to_store_id: 10, quantity: 2, ...(replenishment ? {replenishment: true} : {})}],
            'inventory', 'stats', 'transfers',
        ]);
        assert.equal(a.pendingTransfers[0].id, 42);
        assert.equal(a.loading, false);
        assert.equal(a.error, '');
        assert.equal(timers.length, 1);
        assert.equal(timers[0].delay, 3000);
        assert.equal(a.successMessage, 'Dispatched; awaiting receipt');
        timers[0].callback();
        assert.equal(a.successMessage, '');
    });
}

test('pending dispatch shares busy state with receipt confirmation', async () => {
    const {app: a} = setup();
    let release;
    const calls = [];
    a.transferForm = {inventory_id: '30', to_store_id: '10', quantity: '2'};
    a.showTransferModal = true;
    const form = a.transferForm;
    a.apiCall = async (path, options) => {
        calls.push(path);
        if (options) return new Promise(resolve => { release = resolve; });
        return [];
    };
    a.loadInventory = async () => {};
    a.loadStats = async () => {};
    const pending = a.transferStock();
    assert.equal(a.loading, true);
    assert.equal(a.transferForm, form);
    assert.equal(a.showTransferModal, true);
    await a.confirmTransfer({id: 42, can_receive: true}, 'receive');
    assert.deepEqual(calls, ['/inventory/transfer']);
    release({message: 'Dispatched'});
    await pending;
    assert.deepEqual(calls, ['/inventory/transfer', '/inventory/transfers']);
    assert.equal(a.loading, false);
});

test('dispatch write rejection retains form and modal for correction', async () => {
    const {app: a, timers} = setup();
    a.transferForm = {inventory_id: '30', to_store_id: '10', quantity: '2', replenishment: true, max_quantity: 2};
    a.showTransferModal = true;
    const form = a.transferForm;
    a.successMessage = 'old success';
    let writes = 0;
    a.apiCall = async (path, options) => {
        assert.equal(path, '/inventory/transfer');
        assert.equal(options.method, 'POST');
        writes++;
        throw new Error('Plan changed');
    };
    let refreshes = 0;
    a.loadInventory = a.loadStats = async () => { refreshes++; };
    await a.transferStock();
    assert.equal(writes, 1);
    assert.equal(refreshes, 0);
    assert.equal(a.transferForm, form);
    assert.equal(a.showTransferModal, true);
    assert.deepEqual(plain(form), {inventory_id: '30', to_store_id: '10', quantity: '2', replenishment: true, max_quantity: 2});
    assert.equal(a.successMessage, '');
    assert.equal(a.error, 'Failed to transfer stock: Plan changed');
    assert.equal(a.loading, false);
    assert.equal(timers.length, 0);
});

for (const stage of ['inventory', 'stats', 'transfers']) {
    test(`dispatch refresh rejection at ${stage} retains the saved/reset state`, async () => {
        const {app: a, timers} = setup();
        const calls = [];
        a.transferForm = {inventory_id: '30', to_store_id: '10', quantity: '2'};
        a.showTransferModal = true;
        a.pendingTransfers = [{id: 41}];
        const rows = a.pendingTransfers;
        a.apiCall = async (path, options) => {
            if (options) { calls.push('write'); return {message: 'Dispatched'}; }
            assert.equal(path, '/inventory/transfers');
            calls.push('transfers');
            throw new Error('Refresh failed');
        };
        for (const [method, name] of [['loadInventory', 'inventory'], ['loadStats', 'stats']]) {
            a[method] = async () => {
                calls.push(name);
                if (stage === name) throw new Error('Refresh failed');
            };
        }
        await a.transferStock();
        const order = ['write', 'inventory', 'stats', 'transfers'];
        assert.deepEqual(calls, order.slice(0, order.indexOf(stage) + 1));
        assert.equal(a.pendingTransfers, rows);
        assert.deepEqual(plain(a.transferForm), {inventory_id: '', to_store_id: '', quantity: ''});
        assert.equal(a.showTransferModal, false);
        assert.equal(a.successMessage, 'Dispatched');
        assert.equal(a.error, 'Failed to transfer stock: Refresh failed');
        assert.equal(a.loading, false);
        assert.equal(timers.length, 0);
    });
}

test('dispatch preserves real inventory refresh loading and swallowed-error behavior', async () => {
    const {app: a, timers} = setup();
    const calls = [];
    a.transferForm = {inventory_id: 30, to_store_id: 10, quantity: 2};
    a.apiCall = async (path, options) => {
        calls.push(path);
        if (options) return {message: 'Dispatched'};
        if (path === '/inventory') throw new Error('Offline');
        assert.equal(path, '/inventory/transfers');
        return [{id: 42}];
    };
    a.loadStats = async () => {
        assert.equal(a.loading, false);
        assert.equal(a.inventoryLoadFailed, true);
        calls.push('stats');
    };
    await a.transferStock();
    assert.deepEqual(calls, ['/inventory/transfer', '/inventory', 'stats', '/inventory/transfers']);
    assert.equal(a.error, 'Inventory could not refresh. Retry or reload the page: Offline');
    assert.equal(a.successMessage, 'Dispatched');
    assert.equal(a.pendingTransfers[0].id, 42);
    assert.equal(a.loading, false);
    assert.equal(timers.length, 1);
    assert.equal(timers[0].delay, 3000);
});

test('real replenishment review fills dispatch and manual opening clears its mode', async () => {
    const {app: a} = setup();
    const suggestion = {inventory_id: 30, quantity: 2, can_dispatch: true};
    const row = {store_id: 10, part_id: 20, suggestions: [suggestion]};
    const calls = [];
    a.showLowStockPanel = true;
    a.apiCall = async (path, options) => {
        assert.equal(options, undefined);
        calls.push(path);
        if (path === '/inventory') return [{id: 30, quantity: 10}];
        assert.equal(path, '/inventory/replenishment');
        return {rows: [row]};
    };
    const form = a.transferForm;
    await a.reviewReplenishmentTransfer(row, suggestion);
    assert.deepEqual(calls, ['/inventory', '/inventory/replenishment']);
    assert.equal(a.transferForm, form);
    assert.deepEqual(plain(form), {inventory_id: 30, to_store_id: 10, quantity: 2, replenishment: true, max_quantity: 2});
    assert.equal(a.showTransferModal, true);
    await a.transferItem({id: 40});
    assert.equal(a.transferForm, form);
    assert.deepEqual(plain(form), {inventory_id: 40, to_store_id: '', quantity: 1, replenishment: false, max_quantity: null});
    assert.equal(a.showTransferModal, true);
});

test('core navigation closes the composed dispatch modal without resetting its form', async () => {
    const {app: a} = setup();
    await a.transferItem({id: 30});
    const form = a.transferForm;
    a.openPanel('showInventoryPanel');
    assert.equal(a.showTransferModal, false);
    assert.equal(a.showInventoryPanel, true);
    assert.equal(a.transferForm, form);
    assert.equal(a.transferForm.inventory_id, 30);
});

test('shipped dispatch forms remain independent through opening and reset', async () => {
    const {app: first} = setup();
    const {app: second} = setup();
    await first.transferItem({id: 30});
    assert.deepEqual(plain(second.transferForm), {inventory_id: '', to_store_id: '', quantity: ''});
    assert.equal(second.showTransferModal, false);
    first.transferForm.to_store_id = 10;
    first.apiCall = async (path, options) => options ? {message: 'Dispatched'} : [];
    first.loadInventory = first.loadStats = async () => {};
    await first.transferStock();
    first.transferForm.quantity = 7;
    assert.equal(second.transferForm.quantity, '');
});
