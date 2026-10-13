const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const {loadPageScripts} = require('./helpers/frontend.cjs');
const plain = value => JSON.parse(JSON.stringify(value));

function setup() {
    const timers = [];
    let app;
    const context = vm.createContext({console, setTimeout(callback, delay) {
        timers.push({callback, delay, storeIds: app.storeInventory.map(row => row.store_id)});
    }});
    loadPageScripts('index.html', context);
    app = context.inventoryApp();
    context.app = app;
    return {app, timers, context};
}

const item = {id: 42, part_number: 'P-A', description: 'Test part', store_name: 'Same name', quantity: 5};
function fill(app, notes = '') {
    app.consumeItem(item);
    Object.assign(app.consumeForm, {inventory_id: '42', quantity: '2', work_order_number: ' WO-42 ', notes});
}

test('shipped cancel binding clears the form and reopening replaces all item metadata', () => {
    const {app: a, context} = setup();
    fill(a, 'old note');
    const expression = fs.readFileSync('static/index.html', 'utf8').match(/@click="(showConsumeModal = false; consumeForm = \{\};)"/);
    assert.ok(expression, 'consumption cancel binding must remain present');
    vm.runInContext('with (app) {' + expression[1] + '}', context);
    assert.equal(a.showConsumeModal, false);
    assert.deepEqual(plain(a.consumeForm), {});
    a.consumeItem({id: 43, part_number: 'P-B', description: 'Another part', store_name: 'Other', quantity: 3});
    assert.deepEqual(plain(a.consumeForm), {inventory_id: 43, part_number: 'P-B', description: 'Another part',
        store_name: 'Other', available_quantity: 3, quantity: 1, work_order_number: '', notes: ''});
    assert.equal(a.showConsumeModal, true);
});

for (const notes of ['', '  Technician note  ']) {
    for (const selected of [false, true]) {
        test(`consumption with ${notes ? 'present' : 'blank'} notes and ${selected ? 'selected' : 'no selected'} store preserves save lifecycle`, async () => {
            const {app: a, timers} = setup();
            const calls = [];
            fill(a, notes);
            a.selectedStore = selected ? {id: 7, name: 'Same name'} : null;
            a.storeInventory = [{store_id: 99, quantity: 1}];
            a.error = 'old error';
            a.successMessage = 'old success';
            a.apiCall = async (path, options) => {
                assert.equal(a.loading, true);
                assert.equal(a.error, '');
                assert.equal(a.successMessage, '');
                calls.push(['write', path, options.method, JSON.parse(options.body)]);
                return {message: 'Consumed for WO-42'};
            };
            a.loadInventory = async () => {
                assert.equal(a.showConsumeModal, false);
                assert.deepEqual(plain(a.consumeForm), {});
                assert.equal(a.successMessage, 'Consumed for WO-42');
                assert.equal(timers.length, 0);
                a.inventory = [
                    {store_id: 7, store_name: 'Same name', quantity: 3},
                    {store_id: 8, store_name: 'Same name', quantity: 9},
                ];
                calls.push('inventory');
            };
            a.loadMovements = async () => { assert.equal(timers.length, 0); calls.push('movements'); };
            a.loadStats = async () => { assert.equal(timers.length, 0); calls.push('stats'); };
            a.loadEquipmentStats = async () => { assert.equal(timers.length, 0); calls.push('equipment'); };
            await a.consumeStock();
            assert.deepEqual(calls, [
                ['write', '/inventory/consume', 'POST', {inventory_id: 42, quantity: 2, work_order_number: 'WO-42', notes: notes || null}],
                'inventory', 'movements', 'stats', 'equipment',
            ]);
            assert.equal(a.storeInventory.length, 1);
            assert.equal(a.storeInventory[0].store_id, selected ? 7 : 99);
            assert.equal(a.loading, false);
            assert.equal(a.error, '');
            assert.equal(timers.length, 1);
            assert.equal(timers[0].delay, 5000);
            assert.deepEqual(timers[0].storeIds, [selected ? 7 : 99]);
            timers[0].callback();
            assert.equal(a.successMessage, '');
        });
    }
}

test('pending consumption write retains form/modal and shared loading', async () => {
    const {app: a} = setup();
    fill(a);
    const form = a.consumeForm;
    let release;
    let writes = 0;
    a.apiCall = async () => { writes++; return new Promise(resolve => { release = resolve; }); };
    a.loadInventory = a.loadMovements = a.refreshDashboard = async () => {};
    const pending = a.consumeStock();
    assert.equal(a.loading, true);
    assert.equal(a.consumeForm, form);
    assert.equal(a.showConsumeModal, true);
    assert.equal(writes, 1);
    release({message: 'Consumed'});
    await pending;
    assert.equal(a.loading, false);
});

test('consumption write rejection retains input and modal without refresh or timer', async () => {
    const {app: a, timers} = setup();
    fill(a, 'keep note');
    const form = a.consumeForm;
    const before = plain(form);
    let writes = 0;
    a.apiCall = async () => { writes++; throw new Error('Insufficient stock'); };
    let refreshes = 0;
    a.loadInventory = a.loadMovements = a.refreshDashboard = async () => { refreshes++; };
    await a.consumeStock();
    assert.equal(writes, 1);
    assert.equal(refreshes, 0);
    assert.equal(a.consumeForm, form);
    assert.deepEqual(plain(form), before);
    assert.equal(a.showConsumeModal, true);
    assert.equal(a.error, 'Failed to consume stock: Insufficient stock');
    assert.equal(a.successMessage, '');
    assert.equal(a.loading, false);
    assert.equal(timers.length, 0);
});

for (const stage of ['inventory', 'movements', 'dashboard']) {
    test(`consumption refresh rejection at ${stage} retains saved/cleared state`, async () => {
        const {app: a, timers} = setup();
        fill(a);
        const calls = [];
        a.selectedStore = {id: 7};
        a.storeInventory = [{store_id: 7, quantity: 5}];
        const oldRows = a.storeInventory;
        a.apiCall = async () => { calls.push('write'); return {message: 'Consumed'}; };
        for (const [provider, name] of [['loadInventory', 'inventory'], ['loadMovements', 'movements'], ['refreshDashboard', 'dashboard']]) {
            a[provider] = async () => {
                calls.push(name);
                if (stage === name) throw new Error('Refresh failed');
            };
        }
        await a.consumeStock();
        const order = ['write', 'inventory', 'movements', 'dashboard'];
        assert.deepEqual(calls, order.slice(0, order.indexOf(stage) + 1));
        assert.deepEqual(plain(a.consumeForm), {});
        assert.equal(a.showConsumeModal, false);
        assert.equal(a.successMessage, 'Consumed');
        assert.equal(a.error, 'Failed to consume stock: Refresh failed');
        assert.equal(a.storeInventory, oldRows);
        assert.equal(a.loading, false);
        assert.equal(timers.length, 0);
    });
}

test('real dashboard starts both refreshes and completes before selected-store filtering and timer', {timeout: 5000}, async () => {
    const {app: a, timers} = setup();
    fill(a);
    a.selectedStore = {id: 7};
    a.storeInventory = [{store_id: 99, quantity: 1}];
    let releaseStats;
    let releaseEquipment;
    let dashboardStarted;
    const started = new Promise(resolve => { dashboardStarted = resolve; });
    a.apiCall = async () => ({message: 'Consumed'});
    a.loadInventory = async () => { a.inventory = [{store_id: 7, quantity: 3}]; };
    a.loadMovements = async () => {};
    a.loadStats = () => new Promise(resolve => { releaseStats = resolve; });
    a.loadEquipmentStats = () => new Promise(resolve => { releaseEquipment = resolve; dashboardStarted(); });
    let finished = false;
    const pending = a.consumeStock().then(() => { finished = true; });
    await started;
    assert.equal(typeof releaseStats, 'function');
    assert.equal(typeof releaseEquipment, 'function');
    assert.equal(finished, false);
    assert.equal(a.storeInventory[0].store_id, 99);
    assert.equal(timers.length, 0);
    releaseStats();
    await Promise.resolve();
    assert.equal(finished, false);
    assert.equal(a.storeInventory[0].store_id, 99);
    assert.equal(timers.length, 0);
    releaseEquipment();
    await pending;
    assert.equal(a.storeInventory[0].store_id, 7);
    assert.equal(timers.length, 1);
    assert.deepEqual(timers[0].storeIds, [7]);
});

test('consumption preserves real inventory-refresh swallowed-error and loading semantics', async () => {
    const {app: a, timers} = setup();
    fill(a);
    const calls = [];
    a.apiCall = async (path, options) => {
        calls.push(path);
        if (options) return {message: 'Consumed'};
        assert.equal(path, '/inventory');
        throw new Error('Offline');
    };
    a.loadMovements = async () => {
        assert.equal(a.loading, false);
        assert.equal(a.inventoryLoadFailed, true);
        calls.push('movements');
    };
    a.loadStats = async () => { calls.push('stats'); };
    a.loadEquipmentStats = async () => { calls.push('equipment'); };
    await a.consumeStock();
    assert.deepEqual(calls, ['/inventory/consume', '/inventory', 'movements', 'stats', 'equipment']);
    assert.equal(a.error, 'Inventory could not refresh. Retry or reload the page: Offline');
    assert.equal(a.successMessage, 'Consumed');
    assert.equal(a.loading, false);
    assert.equal(timers.length, 1);
    assert.equal(timers[0].delay, 5000);
});

test('shipped consumption forms remain independent through replacement and clearing', async () => {
    const {app: first} = setup();
    const {app: second} = setup();
    const secondForm = second.consumeForm;
    fill(first, 'first note');
    assert.equal(second.consumeForm, secondForm);
    assert.equal(second.consumeForm.work_order_number, '');
    assert.equal(second.consumeForm.notes, '');
    assert.equal(second.showConsumeModal, false);
    first.apiCall = async () => ({message: 'Consumed'});
    first.loadInventory = first.loadMovements = first.refreshDashboard = async () => {};
    await first.consumeStock();
    assert.deepEqual(plain(first.consumeForm), {});
    assert.equal(second.consumeForm, secondForm);
    assert.equal(second.consumeForm.available_quantity, 0);
});
