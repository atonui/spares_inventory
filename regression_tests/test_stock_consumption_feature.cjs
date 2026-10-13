const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const plain = value => JSON.parse(JSON.stringify(value));

function setup(globals = {}) {
    const c = vm.createContext(globals);
    vm.runInContext(fs.readFileSync('static/js/shared/features.js', 'utf8'), c);
    const filename = 'static/js/inventory/stock-consumption.js';
    assert.ok(fs.existsSync(filename), 'stock consumption feature must exist');
    vm.runInContext(fs.readFileSync(filename, 'utf8'), c, {filename});
    return c;
}

const defaults = {inventory_id: '', part_number: '', description: '', store_name: '',
    available_quantity: 0, quantity: '', work_order_number: '', notes: ''};
const item = {id: 42, part_number: 'P-A', description: 'Test part', store_name: 'Target', quantity: 5};

test('stock consumption owns exactly four properties with fresh form defaults', () => {
    const c = setup();
    const first = c.stockConsumptionFeature();
    const second = c.stockConsumptionFeature();
    assert.deepEqual(Object.keys(first).sort(), ['consumeForm', 'consumeItem', 'consumeStock', 'showConsumeModal']);
    assert.equal(first.showConsumeModal, false);
    assert.deepEqual(plain(first.consumeForm), defaults);
    first.consumeForm.work_order_number = 'OLD';
    first.consumeForm.notes = 'old note';
    first.showConsumeModal = true;
    assert.deepEqual(plain(second.consumeForm), defaults);
    assert.equal(second.showConsumeModal, false);
});

test('consumption opener replaces all metadata and works after a cleared form', () => {
    const c = setup();
    const app = c.composeInventoryFeatures({}, c.stockConsumptionFeature());
    const oldForm = app.consumeForm;
    oldForm.work_order_number = 'OLD';
    oldForm.notes = 'old note';
    app.consumeItem(item);
    assert.notEqual(app.consumeForm, oldForm);
    assert.deepEqual(plain(app.consumeForm), {inventory_id: 42, part_number: 'P-A', description: 'Test part',
        store_name: 'Target', available_quantity: 5, quantity: 1, work_order_number: '', notes: ''});
    assert.equal(app.showConsumeModal, true);
    app.showConsumeModal = false;
    app.consumeForm = {};
    app.consumeItem({...item, id: 43, part_number: 'P-B', description: 'Another part', store_name: 'Other', quantity: 3});
    assert.deepEqual(plain(app.consumeForm), {inventory_id: 43, part_number: 'P-B', description: 'Another part',
        store_name: 'Other', available_quantity: 3, quantity: 1, work_order_number: '', notes: ''});
    assert.equal(app.showConsumeModal, true);
});

test('consumption save calls core providers with the composed receiver and filters before its timer', async () => {
    const calls = [];
    let callback;
    const c = setup({setTimeout(fn, delay) {
        assert.equal(app.storeInventory.length, 1);
        assert.equal(app.storeInventory[0].store_id, 7);
        calls.push(['timer', delay]);
        callback = fn;
    }});
    const app = c.composeInventoryFeatures({
        loading: false, error: 'old error', successMessage: 'old success', inventory: [], selectedStore: {id: 7}, storeInventory: [],
        async apiCall(path, options) {
            assert.equal(this, app);
            assert.equal(this.loading, true);
            assert.equal(this.error, '');
            assert.equal(this.successMessage, '');
            calls.push(['write', path, options.method, JSON.parse(options.body)]);
            return {message: 'Consumption saved'};
        },
        async loadInventory() {
            assert.equal(this, app);
            assert.equal(this.showConsumeModal, false);
            assert.deepEqual(plain(this.consumeForm), {});
            this.inventory = [{store_id: 7, quantity: 3}, {store_id: 8, quantity: 9}];
            calls.push('inventory');
        },
        async loadMovements() { assert.equal(this, app); calls.push('movements'); },
        async refreshDashboard() { assert.equal(this, app); calls.push('dashboard'); },
    }, c.stockConsumptionFeature());
    app.consumeItem(item);
    Object.assign(app.consumeForm, {inventory_id: '42', quantity: '2', work_order_number: ' WO-42 ', notes: ''});
    await app.consumeStock();
    assert.deepEqual(calls, [
        ['write', '/inventory/consume', 'POST', {inventory_id: 42, quantity: 2, work_order_number: 'WO-42', notes: null}],
        'inventory', 'movements', 'dashboard', ['timer', 5000],
    ]);
    assert.equal(app.successMessage, 'Consumption saved');
    assert.equal(app.loading, false);
    callback();
    assert.equal(app.successMessage, '');
});
