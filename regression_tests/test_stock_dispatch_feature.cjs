const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const plain = value => JSON.parse(JSON.stringify(value));

function setup(globals = {}) {
    const c = vm.createContext(globals);
    for (const file of ['static/js/shared/features.js', 'static/js/inventory/transfer-receipts.js']) {
        vm.runInContext(fs.readFileSync(file, 'utf8'), c, {filename: file});
    }
    const filename = 'static/js/inventory/stock-dispatch.js';
    assert.ok(fs.existsSync(filename), 'stock dispatch feature must exist');
    vm.runInContext(fs.readFileSync(filename, 'utf8'), c, {filename});
    return c;
}

test('stock dispatch owns exactly four properties with fresh form defaults', () => {
    const c = setup();
    const first = c.stockDispatchFeature();
    const second = c.stockDispatchFeature();
    assert.deepEqual(Object.keys(first).sort(), ['showTransferModal', 'transferForm', 'transferItem', 'transferStock']);
    assert.equal(first.showTransferModal, false);
    assert.deepEqual(plain(first.transferForm), {inventory_id: '', to_store_id: '', quantity: ''});
    first.transferForm.quantity = 4;
    first.showTransferModal = true;
    assert.deepEqual(plain(second.transferForm), {inventory_id: '', to_store_id: '', quantity: ''});
    assert.equal(second.showTransferModal, false);
});

test('manual opener retains the form object and clears replenishment fields', async () => {
    const c = setup();
    const app = c.composeInventoryFeatures({error: 'keep'}, c.stockDispatchFeature());
    const form = app.transferForm;
    Object.assign(form, {inventory_id: 1, to_store_id: 7, quantity: 4, replenishment: true, max_quantity: 4});
    await app.transferItem({id: 42});
    assert.equal(app.transferForm, form);
    assert.deepEqual(plain(form), {inventory_id: 42, to_store_id: '', quantity: 1, replenishment: false, max_quantity: null});
    assert.equal(app.showTransferModal, true);
    assert.equal(app.error, 'keep');
});

test('dispatch uses core and receipt providers on the composed receiver in refresh order', async () => {
    const calls = [];
    let callback;
    const c = setup({setTimeout(fn, delay) { calls.push(['timer', delay]); callback = fn; }});
    const app = c.composeInventoryFeatures({
        loading: false, error: '', successMessage: '',
        async apiCall(path, options) {
            assert.equal(this, app);
            if (options) {
                calls.push(['write', path, options.method, JSON.parse(options.body)]);
                return {message: 'Dispatched; awaiting receipt'};
            }
            assert.equal(path, '/inventory/transfers');
            calls.push('transfers');
            return [{id: 42}];
        },
        async loadInventory() {
            assert.equal(this, app);
            assert.equal(this.showTransferModal, false);
            assert.deepEqual(plain(this.transferForm), {inventory_id: '', to_store_id: '', quantity: ''});
            calls.push('inventory');
        },
        async loadStats() { assert.equal(this, app); calls.push('stats'); },
    }, c.transferReceiptsFeature(), c.stockDispatchFeature());
    app.transferForm = {inventory_id: '1', to_store_id: '7', quantity: '4'};
    app.showTransferModal = true;
    await app.transferStock();
    assert.deepEqual(calls, [
        ['write', '/inventory/transfer', 'POST', {inventory_id: 1, to_store_id: 7, quantity: 4}],
        'inventory', 'stats', 'transfers', ['timer', 3000],
    ]);
    assert.equal(app.pendingTransfers[0].id, 42);
    assert.equal(app.successMessage, 'Dispatched; awaiting receipt');
    assert.equal(app.loading, false);
    callback();
    assert.equal(app.successMessage, '');
});
