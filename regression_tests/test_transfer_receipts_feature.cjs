const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

function context() {
    const c = vm.createContext({confirm: () => true});
    vm.runInContext(fs.readFileSync('static/js/shared/features.js', 'utf8'), c);
    const filename = 'static/js/inventory/transfer-receipts.js';
    assert.ok(fs.existsSync(filename), 'transfer receipt feature must exist');
    vm.runInContext(fs.readFileSync(filename, 'utf8'), c, {filename});
    return c;
}

test('transfer receipts own exactly four properties and allocate independent pending arrays', () => {
    const c = context();
    const first = c.transferReceiptsFeature();
    const second = c.transferReceiptsFeature();
    assert.deepEqual(Object.keys(first).sort(), ['confirmTransfer', 'loadPendingTransfers', 'pendingTransfers', 'refreshTransfers']);
    assert.equal(first.pendingTransfers.length, 0);
    assert.equal(second.pendingTransfers.length, 0);
    first.pendingTransfers.push({id: 42});
    assert.equal(second.pendingTransfers.length, 0);
});

test('transfer reads and explicit refresh use providers on the composed receiver', async () => {
    const c = context();
    const calls = [];
    const rows = [{id: 42}];
    const app = c.composeInventoryFeatures({
        error: 'old error',
        async apiCall(path) {
            assert.equal(this, app);
            assert.equal(path, '/inventory/transfers');
            calls.push('transfers');
            return rows;
        },
        async loadStats() {
            assert.equal(this, app);
            assert.equal(this.pendingTransfers, rows);
            calls.push('stats');
        },
    }, c.transferReceiptsFeature());
    await app.loadPendingTransfers();
    assert.equal(app.pendingTransfers, rows);
    assert.equal(app.error, 'old error');
    calls.length = 0;
    await app.refreshTransfers();
    assert.equal(app.error, '');
    assert.deepEqual(calls, ['transfers', 'stats']);
});

test('receipt confirmation calls each core provider with the composed receiver', async () => {
    const c = context();
    const calls = [];
    const app = c.composeInventoryFeatures({
        loading: false, error: '', successMessage: '', selectedStore: {id: 7}, inventory: [],
        async apiCall(path, options) {
            assert.equal(this, app);
            calls.push(path);
            if (!options) return [{id: 43}];
            assert.equal(options.method, 'POST');
            assert.deepEqual(JSON.parse(options.body), {confirmed: true});
            return {message: 'Received'};
        },
        async loadInventory() {
            assert.equal(this, app);
            this.inventory = [{store_id: 7, quantity: 2}, {store_id: 8, quantity: 3}];
            calls.push('inventory');
        },
        async loadMovements() {
            assert.equal(this, app);
            assert.equal(this.storeInventory.length, 1);
            assert.equal(this.storeInventory[0].store_id, 7);
            calls.push('movements');
        },
        async loadStats() { assert.equal(this, app); calls.push('stats'); },
    }, c.transferReceiptsFeature());
    await app.confirmTransfer({id: 42, quantity: 2, part_number: 'A', to_store_name: 'Target', can_receive: true}, 'receive');
    assert.deepEqual(calls, ['/inventory/transfers/42/receive', '/inventory/transfers', 'inventory', 'movements', 'stats']);
    assert.equal(app.successMessage, 'Received');
    assert.equal(app.loading, false);
});
