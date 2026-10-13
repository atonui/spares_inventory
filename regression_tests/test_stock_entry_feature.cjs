const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const plain = value => JSON.parse(JSON.stringify(value));

function setup(globals = {}) {
    const c = vm.createContext(globals);
    vm.runInContext(fs.readFileSync('static/js/shared/features.js', 'utf8'), c);
    const filename = 'static/js/inventory/stock-entry.js';
    assert.ok(fs.existsSync(filename), 'stock entry feature must exist');
    vm.runInContext(fs.readFileSync(filename, 'utf8'), c, {filename});
    return c;
}

const owned = ['addingStock', 'addForm', 'editForm', 'showAddModal', 'showEditModal',
    'partSearchTerm', 'filteredPartsForSelection', 'addStockToStore', 'filterPartsForSelection',
    'selectPart', 'addStock', 'editItem', 'updateStock'].sort();

const parts = [
    {id: 1, part_number: 'VALVE-A', description: 'Water control', category: 'Cooling'},
    {id: 2, part_number: 'PCB-B', description: 'Grid controller', category: 'Electronics'},
];

test('stock entry owns thirteen properties with fresh forms and picker defaults', () => {
    const c = setup();
    const first = c.stockEntryFeature();
    const second = c.stockEntryFeature();
    assert.deepEqual(Object.keys(first).sort(), owned);
    for (const key of ['addingStock', 'showAddModal', 'showEditModal']) assert.equal(first[key], false);
    assert.equal(first.partSearchTerm, '');
    assert.deepEqual(plain(first.filteredPartsForSelection), []);
    assert.deepEqual(plain(first.addForm), {part_id: '', store_id: '', quantity: '', work_order_number: ''});
    assert.deepEqual(plain(first.editForm), {inventory_id: '', new_quantity: ''});
    first.addForm.quantity = 2;
    first.editForm.new_quantity = 0;
    first.filteredPartsForSelection.push(parts[0]);
    first.partSearchTerm = 'valve';
    first.addingStock = first.showAddModal = first.showEditModal = true;
    assert.deepEqual(plain(second.addForm), {part_id: '', store_id: '', quantity: '', work_order_number: ''});
    assert.deepEqual(plain(second.editForm), {inventory_id: '', new_quantity: ''});
    assert.equal(second.filteredPartsForSelection.length, 0);
    assert.equal(second.partSearchTerm, '');
    for (const key of ['addingStock', 'showAddModal', 'showEditModal']) assert.equal(second[key], false);
});

test('store opener retains the add form and aliases the full catalog after clearing selection', async () => {
    const c = setup();
    const app = c.composeInventoryFeatures({parts, error: 'keep'}, c.stockEntryFeature());
    const form = app.addForm;
    Object.assign(form, {part_id: 1, store_id: 9, quantity: 5, work_order_number: 'OLD'});
    app.partSearchTerm = 'old';
    await app.addStockToStore({id: 7});
    assert.equal(app.addForm, form);
    assert.deepEqual(plain(form), {part_id: '', store_id: 7, quantity: '', work_order_number: ''});
    assert.equal(app.filteredPartsForSelection, parts);
    assert.equal(app.partSearchTerm, '');
    assert.equal(app.showAddModal, true);
    assert.equal(app.error, 'keep');
});

test('picker search matches all three catalog fields and preserves empty-search aliasing', () => {
    const c = setup();
    const app = c.composeInventoryFeatures({parts}, c.stockEntryFeature());
    for (const [term, id] of [['valve', 1], ['WATER', 1], ['coolING', 1], ['grid', 2], ['electronics', 2]]) {
        app.partSearchTerm = term;
        app.filterPartsForSelection();
        assert.equal(app.filteredPartsForSelection.length, 1);
        assert.equal(app.filteredPartsForSelection[0].id, id);
    }
    app.partSearchTerm = 'not-found';
    app.filterPartsForSelection();
    assert.equal(app.filteredPartsForSelection.length, 0);
    app.partSearchTerm = '';
    app.filterPartsForSelection();
    assert.equal(app.filteredPartsForSelection, parts);
    const form = app.addForm;
    app.selectPart(parts[1]);
    assert.equal(app.addForm, form);
    assert.equal(form.part_id, 2);
    assert.equal(app.partSearchTerm, 'PCB-B - Grid controller');
});

test('edit opener retains its form and opens a zero-quantity item', async () => {
    const c = setup();
    const app = c.composeInventoryFeatures({}, c.stockEntryFeature());
    const form = app.editForm;
    await app.editItem({id: 42, quantity: 0});
    assert.equal(app.editForm, form);
    assert.deepEqual(plain(form), {inventory_id: 42, new_quantity: 0});
    assert.equal(app.showEditModal, true);
});

for (const operation of ['add', 'update']) {
    test(`${operation} save accesses core providers on the composed receiver`, async () => {
        const calls = [];
        let callback;
        const c = setup({setTimeout(fn, delay) { calls.push(['timer', delay]); callback = fn; }});
        const store = {id: 7};
        const app = c.composeInventoryFeatures({
            loading: false, error: 'old error', successMessage: 'old success', selectedStore: store, parts,
            async apiCall(path, options) {
                assert.equal(this, app);
                calls.push(['write', path, options.method, JSON.parse(options.body)]);
                return {};
            },
            async loadInventory() {
                assert.equal(this, app);
                assert.equal(operation === 'add' ? this.showAddModal : this.showEditModal, false);
                calls.push('inventory');
            },
            async loadStats() { assert.equal(this, app); calls.push('stats'); },
            async loadEquipmentStats() { assert.equal(this, app); calls.push('equipment'); },
            async viewStoreInventory(selected) {
                assert.equal(this, app);
                assert.equal(selected, store);
                calls.push('store');
            },
        }, c.stockEntryFeature());
        if (operation === 'add') {
            app.addForm = {part_id: '1', store_id: '7', quantity: '2', work_order_number: ''};
            app.partSearchTerm = 'old';
            app.showAddModal = true;
            await app.addStock();
            assert.deepEqual(calls, [
                ['write', '/inventory/add', 'POST', {part_id: '1', store_id: '7', quantity: 2, work_order_number: null}],
                'inventory', 'stats', 'equipment', 'store', ['timer', 3000],
            ]);
            assert.deepEqual(plain(app.addForm), {part_id: '', store_id: '', quantity: '', work_order_number: ''});
            assert.equal(app.partSearchTerm, '');
            assert.equal(app.addingStock, false);
            assert.equal(app.successMessage, 'Stock added successfully');
        } else {
            app.editForm = {inventory_id: '42', new_quantity: '0'};
            app.showEditModal = true;
            await app.updateStock();
            assert.deepEqual(calls, [
                ['write', '/inventory/update', 'PUT', {inventory_id: 42, new_quantity: 0}],
                'inventory', 'stats', ['timer', 3000],
            ]);
            assert.deepEqual(plain(app.editForm), {inventory_id: '', new_quantity: ''});
            assert.equal(app.loading, false);
            assert.equal(app.successMessage, 'Stock updated successfully!');
        }
        assert.equal(app.error, '');
        callback();
        assert.equal(app.successMessage, '');
    });
}
