const {test} = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const {loadPageScripts} = require('./helpers/frontend.cjs');
const plain = value => JSON.parse(JSON.stringify(value));

function setup() {
    const timers = [];
    const c = vm.createContext({console, setTimeout(callback, delay) { timers.push({callback, delay}); }});
    loadPageScripts('index.html', c);
    return {app: c.inventoryApp(), timers};
}

const addDefaults = {part_id: '', store_id: '', quantity: '', work_order_number: ''};
const editDefaults = {inventory_id: '', new_quantity: ''};

for (const workOrder of ['', 'WO-42']) {
    for (const selected of [false, true]) {
        test(`add stock with ${workOrder || 'blank work order'} and ${selected ? 'selected store' : 'no selected store'} preserves its lifecycle`, async () => {
            const {app: a, timers} = setup();
            const calls = [];
            const store = {id: 7, name: 'Same name'};
            a.selectedStore = selected ? store : null;
            a.addForm = {part_id: '1', store_id: '7', quantity: '2', work_order_number: workOrder};
            a.showAddModal = true;
            a.partSearchTerm = 'old search';
            a.error = 'old error';
            a.successMessage = 'old success';
            a.apiCall = async (path, options) => {
                assert.equal(a.addingStock, true);
                assert.equal(a.loading, false);
                assert.equal(a.error, '');
                assert.equal(a.successMessage, '');
                calls.push(['write', path, options.method, JSON.parse(options.body)]);
                return {};
            };
            a.loadInventory = async () => {
                assert.equal(a.showAddModal, false);
                assert.deepEqual(plain(a.addForm), addDefaults);
                assert.equal(a.partSearchTerm, '');
                assert.equal(a.successMessage, 'Stock added successfully');
                assert.equal(timers.length, 0);
                a.inventory = [
                    {id: 1, store_id: 7, store_name: 'Same name', quantity: 2},
                    {id: 2, store_id: 8, store_name: 'Same name', quantity: 9},
                ];
                calls.push('inventory');
            };
            a.loadStats = async () => { assert.equal(timers.length, 0); calls.push('stats'); };
            a.loadEquipmentStats = async () => { assert.equal(timers.length, 0); calls.push('equipment'); };
            const viewStore = a.viewStoreInventory;
            a.viewStoreInventory = async function(value) {
                assert.equal(this, a);
                assert.equal(value, store);
                assert.equal(timers.length, 0);
                calls.push('store');
                return viewStore.call(this, value);
            };
            await a.addStock();
            assert.deepEqual(calls, [
                ['write', '/inventory/add', 'POST', {part_id: '1', store_id: '7', quantity: 2, work_order_number: workOrder || null}],
                'inventory', 'stats', 'equipment', ...(selected ? ['store'] : []),
            ]);
            if (selected) {
                assert.equal(a.selectedStore, store);
                assert.equal(a.showStoreInventoryPanel, true);
                assert.equal(a.storeInventory.length, 1);
                assert.equal(a.storeInventory[0].store_id, 7);
            } else {
                assert.equal(a.showStoreInventoryPanel, false);
            }
            assert.equal(a.addingStock, false);
            assert.equal(a.error, '');
            assert.equal(timers.length, 1);
            assert.equal(timers[0].delay, 3000);
            timers[0].callback();
            assert.equal(a.successMessage, '');
        });
    }
}

for (const quantity of ['0', '5']) {
    test(`quantity adjustment preserves parsed payload for ${quantity}`, async () => {
        const {app: a, timers} = setup();
        const calls = [];
        a.editForm = {inventory_id: '42', new_quantity: quantity};
        a.showEditModal = true;
        a.apiCall = async (path, options) => {
            assert.equal(a.loading, true);
            assert.equal(a.addingStock, false);
            calls.push(['write', path, options.method, JSON.parse(options.body)]);
            return {};
        };
        a.loadInventory = async () => {
            assert.equal(a.showEditModal, false);
            assert.deepEqual(plain(a.editForm), editDefaults);
            assert.equal(a.successMessage, 'Stock updated successfully!');
            assert.equal(timers.length, 0);
            calls.push('inventory');
        };
        a.loadStats = async () => { assert.equal(timers.length, 0); calls.push('stats'); };
        await a.updateStock();
        assert.deepEqual(calls, [
            ['write', '/inventory/update', 'PUT', {inventory_id: 42, new_quantity: Number(quantity)}],
            'inventory', 'stats',
        ]);
        assert.equal(a.loading, false);
        assert.equal(timers.length, 1);
        assert.equal(timers[0].delay, 3000);
        timers[0].callback();
        assert.equal(a.successMessage, '');
    });
}

for (const operation of ['add', 'update']) {
    const formKey = operation === 'add' ? 'addForm' : 'editForm';
    const modalKey = operation === 'add' ? 'showAddModal' : 'showEditModal';
    const busyKey = operation === 'add' ? 'addingStock' : 'loading';
    const method = operation === 'add' ? 'addStock' : 'updateStock';
    const initialForm = operation === 'add'
        ? {part_id: '1', store_id: '7', quantity: '2', work_order_number: 'WO-42'}
        : {inventory_id: '42', new_quantity: '0'};
    const defaults = operation === 'add' ? addDefaults : editDefaults;
    const success = operation === 'add' ? 'Stock added successfully' : 'Stock updated successfully!';
    const failure = operation === 'add' ? 'Failed to add stock: ' : 'Failed to update stock: ';

    test(`${operation} pending write retains form/modal and uses its own busy flag`, async () => {
        const {app: a} = setup();
        let release;
        let writes = 0;
        a[formKey] = {...initialForm};
        a[modalKey] = true;
        const form = a[formKey];
        a.apiCall = async () => { writes++; return new Promise(resolve => { release = resolve; }); };
        a.loadInventory = a.loadStats = a.loadEquipmentStats = async () => {};
        const pending = a[method]();
        assert.equal(a[busyKey], true);
        assert.equal(a[operation === 'add' ? 'loading' : 'addingStock'], false);
        assert.equal(a[formKey], form);
        assert.equal(a[modalKey], true);
        assert.equal(writes, 1);
        release({});
        await pending;
        assert.equal(a[busyKey], false);
    });

    test(`${operation} write rejection retains input/modal and releases busy state`, async () => {
        const {app: a, timers} = setup();
        a[formKey] = {...initialForm};
        a[modalKey] = true;
        a.partSearchTerm = 'keep search';
        const form = a[formKey];
        let writes = 0;
        a.apiCall = async () => { writes++; throw new Error('Rejected'); };
        let refreshes = 0;
        a.loadInventory = a.loadStats = a.loadEquipmentStats = async () => { refreshes++; };
        await a[method]();
        assert.equal(writes, 1);
        assert.equal(refreshes, 0);
        assert.equal(a[formKey], form);
        assert.deepEqual(plain(form), initialForm);
        assert.equal(a[modalKey], true);
        assert.equal(a.partSearchTerm, 'keep search');
        assert.equal(a.successMessage, '');
        assert.equal(a.error, failure + 'Rejected');
        assert.equal(a[busyKey], false);
        assert.equal(timers.length, 0);
    });

    const stages = operation === 'add' ? ['inventory', 'stats', 'equipment', 'store'] : ['inventory', 'stats'];
    for (const stage of stages) {
        test(`${operation} refresh rejection at ${stage} preserves saved/reset state`, async () => {
            const {app: a, timers} = setup();
            const calls = [];
            a[formKey] = {...initialForm};
            a[modalKey] = true;
            a.partSearchTerm = 'old search';
            a.selectedStore = {id: 7};
            a.apiCall = async () => { calls.push('write'); return {}; };
            for (const [provider, name] of [['loadInventory', 'inventory'], ['loadStats', 'stats'], ['loadEquipmentStats', 'equipment'], ['viewStoreInventory', 'store']]) {
                a[provider] = async () => {
                    calls.push(name);
                    if (stage === name) throw new Error('Refresh failed');
                };
            }
            await a[method]();
            const order = ['write', ...stages];
            assert.deepEqual(calls, order.slice(0, order.indexOf(stage) + 1));
            assert.deepEqual(plain(a[formKey]), defaults);
            assert.equal(a[modalKey], false);
            if (operation === 'add') assert.equal(a.partSearchTerm, '');
            assert.equal(a.successMessage, success);
            assert.equal(a.error, failure + 'Refresh failed');
            assert.equal(a[busyKey], false);
            assert.equal(timers.length, 0);
        });
    }

    test(`${operation} preserves real inventory-refresh loading and swallowed-error behavior`, async () => {
        const {app: a, timers} = setup();
        const calls = [];
        a[formKey] = {...initialForm};
        a.apiCall = async (path, options) => {
            calls.push(path);
            if (options) return {};
            assert.equal(path, '/inventory');
            throw new Error('Offline');
        };
        a.loadStats = async () => {
            assert.equal(a.loading, false);
            assert.equal(a.inventoryLoadFailed, true);
            if (operation === 'add') assert.equal(a.addingStock, true);
            calls.push('stats');
        };
        a.loadEquipmentStats = async () => { calls.push('equipment'); };
        await a[method]();
        assert.deepEqual(calls, ['/inventory/' + operation, '/inventory', 'stats', ...(operation === 'add' ? ['equipment'] : [])]);
        assert.equal(a.error, 'Inventory could not refresh. Retry or reload the page: Offline');
        assert.equal(a.successMessage, success);
        assert.equal(a[busyKey], false);
        assert.equal(timers.length, 1);
        assert.equal(timers[0].delay, 3000);
    });
}

test('shipped add-stock picker retains catalog aliasing and exact selected label', async () => {
    const {app: a} = setup();
    a.parts = [
        {id: 1, part_number: 'VALVE-A', description: 'Water control', category: 'Cooling'},
        {id: 2, part_number: 'PCB-B', description: 'Grid controller', category: 'Electronics'},
    ];
    const form = a.addForm;
    Object.assign(form, {part_id: 2, store_id: 8, quantity: 9, work_order_number: 'OLD'});
    a.partSearchTerm = 'old';
    await a.addStockToStore({id: 7});
    assert.equal(a.addForm, form);
    assert.deepEqual(plain(form), {part_id: '', store_id: 7, quantity: '', work_order_number: ''});
    assert.equal(a.filteredPartsForSelection, a.parts);
    assert.equal(a.partSearchTerm, '');
    for (const [term, id] of [['valve', 1], ['WATER', 1], ['cOOLing', 1], ['grid', 2], ['electronics', 2]]) {
        a.partSearchTerm = term;
        a.filterPartsForSelection();
        assert.equal(a.filteredPartsForSelection.length, 1);
        assert.equal(a.filteredPartsForSelection[0].id, id);
    }
    a.partSearchTerm = 'missing';
    a.filterPartsForSelection();
    assert.equal(a.filteredPartsForSelection.length, 0);
    a.partSearchTerm = '';
    a.filterPartsForSelection();
    assert.equal(a.filteredPartsForSelection, a.parts);
    a.selectPart(a.parts[1]);
    assert.equal(a.addForm, form);
    assert.equal(a.addForm.part_id, 2);
    assert.equal(a.partSearchTerm, 'PCB-B - Grid controller');
});

test('core navigation closes add/edit modals while retaining both forms', async () => {
    const {app: a} = setup();
    const addForm = a.addForm;
    const editForm = a.editForm;
    await a.addStockToStore({id: 7});
    await a.editItem({id: 42, quantity: 0});
    assert.equal(a.showAddModal, true);
    assert.equal(a.showEditModal, true);
    a.openPanel('showInventoryPanel');
    assert.equal(a.showAddModal, false);
    assert.equal(a.showEditModal, false);
    assert.equal(a.addForm, addForm);
    assert.equal(a.editForm, editForm);
    assert.equal(a.addForm.store_id, 7);
    assert.equal(a.editForm.new_quantity, 0);
});

test('shipped stock-entry forms and initial picker arrays are independent', async () => {
    const {app: first} = setup();
    const {app: second} = setup();
    first.filteredPartsForSelection.push({id: 1});
    first.addForm.quantity = 2;
    first.editForm.new_quantity = 0;
    first.addingStock = first.showAddModal = first.showEditModal = true;
    first.partSearchTerm = 'first';
    assert.deepEqual(plain(second.addForm), addDefaults);
    assert.deepEqual(plain(second.editForm), editDefaults);
    assert.equal(second.filteredPartsForSelection.length, 0);
    assert.equal(second.partSearchTerm, '');
    assert.equal(second.addingStock, false);
    assert.equal(second.showAddModal, false);
    assert.equal(second.showEditModal, false);
});
