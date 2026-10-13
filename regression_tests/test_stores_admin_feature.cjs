const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const plain = value => JSON.parse(JSON.stringify(value));
const defaults = {name: '', type: 'customer_site', location: '', assigned_user_id: ''};
const csv = 'name,type,location,assigned_user_email\nTarget,custom_type,Kitale,user@example.test';

function setup(globals = {}) {
    const c = vm.createContext({FormData, File, ...globals});
    vm.runInContext(fs.readFileSync('static/js/shared/features.js', 'utf8'), c);
    const filename = 'static/js/inventory/stores-admin.js';
    assert.ok(fs.existsSync(filename), 'stores admin feature must exist');
    vm.runInContext(fs.readFileSync(filename, 'utf8'), c, {filename});
    return c;
}

test('store administration owns exactly nine properties with independent forms', () => {
    const c = setup();
    const first = c.storesAdminFeature();
    const second = c.storesAdminFeature();
    assert.deepEqual(Object.keys(first).sort(), ['storeForm', 'showStoreModal', 'editingStore',
        'createStore', 'editStore', 'updateStore', 'deleteStore', 'importStores', 'downloadStoreTemplate'].sort());
    assert.deepEqual(plain(first.storeForm), defaults);
    assert.equal(first.showStoreModal, false);
    assert.equal(first.editingStore, null);
    first.storeForm.name = 'FIRST';
    first.showStoreModal = true;
    first.editingStore = 42;
    assert.deepEqual(plain(second.storeForm), defaults);
    assert.equal(second.showStoreModal, false);
    assert.equal(second.editingStore, null);
});

test('edit store replaces form while retaining custom type and optional-field fallbacks', () => {
    const c = setup();
    const app = c.composeInventoryFeatures({}, c.storesAdminFeature());
    const original = app.storeForm;
    app.editStore({id: 42, name: 'Target', type: 'custom_type', location: null, assigned_user_id: null});
    assert.notEqual(app.storeForm, original);
    assert.deepEqual(plain(app.storeForm), {name: 'Target', type: 'custom_type', location: '', assigned_user_id: ''});
    assert.equal(app.editingStore, 42);
    assert.equal(app.showStoreModal, true);
    app.editStore({id: 43, name: 'Other', type: 'engineer', location: 'Kitale', assigned_user_id: 3});
    assert.deepEqual(plain(app.storeForm), {name: 'Other', type: 'engineer', location: 'Kitale', assigned_user_id: 3});
    assert.equal(app.editingStore, 43);
});

for (const operation of ['create', 'update', 'archive', 'import']) {
    test(`${operation} uses core providers with the composed receiver in its existing order`, async () => {
        const calls = [];
        let callback;
        const c = setup({confirm(message) {
            assert.equal(message, 'Archive store Target? History will be preserved.');
            calls.push('confirm');
            return true;
        }, setTimeout(fn, delay) { calls.push(['timer', delay]); callback = fn; }});
        const app = c.composeInventoryFeatures({
            loading: false, error: 'old error', successMessage: 'old success', showArchivedPanel: true,
            selectedStore: {id: 42}, storeInventory: [{store_id: 42}], showStoreInventoryPanel: true,
            async apiCall(path, options) {
                assert.equal(this, app);
                assert.equal(this.loading, true);
                assert.equal(this.error, '');
                assert.equal(this.successMessage, '');
                if (options.body instanceof FormData) {
                    assert.deepEqual([...options.body.keys()], ['file']);
                    assert.equal(await options.body.get('file').text(), csv);
                    calls.push(['write', path, options.method, 'multipart']);
                } else {
                    calls.push(['write', path, options.method, options.body ? JSON.parse(options.body) : null]);
                }
                return {message: operation === 'import' ? 'Stores imported' : 'Archived', errors: ['Row 2 rejected']};
            },
            async loadStores() {
                assert.equal(this, app);
                if (operation === 'archive') {
                    assert.equal(this.selectedStore, null);
                    assert.equal(this.storeInventory.length, 0);
                    assert.equal(this.showStoreInventoryPanel, false);
                }
                calls.push('stores');
            },
            async loadInventory() { assert.equal(this, app); calls.push('inventory'); },
            async loadStats() { assert.equal(this, app); calls.push('stats'); },
            async loadArchivedRecords() { assert.equal(this, app); calls.push('archived'); },
        }, c.storesAdminFeature());
        app.storeForm = {name: 'Target', type: 'custom_type', location: 'Kitale', assigned_user_id: '3'};
        const body = {name: 'Target', type: 'custom_type', location: 'Kitale', assigned_user_id: 3};
        if (operation === 'create') {
            app.showStoreModal = true;
            await app.createStore();
            assert.deepEqual(calls, [['write', '/stores', 'POST', body], 'stores', 'stats', ['timer', 3000]]);
            assert.deepEqual(plain(app.storeForm), defaults);
            assert.equal(app.showStoreModal, false);
            assert.equal(app.successMessage, 'Store created successfully!');
        } else if (operation === 'update') {
            app.showStoreModal = true;
            app.editingStore = 42;
            await app.updateStore();
            assert.deepEqual(calls, [['write', '/stores/42', 'PUT', body], 'stores', 'inventory', 'stats', ['timer', 3000]]);
            assert.deepEqual(plain(app.storeForm), defaults);
            assert.equal(app.showStoreModal, false);
            assert.equal(app.editingStore, null);
            assert.equal(app.successMessage, 'Store updated successfully!');
        } else if (operation === 'archive') {
            await app.deleteStore(42, 'Target');
            assert.deepEqual(calls, ['confirm', ['write', '/stores/42', 'DELETE', null], 'stores', 'stats', 'inventory', 'archived', ['timer', 3000]]);
            assert.equal(app.successMessage, 'Archived');
        } else {
            const event = {target: {files: [new File([csv], 'stores.csv', {type: 'text/csv'})], value: 'stores.csv'}};
            await app.importStores(event);
            assert.deepEqual(calls, [['write', '/stores/bulk-import', 'POST', 'multipart'], 'stores', ['timer', 5000]]);
            assert.equal(event.target.value, '');
            assert.equal(app.successMessage, 'Stores imported');
            assert.equal(app.error, 'Some errors occurred:\nRow 2 rejected');
        }
        assert.equal(app.loading, false);
        if (operation !== 'import') assert.equal(app.error, '');
        callback();
        assert.equal(app.successMessage, '');
        assert.equal(app.error, '');
    });
}

test('store template preserves exact CSV, type and filename', () => {
    const calls = [];
    const anchor = {click() { calls.push(['click', this.href, this.download]); }};
    const c = setup({
        Blob: class { constructor(parts, options) { this.parts = parts; this.options = options; } },
        URL: {createObjectURL(blob) { calls.push(['blob', plain(blob.parts), plain(blob.options)]); return 'blob:stores'; }},
        document: {createElement(tag) { assert.equal(tag, 'a'); return anchor; }},
    });
    c.storesAdminFeature().downloadStoreTemplate();
    assert.deepEqual(calls, [
        ['blob', ['name,type,location,assigned_user_email\nSample Store,customer_site,Sample Location,user@example.com'], {type: 'text/csv'}],
        ['click', 'blob:stores', 'stores_import_template.csv'],
    ]);
});
