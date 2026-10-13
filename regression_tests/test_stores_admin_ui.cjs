const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const {loadPageScripts} = require('./helpers/frontend.cjs');
const plain = value => JSON.parse(JSON.stringify(value));
const defaults = {name: '', type: 'customer_site', location: '', assigned_user_id: ''};
const store = {id: 42, name: 'Target', type: 'custom_type', location: null, assigned_user_id: null};
const csv = 'name,type,location,assigned_user_email\nTarget,custom_type,Kitale,user@example.test';

function setup({confirm = () => true, fetch} = {}) {
    const timers = [];
    const context = vm.createContext({FormData, File, Headers, URLSearchParams, fetch, confirm,
        console: {log() {}, error() {}}, setTimeout(callback, delay) { timers.push({callback, delay}); }});
    loadPageScripts('index.html', context);
    const app = context.inventoryApp();
    context.app = app;
    return {app, context, timers};
}
function upload() { return {target: {files: [new File([csv], 'stores.csv', {type: 'text/csv'})], value: 'stores.csv'}}; }
function fill(app, operation = 'update') { app.editStore(store); if (operation === 'create') app.editingStore = null; }
const expressions = () => [...fs.readFileSync('static/index.html', 'utf8').matchAll(/@click="([^"]*)"/g)].map(m => m[1]);

test('actual store add/cancel bindings preserve mode and optional-field fallbacks', () => {
    const {app: a, context} = setup();
    a.editStore(store);
    assert.deepEqual(plain(a.storeForm), {name: 'Target', type: 'custom_type', location: '', assigned_user_id: ''});
    assert.equal(a.editingStore, 42);
    const add = expressions().find(e => e.startsWith('editingStore = null; storeForm =') && e.endsWith('showStoreModal = true'));
    assert.ok(add);
    vm.runInContext('with (app) {' + add + '}', context);
    assert.equal(a.editingStore, null);
    assert.deepEqual(plain(a.storeForm), defaults);
    assert.equal(a.showStoreModal, true);
    a.editStore({...store, location: 'Kitale', assigned_user_id: 3});
    const form = a.storeForm;
    const cancel = expressions().find(e => e === 'showStoreModal = false; editingStore = null;');
    assert.ok(cancel);
    vm.runInContext('with (app) {' + cancel + '}', context);
    assert.equal(a.showStoreModal, false);
    assert.equal(a.editingStore, null);
    assert.equal(a.storeForm, form);
    assert.equal(form.assigned_user_id, 3);
    assert.equal(form.location, 'Kitale');
});

for (const operation of ['create', 'update']) {
    for (const optional of [false, true]) {
        test(`${operation} store preserves ${optional ? 'present' : 'blank'} location/assignment and refresh order`, async () => {
            const {app: a, timers} = setup();
            fill(a, operation);
            a.storeForm.location = optional ? 'Kitale' : '';
            a.storeForm.assigned_user_id = optional ? '3' : '';
            const calls = [];
            a.apiCall = async (path, options) => {
                assert.equal(a.loading, true);
                calls.push(['write', path, options.method, JSON.parse(options.body)]);
                return {};
            };
            a.loadStores = async () => {
                assert.equal(a.showStoreModal, false);
                assert.equal(a.editingStore, null);
                assert.deepEqual(plain(a.storeForm), defaults);
                assert.equal(timers.length, 0);
                calls.push('stores');
            };
            a.loadInventory = async () => { assert.equal(timers.length, 0); calls.push('inventory'); };
            a.loadStats = async () => { assert.equal(timers.length, 0); calls.push('stats'); };
            await a[operation === 'create' ? 'createStore' : 'updateStore']();
            assert.deepEqual(calls, [
                ['write', operation === 'create' ? '/stores' : '/stores/42', operation === 'create' ? 'POST' : 'PUT',
                    {name: 'Target', type: 'custom_type', location: optional ? 'Kitale' : null, assigned_user_id: optional ? 3 : null}],
                'stores', ...(operation === 'update' ? ['inventory'] : []), 'stats',
            ]);
            assert.equal(a.successMessage, operation === 'create' ? 'Store created successfully!' : 'Store updated successfully!');
            assert.equal(a.loading, false);
            assert.equal(a.error, '');
            assert.equal(timers.length, 1);
            assert.equal(timers[0].delay, 3000);
            timers[0].callback();
            assert.equal(a.successMessage, '');
        });
    }
}

test('declining archive retains selected store and shared feedback', async () => {
    const prompts = [];
    const {app: a, timers} = setup({confirm(message) { prompts.push(message); return false; }});
    const selected = {id: 42, name: 'Target'};
    const rows = [{store_id: 42}];
    a.selectedStore = selected;
    a.storeInventory = rows;
    a.showStoreInventoryPanel = true;
    a.error = 'keep error';
    a.successMessage = 'keep success';
    let writes = 0;
    a.apiCall = async () => { writes++; };
    await a.deleteStore(42, 'Target');
    assert.deepEqual(prompts, ['Archive store Target? History will be preserved.']);
    assert.equal(writes, 0);
    assert.equal(a.selectedStore, selected);
    assert.equal(a.storeInventory, rows);
    assert.equal(a.showStoreInventoryPanel, true);
    assert.equal(a.error, 'keep error');
    assert.equal(a.successMessage, 'keep success');
    assert.equal(a.loading, false);
    assert.equal(timers.length, 0);
});

for (const selectedTarget of [false, true]) {
    for (const archivedPanel of [false, true]) {
        test(`archive ${selectedTarget ? 'selected target' : 'different ID with equal name'}, archived panel ${archivedPanel ? 'open' : 'closed'}`, async () => {
            const calls = [];
            const {app: a, timers} = setup({confirm(message) { calls.push(['confirm', message]); return true; }});
            const selected = {id: selectedTarget ? 42 : 43, name: 'Target'};
            const rows = [{store_id: selected.id, quantity: 9}];
            a.selectedStore = selected;
            a.storeInventory = rows;
            a.showStoreInventoryPanel = true;
            a.showArchivedPanel = archivedPanel;
            a.apiCall = async (path, options) => {
                assert.equal(a.selectedStore, selected);
                calls.push(['write', path, options.method]);
                assert.equal(options.body, undefined);
                return {message: 'Store archived; history preserved'};
            };
            for (const [provider, name] of [['loadStores', 'stores'], ['loadStats', 'stats'], ['loadInventory', 'inventory'], ['loadArchivedRecords', 'archived']]) {
                a[provider] = async () => {
                    assert.equal(timers.length, 0);
                    if (selectedTarget) {
                        assert.equal(a.selectedStore, null);
                        assert.equal(a.storeInventory.length, 0);
                        assert.equal(a.showStoreInventoryPanel, false);
                    } else {
                        assert.equal(a.selectedStore, selected);
                        assert.equal(a.storeInventory, rows);
                        assert.equal(a.showStoreInventoryPanel, true);
                    }
                    calls.push(name);
                };
            }
            await a.deleteStore(42, 'Target');
            assert.deepEqual(calls, [
                ['confirm', 'Archive store Target? History will be preserved.'], ['write', '/stores/42', 'DELETE'],
                'stores', 'stats', 'inventory', ...(archivedPanel ? ['archived'] : []),
            ]);
            assert.equal(a.successMessage, 'Store archived; history preserved');
            assert.equal(a.loading, false);
            assert.equal(timers.length, 1);
            assert.equal(timers[0].delay, 3000);
            timers[0].callback();
            assert.equal(a.successMessage, '');
        });
    }
}

for (const operation of ['create', 'update', 'archive']) {
    const invoke = a => operation === 'archive' ? a.deleteStore(42, 'Target') : a[operation === 'create' ? 'createStore' : 'updateStore']();
    const success = operation === 'archive' ? 'Archived' : operation === 'create' ? 'Store created successfully!' : 'Store updated successfully!';
    const failure = operation === 'archive' ? 'Failed to archive store: ' : `Failed to ${operation} store: `;
    const stages = operation === 'create' ? ['stores', 'stats'] : operation === 'update'
        ? ['stores', 'inventory', 'stats'] : ['stores', 'stats', 'inventory', 'archived'];

    test(`${operation} write rejection retains form, mode and selection`, async () => {
        const {app: a, timers} = setup();
        fill(a, operation);
        const form = a.storeForm;
        const editing = a.editingStore;
        const selected = {id: 42};
        const rows = [{store_id: 42}];
        a.selectedStore = selected;
        a.storeInventory = rows;
        a.showStoreInventoryPanel = true;
        let writes = 0;
        a.apiCall = async () => { writes++; throw new Error('Rejected'); };
        let refreshes = 0;
        for (const provider of ['loadStores', 'loadInventory', 'loadStats', 'loadArchivedRecords']) a[provider] = async () => { refreshes++; };
        await invoke(a);
        assert.equal(writes, 1);
        assert.equal(refreshes, 0);
        assert.equal(a.storeForm, form);
        assert.equal(a.editingStore, editing);
        assert.equal(a.showStoreModal, true);
        assert.equal(a.selectedStore, selected);
        assert.equal(a.storeInventory, rows);
        assert.equal(a.showStoreInventoryPanel, true);
        assert.equal(a.error, failure + 'Rejected');
        assert.equal(a.successMessage, '');
        assert.equal(a.loading, false);
        assert.equal(timers.length, 0);
    });

    for (const stage of stages) {
        test(`${operation} refresh rejection at ${stage} retains saved/reset selection state`, async () => {
            const {app: a, timers} = setup();
            fill(a, operation);
            a.showArchivedPanel = true;
            const selected = {id: 42};
            a.selectedStore = selected;
            a.storeInventory = [{store_id: 42}];
            a.showStoreInventoryPanel = true;
            const form = a.storeForm;
            const calls = [];
            a.apiCall = async () => { calls.push('write'); return {message: 'Archived'}; };
            for (const [provider, name] of [['loadStores', 'stores'], ['loadInventory', 'inventory'], ['loadStats', 'stats'], ['loadArchivedRecords', 'archived']]) {
                a[provider] = async () => { calls.push(name); if (stage === name) throw new Error('Refresh failed'); };
            }
            await invoke(a);
            const order = ['write', ...stages];
            assert.deepEqual(calls, order.slice(0, order.indexOf(stage) + 1));
            if (operation === 'archive') {
                assert.equal(a.storeForm, form);
                assert.equal(a.showStoreModal, true);
                assert.equal(a.editingStore, 42);
                assert.equal(a.selectedStore, null);
                assert.equal(a.storeInventory.length, 0);
                assert.equal(a.showStoreInventoryPanel, false);
            } else {
                assert.deepEqual(plain(a.storeForm), defaults);
                assert.equal(a.showStoreModal, false);
                assert.equal(a.editingStore, null);
                assert.equal(a.selectedStore, selected);
            }
            assert.equal(a.successMessage, success);
            assert.equal(a.error, failure + 'Refresh failed');
            assert.equal(a.loading, false);
            assert.equal(timers.length, 0);
        });
    }
}

test('no selected CSV file retains feedback without API requests', async () => {
    const {app: a, timers} = setup();
    a.error = 'keep error';
    a.successMessage = 'keep success';
    let calls = 0;
    a.apiCall = async () => { calls++; };
    const event = {target: {files: [], value: ''}};
    await a.importStores(event);
    assert.equal(calls, 0);
    assert.equal(a.error, 'keep error');
    assert.equal(a.successMessage, 'keep success');
    assert.equal(a.loading, false);
    assert.equal(timers.length, 0);
});

for (const errors of [[], ['Row 2: unknown user', 'Row 3: unknown store type']]) {
    test(`store CSV ${errors.length ? 'with row errors' : 'without row errors'} refreshes stores only and clears both feedback fields later`, async () => {
        const {app: a, timers} = setup();
        const event = upload();
        const calls = [];
        a.apiCall = async (path, options) => {
            assert.equal(a.loading, true);
            assert.equal(path, '/stores/bulk-import');
            assert.equal(options.method, 'POST');
            assert.ok(options.body instanceof FormData);
            assert.deepEqual([...options.body.keys()], ['file']);
            assert.equal(options.body.get('file').name, 'stores.csv');
            assert.equal(await options.body.get('file').text(), csv);
            calls.push('write');
            return {message: 'Imported one store', errors};
        };
        a.loadStores = async () => {
            assert.equal(event.target.value, 'stores.csv');
            assert.equal(timers.length, 0);
            assert.equal(a.successMessage, 'Imported one store');
            assert.equal(a.error, errors.length ? 'Some errors occurred:\n' + errors.join('\n') : '');
            calls.push('stores');
        };
        let extraRefreshes = 0;
        a.loadStats = a.loadInventory = a.loadUsers = a.loadStoreTypes = async () => { extraRefreshes++; };
        await a.importStores(event);
        assert.deepEqual(calls, ['write', 'stores']);
        assert.equal(extraRefreshes, 0);
        assert.equal(event.target.value, '');
        assert.equal(a.successMessage, 'Imported one store');
        assert.equal(a.error, errors.length ? 'Some errors occurred:\n' + errors.join('\n') : '');
        assert.equal(a.loading, false);
        assert.equal(timers.length, 1);
        assert.equal(timers[0].delay, 5000);
        timers[0].callback();
        assert.equal(a.successMessage, '');
        assert.equal(a.error, '');
    });
}

const response = (status, data) => new Response(JSON.stringify(data), {status, headers: {'Content-Type': 'application/json'}});
for (const rejectedToken of [false, true]) {
    test(`real store multipart helper ${rejectedToken ? 'replays explicit CSRF rejection' : 'acquires initial token once'}`, async () => {
        const calls = [];
        const bodies = [];
        let writes = 0;
        const {app: a, timers} = setup({fetch: async (url, options) => {
            assert.equal(options.credentials, 'include');
            if (url.endsWith('/csrf-token')) {
                calls.push('csrf');
                return response(200, {csrf_token: 'fresh'});
            }
            assert.equal(url, '/api/stores/bulk-import');
            assert.equal(options.method, 'POST');
            assert.ok(options.body instanceof FormData);
            assert.equal(new Headers(options.headers).has('Content-Type'), false);
            const used = new Headers(options.headers).get('X-CSRF-Token');
            assert.equal(used, rejectedToken && writes === 0 ? 'old' : 'fresh');
            assert.equal(options.body.get('file').name, 'stores.csv');
            assert.equal(await options.body.get('file').text(), csv);
            bodies.push(options.body);
            calls.push('write');
            writes++;
            return rejectedToken && writes === 1
                ? response(403, {detail: 'Invalid CSRF token'})
                : response(200, {message: 'Stores imported', errors: []});
        }});
        const event = upload();
        a.csrfToken = rejectedToken ? 'old' : '';
        a.loadStores = async () => { calls.push('stores'); };
        await a.importStores(event);
        assert.deepEqual(calls, [...(rejectedToken ? ['write', 'csrf', 'write'] : ['csrf', 'write']), 'stores']);
        assert.equal(writes, rejectedToken ? 2 : 1);
        if (rejectedToken) assert.equal(bodies[0], bodies[1]);
        assert.equal(a.csrfToken, 'fresh');
        assert.equal(event.target.value, '');
        assert.equal(a.error, '');
        assert.equal(a.successMessage, 'Stores imported');
        assert.equal(a.loading, false);
        assert.equal(timers.length, 1);
    });
}

test('real token-service failure prevents store upload and retains session/input', async () => {
    const calls = [];
    const {app: a, timers} = setup({fetch: async (url, options) => {
        assert.equal(options.credentials, 'include');
        assert.equal(url, '/api/csrf-token');
        calls.push(url);
        return response(503, {});
    }});
    a.currentUser = {id: 1, role: 'admin'};
    a.isAuthenticated = true;
    const user = a.currentUser;
    const event = upload();
    await a.importStores(event);
    assert.deepEqual(calls, ['/api/csrf-token']);
    assert.equal(a.csrfToken, '');
    assert.equal(event.target.value, 'stores.csv');
    assert.match(a.error, /Failed to import stores: .*security token/i);
    assert.equal(a.currentUser, user);
    assert.equal(a.isAuthenticated, true);
    assert.equal(a.loading, false);
    assert.equal(timers.length, 0);
});

test('permission rejection does not replay store upload or clear its input', async () => {
    let writes = 0;
    const {app: a, timers} = setup({fetch: async url => {
        assert.equal(url, '/api/stores/bulk-import');
        writes++;
        return response(403, {detail: 'Access forbidden'});
    }});
    a.csrfToken = 'fixture';
    const event = upload();
    await a.importStores(event);
    assert.equal(writes, 1);
    assert.equal(a.csrfToken, 'fixture');
    assert.equal(a.error, 'Failed to import stores: Access forbidden');
    assert.equal(event.target.value, 'stores.csv');
    assert.equal(a.loading, false);
    assert.equal(timers.length, 0);
});

for (const stage of ['write', 'stores']) {
    test(`store CSV failure at ${stage} retains input and current server feedback`, async () => {
        const {app: a, timers} = setup();
        const calls = [];
        const event = upload();
        a.apiCall = async () => {
            calls.push('write');
            if (stage === 'write') throw new Error('Failed');
            return {message: 'One store imported', errors: ['Row 2: unknown user']};
        };
        a.loadStores = async () => { calls.push('stores'); throw new Error('Failed'); };
        await a.importStores(event);
        assert.deepEqual(calls, stage === 'write' ? ['write'] : ['write', 'stores']);
        assert.equal(event.target.value, 'stores.csv');
        assert.equal(a.successMessage, stage === 'write' ? '' : 'One store imported');
        assert.equal(a.error, 'Failed to import stores: Failed');
        assert.equal(a.loading, false);
        assert.equal(timers.length, 0);
    });
}

test('navigation retains store editing and store-type form data while closing existing modals', () => {
    const {app: a} = setup();
    a.editingStoreType = 7;
    a.storeTypeForm.type_code = 'custom_type';
    a.showStoreTypeModal = true;
    const typeForm = a.storeTypeForm;
    a.editStore(store);
    assert.equal(a.editingStoreType, 7);
    assert.equal(a.showStoreTypeModal, true);
    const form = a.storeForm;
    a.openPanel('showInventoryPanel');
    assert.equal(a.showStoreModal, false);
    assert.equal(a.showStoreTypeModal, false);
    assert.equal(a.editingStore, 42);
    assert.equal(a.storeForm, form);
    assert.equal(a.editingStoreType, 7);
    assert.equal(a.storeTypeForm, typeForm);
    assert.equal(a.storeTypeForm.type_code, 'custom_type');
});

test('shipped store-administration forms remain independent', () => {
    const {app: first} = setup();
    const {app: second} = setup();
    first.editStore(store);
    first.storeForm.name = 'FIRST';
    assert.deepEqual(plain(second.storeForm), defaults);
    assert.equal(second.editingStore, null);
    assert.equal(second.showStoreModal, false);
});
