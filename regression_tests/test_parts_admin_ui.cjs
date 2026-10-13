const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const {loadPageScripts} = require('./helpers/frontend.cjs');
const plain = value => JSON.parse(JSON.stringify(value));
const defaults = {part_number: '', description: '', category: '', unit_cost: ''};
const part = {id: 42, part_number: 'P-A', description: 'Test part', category: 'Test', unit_cost: 0};
const csv = 'part_number,description,category,unit_cost\nP-A,Test part,Test,0';

function setup({confirm = () => true, fetch} = {}) {
    const timers = [];
    const logs = [];
    const errors = [];
    const context = vm.createContext({
        FormData, File, Headers, URLSearchParams, fetch, confirm,
        console: {log(...args) { logs.push(args); }, error(...args) { errors.push(args); }},
        setTimeout(callback, delay) { timers.push({callback, delay}); },
    });
    loadPageScripts('index.html', context);
    const app = context.inventoryApp();
    context.app = app;
    return {app, context, timers, logs, errors};
}
function upload() {
    return {target: {files: [new File([csv], 'parts.csv', {type: 'text/csv'})], value: 'parts.csv'}};
}
function fill(app, operation = 'update') {
    app.editPart(part);
    app.partForm.unit_cost = '0';
    if (operation === 'create') app.editingPart = null;
}

const expressions = () => [...fs.readFileSync('static/index.html', 'utf8').matchAll(/@click="([^"]*)"/g)].map(m => m[1]);
test('actual add/cancel bindings preserve create/edit mode and zero-cost form values', () => {
    const {app: a, context} = setup();
    a.editPart(part);
    assert.equal(a.partForm.unit_cost, 0);
    assert.equal(a.editingPart, 42);
    const add = expressions().find(e => e.startsWith('editingPart = null; partForm =') && e.endsWith('showPartModal = true'));
    assert.ok(add, 'add-part binding remains present');
    vm.runInContext('with (app) {' + add + '}', context);
    assert.equal(a.editingPart, null);
    assert.deepEqual(plain(a.partForm), defaults);
    assert.equal(a.showPartModal, true);
    a.editPart(part);
    const form = a.partForm;
    const cancel = expressions().find(e => e === 'showPartModal = false; editingPart = null;');
    assert.ok(cancel, 'cancel-part binding remains present');
    vm.runInContext('with (app) {' + cancel + '}', context);
    assert.equal(a.showPartModal, false);
    assert.equal(a.editingPart, null);
    assert.equal(a.partForm, form);
    assert.equal(a.partForm.unit_cost, 0);
});

for (const operation of ['create', 'update']) {
    test(`${operation} part preserves payload, resets and refresh/timer order`, async () => {
        const {app: a, timers} = setup();
        fill(a, operation);
        const calls = [];
        a.error = 'old error';
        a.successMessage = 'old success';
        a.apiCall = async (path, options) => {
            assert.equal(a.loading, true);
            assert.equal(a.error, '');
            assert.equal(a.successMessage, '');
            calls.push(['write', path, options.method, JSON.parse(options.body)]);
            return {};
        };
        a.loadParts = async () => {
            assert.equal(a.showPartModal, false);
            assert.equal(a.editingPart, null);
            assert.deepEqual(plain(a.partForm), defaults);
            assert.equal(timers.length, 0);
            calls.push('parts');
        };
        a.loadInventory = async () => { assert.equal(timers.length, 0); calls.push('inventory'); };
        a.loadStats = async () => { assert.equal(timers.length, 0); calls.push('stats'); };
        await a[operation === 'create' ? 'createPart' : 'updatePart']();
        assert.deepEqual(calls, [
            ['write', operation === 'create' ? '/parts' : '/parts/42', operation === 'create' ? 'POST' : 'PUT',
                {part_number: 'P-A', description: 'Test part', category: 'Test', unit_cost: 0}],
            'parts', ...(operation === 'update' ? ['inventory'] : []), 'stats',
        ]);
        assert.equal(a.successMessage, operation === 'create' ? 'Part created successfully!' : 'Part updated successfully!');
        assert.equal(a.loading, false);
        assert.equal(a.error, '');
        assert.equal(timers.length, 1);
        assert.equal(timers[0].delay, 3000);
        timers[0].callback();
        assert.equal(a.successMessage, '');
    });
}

test('declined part archive preserves shared feedback and sends no request', async () => {
    const prompts = [];
    const {app: a, timers} = setup({confirm(message) { prompts.push(message); return false; }});
    a.error = 'keep error';
    a.successMessage = 'keep success';
    let writes = 0;
    a.apiCall = async () => { writes++; };
    await a.deletePart(42, 'P-A');
    assert.deepEqual(prompts, ['Archive part P-A? History will be preserved.']);
    assert.equal(writes, 0);
    assert.equal(a.error, 'keep error');
    assert.equal(a.successMessage, 'keep success');
    assert.equal(a.loading, false);
    assert.equal(timers.length, 0);
});

for (const archivedPanel of [false, true]) {
    test(`confirmed archive refreshes ${archivedPanel ? 'open' : 'closed'} archived panel in existing order`, async () => {
        const calls = [];
        const {app: a, timers} = setup({confirm(message) { calls.push(['confirm', message]); return true; }});
        a.showArchivedPanel = archivedPanel;
        a.apiCall = async (path, options) => {
            assert.equal(a.loading, true);
            calls.push(['write', path, options.method]);
            assert.equal(options.body, undefined);
            return {message: 'Part archived; history preserved'};
        };
        for (const [provider, name] of [['loadParts', 'parts'], ['loadStats', 'stats'], ['loadInventory', 'inventory'], ['loadArchivedRecords', 'archived']]) {
            a[provider] = async () => { assert.equal(timers.length, 0); calls.push(name); };
        }
        await a.deletePart(42, 'P-A');
        assert.deepEqual(calls, [
            ['confirm', 'Archive part P-A? History will be preserved.'], ['write', '/parts/42', 'DELETE'],
            'parts', 'stats', 'inventory', ...(archivedPanel ? ['archived'] : []),
        ]);
        assert.equal(a.successMessage, 'Part archived; history preserved');
        assert.equal(a.loading, false);
        assert.equal(timers.length, 1);
        assert.equal(timers[0].delay, 3000);
        timers[0].callback();
        assert.equal(a.successMessage, '');
    });
}

for (const operation of ['create', 'update', 'archive']) {
    const invoke = a => operation === 'archive' ? a.deletePart(42, 'P-A') : a[operation === 'create' ? 'createPart' : 'updatePart']();
    const success = operation === 'archive' ? 'Archived' : operation === 'create' ? 'Part created successfully!' : 'Part updated successfully!';
    const failure = operation === 'archive' ? 'Failed to archive part: ' : `Failed to ${operation} part: `;
    const stages = operation === 'create' ? ['parts', 'stats'] : operation === 'update'
        ? ['parts', 'inventory', 'stats'] : ['parts', 'stats', 'inventory', 'archived'];

    test(`${operation} write rejection retains form/mode without refresh or timer`, async () => {
        const {app: a, timers} = setup();
        fill(a, operation);
        const form = a.partForm;
        const editing = a.editingPart;
        let writes = 0;
        a.apiCall = async () => { writes++; throw new Error('Rejected'); };
        let refreshes = 0;
        for (const provider of ['loadParts', 'loadInventory', 'loadStats', 'loadArchivedRecords']) {
            a[provider] = async () => { refreshes++; };
        }
        await invoke(a);
        assert.equal(writes, 1);
        assert.equal(refreshes, 0);
        assert.equal(a.partForm, form);
        assert.equal(a.editingPart, editing);
        assert.equal(a.showPartModal, true);
        assert.equal(a.error, failure + 'Rejected');
        assert.equal(a.successMessage, '');
        assert.equal(a.loading, false);
        assert.equal(timers.length, 0);
    });

    for (const stage of stages) {
        test(`${operation} refresh rejection at ${stage} retains existing saved state`, async () => {
            const {app: a, timers} = setup();
            fill(a, operation);
            a.showArchivedPanel = true;
            const form = a.partForm;
            const calls = [];
            a.apiCall = async () => { calls.push('write'); return {message: 'Archived'}; };
            for (const [provider, name] of [['loadParts', 'parts'], ['loadInventory', 'inventory'], ['loadStats', 'stats'], ['loadArchivedRecords', 'archived']]) {
                a[provider] = async () => { calls.push(name); if (stage === name) throw new Error('Refresh failed'); };
            }
            await invoke(a);
            const order = ['write', ...stages];
            assert.deepEqual(calls, order.slice(0, order.indexOf(stage) + 1));
            if (operation === 'archive') {
                assert.equal(a.partForm, form);
                assert.equal(a.showPartModal, true);
                assert.equal(a.editingPart, 42);
            } else {
                assert.deepEqual(plain(a.partForm), defaults);
                assert.equal(a.showPartModal, false);
                assert.equal(a.editingPart, null);
            }
            assert.equal(a.successMessage, success);
            assert.equal(a.error, failure + 'Refresh failed');
            assert.equal(a.loading, false);
            assert.equal(timers.length, 0);
        });
    }
}

test('cancelled file selection does not clear feedback or acquire a token', async () => {
    const {app: a, timers} = setup();
    a.error = 'keep error';
    a.successMessage = 'keep success';
    let calls = 0;
    a.getCsrfToken = a.apiCall = async () => { calls++; };
    const event = {target: {files: [], value: 'old'}};
    await a.importParts(event);
    assert.equal(calls, 0);
    assert.equal(a.error, 'keep error');
    assert.equal(a.successMessage, 'keep success');
    assert.equal(a.loading, false);
    assert.equal(event.target.value, 'old');
    assert.equal(timers.length, 0);
});

for (const tokenPresent of [false, true]) {
    test(`catalog CSV ${tokenPresent ? 'reuses' : 'acquires'} a token and clears input only after refresh`, async () => {
        const {app: a, timers, logs} = setup();
        const calls = [];
        const event = upload();
        a.csrfToken = tokenPresent ? 'fixture' : '';
        a.getCsrfToken = async () => { calls.push('csrf'); a.csrfToken = 'fixture'; };
        a.apiCall = async (path, options) => {
            assert.equal(a.loading, true);
            assert.equal(a.csrfToken, 'fixture');
            assert.equal(path, '/parts/bulk-import');
            assert.equal(options.method, 'POST');
            assert.ok(options.body instanceof FormData);
            assert.deepEqual([...options.body.keys()], ['file']);
            assert.equal(options.body.get('file').name, 'parts.csv');
            assert.equal(await options.body.get('file').text(), csv);
            calls.push('write');
            return {added: 1, skipped: tokenPresent ? 0 : 1};
        };
        a.loadParts = async () => { assert.equal(event.target.value, 'parts.csv'); assert.equal(timers.length, 0); calls.push('parts'); };
        a.loadStats = async () => { assert.equal(event.target.value, 'parts.csv'); assert.equal(timers.length, 0); calls.push('stats'); };
        await a.importParts(event);
        assert.deepEqual(calls, [...(tokenPresent ? [] : ['csrf']), 'write', 'parts', 'stats']);
        assert.equal(a.successMessage, `Import complete! Added: 1, Skipped: ${tokenPresent ? 0 : 1}`);
        assert.equal(event.target.value, '');
        assert.equal(a.loading, false);
        assert.equal(a.error, '');
        assert.deepEqual(logs, tokenPresent ? [] : [['1 parts were skipped - check if they already exist']]);
        assert.equal(timers.length, 1);
        assert.equal(timers[0].delay, 5000);
        timers[0].callback();
        assert.equal(a.successMessage, '');
    });
}

const response = (status, data) => new Response(JSON.stringify(data), {status, headers: {'Content-Type': 'application/json'}});
for (const rejectedToken of [false, true]) {
    test(`real catalog multipart helper ${rejectedToken ? 'replays explicit CSRF rejection' : 'acquires initial token once'}`, async () => {
        const calls = [];
        const bodies = [];
        let writes = 0;
        const {app: a, timers} = setup({fetch: async (url, options) => {
            assert.equal(options.credentials, 'include');
            if (url.endsWith('/csrf-token')) {
                calls.push('csrf');
                return response(200, {csrf_token: 'fresh'});
            }
            assert.equal(url, '/api/parts/bulk-import');
            assert.equal(options.method, 'POST');
            assert.ok(options.body instanceof FormData);
            assert.equal(new Headers(options.headers).has('Content-Type'), false);
            const used = new Headers(options.headers).get('X-CSRF-Token');
            assert.equal(used, rejectedToken && writes === 0 ? 'old' : 'fresh');
            assert.equal(options.body.get('file').name, 'parts.csv');
            assert.equal(await options.body.get('file').text(), csv);
            bodies.push(options.body);
            calls.push('write');
            writes++;
            return rejectedToken && writes === 1
                ? response(403, {detail: 'Invalid CSRF token'})
                : response(200, {added: 1, skipped: 0});
        }});
        const event = upload();
        a.csrfToken = rejectedToken ? 'old' : '';
        a.loadParts = async () => { calls.push('parts'); };
        a.loadStats = async () => { calls.push('stats'); };
        await a.importParts(event);
        assert.deepEqual(calls, [...(rejectedToken ? ['write', 'csrf', 'write'] : ['csrf', 'write']), 'parts', 'stats']);
        assert.equal(writes, rejectedToken ? 2 : 1);
        if (rejectedToken) assert.equal(bodies[0], bodies[1]);
        assert.equal(a.csrfToken, 'fresh');
        assert.equal(event.target.value, '');
        assert.equal(a.error, '');
        assert.equal(a.successMessage, 'Import complete! Added: 1, Skipped: 0');
        assert.equal(a.loading, false);
        assert.equal(timers.length, 1);
    });
}

test('real token-service failure prevents catalog upload and retains session/input', async () => {
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
    await a.importParts(event);
    assert.deepEqual(calls, ['/api/csrf-token']);
    assert.equal(a.csrfToken, '');
    assert.equal(event.target.value, 'parts.csv');
    assert.match(a.error, /Failed to import parts: .*security token/i);
    assert.equal(a.currentUser, user);
    assert.equal(a.isAuthenticated, true);
    assert.equal(a.loading, false);
    assert.equal(timers.length, 0);
});

test('permission rejection does not replay a catalog upload or clear its input', async () => {
    let writes = 0;
    const {app: a, timers} = setup({fetch: async url => {
        assert.equal(url, '/api/parts/bulk-import');
        writes++;
        return response(403, {detail: 'Access forbidden'});
    }});
    a.csrfToken = 'fixture';
    const event = upload();
    await a.importParts(event);
    assert.equal(writes, 1);
    assert.equal(a.csrfToken, 'fixture');
    assert.equal(a.error, 'Failed to import parts: Access forbidden');
    assert.equal(event.target.value, 'parts.csv');
    assert.equal(a.loading, false);
    assert.equal(timers.length, 0);
});

for (const stage of ['write', 'parts', 'stats']) {
    test(`catalog upload failure at ${stage} retains current input/feedback and avoids timer`, async () => {
        const {app: a, timers} = setup();
        const calls = [];
        const event = upload();
        a.csrfToken = 'fixture';
        a.apiCall = async () => {
            calls.push('write');
            if (stage === 'write') throw new Error('Failed');
            return {added: 1, skipped: 1};
        };
        a.loadParts = async () => { calls.push('parts'); if (stage === 'parts') throw new Error('Failed'); };
        a.loadStats = async () => { calls.push('stats'); if (stage === 'stats') throw new Error('Failed'); };
        await a.importParts(event);
        const order = ['write', 'parts', 'stats'];
        assert.deepEqual(calls, order.slice(0, order.indexOf(stage) + 1));
        assert.equal(event.target.value, 'parts.csv');
        assert.equal(a.successMessage, stage === 'write' ? '' : 'Import complete! Added: 1, Skipped: 1');
        assert.equal(a.error, 'Failed to import parts: Failed');
        assert.equal(a.loading, false);
        assert.equal(timers.length, 0);
    });
}

test('core navigation closes the parts modal while preserving editing data', () => {
    const {app: a} = setup();
    a.editPart(part);
    const form = a.partForm;
    a.openPanel('showInventoryPanel');
    assert.equal(a.showPartModal, false);
    assert.equal(a.editingPart, 42);
    assert.equal(a.partForm, form);
    assert.equal(a.showInventoryPanel, true);
});

test('shipped catalog administration forms remain independent', () => {
    const {app: first} = setup();
    const {app: second} = setup();
    first.editPart(part);
    first.partForm.part_number = 'FIRST';
    assert.deepEqual(plain(second.partForm), defaults);
    assert.equal(second.editingPart, null);
    assert.equal(second.showPartModal, false);
});
