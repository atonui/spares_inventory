const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const plain = value => JSON.parse(JSON.stringify(value));
const defaults = {part_number: '', description: '', category: '', unit_cost: ''};
const part = {id: 42, part_number: 'P-A', description: 'Test part', category: 'Test', unit_cost: 0};

function setup(globals = {}) {
    const c = vm.createContext({FormData, File, console: {log() {}, error() {}}, ...globals});
    vm.runInContext(fs.readFileSync('static/js/shared/features.js', 'utf8'), c);
    const filename = 'static/js/inventory/parts-admin.js';
    assert.ok(fs.existsSync(filename), 'parts admin feature must exist');
    vm.runInContext(fs.readFileSync(filename, 'utf8'), c, {filename});
    return c;
}

test('parts administration owns nine properties with independent form defaults', () => {
    const c = setup();
    const first = c.partsAdminFeature();
    const second = c.partsAdminFeature();
    assert.deepEqual(Object.keys(first).sort(), ['partForm', 'showPartModal', 'editingPart',
        'createPart', 'editPart', 'updatePart', 'deletePart', 'importParts', 'downloadPartTemplate'].sort());
    assert.deepEqual(plain(first.partForm), defaults);
    assert.equal(first.showPartModal, false);
    assert.equal(first.editingPart, null);
    first.partForm.part_number = 'FIRST';
    first.showPartModal = true;
    first.editingPart = 42;
    assert.deepEqual(plain(second.partForm), defaults);
    assert.equal(second.showPartModal, false);
    assert.equal(second.editingPart, null);
});

test('edit part replaces its form with exact values including zero cost', () => {
    const c = setup();
    const app = c.composeInventoryFeatures({}, c.partsAdminFeature());
    const original = app.partForm;
    app.editPart(part);
    assert.notEqual(app.partForm, original);
    assert.deepEqual(plain(app.partForm), {part_number: 'P-A', description: 'Test part', category: 'Test', unit_cost: 0});
    assert.equal(app.editingPart, 42);
    assert.equal(app.showPartModal, true);
});

for (const operation of ['create', 'update', 'archive', 'import']) {
    test(`${operation} calls core providers on the composed receiver in its existing order`, async () => {
        const calls = [];
        let callback;
        const c = setup({confirm(message) {
            assert.equal(message, 'Archive part P-A? History will be preserved.');
            calls.push('confirm');
            return true;
        }, setTimeout(fn, delay) { calls.push(['timer', delay]); callback = fn; }});
        const app = c.composeInventoryFeatures({
            loading: false, error: 'old error', successMessage: 'old success', csrfToken: '', showArchivedPanel: true,
            async getCsrfToken() { assert.equal(this, app); calls.push('csrf'); this.csrfToken = 'fixture'; },
            async apiCall(path, options) {
                assert.equal(this, app);
                assert.equal(this.loading, true);
                assert.equal(this.error, '');
                assert.equal(this.successMessage, '');
                if (options.body instanceof FormData) {
                    assert.deepEqual([...options.body.keys()], ['file']);
                    assert.equal(await options.body.get('file').text(), 'part_number,description,category,unit_cost\nP-A,Test,Test,2.5');
                    calls.push(['write', path, options.method, 'multipart']);
                } else {
                    calls.push(['write', path, options.method, options.body ? JSON.parse(options.body) : null]);
                }
                return {message: 'Archived', added: 1, skipped: 0};
            },
            async loadParts() { assert.equal(this, app); calls.push('parts'); },
            async loadInventory() { assert.equal(this, app); calls.push('inventory'); },
            async loadStats() { assert.equal(this, app); calls.push('stats'); },
            async loadArchivedRecords() { assert.equal(this, app); calls.push('archived'); },
        }, c.partsAdminFeature());
        app.partForm = {part_number: 'P-A', description: 'Test part', category: 'Test', unit_cost: '2.5'};
        const body = {part_number: 'P-A', description: 'Test part', category: 'Test', unit_cost: 2.5};
        if (operation === 'create') {
            app.showPartModal = true;
            await app.createPart();
            assert.deepEqual(calls, [['write', '/parts', 'POST', body], 'parts', 'stats', ['timer', 3000]]);
            assert.deepEqual(plain(app.partForm), defaults);
            assert.equal(app.showPartModal, false);
            assert.equal(app.successMessage, 'Part created successfully!');
        } else if (operation === 'update') {
            app.showPartModal = true;
            app.editingPart = 42;
            await app.updatePart();
            assert.deepEqual(calls, [['write', '/parts/42', 'PUT', body], 'parts', 'inventory', 'stats', ['timer', 3000]]);
            assert.deepEqual(plain(app.partForm), defaults);
            assert.equal(app.showPartModal, false);
            assert.equal(app.editingPart, null);
            assert.equal(app.successMessage, 'Part updated successfully!');
        } else if (operation === 'archive') {
            await app.deletePart(42, 'P-A');
            assert.deepEqual(calls, ['confirm', ['write', '/parts/42', 'DELETE', null], 'parts', 'stats', 'inventory', 'archived', ['timer', 3000]]);
            assert.equal(app.successMessage, 'Archived');
        } else {
            const event = {target: {files: [new File(['part_number,description,category,unit_cost\nP-A,Test,Test,2.5'], 'parts.csv', {type: 'text/csv'})], value: 'parts.csv'}};
            await app.importParts(event);
            assert.deepEqual(calls, ['csrf', ['write', '/parts/bulk-import', 'POST', 'multipart'], 'parts', 'stats', ['timer', 5000]]);
            assert.equal(event.target.value, '');
            assert.equal(app.successMessage, 'Import complete! Added: 1, Skipped: 0');
        }
        assert.equal(app.loading, false);
        assert.equal(app.error, '');
        callback();
        assert.equal(app.successMessage, '');
    });
}

test('part template keeps exact CSV, type and download filename', () => {
    const calls = [];
    const anchor = {click() { calls.push(['click', this.href, this.download]); }};
    const c = setup({
        Blob: class { constructor(parts, options) { this.parts = parts; this.options = options; } },
        URL: {createObjectURL(blob) { calls.push(['blob', plain(blob.parts), plain(blob.options)]); return 'blob:parts'; }},
        document: {createElement(tag) { assert.equal(tag, 'a'); return anchor; }},
    });
    c.partsAdminFeature().downloadPartTemplate();
    assert.deepEqual(calls, [
        ['blob', ['part_number,description,category,unit_cost\nSAMPLE-001,Sample Part Description,Sample Category,99.99'], {type: 'text/csv'}],
        ['click', 'blob:parts', 'parts_import_template.csv'],
    ]);
});
