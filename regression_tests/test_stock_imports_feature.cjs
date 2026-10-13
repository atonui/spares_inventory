const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

function setup(globals = {}) {
    const context = vm.createContext(globals);
    vm.runInContext(fs.readFileSync('static/js/shared/features.js', 'utf8'), context);
    const filename = 'static/js/inventory/stock-imports.js';
    assert.ok(fs.existsSync(filename), 'stock import feature must exist');
    vm.runInContext(fs.readFileSync(filename, 'utf8'), context, {filename});
    return context;
}

const owned = [
    'showDuplicateResolutionModal', 'csvDuplicates', 'storeConflicts', 'pendingImportData',
    'getImportPreview', 'getResolutionSummary', 'setAllCsvDuplicates', 'setAllStoreConflicts',
    'setAllActions', 'cancelDuplicateResolution', 'processDuplicateResolution',
    'importPartsToStore', 'downloadStoreImportTemplate',
].sort();
const plain = value => JSON.parse(JSON.stringify(value));

test('stock imports own exactly thirteen properties with fresh defaults', () => {
    const context = setup();
    const first = context.stockImportsFeature();
    const second = context.stockImportsFeature();
    assert.deepEqual(Object.keys(first).sort(), owned);
    assert.equal(first.showDuplicateResolutionModal, false);
    assert.deepEqual(plain(first.csvDuplicates), []);
    assert.deepEqual(plain(first.storeConflicts), []);
    assert.equal(first.pendingImportData, null);
    first.csvDuplicates.push({partNumber: 'A'});
    first.storeConflicts.push({partNumber: 'A'});
    first.pendingImportData = {parsedRows: [{partNumber: 'A', quantity: 1}], storeId: 7};
    first.showDuplicateResolutionModal = true;
    assert.deepEqual(plain(second.csvDuplicates), []);
    assert.deepEqual(plain(second.storeConflicts), []);
    assert.equal(second.pendingImportData, null);
    assert.equal(second.showDuplicateResolutionModal, false);
});

test('composed preview and summary follow duplicate and conflict choices', () => {
    const context = setup();
    const app = context.composeInventoryFeatures({error: 'keep', loading: false}, context.stockImportsFeature());
    assert.deepEqual(plain(app.getImportPreview()), []);
    app.pendingImportData = {storeId: 7, parsedRows: [
        {partNumber: 'A', quantity: 4}, {partNumber: 'A', quantity: 6},
        {partNumber: 'B', quantity: 0}, {partNumber: 'C', quantity: 3},
    ]};
    app.csvDuplicates = [{partNumber: 'A', action: ''}];
    app.storeConflicts = [{partNumber: 'A', currentQuantity: 8, action: 'replace'}];
    assert.equal(app.getImportPreview()[0].action, 'resolve');
    app.setAllCsvDuplicates('first');
    assert.deepEqual(plain(app.getImportPreview()), [
        {partNumber: 'A', quantity: 4, action: 'replace', currentQuantity: 8},
        {partNumber: 'B', quantity: 0, action: 'create', currentQuantity: null},
        {partNumber: 'C', quantity: 3, action: 'create', currentQuantity: null},
    ]);
    assert.deepEqual(plain(app.getResolutionSummary()), {willAdd: 2, willUpdate: 1, willSkip: 0});
    app.setAllCsvDuplicates('tally');
    assert.equal(app.getImportPreview()[0].quantity, 10);
    app.setAllStoreConflicts('skip');
    assert.deepEqual(plain(app.getResolutionSummary()), {willAdd: 2, willUpdate: 0, willSkip: 1});
    app.setAllActions('skip');
    assert.equal(app.csvDuplicates[0].action, 'skip');
    assert.equal(app.storeConflicts[0].action, 'skip');
    app.cancelDuplicateResolution();
    assert.equal(app.pendingImportData, null);
    assert.equal(app.showDuplicateResolutionModal, false);
    assert.deepEqual(plain(app.csvDuplicates), []);
    assert.deepEqual(plain(app.storeConflicts), []);
    assert.equal(app.error, 'keep');
    assert.equal(app.loading, false);
});

test('import and save use providers on the composed receiver', async () => {
    const context = setup();
    const calls = [];
    const app = context.composeInventoryFeatures({
        loading: false, error: '', successMessage: '', parts: [], inventory: [], selectedStore: {id: 7},
        async loadParts() {
            assert.equal(this, app);
            calls.push('parts');
            this.parts = [{part_number: 'A'}];
        },
        async apiCall(path, options) {
            assert.equal(this, app);
            calls.push(path);
            if (!options) return [{part_number: 'A', store_id: 7, quantity: 8}];
            assert.equal(options.method, 'POST');
            assert.deepEqual(JSON.parse(options.body), {
                store_id: 7, rows: [{part_number: 'A', quantity: 0, expected_quantity: 8}],
            });
            return {added: 0, updated: 1, unchanged: 0};
        },
        async loadInventory() {
            assert.equal(this, app);
            calls.push('refresh');
            this.inventory = [{part_number: 'A', store_id: 7, quantity: 0}];
        },
        async loadStats() { assert.equal(this, app); calls.push('stats'); },
    }, context.stockImportsFeature());
    const target = {files: [{text: async () => 'part_number,quantity\nA,0'}], value: 'file'};
    await app.importPartsToStore({target}, 7);
    assert.equal(target.value, '');
    assert.equal(app.showDuplicateResolutionModal, true);
    assert.deepEqual(calls, ['parts', '/inventory']);
    await app.processDuplicateResolution();
    assert.deepEqual(calls, ['parts', '/inventory', '/inventory/import-balances', 'refresh', 'stats']);
    assert.equal(app.storeInventory[0].quantity, 0);
    assert.equal(app.pendingImportData, null);
    assert.equal(app.loading, false);
});

test('template download keeps the exact CSV and releases its object URL', () => {
    const calls = [];
    const anchor = {click() { calls.push(['click', this.href, this.download]); }};
    const context = setup({
        Blob: class {
            constructor(parts, options) { this.parts = parts; this.options = options; }
        },
        URL: {
            createObjectURL(blob) {
                calls.push(['blob', plain(blob.parts), plain(blob.options)]);
                return 'blob:template';
            },
            revokeObjectURL(url) { calls.push(['revoke', url]); },
        },
        document: {createElement(tag) { assert.equal(tag, 'a'); return anchor; }},
    });
    context.stockImportsFeature().downloadStoreImportTemplate();
    assert.deepEqual(calls, [
        ['blob', ['part_number,quantity\nPART-001,10\nPART-002,5'], {type: 'text/csv'}],
        ['click', 'blob:template', 'store_parts_import_template.csv'],
        ['revoke', 'blob:template'],
    ]);
});
