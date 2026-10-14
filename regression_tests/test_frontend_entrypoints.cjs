const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const vm = require('node:vm');
const {pageScripts, loadPageScripts} = require('./helpers/frontend.cjs');
const root = path.resolve(__dirname, '..');
const expected = {
    'index.html': ['temporal.js','audit.js','js/shared/csrf.js','js/shared/time-context.js','js/shared/features.js','js/inventory/reports.js','js/inventory/replenishment.js','js/inventory/stock-counts.js','js/inventory/stock-imports.js','js/inventory/transfer-receipts.js','js/inventory/stock-dispatch.js','js/inventory/stock-entry.js','js/inventory/stock-consumption.js','js/inventory/parts-admin.js','js/inventory/stores-admin.js','js/inventory/users-admin.js','js/inventory/store-types-admin.js','js/pages/inventory-v13.js'],
    'profile.html': ['temporal.js','js/shared/time-context.js','js/pages/profile.js'],
    'forgot_password.html': ['js/shared/csrf.js','js/pages/password-recovery.js'],
    'reset_password.html': ['js/shared/csrf.js','js/pages/password-recovery.js'],
    'superadmin.html': ['temporal.js','audit.js','js/shared/csrf.js','js/shared/time-context.js','js/pages/superadmin.js'],
};
const factories = ['inventoryApp','profileManager','forgotPassword','resetPassword','superPanel'];
const owned = {'index.html':['inventoryApp'],'profile.html':['profileManager'],'forgot_password.html':['forgotPassword','resetPassword'],'reset_password.html':['forgotPassword','resetPassword'],'superadmin.html':['superPanel']};
function context() {return vm.createContext({console,Intl,Date,URLSearchParams,Headers,FormData,setTimeout:()=>{},document:{activeElement:null}});}
function legacy() {
    const c=context();
    for (const file of ['temporal.js','audit.js','script.js']) vm.runInContext(fs.readFileSync(path.join(root,'static',file),'utf8'),c,{filename:file});
    return c;
}
for (const [page,files] of Object.entries(expected)) {
    test(`${page}: shipped scripts precede Alpine with one controller`,()=>{
        const scripts=pageScripts(page);
        assert.deepEqual(scripts.filter(s=>s.localPath).map(s=>s.src),files.map(f=>f+'?v='+ (page==='index.html' ? '20261014-frontend-13' : '20261013-frontend-1')));
        assert.equal(scripts.length,files.length+1);
        assert.equal(scripts.at(-1).src,'https://cdnjs.cloudflare.com/ajax/libs/alpinejs/3.13.0/cdn.js');
        assert.ok(scripts.every(s=>s.defer));
        assert.equal(files.filter(f=>f.startsWith('js/pages/')).length,1);
    });
    test(`${page}: cold load exposes only its own factories and required helpers`,()=>{
        const c=loadPageScripts(page,context());
        for(const factory of factories) assert.equal(typeof c[factory],owned[page].includes(factory)?'function':'undefined',factory);
        for(const factory of owned[page]) assert.equal(typeof c[factory](),'object');
        if(files.includes('js/shared/time-context.js')) {
            assert.equal(c.validTimezoneContext(null),false);
            assert.equal(c.validTimezoneContext({business_timezone:'invalid',display_timezone:'UTC',revision:1}),false);
            assert.equal(c.validTimezoneContext({business_timezone:'Africa/Nairobi',display_timezone:'UTC',revision:1}),true);
        }
        if(files.includes('js/shared/csrf.js')) assert.equal(vm.runInContext('typeof InventoryCsrf.request',c),'function');
    });
}
test('inventory and profile retain lazy getters and method receivers',()=>{
    const old=legacy();
    for(const [page,factory] of [['index.html','inventoryApp'],['profile.html','profileManager']]) {
        const current=loadPageScripts(page,context())[factory]();const prior=old[factory]();
        const shape=obj=>Object.entries(Object.getOwnPropertyDescriptors(obj)).map(([key,d])=>[key,typeof d.get,typeof d.set,d.enumerable,d.writable]).sort();
        assert.deepEqual(shape(current),shape(prior));
        if(factory==='inventoryApp') {
            current.replenishmentPlan={rows:[{store_id:1},{store_id:2}]};current.replenishmentStoreFilter='2';
            assert.equal(current.replenishmentRows.length,1);assert.equal(current.replenishmentRows[0].store_id,2);
            current.replenishmentStoreFilter='';assert.equal(current.replenishmentRows.length,2);
            current.reportDirty=false;current.markReportDirty();assert.equal(current.reportDirty,true);
        } else {
            current.profile.display_timezone='UTC';current.displayTimezoneDraft='UTC';assert.equal(current.displayTimezoneDirty,false);
            current.displayTimezoneDraft='Africa/Nairobi';assert.equal(current.displayTimezoneDirty,true);
            current.displayTimezoneError='fixture';current.clearDisplayTimezoneFeedback();assert.equal(current.displayTimezoneError,'');
        }
    }
});
test('controllers create independent state for each instance',()=>{
    const c=context();for(const page of ['index.html','profile.html','superadmin.html'])loadPageScripts(page,c);
    const a=c.inventoryApp(),b=c.inventoryApp();a.inventory.push({id:1});a.reportForm.part_id='fixture';assert.equal(b.inventory.length,0);assert.equal(b.reportForm.part_id,'');
    const p=c.profileManager(),q=c.profileManager();p.passwordForm.new_password='fixture';assert.equal(q.passwordForm.new_password,'');
    const s=c.superPanel(),t=c.superPanel();s.selectedLocked.push(1);s.resetModal.password='fixture';assert.equal(t.selectedLocked.length,0);assert.equal(t.resetModal.password,'');
});
test('cached-page legacy entrypoint remains self-contained and byte-identical',()=>{
    const content=fs.readFileSync(path.join(root,'static/script.js'));
    const hash=crypto.createHash('sha1').update('blob '+content.length+'\0').update(content).digest('hex');
    assert.equal(hash,'4ac2430b70019cee3b5e53ca083b74d16c44a692');
    const c=legacy();for(const factory of factories.slice(0,4))assert.equal(typeof c[factory],'function');
    assert.equal(vm.runInContext('typeof InventoryCsrf.token',c),'function');
});
test('combined page fixtures execute shared dependencies once',()=>{
    const c=context();for(const page of ['index.html','profile.html','superadmin.html','forgot_password.html'])loadPageScripts(page,c);
    assert.equal(typeof c.inventoryApp,'function');assert.equal(typeof c.profileManager,'function');assert.equal(typeof c.superPanel,'function');assert.equal(typeof c.forgotPassword,'function');
});
test('page loader rejects duplicate references even after loading shared code',t=>{
    const original=fs.readFileSync;const filename=path.join(root,'static/profile.html');
    t.mock.method(fs,'readFileSync',(file,...args)=>file===filename?'<script src="temporal.js" defer></script><script src="temporal.js" defer></script>':original(file,...args));
    assert.throws(()=>pageScripts('profile.html'),/Duplicate local script/);
});
test('page loader refuses inline, asynchronous and escaping local scripts',t=>{
    const original=fs.readFileSync;const filename=path.join(root,'static/profile.html');let html='';
    t.mock.method(fs,'readFileSync',(file,...args)=>file===filename?html:original(file,...args));
    for(const [source,error] of [['<script>alert(1)</script>',/inline/],['<script src="temporal.js" defer async></script>',/Async/],['<script src="../main.py" defer></script>',/escapes/]]) {html=source;assert.throws(()=>pageScripts('profile.html'),error);}
});
test('controller regressions cannot silently exercise the frozen legacy script',()=>{
    for(const file of fs.readdirSync(__dirname).filter(f=>/\.(?:py|cjs|js)$/.test(f) && f!=='test_frontend_entrypoints.cjs')) {
        const source=fs.readFileSync(path.join(__dirname,file),'utf8');
        assert.equal(/(?:['"]script\.js['"]|static\/script\.js|['"](?:static\/)?js\/pages\/inventory(?:-v(?:[2-9]|10|11|12))?\.js['"])/.test(source),false,file+' must use the shipped-page loader');
    }
});

test('cached PR101 controller retains report behaviour and its original bytes',async()=>{
    const c=context();
    for(const file of ['temporal.js','audit.js','js/shared/csrf.js','js/shared/time-context.js','js/pages/inventory.js'])vm.runInContext(fs.readFileSync(path.join(root,'static',file),'utf8'),c,{filename:file});
    const content=fs.readFileSync(path.join(root,'static/js/pages/inventory.js'));
    assert.equal(crypto.createHash('sha1').update('blob '+content.length+'\0').update(content).digest('hex'),'5d0cae3938b31619656eb80a2fa70beaeb0a89b6');
    const a=c.inventoryApp();a.timezoneContext={business_timezone:'Africa/Nairobi'};a.reportForm.allDates=true;a.currentUser={id:1};a.apiCall=async()=>({offset:0});await a.openWorkOrderReport('WO-cache');assert.equal(a.showReportsPanel,true);assert.match(a.reportAppliedQuery,/WO-cache/);
});
test('only the inventory page loads report composition and feature factories',()=>{
    for(const page of Object.keys(expected)){
        const c=loadPageScripts(page,context());
        assert.equal(typeof c.composeInventoryFeatures,page==='index.html'?'function':'undefined');
        assert.equal(typeof c.consumptionReportsFeature,page==='index.html'?'function':'undefined');
        assert.equal(typeof c.replenishmentFeature,page==='index.html'?'function':'undefined');
        assert.equal(typeof c.stockCountsFeature,page==='index.html'?'function':'undefined');
        assert.equal(typeof c.stockImportsFeature,page==='index.html'?'function':'undefined');
        assert.equal(typeof c.transferReceiptsFeature,page==='index.html'?'function':'undefined');
        assert.equal(typeof c.stockDispatchFeature,page==='index.html'?'function':'undefined');
        assert.equal(typeof c.stockEntryFeature,page==='index.html'?'function':'undefined');
        assert.equal(typeof c.stockConsumptionFeature,page==='index.html'?'function':'undefined');
        assert.equal(typeof c.partsAdminFeature,page==='index.html'?'function':'undefined');
        assert.equal(typeof c.storesAdminFeature,page==='index.html'?'function':'undefined');
        assert.equal(typeof c.usersAdminFeature,page==='index.html'?'function':'undefined');
        assert.equal(typeof c.storeTypesAdminFeature,page==='index.html'?'function':'undefined');
    }
});

test('cached PR102 controller retains reports and replenishment without new dependencies',()=>{
    const c=context();
    for(const file of ['temporal.js','audit.js','js/shared/csrf.js','js/shared/time-context.js','js/shared/features.js','js/inventory/reports.js','js/pages/inventory-v2.js']) {
        vm.runInContext(fs.readFileSync(path.join(root,'static',file),'utf8'),c,{filename:file});
    }
    const content=fs.readFileSync(path.join(root,'static/js/pages/inventory-v2.js'));
    assert.equal(crypto.createHash('sha1').update('blob '+content.length+'\0').update(content).digest('hex'),'63f39d96fbcd2e7d2be946bc784d42f5a9c5e948');
    assert.equal(typeof c.replenishmentFeature,'undefined');
    const a=c.inventoryApp();a.replenishmentPlan={rows:[{store_id:1},{store_id:2}]};a.replenishmentStoreFilter='2';
    assert.equal(a.replenishmentRows.length,1);assert.equal(a.replenishmentRows[0].store_id,2);
    a.reportForm.start_date='2026-10-01';a.reportForm.end_date='2026-10-13';a.timezoneContext={business_timezone:'Africa/Nairobi'};
    assert.equal(a.reportQuery().get('start_date'),'2026-10-01');
});

test('cached PR103 controller still constructs stock counts with its original dependencies',async()=>{
    const c=context();c.confirm=()=>true;
    for(const file of ['temporal.js','audit.js','js/shared/csrf.js','js/shared/time-context.js','js/shared/features.js','js/inventory/reports.js','js/inventory/replenishment.js','js/pages/inventory-v3.js']) {
        vm.runInContext(fs.readFileSync(path.join(root,'static',file),'utf8'),c,{filename:file});
    }
    const content=fs.readFileSync(path.join(root,'static/js/pages/inventory-v3.js'));
    assert.equal(crypto.createHash('sha1').update('blob '+content.length+'\0').update(content).digest('hex'),'2bbb4df29f9ec3f5d403a59e8bb90f26cca10ca8');
    assert.equal(typeof c.stockCountsFeature,'undefined');
    const a=c.inventoryApp();a.apiCall=async()=>({sheet_token:'fixture',rows:[{inventory_id:1,quantity:3}]});
    await a.startStockCount({id:7});assert.equal(a.stockCount.sheet_token,'fixture');assert.equal(a.stockCount.rows[0].counted_quantity,'');
});


test('cached PR104 controller retains imports and matches the active application contract', async () => {
    const cached = context();
    for (const file of ['temporal.js', 'audit.js', 'js/shared/csrf.js', 'js/shared/time-context.js',
        'js/shared/features.js', 'js/inventory/reports.js', 'js/inventory/replenishment.js',
        'js/inventory/stock-counts.js', 'js/pages/inventory-v4.js']) {
        vm.runInContext(fs.readFileSync(path.join(root, 'static', file), 'utf8'), cached, {filename: file});
    }
    const content = fs.readFileSync(path.join(root, 'static/js/pages/inventory-v4.js'));
    assert.equal(crypto.createHash('sha1').update('blob ' + content.length + '\0').update(content).digest('hex'),
        'fcb9d4dd8d520e096908ef550850ccd45bb7b149');
    assert.equal(typeof cached.stockImportsFeature, 'undefined');
    const prior = cached.inventoryApp();
    const current = loadPageScripts('index.html', context()).inventoryApp();
    const describe = app => Object.entries(Object.getOwnPropertyDescriptors(app)).map(([key, descriptor]) => [
        key, descriptor.enumerable, descriptor.configurable, descriptor.writable,
        descriptor.get?.toString(), descriptor.set?.toString(),
        typeof descriptor.value === 'function' ? descriptor.value.toString() : JSON.stringify(descriptor.value),
    ]).sort(([a], [b]) => a.localeCompare(b));
    assert.equal(Object.keys(current).length, 265);
    assert.deepEqual(describe(current), describe(prior));
    prior.parts = [{part_number: 'CACHE-A'}];
    prior.loadParts = async () => {};
    prior.apiCall = async () => [];
    const target = {files: [{text: async () => 'part_number,quantity\nCACHE-A,0'}], value: 'file'};
    await prior.importPartsToStore({target}, 7);
    assert.equal(prior.showDuplicateResolutionModal, true);
    assert.equal(prior.getImportPreview()[0].quantity, 0);
    assert.equal(target.value, '');
});


test('cached PR105 controller retains receipts and matches the active application contract', async () => {
    const cached = context();
    for (const file of ['temporal.js', 'audit.js', 'js/shared/csrf.js', 'js/shared/time-context.js',
        'js/shared/features.js', 'js/inventory/reports.js', 'js/inventory/replenishment.js',
        'js/inventory/stock-counts.js', 'js/inventory/stock-imports.js', 'js/pages/inventory-v5.js']) {
        vm.runInContext(fs.readFileSync(path.join(root, 'static', file), 'utf8'), cached, {filename: file});
    }
    const content = fs.readFileSync(path.join(root, 'static/js/pages/inventory-v5.js'));
    assert.equal(crypto.createHash('sha1').update('blob ' + content.length + '\0').update(content).digest('hex'),
        '8b03ce5ad0577f7d25fc2e2bcb52ee0d1ec508b5');
    assert.equal(typeof cached.transferReceiptsFeature, 'undefined');
    const prior = cached.inventoryApp();
    const current = loadPageScripts('index.html', context()).inventoryApp();
    const describe = app => Object.entries(Object.getOwnPropertyDescriptors(app)).map(([key, descriptor]) => [
        key, descriptor.enumerable, descriptor.configurable, descriptor.writable,
        descriptor.get?.toString(), descriptor.set?.toString(),
        typeof descriptor.value === 'function' ? descriptor.value.toString() : JSON.stringify(descriptor.value),
    ]).sort(([a], [b]) => a.localeCompare(b));
    assert.equal(Object.keys(current).length, 265);
    assert.deepEqual(describe(current), describe(prior));
    const rows = [{id: 42}];
    prior.apiCall = async path => {
        assert.equal(path, '/inventory/transfers');
        return rows;
    };
    await prior.loadPendingTransfers();
    assert.equal(prior.pendingTransfers, rows);
});


test('cached PR106 controller retains dispatch and matches the active application contract', async () => {
    const cached = context();
    for (const file of ['temporal.js', 'audit.js', 'js/shared/csrf.js', 'js/shared/time-context.js',
        'js/shared/features.js', 'js/inventory/reports.js', 'js/inventory/replenishment.js',
        'js/inventory/stock-counts.js', 'js/inventory/stock-imports.js', 'js/inventory/transfer-receipts.js',
        'js/pages/inventory-v6.js']) {
        vm.runInContext(fs.readFileSync(path.join(root, 'static', file), 'utf8'), cached, {filename: file});
    }
    const content = fs.readFileSync(path.join(root, 'static/js/pages/inventory-v6.js'));
    assert.equal(crypto.createHash('sha1').update('blob ' + content.length + '\0').update(content).digest('hex'),
        '1ea6022d24ad4c5b3d332c7bd557bc09026d35e2');
    assert.equal(typeof cached.stockDispatchFeature, 'undefined');
    const prior = cached.inventoryApp();
    const current = loadPageScripts('index.html', context()).inventoryApp();
    const describe = app => Object.entries(Object.getOwnPropertyDescriptors(app)).map(([key, descriptor]) => [
        key, descriptor.enumerable, descriptor.configurable, descriptor.writable,
        descriptor.get?.toString(), descriptor.set?.toString(),
        typeof descriptor.value === 'function' ? descriptor.value.toString() : JSON.stringify(descriptor.value),
    ]).sort(([a], [b]) => a.localeCompare(b));
    assert.equal(Object.keys(current).length, 265);
    assert.deepEqual(describe(current), describe(prior));
    await prior.transferItem({id: 42});
    assert.equal(prior.transferForm.inventory_id, 42);
    assert.equal(prior.transferForm.quantity, 1);
    assert.equal(prior.showTransferModal, true);
});


test('cached PR108 controller retains stock entry and matches the active application contract', async () => {
    const cached = context();
    for (const file of ['temporal.js', 'audit.js', 'js/shared/csrf.js', 'js/shared/time-context.js',
        'js/shared/features.js', 'js/inventory/reports.js', 'js/inventory/replenishment.js',
        'js/inventory/stock-counts.js', 'js/inventory/stock-imports.js', 'js/inventory/transfer-receipts.js',
        'js/inventory/stock-dispatch.js', 'js/pages/inventory-v7.js']) {
        vm.runInContext(fs.readFileSync(path.join(root, 'static', file), 'utf8'), cached, {filename: file});
    }
    const content = fs.readFileSync(path.join(root, 'static/js/pages/inventory-v7.js'));
    assert.equal(crypto.createHash('sha1').update('blob ' + content.length + '\0').update(content).digest('hex'),
        '62ef53d129f439b75beda38f08604fd326c160ce');
    assert.equal(typeof cached.stockEntryFeature, 'undefined');
    const prior = cached.inventoryApp();
    const current = loadPageScripts('index.html', context()).inventoryApp();
    const describe = app => Object.entries(Object.getOwnPropertyDescriptors(app)).map(([key, descriptor]) => [
        key, descriptor.enumerable, descriptor.configurable, descriptor.writable,
        descriptor.get?.toString(), descriptor.set?.toString(),
        typeof descriptor.value === 'function' ? descriptor.value.toString() : JSON.stringify(descriptor.value),
    ]).sort(([a], [b]) => a.localeCompare(b));
    assert.equal(Object.keys(current).length, 265);
    assert.deepEqual(describe(current), describe(prior));
    await prior.addStockToStore({id: 7});
    assert.equal(prior.addForm.store_id, 7);
    assert.equal(prior.showAddModal, true);
    await prior.editItem({id: 42, quantity: 0});
    assert.equal(prior.editForm.new_quantity, 0);
    assert.equal(prior.showEditModal, true);
});


test('cached PR109 controller retains consumption and matches the active application contract', () => {
    const cached = context();
    for (const file of ['temporal.js', 'audit.js', 'js/shared/csrf.js', 'js/shared/time-context.js',
        'js/shared/features.js', 'js/inventory/reports.js', 'js/inventory/replenishment.js',
        'js/inventory/stock-counts.js', 'js/inventory/stock-imports.js', 'js/inventory/transfer-receipts.js',
        'js/inventory/stock-dispatch.js', 'js/inventory/stock-entry.js', 'js/pages/inventory-v8.js']) {
        vm.runInContext(fs.readFileSync(path.join(root, 'static', file), 'utf8'), cached, {filename: file});
    }
    const content = fs.readFileSync(path.join(root, 'static/js/pages/inventory-v8.js'));
    assert.equal(crypto.createHash('sha1').update('blob ' + content.length + '\0').update(content).digest('hex'),
        '469bebef2d610aca63fb36050b90d1e1941003c4');
    assert.equal(typeof cached.stockConsumptionFeature, 'undefined');
    const prior = cached.inventoryApp();
    const current = loadPageScripts('index.html', context()).inventoryApp();
    const describe = app => Object.entries(Object.getOwnPropertyDescriptors(app)).map(([key, descriptor]) => [
        key, descriptor.enumerable, descriptor.configurable, descriptor.writable,
        descriptor.get?.toString(), descriptor.set?.toString(),
        typeof descriptor.value === 'function' ? descriptor.value.toString() : JSON.stringify(descriptor.value),
    ]).sort(([a], [b]) => a.localeCompare(b));
    assert.equal(Object.keys(current).length, 265);
    assert.deepEqual(describe(current), describe(prior));
    prior.consumeItem({id: 42, part_number: 'P-A', description: 'Cached part', store_name: 'Target', quantity: 3});
    assert.equal(prior.consumeForm.inventory_id, 42);
    assert.equal(prior.consumeForm.quantity, 1);
    assert.equal(prior.consumeForm.available_quantity, 3);
    assert.equal(prior.showConsumeModal, true);
});


test('cached PR110 controller retains catalog administration and matches the active application contract', () => {
    const cached = context();
    for (const file of ['temporal.js', 'audit.js', 'js/shared/csrf.js', 'js/shared/time-context.js',
        'js/shared/features.js', 'js/inventory/reports.js', 'js/inventory/replenishment.js',
        'js/inventory/stock-counts.js', 'js/inventory/stock-imports.js', 'js/inventory/transfer-receipts.js',
        'js/inventory/stock-dispatch.js', 'js/inventory/stock-entry.js', 'js/inventory/stock-consumption.js',
        'js/pages/inventory-v9.js']) {
        vm.runInContext(fs.readFileSync(path.join(root, 'static', file), 'utf8'), cached, {filename: file});
    }
    const content = fs.readFileSync(path.join(root, 'static/js/pages/inventory-v9.js'));
    assert.equal(crypto.createHash('sha1').update('blob ' + content.length + '\0').update(content).digest('hex'),
        'a99571ce0ea040130fb44a76c9e4b2d4c2fc5825');
    assert.equal(typeof cached.partsAdminFeature, 'undefined');
    const prior = cached.inventoryApp();
    const current = loadPageScripts('index.html', context()).inventoryApp();
    const describe = app => Object.entries(Object.getOwnPropertyDescriptors(app)).map(([key, descriptor]) => [
        key, descriptor.enumerable, descriptor.configurable, descriptor.writable,
        descriptor.get?.toString(), descriptor.set?.toString(),
        typeof descriptor.value === 'function' ? descriptor.value.toString() : JSON.stringify(descriptor.value),
    ]).sort(([a], [b]) => a.localeCompare(b));
    assert.equal(Object.keys(current).length, 265);
    assert.deepEqual(describe(current), describe(prior));
    prior.editPart({id: 42, part_number: 'P-A', description: 'Cached part', category: 'Test', unit_cost: 0});
    assert.equal(prior.editingPart, 42);
    assert.equal(prior.partForm.unit_cost, 0);
    assert.equal(prior.showPartModal, true);
});

test('cached PR111 controller retains store administration and matches the active application contract', () => {
    const cached = context();
    for (const file of ['temporal.js', 'audit.js', 'js/shared/csrf.js', 'js/shared/time-context.js',
        'js/shared/features.js', 'js/inventory/reports.js', 'js/inventory/replenishment.js',
        'js/inventory/stock-counts.js', 'js/inventory/stock-imports.js', 'js/inventory/transfer-receipts.js',
        'js/inventory/stock-dispatch.js', 'js/inventory/stock-entry.js', 'js/inventory/stock-consumption.js',
        'js/inventory/parts-admin.js', 'js/pages/inventory-v10.js']) {
        vm.runInContext(fs.readFileSync(path.join(root, 'static', file), 'utf8'), cached, {filename: file});
    }
    const content = fs.readFileSync(path.join(root, 'static/js/pages/inventory-v10.js'));
    assert.equal(crypto.createHash('sha1').update('blob ' + content.length + '\0').update(content).digest('hex'),
        '150ca58feedd23f30790935c3fd35df5741aad52');
    assert.equal(typeof cached.storesAdminFeature, 'undefined');
    const prior = cached.inventoryApp();
    const current = loadPageScripts('index.html', context()).inventoryApp();
    const describe = app => Object.entries(Object.getOwnPropertyDescriptors(app)).map(([key, descriptor]) => [
        key, descriptor.enumerable, descriptor.configurable, descriptor.writable,
        descriptor.get?.toString(), descriptor.set?.toString(),
        typeof descriptor.value === 'function' ? descriptor.value.toString() : JSON.stringify(descriptor.value),
    ]).sort(([a], [b]) => a.localeCompare(b));
    assert.equal(Object.keys(current).length, 265);
    assert.deepEqual(describe(current), describe(prior));
    prior.editStore({id: 42, name: 'Cached store', type: 'custom_type', location: null, assigned_user_id: null});
    assert.equal(prior.editingStore, 42);
    assert.equal(prior.storeForm.location, '');
    assert.equal(prior.storeForm.assigned_user_id, '');
    assert.equal(prior.showStoreModal, true);
});

test('cached PR112 controller retains user administration and matches the active application contract', () => {
    const cached = context();
    for (const file of ['temporal.js', 'audit.js', 'js/shared/csrf.js', 'js/shared/time-context.js',
        'js/shared/features.js', 'js/inventory/reports.js', 'js/inventory/replenishment.js',
        'js/inventory/stock-counts.js', 'js/inventory/stock-imports.js', 'js/inventory/transfer-receipts.js',
        'js/inventory/stock-dispatch.js', 'js/inventory/stock-entry.js', 'js/inventory/stock-consumption.js',
        'js/inventory/parts-admin.js', 'js/inventory/stores-admin.js', 'js/pages/inventory-v11.js']) {
        vm.runInContext(fs.readFileSync(path.join(root, 'static', file), 'utf8'), cached, {filename: file});
    }
    const content = fs.readFileSync(path.join(root, 'static/js/pages/inventory-v11.js'));
    assert.equal(crypto.createHash('sha1').update('blob ' + content.length + '\0').update(content).digest('hex'),
        '8264fed6ef3d84fc8dac1ec410f38e2b1044729b');
    assert.equal(typeof cached.usersAdminFeature, 'undefined');
    const prior = cached.inventoryApp();
    const current = loadPageScripts('index.html', context()).inventoryApp();
    const describe = app => Object.entries(Object.getOwnPropertyDescriptors(app)).map(([key, descriptor]) => [
        key, descriptor.enumerable, descriptor.configurable, descriptor.writable,
        descriptor.get?.toString(), descriptor.set?.toString(),
        typeof descriptor.value === 'function' ? descriptor.value.toString() : JSON.stringify(descriptor.value),
    ]).sort(([a], [b]) => a.localeCompare(b));
    assert.equal(Object.keys(current).length, 265);
    assert.deepEqual(describe(current), describe(prior));
    prior.editUser({id:42,email:'cached@example.test',name:'Cached',role:'engineer',territory:null});
    assert.equal(prior.editingUser,42);
    assert.equal(prior.userForm.password,'');
    assert.equal(prior.userForm.territory,'');
    assert.equal(prior.showUserModal,true);
});

test('cached PR113 controller retains store-type administration and matches the active application contract', () => {
    const cached = context();
    for (const file of ['temporal.js', 'audit.js', 'js/shared/csrf.js', 'js/shared/time-context.js',
        'js/shared/features.js', 'js/inventory/reports.js', 'js/inventory/replenishment.js',
        'js/inventory/stock-counts.js', 'js/inventory/stock-imports.js', 'js/inventory/transfer-receipts.js',
        'js/inventory/stock-dispatch.js', 'js/inventory/stock-entry.js', 'js/inventory/stock-consumption.js',
        'js/inventory/parts-admin.js', 'js/inventory/stores-admin.js', 'js/inventory/users-admin.js', 'js/pages/inventory-v12.js']) {
        vm.runInContext(fs.readFileSync(path.join(root, 'static', file), 'utf8'), cached, {filename: file});
    }
    const content = fs.readFileSync(path.join(root, 'static/js/pages/inventory-v12.js'));
    assert.equal(crypto.createHash('sha1').update('blob ' + content.length + '\0').update(content).digest('hex'),
        'e1eb475af20aab48886967706412185183417dd7');
    assert.equal(typeof cached.storeTypesAdminFeature, 'undefined');
    const prior = cached.inventoryApp();
    const current = loadPageScripts('index.html', context()).inventoryApp();
    const describe = app => Object.entries(Object.getOwnPropertyDescriptors(app)).map(([key, descriptor]) => [
        key, descriptor.enumerable, descriptor.configurable, descriptor.writable,
        descriptor.get?.toString(), descriptor.set?.toString(),
        typeof descriptor.value === 'function' ? descriptor.value.toString() : JSON.stringify(descriptor.value),
    ]).sort(([a], [b]) => a.localeCompare(b));
    assert.equal(Object.keys(current).length, 265);
    assert.deepEqual(describe(current), describe(prior));
    prior.editStoreType({id:42,type_code:'custom',type_name:'Cached',description:null,display_order:0,is_active:false});
    assert.equal(prior.editingStoreType,42);
    assert.equal(prior.storeTypeForm.description,'');
    assert.equal(prior.storeTypeForm.is_active,false);
    assert.equal(prior.showStoreTypeModal,true);
});
