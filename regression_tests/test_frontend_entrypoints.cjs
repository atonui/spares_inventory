const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {pageScripts, loadPageScripts} = require('./helpers/frontend.cjs');
const root = path.resolve(__dirname, '..');
const expected = {
    'index.html': ['temporal.js','audit.js','js/shared/csrf.js','js/shared/time-context.js','js/shared/features.js','js/shared/back-to-top.js','js/inventory/application-core.js','js/inventory/dialog-focus.js','js/inventory/reports.js','js/inventory/replenishment.js','js/inventory/stock-counts.js','js/inventory/stock-imports.js','js/inventory/transfer-receipts.js','js/inventory/stock-dispatch.js','js/inventory/stock-entry.js','js/inventory/stock-consumption.js','js/inventory/parts-admin.js','js/inventory/stores-admin.js','js/inventory/users-admin.js','js/inventory/store-types-admin.js','js/inventory/equipment.js','js/inventory/activity-logs.js','js/inventory/movement-history.js','js/inventory/exports.js','js/inventory/browsing.js','js/inventory/archived-records.js','js/inventory/navigation.js','js/inventory/notification-links.js','js/pages/inventory-v21.js','js/shared/password-visibility.js',],
    'profile.html': ['temporal.js','js/shared/csrf.js','js/shared/time-context.js','js/pages/profile.js','js/shared/password-visibility.js',],
    'forgot_password.html': ['js/shared/csrf.js','js/pages/password-recovery.js'],
    'reset_password.html': ['js/shared/csrf.js','js/pages/password-recovery.js','js/shared/password-visibility.js',],
    'superadmin.html': ['temporal.js','audit.js','js/shared/csrf.js','js/shared/time-context.js','js/shared/back-to-top.js','js/shared/announcement-time.js','js/pages/superadmin.js','js/shared/password-visibility.js',],
};
const factories = ['inventoryApp','profileManager','forgotPassword','resetPassword','superPanel'];
const owned = {'index.html':['inventoryApp'],'profile.html':['profileManager'],'forgot_password.html':['forgotPassword','resetPassword'],'reset_password.html':['forgotPassword','resetPassword'],'superadmin.html':['superPanel']};
function context() {return vm.createContext({console,Intl,Date,URLSearchParams,Headers,FormData,setTimeout:()=>{},document:{activeElement:null}});}
test('HTML entrypoints begin with a doctype',()=>{
    for(const page of Object.keys(expected)) {
        const html=fs.readFileSync(path.join(root,'static',page),'utf8');
        assert.equal(html.startsWith('<!DOCTYPE html>'),true,`${page} must begin with a doctype`);
    }
});
for (const [page,files] of Object.entries(expected)) {
    files.push('js/shared/announcements.js');
    test(`${page}: shipped scripts precede Alpine with one controller`,()=>{
        const scripts=pageScripts(page);
        assert.deepEqual(scripts.filter(s=>s.localPath).map(s=>s.src),files.map(f=>f+'?v='+ (f==='js/shared/password-visibility.js' ? '20261029-password-visibility' : f==='js/shared/back-to-top.js' ? '20261029-back-to-top-frame' : f==='js/inventory/dialog-focus.js' ? '20261016-dialog-focus' : f==='js/inventory/application-core.js' || f==='js/inventory/notification-links.js' || (page==='index.html' && f==='js/pages/inventory-v21.js') ? '20261030-store-email-notifications' : f==='js/inventory/users-admin.js' ? '20261030-admin-managed-email' : f==='js/inventory/archived-records.js' ? '20261025-frontend-22' : f==='js/pages/profile.js' ? '20261031-mobile-session-policy' : f==='js/pages/superadmin.js' ? '20261031-mobile-session-policy' : f==='js/shared/announcement-time.js' || f==='js/shared/announcements.js' || (page==='profile.html' && f==='js/shared/csrf.js') ? '20261014-announcement-controls' : f==='js/shared/announcements.js' ? '20261014-broadcasts' : page==='index.html' ? '20261014-frontend-21' : '20261013-frontend-1')));
        assert.equal(scripts.length,files.length+1);
        assert.equal(scripts.at(-1).src,'https://cdnjs.cloudflare.com/ajax/libs/alpinejs/3.13.0/cdn.min.js');
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
    for(const [page,factory] of [['index.html','inventoryApp'],['profile.html','profileManager']]) {
        const current=loadPageScripts(page,context())[factory]();
        const getter=factory==='inventoryApp'?'replenishmentRows':'displayTimezoneDirty';
        assert.equal(typeof Object.getOwnPropertyDescriptor(current,getter).get,'function');
        if(factory==='inventoryApp') assert.equal(Object.keys(current).length,291);
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
test('email-change confirmation is a standalone local script page',()=>{
    const html=fs.readFileSync(path.join(root,'static','email_change_confirmation.html'),'utf8');
    assert.equal(html.startsWith('<!doctype html>'),true);
    const scripts=pageScripts('email_change_confirmation.html');
    assert.deepEqual(scripts.map(script=>script.src),['js/pages/email-change-confirmation.js?v=20261030-admin-managed-email']);
    assert.ok(scripts.every(script=>script.defer));
});
test('controllers create independent state for each instance',()=>{
    const c=context();for(const page of ['index.html','profile.html','superadmin.html'])loadPageScripts(page,c);
    const a=c.inventoryApp(),b=c.inventoryApp();a.inventory.push({id:1});a.reportForm.part_id='fixture';assert.equal(b.inventory.length,0);assert.equal(b.reportForm.part_id,'');
    const p=c.profileManager(),q=c.profileManager();p.passwordForm.new_password='fixture';assert.equal(q.passwordForm.new_password,'');
    const s=c.superPanel(),t=c.superPanel();s.selectedLocked.push(1);s.resetModal.password='fixture';assert.equal(t.selectedLocked.length,0);assert.equal(t.resetModal.password,'');
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
test('controller regressions cannot exercise retired entrypoints',()=>{
    for(const file of fs.readdirSync(__dirname).filter(f=>/\.(?:py|cjs|js)$/.test(f) && f!=='test_frontend_entrypoints.cjs')) {
        const source=fs.readFileSync(path.join(__dirname,file),'utf8');
        assert.equal(/(?:['"]script\.js['"]|static\/script\.js|['"](?:static\/)?js\/pages\/inventory(?:-v(?:[2-9]|10|11|12|13|14|15|16|17|18|19|20))?\.js['"])/.test(source),false,file+' must use the shipped-page loader');
    }
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
        assert.equal(typeof c.equipmentFeature,page==='index.html'?'function':'undefined');
        assert.equal(typeof c.activityLogsFeature,page==='index.html'?'function':'undefined');
        assert.equal(typeof c.movementHistoryFeature,page==='index.html'?'function':'undefined');
        assert.equal(typeof c.inventoryExportsFeature,page==='index.html'?'function':'undefined');
        assert.equal(typeof c.inventoryBrowsingFeature,page==='index.html'?'function':'undefined');
        assert.equal(typeof c.archivedRecordsFeature,page==='index.html'?'function':'undefined');
        assert.equal(typeof c.navigationFeature,page==='index.html'?'function':'undefined');
        assert.equal(typeof c.inventoryCoreFeature,page==='index.html'?'function':'undefined');
    }
});


























test('active entrypoint only composes and allocates each factory once per application',()=>{
 const c=loadPageScripts('index.html',context());
 assert.equal(typeof c.inventoryCoreFeature,'function');
 assert.match(c.inventoryApp.toString(),/^function inventoryApp\(\) \{\s*return composeInventoryFeatures\(/);
 assert.doesNotMatch(c.inventoryApp.toString(),/const core|async |apiCall\(/);
 const names=['inventoryCoreFeature','consumptionReportsFeature','replenishmentFeature','stockCountsFeature','stockImportsFeature','transferReceiptsFeature','stockDispatchFeature','stockEntryFeature','stockConsumptionFeature','partsAdminFeature','storesAdminFeature','usersAdminFeature','storeTypesAdminFeature','equipmentFeature','activityLogsFeature','movementHistoryFeature','inventoryExportsFeature','inventoryBrowsingFeature','archivedRecordsFeature','navigationFeature'];
 const counts={};for(const name of names){const original=c[name];c[name]=function(){counts[name]=(counts[name]||0)+1;return original();};}
 const first=c.inventoryApp(),second=c.inventoryApp();for(const name of names)assert.equal(counts[name],2,name);
 assert.notEqual(first.loginForm,second.loginForm);assert.notEqual(first.inventory,second.inventory);
});

const retiredControllers = ['script.js', 'js/pages/inventory.js', ...Array.from({length:19}, (_, i) => `js/pages/inventory-v${i+2}.js`)];
test('retired controllers are absent from the served static tree',()=>{
    for(const file of retiredControllers) assert.equal(fs.existsSync(path.join(root,'static',file)),false,file);
});
test('current HTML never references retired controllers',()=>{
    for(const page of Object.keys(expected)) {
        const scripts=pageScripts(page);
        for(const script of scripts) assert.ok(!retiredControllers.includes(script.src.split(/[?#]/)[0]),`${page}: ${script.localPath}`);
    }
});
