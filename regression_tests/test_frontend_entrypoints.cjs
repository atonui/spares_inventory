const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const vm = require('node:vm');
const {pageScripts, loadPageScripts} = require('./helpers/frontend.cjs');
const root = path.resolve(__dirname, '..');
const expected = {
    'index.html': ['temporal.js','audit.js','js/shared/csrf.js','js/shared/time-context.js','js/shared/features.js','js/inventory/reports.js','js/pages/inventory-v2.js'],
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
        assert.deepEqual(scripts.filter(s=>s.localPath).map(s=>s.src),files.map(f=>f+'?v='+ (page==='index.html' ? '20261013-frontend-2' : '20261013-frontend-1')));
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
        assert.equal(/(?:['"]script\.js['"]|static\/script\.js|['"](?:static\/)?js\/pages\/inventory\.js['"])/.test(source),false,file+' must use the shipped-page loader');
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
    }
});
