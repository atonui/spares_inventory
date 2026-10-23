const {test}=require('node:test');const assert=require('node:assert/strict');const fs=require('node:fs');const vm=require('node:vm');const {loadPageScripts}=require('./helpers/frontend.cjs');const plain=v=>JSON.parse(JSON.stringify(v));
function setup(){const c=vm.createContext({Headers,FormData,URLSearchParams,console:{log(){},error(){}},setTimeout(){}});loadPageScripts('index.html',c);const a=c.inventoryApp();c.app=a;a.currentUser={id:7,role:'engineer'};return {a,c};}
const rows=[{id:1,part_number:'ABC',description:'Red Pump',store_name:'Same',store_id:1,quantity:0,min_threshold:2,store_owner:7},{id:2,part_number:'XYZ',description:'Blue Pump',store_name:'Same',store_id:2,quantity:5,min_threshold:2,work_order:'WO1',store_owner:'7'},{id:3,part_number:null,description:null,store_name:null,store_id:1,quantity:-1,min_threshold:0}];
test('selected-store panel contains its search and inventory table instead of truncated output',()=>{const source=fs.readFileSync('static/index.html','utf8');const start=source.indexOf('x-show="showStoreInventoryPanel"');const end=source.indexOf('<!-- Edit Stock Modal -->',start);const panel=source.slice(start,end);assert.ok(!panel.includes('tokens truncated'),'store panel must not contain truncated source text');assert.equal((panel.match(/<label for="store-stock-search">/g)||[]).length,1,'store search label must not be duplicated');assert.match(panel,/<label for="store-stock-search">(?:<svg\b[^>]*>[\s\S]*?<\/svg>\s*)?Find stock in this store<\/label>/,'store search label text and association must remain valid, with an optional decorative icon');assert.ok(panel.includes('id="store-stock-search"'),'store panel must render store stock search');assert.ok(panel.includes('x-for="item in filteredStoreInventory"'),'store panel must render selected-store inventory rows');assert.ok(source.includes('<!-- Inventory Panel -->'),'main inventory panel must exist');assert.ok(source.includes('x-for="item in filteredInventory"'),'main inventory rows must render');});
test('all-stores and selected-store headers use the shared responsive panel toolbar',()=>{
    const source=fs.readFileSync('static/index.html','utf8');
    const css=fs.readFileSync('static/mystyle.css','utf8');
    const allStoresStart=source.indexOf('x-show="showAllStoresPanel"');
    const selectedStoreStart=source.indexOf('x-show="showStoreInventoryPanel"');
    const allStores=source.slice(allStoresStart,selectedStoreStart);
    const selectedStore=source.slice(selectedStoreStart,source.indexOf('<!-- Edit Stock Modal -->',selectedStoreStart));

    assert.ok(allStores.includes('class="inventory-panel-heading"'));
    assert.ok(allStores.includes('class="inventory-panel-actions"'));
    assert.ok(allStores.includes('aria-label="Close panel"'));
    assert.ok(selectedStore.includes('class="inventory-panel-heading"'));
    assert.ok(selectedStore.includes('class="inventory-panel-actions"'));
    assert.ok(selectedStore.includes("x-text=\"selectedStore?.name + ' Inventory'\""));
    assert.ok(selectedStore.includes("x-text=\"storeInventory.length + ' items in stock'\""));
    assert.match(selectedStore,/@click="downloadStoreImportTemplate\(\)"/);
    assert.match(selectedStore,/@click="addStockToStore\(selectedStore\)"/);
    assert.match(selectedStore,/Download Template[\s\S]*Import CSV[\s\S]*Export CSV[\s\S]*Count Stock[\s\S]*class="btn btn-sm store-inventory-action"[\s\S]*Add Single Part/);
    assert.equal((selectedStore.match(/class="[^"]*\bstore-inventory-action\b/g)||[]).length,6,'every store header control must use the same visual treatment');
    assert.doesNotMatch(selectedStore,/store-inventory-primary-action|store-inventory-utility-group/);
    assert.match(css,/\.inventory-panel-actions \.store-inventory-action\s*\{[^}]*border: 1px solid var\(--brand-border\)[^}]*background: var\(--brand-surface\)[^}]*color: var\(--brand-navy\)/s);
    assert.doesNotMatch(css,/\.store-inventory-primary-action|\.store-inventory-utility-group/);
    assert.match(selectedStore,/x-show="canEdit\(selectedStore\?\.assigned_user_id, selectedStore\?\.type\)"/);
    assert.match(css,/\.inventory-panel-actions > \.btn:not\(\.ui-icon-only\),\s*\.inventory-panel-actions > label\.btn \{ flex: 1 1 9rem; min-height: 44px; white-space: normal; \}/);
});
test('my-parts panel uses the shared responsive heading and keeps its existing close action',()=>{
    const source=fs.readFileSync('static/index.html','utf8');
    const start=source.indexOf('<!-- My Parts Panel -->');
    const end=source.indexOf('<!-- Edit Stock Modal -->',start);
    const panel=source.slice(start,end);

    assert.ok(panel.includes('class="inventory-panel-heading"'));
    assert.ok(panel.includes('class="inventory-panel-heading-content"'));
    assert.ok(panel.includes('class="inventory-panel-title">My Parts Inventory</h3>'));
    assert.ok(panel.includes('class="inventory-panel-actions"'));
    assert.match(panel,/<button class="btn btn-sm ui-icon-only" @click="closeAllPanels\(\)" aria-label="Close panel" title="Close panel">/);
    assert.ok(panel.includes('x-show="showMyPartsPanel"'));
    assert.ok(panel.includes('x-for="item in myPartsView"'));
    for(const action of ['Edit','Transfer','Consume']) assert.ok(panel.includes(action));
});
test('all-parts catalog uses the shared responsive heading and retains its catalog data',()=>{
    const source=fs.readFileSync('static/index.html','utf8');
    const start=source.indexOf('<!-- All Parts Panel -->');
    const end=source.indexOf('<!-- User Management Panel',start);
    const panel=source.slice(start,end);

    assert.ok(panel.includes('class="inventory-panel-heading"'));
    assert.ok(panel.includes('class="inventory-panel-heading-content"'));
    assert.ok(panel.includes('class="inventory-panel-title">All Parts Catalog</h3>'));
    assert.ok(panel.includes('class="inventory-panel-actions"'));
    assert.match(panel,/@click="closeAllPanels\(\)" aria-label="Close panel" title="Close panel"/);
    assert.ok(panel.includes('x-show="showAllPartsPanel"'));
    assert.ok(panel.includes('x-for="part in allPartsView"'));
    assert.ok(panel.includes('inventory.filter(i => i.part_number === part.part_number).reduce((sum, i) => sum + i.quantity, 0)'));
});
for(const [query,ids] of [['  RED   pump ',[1]],['pump same',[1,2]],['wo1',[2]],['',[1,2,3]],['red blue',[]]])test('search exact matching '+JSON.stringify(query),()=>{const {a}=setup();assert.deepEqual(Array.from(a.matchInventoryRows(rows,query),r=>r.id),ids);});
for(const [filter,ids] of [[1,[1,3]],['2',[2]],['bad',[]],['',[1,2,3]]])test('store filter strict ID '+filter,()=>{const {a}=setup();a.inventory=rows;a.storeFilter=filter;a.filterInventory();assert.deepEqual(Array.from(a.filteredInventory,r=>r.id),ids);});
for(const [patch,ids] of [[{},[1,2,3]],[{partNumber:'ab'},[1]],[{category:'A'},[1]],[{lowStockOnly:true},[1]],[{minQuantity:0},[1,2,3]],[{minQuantity:'0'},[1,2]],[{maxQuantity:'0'},[1,3]],[{minQuantity:'1.9'},[2]],[{minQuantity:'bad'},[]],[{description:'ignored',storeType:'ignored'},[1,2,3]]])test('advanced filters preserve existing behavior '+JSON.stringify(patch),()=>{const {a}=setup();a.inventory=rows.map(r=>({...r,part_number:r.part_number||''}));a.parts=[{part_number:'ABC',category:'A'},{part_number:'XYZ',category:'a'}];Object.assign(a.advancedSearch,patch);a.filterInventoryAdvanced();assert.deepEqual(Array.from(a.filteredInventory,r=>r.id),ids);if(!Object.keys(patch).length)assert.equal(a.filteredInventory,a.inventory);});
for(const [user,owner,type,allowed] of [[null,7,'central',false],[{id:7,role:'admin'},9,'custom',true],[{id:7,role:'superadmin'},9,'custom',true],[{id:7,role:'manager'},9,'custom',false],[{id:7,role:'engineer'},7,'custom',true],[{id:7,role:'engineer'},'7','custom',false],[{id:7,role:'engineer'},9,'central',true]])test('permissions '+JSON.stringify([user,owner,type]),()=>{const {a}=setup();a.currentUser=user;assert.equal(a.canEdit(owner,type),allowed);if(user)assert.equal(a.getStoreClass(type,owner),owner===user.id?'store-mine':'store-'+type);});
test('live predicates/getters retain allocation/workorder/strict actors and provider identity',()=>{const {a}=setup();a.inventory=[...rows,{...rows[0],id:4,is_allocated:true},{...rows[0],id:5,work_order:'WO'}];assert.deepEqual(Array.from(a.lowStockItems,r=>r.id),[1]);assert.deepEqual(Array.from(a.myPartsView,r=>r.id),[1,4,5]);a.currentUser.id='7';assert.deepEqual(Array.from(a.myPartsView,r=>r.id),[2]);a.parts=[{id:1}];a.stores=[{id:1,assigned_user_id:'7',type:'custom'}];assert.equal(a.allPartsView,a.parts);assert.equal(a.allStoresView,a.stores);assert.equal(a.editableStores.length,1);a.currentUser=null;assert.equal(a.editableStores.length,0);});
test('actual search/clear/store bindings preserve selection/filter reset/navigation order',async()=>{const {a,c}=setup();a.inventory=rows;a.stores=[{id:1,name:'Same'},{id:2,name:'Same'}];a.storeOptions=a.stores.map(({id,name})=>({id,name}));a.searchTerm='pump';a.storeFilter='2';a.advancedSearch.category='keep';a.storeSearchTerm='old';const source=fs.readFileSync('static/index.html','utf8');assert.ok(source.includes('@input.debounce.150ms="filterInventory()"'));vm.runInContext('with(app){filterInventory()}',c);assert.deepEqual(Array.from(a.filteredInventory,r=>r.id),[2]);const open=[...source.matchAll(/@click="([^"]*)"/g)].map(m=>m[1]).find(e=>e.startsWith('viewStoreInventory(storeOptions.find'));assert.ok(open);await vm.runInContext('with(app){'+open+'}',c);assert.equal(a.selectedStore,a.storeOptions[1]);assert.equal(a.storeSearchTerm,'');assert.deepEqual(Array.from(a.storeInventory,r=>r.id),[2]);assert.equal(a.searchTerm,'pump');const selected=a.selectedStore;await a.viewStoreInventory(null);assert.equal(a.selectedStore,selected);let filters=0;const original=a.filterInventory;a.filterInventory=function(){filters++;return original.call(this);};assert.ok(source.includes('@click="clearInventoryFilters()"'));a.clearInventoryFilters();assert.equal(filters,2);assert.equal(a.searchTerm,'');assert.equal(a.storeFilter,'');assert.equal(a.advancedSearch.category,'keep');assert.equal(a.showInventoryPanel,true);});
test('selected-store matcher/live balances and core refresh preserve browsing state',async()=>{const {a}=setup();a.inventory=rows;await a.viewStoreInventory({id:1,name:'Same'});a.storeSearchTerm='red';assert.deepEqual(Array.from(a.filteredStoreInventory,r=>r.id),[1]);a.apiCall=async()=>[{...rows[0],quantity:9}];await a.loadInventory();assert.equal(a.storeInventory[0].quantity,9);assert.equal(a.storeSearchTerm,'red');const {a:b}=setup();a.advancedSearch.category='A';a.filteredInventory.push({id:4});assert.equal(b.advancedSearch.category,'');assert.equal(b.filteredInventory.length,0);assert.equal(b.selectedStore,null);});
