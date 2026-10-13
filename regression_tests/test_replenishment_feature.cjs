const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

function setup() {
    const c = vm.createContext({Date, Number});
    for (const file of ['static/js/shared/features.js', 'static/js/inventory/replenishment.js']) {
        vm.runInContext(fs.readFileSync(file, 'utf8'), c);
    }
    return c;
}
const owned = ['showLowStockPanel','replenishmentPlan','replenishmentBusy','replenishmentError','replenishmentStoreFilter','minimumBusy','minimumForm','replenishmentRows','loadReplenishment','selectMinimum','saveMinimum','reloadMinimum','reviewReplenishmentTransfer','exportProcurementCSV'].sort();

test('replenishment has one owner and fresh defaults for each instance', () => {
    const c = setup(), a = c.replenishmentFeature(), b = c.replenishmentFeature();
    assert.deepEqual(Object.keys(a).sort(), owned);
    a.minimumForm.store_id = '1'; a.showLowStockPanel = true;
    assert.equal(b.minimumForm.store_id, ''); assert.equal(b.showLowStockPanel, false);
    assert.equal(b.replenishmentPlan, null); assert.equal(b.minimumBusy, false);
});

test('composed replenishment getter stays lazy and filters server rows', () => {
    const c = setup(), feature = c.replenishmentFeature();
    const a = c.composeInventoryFeatures({inventory: []}, feature);
    assert.equal(typeof Object.getOwnPropertyDescriptor(a, 'replenishmentRows').get, 'function');
    a.replenishmentPlan = {rows: [{store_id:1, internal_quantity:3}, {store_id:2, internal_quantity:4}]};
    a.replenishmentStoreFilter = '2';
    assert.equal(a.replenishmentRows.length, 1); assert.equal(a.replenishmentRows[0].internal_quantity, 4);
    a.replenishmentStoreFilter = ''; assert.equal(a.replenishmentRows.length, 2);
    assert.equal(feature.replenishmentPlan, null);
});

test('minimum save uses composed providers and preserves payload/refresh order', async () => {
    const c = setup(), calls = [];
    const a = c.composeInventoryFeatures({
        inventory: [{store_id:1,part_id:2,is_allocated:true,min_threshold:99}, {store_id:1,part_id:2,is_allocated:false,min_threshold:5}],
        successMessage: '',
        async apiCall(path, options) {assert.equal(this, a); calls.push(path); assert.deepEqual(JSON.parse(options.body), {store_id:1,part_id:2,min_threshold:6,expected_minimum:5});},
        async loadInventory(options) {assert.equal(this, a); assert.equal(options.refreshReplenishment, false); calls.push('inventory');},
        async loadStats() {assert.equal(this, a); calls.push('stats');}
    }, c.replenishmentFeature());
    a.minimumForm.store_id = '1'; a.minimumForm.part_id = '2'; a.selectMinimum();
    assert.equal(a.minimumForm.min_threshold, 5); a.minimumForm.min_threshold = '6';
    a.loadReplenishment = async function() {assert.equal(this, a); calls.push('plan'); return true;};
    await a.saveMinimum();
    assert.deepEqual(calls, ['/inventory/minimum','inventory','plan','stats']);
    assert.equal(a.minimumForm.expected_minimum, 6); assert.equal(a.minimumBusy, false);
});
