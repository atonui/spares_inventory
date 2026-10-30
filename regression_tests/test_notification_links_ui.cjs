const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const plain = value => JSON.parse(JSON.stringify(value));

function setup(search, elements = {}) {
    const c = vm.createContext({
        URLSearchParams,
        window: {location: {search}},
        document: {getElementById: id => elements[id] || null},
        requestAnimationFrame(callback) { callback(); },
        setTimeout(callback) { callback(); },
    });
    vm.runInContext(fs.readFileSync('static/js/shared/features.js', 'utf8'), c);
    vm.runInContext(fs.readFileSync('static/js/inventory/notification-links.js', 'utf8'), c);
    return c;
}

test('transfer email link scrolls to the matching pending transfer', async () => {
    const calls = [];
    const row = {scrollIntoView: options => calls.push(options)};
    const c = setup('?transfer_id=55', {'transfer-row-55': row});
    const app = c.composeInventoryFeatures(
        {pendingTransfers: [{id: 55}]}, c.notificationLinksFeature(),
    );

    await app.applyNotificationLink();

    assert.deepEqual(plain(calls), [{behavior: 'smooth', block: 'center'}]);
});

test('stock email link opens its store and scrolls to the affected inventory row', async () => {
    const calls = [];
    const store = {id: 7, name: 'Nairobi Main'};
    const row = {scrollIntoView: options => calls.push(['scroll', options])};
    const c = setup('?store_id=7&inventory_id=42', {'store-inventory-row-42': row});
    const app = c.composeInventoryFeatures({
        storeOptions: [store],
        async viewStoreInventory(selected) { calls.push(['store', selected]); },
    }, c.notificationLinksFeature());

    await app.applyNotificationLink();

    assert.equal(calls[0][0], 'store');
    assert.equal(calls[0][1], store);
    assert.deepEqual(plain(calls[1]), ['scroll', {behavior: 'smooth', block: 'center'}]);
});

test('notification links cannot open a store unavailable to the signed-in account', async () => {
    const c = setup('?store_id=999');
    const app = c.composeInventoryFeatures({storeOptions: []}, c.notificationLinksFeature());

    await app.applyNotificationLink();

    assert.equal(app.error, 'This store is unavailable to your account.');
});

test('notification link is applied only once per page load', async () => {
    let scrolls = 0;
    const c = setup('?transfer_id=55', {'transfer-row-55': {scrollIntoView() { scrolls += 1; }}});
    const app = c.composeInventoryFeatures({pendingTransfers: [{id: 55}]}, c.notificationLinksFeature());

    await app.applyNotificationLink();
    await app.applyNotificationLink();

    assert.equal(scrolls, 1);
});
