const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const staticDir = path.join(__dirname, '..', 'static');
const html = fs.readFileSync(path.join(staticDir, 'index.html'), 'utf8');
const focus = fs.readFileSync(path.join(staticDir, 'js/inventory/dialog-focus.js'), 'utf8');

function createFeature() {
    const context = {};
    vm.runInNewContext(`${focus}\nthis.feature = inventoryDialogFocusFeature();`, context);
    return context.feature;
}

function createDialog() {
    const document = {activeElement: null};
    const focusable = ['first', 'middle', 'last'].map(name => ({
        name,
        getClientRects: () => [{}],
        focus() { document.activeElement = this; }
    }));
    const dialog = {
        ownerDocument: document,
        querySelectorAll: () => focusable,
        contains: node => node === dialog || focusable.includes(node),
        focus() { document.activeElement = dialog; }
    };
    return {dialog, document, focusable};
}

test('inventory dialogs initialize focus, trap Tab, and restore focus when closed', () => {
    const feature = createFeature();
    const {dialog, document, focusable} = createDialog();
    const trigger = {focus() { document.activeElement = trigger; }};
    document.activeElement = trigger;
    let watch;
    const component = {
        $watch: (_key, callback) => { watch = callback; },
        $nextTick: callback => callback()
    };

    feature.initDialogFocus.call(component, dialog, 'showEditModal');
    watch(true);
    assert.equal(document.activeElement, focusable[0]);
    watch(false);
    assert.equal(document.activeElement, trigger);
});

test('Tab and Shift+Tab stay within inventory dialogs', () => {
    const feature = createFeature();
    const {dialog, document, focusable} = createDialog();
    let prevented = false;
    const event = {key: 'Tab', currentTarget: dialog, preventDefault: () => { prevented = true; }};

    document.activeElement = focusable[2];
    feature.trapDialogFocus(event);
    assert.equal(prevented, true);
    assert.equal(document.activeElement, focusable[0]);

    prevented = false;
    event.shiftKey = true;
    document.activeElement = focusable[0];
    feature.trapDialogFocus(event);
    assert.equal(prevented, true);
    assert.equal(document.activeElement, focusable[2]);
});

test('every inventory dialog wires Escape and Tab handling', () => {
    const dialogs = [...html.matchAll(/<div\b[^>]*class="modal"[^>]*>/g)].map(match => match[0]);
    assert.equal(dialogs.length, 13);
    for (const dialog of dialogs) {
        assert.match(dialog, /x-init="initDialogFocus\(\$el, 'show\w+'\)"/);
        assert.match(dialog, /@keydown\.tab="trapDialogFocus\(\$event\)"/);
        assert.match(dialog, /@keydown\.escape\.stop\.prevent="closeDialog\('show\w+'\)"/);
    }
});
