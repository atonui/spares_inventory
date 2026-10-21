const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');

const html = fs.readFileSync('static/index.html', 'utf8');
const css = fs.readFileSync('static/mystyle.css', 'utf8');

test('inventory filters keep only search and store controls', () => {
    const filters = html.slice(html.indexOf('class="inventory-filters"'), html.indexOf('class="inventory-toolbar"'));
    assert.match(filters, /id="inventory-search"/);
    assert.match(filters, /id="inventory-store"/);
    assert.match(filters, /x-text="store\.name"/);
    assert.doesNotMatch(filters, /store\.type|store\.location/);
});

test('inventory toolbar groups filter actions separately from stock actions', () => {
    const start = html.indexOf('class="inventory-toolbar"');
    const toolbar = html.slice(start, html.indexOf('</section>', start));
    assert.match(toolbar, /class="inventory-toolbar-actions" role="group" aria-label="Inventory actions"/);
    assert.doesNotMatch(toolbar, /Clear filters|Open store/);
    assert.match(toolbar, /class="toolbar-actions inventory-action-group" role="group" aria-label="Stock actions"/);
    assert.match(toolbar, /class="btn inventory-add-action"/);
    assert.match(toolbar, /class="btn inventory-export-action"[^>]*:aria-expanded="showExportMenu" aria-haspopup="true"/);
    assert.match(toolbar, /Export CSV <span class="inventory-export-chevron" aria-hidden="true">⌄<\/span>/);
    assert.match(toolbar, /class="inventory-export-menu__items"/);
    assert.match(toolbar, /class="inventory-export-menu__item"/);
    assert.doesNotMatch(toolbar, /style="[^"]*(?:background|border|width|box-shadow)/);
    assert.match(css, /\.inventory-toolbar \.inventory-add-action \{ background:\s*var\(--brand-navy\); color:\s*#ffffff/);
    assert.match(css, /\.inventory-controls \.inventory-export-action\s*\{[^}]*border:\s*1px solid var\(--brand-border\)/s);
    const filters = html.slice(html.indexOf('class="inventory-filters"'), html.indexOf('class="inventory-toolbar"'));
    assert.match(filters, /class="inventory-filter-actions" role="group" aria-label="Filter actions"/);
    assert.match(filters, /class="btn inventory-filter-action"[^>]*clearInventoryFilters/);
    assert.match(filters, /class="btn inventory-filter-action"[^>]*viewStoreInventory/);
    assert.match(html, /x-for="store in storeOptions"[\s\S]*?x-text="store\.name"/);
});

test('inventory toolbar actions remain touch-friendly and separate on mobile', () => {
    assert.match(css, /@media \(max-width: 768px\)[\s\S]*?\.inventory-toolbar-actions \{ width:\s*100%; margin-left:\s*0; display:\s*grid; grid-template-columns:\s*repeat\(2, minmax\(0, 1fr\)\); gap:\s*var\(--space-2\); \}[\s\S]*?\.toolbar-actions\.inventory-action-group \{ display:\s*contents; \}[\s\S]*?\.inventory-filter-actions \{ display:\s*grid; grid-template-columns:\s*repeat\(2, minmax\(0, 1fr\)\); width:\s*100%; margin-left:\s*0; \}/);
});
