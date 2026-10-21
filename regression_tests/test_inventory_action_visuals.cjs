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
    assert.match(toolbar, /class="inventory-action-group inventory-filter-actions" role="group" aria-label="Filter actions"/);
    assert.match(toolbar, /class="toolbar-actions inventory-action-group" role="group" aria-label="Stock actions"/);
    assert.match(toolbar, /class="btn inventory-add-action"/);
    assert.match(toolbar, /class="btn inventory-export-action"[^>]*:aria-expanded="showExportMenu" aria-haspopup="true"/);
    assert.match(toolbar, /Export CSV <span class="inventory-export-chevron" aria-hidden="true">⌄<\/span>/);
    assert.match(css, /\.inventory-toolbar \.inventory-add-action \{ background:\s*var\(--brand-navy\); color:\s*#ffffff/);
    assert.match(css, /\.inventory-controls \.inventory-export-action\s*\{[^}]*border:\s*1px solid var\(--brand-border\)/s);
});

test('inventory toolbar actions remain touch-friendly and separate on mobile', () => {
    assert.match(css, /@media \(max-width: 768px\)[\s\S]*?\.inventory-toolbar-actions \{ width:\s*100%; margin-left:\s*0; display:\s*grid; grid-template-columns:\s*minmax\(0, 1fr\); gap:\s*var\(--space-2\); \}[\s\S]*?\.inventory-action-group \.btn \{ flex:\s*1 1 0; width:\s*auto; min-width:\s*0; min-height:\s*44px; white-space:\s*normal; \}/);
});
