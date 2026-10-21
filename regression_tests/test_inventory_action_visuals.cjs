const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');

const html = fs.readFileSync('static/index.html', 'utf8');
const css = fs.readFileSync('static/mystyle.css', 'utf8');

test('inventory filters group quiet secondary actions without changing their handlers', () => {
    const filters = html.slice(html.indexOf('class="inventory-filters"'), html.indexOf('class="inventory-toolbar"'));
    assert.match(filters, /class="inventory-filter-actions" role="group" aria-label="Inventory filter actions"/);
    assert.match(filters, /class="btn inventory-filter-action" @click="clearInventoryFilters\(\)"/);
    assert.match(filters, /class="btn inventory-filter-action" @click="viewStoreInventory\(stores\.find\(store=>store\.id===Number\(storeFilter\)\)\)"/);
    assert.match(css, /\.inventory-controls \.inventory-filter-action,\s*\.inventory-controls \.inventory-export-action\s*\{[^}]*background:\s*var\(--brand-surface\)/s);
    assert.match(css, /\.inventory-controls \.inventory-filter-action:disabled\s*\{[^}]*background:\s*var\(--brand-page\)/s);
    assert.match(css, /\.inventory-filter-actions\s*\{[^}]*display:\s*flex[^}]*gap:\s*var\(--space-2\)/s);
});

test('inventory toolbar uses one amber primary action and a restrained accessible export trigger', () => {
    const start = html.indexOf('class="inventory-toolbar"');
    const toolbar = html.slice(start, html.indexOf('</section>', start));
    assert.match(toolbar, /class="btn inventory-add-action"/);
    assert.match(toolbar, /class="btn inventory-export-action"[^>]*:aria-expanded="showExportMenu" aria-haspopup="true"/);
    assert.match(toolbar, /Export CSV <span class="inventory-export-chevron" aria-hidden="true">⌄<\/span>/);
    assert.match(css, /\.inventory-toolbar \.inventory-add-action,\s*\.store-inventory-primary-action \{ background:\s*var\(--brand-amber\)/);
    assert.match(css, /\.inventory-controls \.inventory-export-action\s*\{[^}]*border:\s*1px solid var\(--brand-border\)/s);
});

test('inventory filter actions remain touch-friendly and paired on mobile', () => {
    assert.match(css, /@media \(max-width: 768px\)[\s\S]*?\.inventory-filter-actions \{ width:\s*100%; \}[\s\S]*?\.inventory-filter-actions \.btn \{ flex:\s*1 1 0; width:\s*auto; min-width:\s*0; min-height:\s*44px; \}/);
});
