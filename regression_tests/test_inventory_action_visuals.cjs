const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');

const html = fs.readFileSync('static/index.html', 'utf8');
const css = fs.readFileSync('static/mystyle.css', 'utf8');
const start = html.indexOf('class="inventory-toolbar"');
const controls = html.slice(start, html.indexOf('</section>', start));

test('inventory summary and Add Stock are separated from filter and export controls', () => {
    assert.match(controls, /class="inventory-toolbar"[\s\S]*?stock entries[\s\S]*?class="btn inventory-add-action"/);
    assert.match(controls, /class="inventory-filter-row"[\s\S]*?class="[^"]*inventory-search-field"[\s\S]*?id="inventory-search"/);
    assert.match(controls, /class="inventory-filter-row-actions" role="group" aria-label="Inventory filters and exports"/);
    assert.match(controls, /class="btn inventory-filter-action"[^>]*:aria-expanded="showInventoryFilters" aria-controls="inventory-filter-panel"/);
    assert.match(controls, /<svg class="inventory-action-icon"[\s\S]*?<\/svg>\s*Filters/);
    assert.match(controls, /class="btn inventory-export-action"[^>]*:aria-expanded="showExportMenu" aria-controls="inventory-export-options"[\s\S]*?<\/svg>\s*Export/);
    assert.doesNotMatch(controls, /Export CSV|inventory-export-chevron|⌄/);
    assert.match(controls, /class="inventory-export-menu__items"/);
    assert.match(controls, /exportInventoryCSV\(\)/);
    assert.match(controls, /exportComprehensiveReport\(\)/);
    assert.match(css, /\.inventory-controls \.inventory-filter-action,[\s\S]*?\.inventory-controls \.inventory-export-action/);
    assert.match(css, /\.inventory-action-icon \{[^}]*stroke:\s*currentColor/);
});

test('filter disclosure keeps store, clear, and open-store behaviors available', () => {
    const panelStart = controls.indexOf('class="inventory-filter-panel"');
    const panel = controls.slice(panelStart, controls.indexOf('class="inventory-filter-actions"', panelStart));
    assert.match(panel, /id="inventory-filter-panel"[^>]*x-show="showInventoryFilters"/);
    assert.match(panel, /id="inventory-store"/);
    assert.match(panel, /x-for="store in storeOptions"[\s\S]*?x-text="store\.name"/);
    assert.match(controls, /class="inventory-filter-actions" role="group" aria-label="Filter actions" x-show="searchTerm \|\| storeFilter"/);
    assert.match(controls, /class="inventory-clear-filters"[^>]*clearInventoryFilters/);
    assert.match(controls, /class="inventory-open-store"[^>]*x-show="storeFilter"[^>]*viewStoreInventory/);
    assert.doesNotMatch(controls, /store\.type|store\.location/);
});

test('inventory toolbar controls stay touch-friendly and responsive', () => {
    assert.match(css, /\.inventory-filter-row \{ display: grid; grid-template-columns: minmax\(0, 1fr\) auto/);
    assert.match(css, /\.inventory-filter-panel \{ grid-column: 1 \/ -1/);
    assert.match(css, /@media \(max-width: 768px\)[\s\S]*?\.inventory-filter-row \{ grid-template-columns: minmax\(0, 1fr\); \}[\s\S]*?\.inventory-filter-row-actions \.inventory-export-action \{ width: 100%; min-height: 44px; \}/);
});
