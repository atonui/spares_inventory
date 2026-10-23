const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');

const html = fs.readFileSync('static/index.html', 'utf8');
const css = fs.readFileSync('static/mystyle.css', 'utf8');
const loginCss = fs.readFileSync('static/login.css', 'utf8');

function sectionBetween(startMarker, endMarker) {
    const start = html.indexOf(startMarker);
    assert.notEqual(start, -1, `missing section start: ${startMarker}`);
    const end = html.indexOf(endMarker, start);
    assert.notEqual(end, -1, `missing section end: ${endMarker}`);
    return html.slice(start, end);
}

test('responsive primary navigation has an accessible drawer trigger and preserves all destinations', () => {
    const start = html.indexOf('class="workspace-layout"');
    const shell = html.slice(start, html.indexOf('<!-- Quick Stats -->', start));
    assert.match(shell, /class="mobile-nav-toggle"/);
    assert.match(shell, /aria-label="Main navigation"/);
    assert.match(shell, /aria-controls="primary-navigation"/);
    assert.match(shell, /:aria-expanded="mobileNavigationOpen"/);
    assert.match(shell, /@keydown\.escape\.window=.*mobileNavigationOpen.*\$nextTick/);
    assert.match(shell, /x-ref="mobileNavigationTrigger"/);
    assert.match(shell, /@click\.outside="if \(mobileNavigationOpen\) mobileNavigationOpen = false"/);
    assert.match(shell, /id="primary-navigation"/);
    assert.match(shell, /@click="if \(mobileNavigationOpen\) \{ mobileNavigationOpen = false; \$nextTick\(\(\) => \$refs\.mobileNavigationTrigger\.focus\(\)\) \}"/);
    assert.match(shell, /class="sidebar-backdrop"/);
    for (const panel of ['showInventoryPanel', 'showAllStoresPanel', 'showLowStockPanel', 'showReportsPanel', 'showAllPartsPanel', 'showEquipmentPanel', 'showMovementsPanel']) {
        assert.ok(shell.includes(`openPanel('${panel}')`), `navigation must preserve ${panel}`);
    }
});

test('inventory lookup keeps its common controls and stock actions in the shell', () => {
    const start = html.indexOf('class="workspace-layout"');
    const shell = html.slice(start, html.indexOf('<!-- Quick Stats -->', start));
    for (const contract of [
        'id="inventory-search"',
        'id="inventory-store"',
        'clearInventoryFilters()',
        'viewStoreInventory(storeOptions.find',
        'aria-label="Refresh inventory"',
        'Add Stock',
        'class="sidebar-management"',
    ]) assert.ok(shell.includes(contract), `inventory shell must retain ${contract}`);
    assert.equal((shell.match(/id="inventory-search"/g) || []).length, 1);
    assert.equal((shell.match(/id="inventory-store"/g) || []).length, 1);
    assert.match(css, /\.inventory-panel-actions \.store-inventory-action\s*\{[^}]*border: 1px solid var\(--brand-border\)[^}]*background: var\(--brand-surface\)[^}]*color: var\(--brand-navy\)/s);
    assert.match(html, /class="btn btn-sm store-inventory-action"[\s\S]*Add Single Part/);
    assert.doesNotMatch(css, /\.store-inventory-primary-action/);
});

test('shared visual tokens are present without replacing the established palette', () => {
    for (const [name, value] of Object.entries({
        '--brand-navy': '#15263B',
        '--brand-amber': '#E9A23B',
        '--brand-slate': '#64748B',
        '--brand-page': '#F5F7FA',
        '--brand-surface': '#FFFFFF',
    })) assert.match(css, new RegExp(`${name}:\\s*${value.replace('#', '\\#')}`, 'i'));
    for (const token of ['--font-sans', '--space-1', '--space-2', '--space-3', '--space-4', '--radius-control', '--radius-surface', '--shadow-surface', '--control-height']) {
        assert.ok(css.includes(`${token}:`), `shared token ${token} must be defined`);
    }
    assert.match(loginCss, /var\(--font-sans(?:,|\))/ , 'sign-in should use the shared font token');
});

test('mobile stock rows retain labeled fields and provide touch-sized actions', () => {
    const storePanel = sectionBetween('<!-- Store Inventory Management Panel -->', '<!-- Duplicate Resolution Modal -->');
    for (const label of ['Part number', 'Description', 'Quantity', 'Work order', 'Actions']) {
        assert.ok(storePanel.includes(`data-label="${label}"`), `store stock rows must retain ${label}`);
    }
    assert.match(storePanel, /x-show="isLowStock\(item\)"[\s\S]{0,120}aria-label="Low stock"/);
    assert.match(css, /\.stock-table\s+\.btn[^{]*\{[^}]*min-height:\s*44px/s);
});

test('replenishment uses the shared panel heading and retains its setup guidance', () => {
    const panel = sectionBetween('<section x-show="showLowStockPanel"', '<section x-show="showReportsPanel"');
    assert.match(panel, /class="inventory-panel-heading"/);
    assert.match(panel, /class="inventory-panel-heading-content"/);
    assert.match(panel, /<h3 id="replenishment-heading" class="inventory-panel-title">Plan stock replenishment<\/h3>/);
    assert.match(panel, /class="inventory-panel-meta replenishment-copy"[^>]*>Set a minimum for each store and part\./);
    for (const contract of ['Set minimum stock', 'id="replenishment-store"', 'aria-label="Refresh plan"', 'Export purchases CSV', 'replenishmentRows.length']) {
        assert.ok(panel.includes(contract), `replenishment must retain ${contract}`);
    }
});
