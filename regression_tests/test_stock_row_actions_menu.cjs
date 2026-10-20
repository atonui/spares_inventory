const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');

const html = fs.readFileSync('static/index.html', 'utf8');
const css = fs.readFileSync('static/mystyle.css', 'utf8');

function stockActionsFor(listName) {
    const listStart = html.indexOf(`x-for="item in ${listName}"`);
    assert.notEqual(listStart, -1, `missing inventory list: ${listName}`);
    const cellStart = html.indexOf('<td role="cell" data-label="Actions"', listStart);
    assert.notEqual(cellStart, -1, `missing Actions cell for ${listName}`);
    const cellEnd = html.indexOf('</td>', cellStart);
    assert.notEqual(cellEnd, -1, `unclosed Actions cell for ${listName}`);
    return html.slice(cellStart, cellEnd);
}

test('inventory stock tables use compact, item-labelled overflow actions', () => {
    assert.ok(html.includes('class="stock-table stock-inventory-table stock-inventory-table--store"'));
    assert.ok(html.includes('class="stock-table stock-inventory-table stock-inventory-table--all"'));
    for (const listName of ['filteredStoreInventory', 'filteredInventory']) {
        const cell = stockActionsFor(listName);
        assert.match(cell, /<details class="stock-action-menu"/);
        assert.match(cell, /class="stock-actions-cell"/);
        assert.match(cell, /stock-actions-cell--readonly/);
        assert.match(cell, /<summary[^>]*class="stock-action-trigger"[^>]*:aria-label="'Actions for ' \+ item\.part_number"/);
        assert.match(cell, /class="stock-action-icon"/);
        assert.match(cell, /x-show="canEdit\(item\.store_owner, item\.store_type\)"/);
        assert.match(cell, /x-show="!canEdit\(item\.store_owner, item\.store_type\)"[^>]*>Read only/);
        assert.doesNotMatch(cell, /btn-warning|btn-consume/);

        for (const [label, handler] of [
            ['Adjust quantity', 'editItem(item)'],
            ['Transfer stock', 'transferItem(item)'],
            ['Consume for work order', 'consumeItem(item)'],
        ]) {
            assert.match(cell, new RegExp(`class="stock-action-item"[^>]*@click="\\$el\\.closest\\('details'\\)\\.open = false; ${handler.replace(/[()]/g, '\\$&')}`));
            assert.ok(cell.includes(label), `${listName} must retain ${label}`);
        }
    }
});

test('stock action menu floats over rows and inventory tables have a compact mobile-card layout', () => {
    assert.match(css, /\.stock-action-menu\s*\{[^}]*position:\s*relative/s);
    assert.match(css, /\.stock-action-menu__items\s*\{[^}]*position:\s*absolute/s);
    assert.match(css, /\.stock-action-trigger:focus-visible,\s*\.stock-action-item:focus-visible\s*\{[^}]*outline/s);
    assert.match(css, /\.stock-action-trigger\s*\{[^}]*width:\s*40px/s);
    assert.match(css, /\.stock-inventory-table \.stock-action-trigger\s*\{[^}]*width:\s*44px[^}]*height:\s*44px[^}]*min-height:\s*44px/s);
    assert.match(css, /\.stock-inventory-table\s+tr\s*\{[^}]*grid-template-columns:\s*minmax\(0,\s*1fr\)\s+auto/s);
    assert.match(css, /\.stock-inventory-table\s+td\[data-label="Description"\]\s*\{[^}]*grid-column:\s*1\s*\/\s*-1/s);
    assert.match(css, /\.inventory-table:has\(\.stock-action-menu\[open\]\)\s*\{[^}]*overflow:\s*visible/s);
});
