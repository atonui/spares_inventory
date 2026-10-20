const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');

const html = fs.readFileSync('static/index.html', 'utf8');
const css = fs.readFileSync('static/mystyle.css', 'utf8');

function stockActionsFor(listName) {
    const listStart = html.indexOf(`x-for="item in ${listName}"`);
    assert.notEqual(listStart, -1, `missing inventory list: ${listName}`);
    const cellStart = html.indexOf('<td role="cell" data-label="Actions">', listStart);
    assert.notEqual(cellStart, -1, `missing Actions cell for ${listName}`);
    const cellEnd = html.indexOf('</td>', cellStart);
    assert.notEqual(cellEnd, -1, `unclosed Actions cell for ${listName}`);
    return html.slice(cellStart, cellEnd);
}

test('stock action controls use one native disclosure menu in both inventory tables', () => {
    for (const listName of ['filteredStoreInventory', 'filteredInventory']) {
        const cell = stockActionsFor(listName);
        assert.match(cell, /<details class="stock-action-menu"/);
        assert.match(cell, /<summary[^>]*class="stock-action-trigger"[^>]*>\s*Actions\s*<\/summary>/);
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

test('stock action menu has visible keyboard focus and touch-sized trigger styling', () => {
    assert.match(css, /\.stock-action-menu\s*\{[^}]*position:\s*relative/s);
    assert.match(css, /\.stock-action-menu__items\s*\{[^}]*display:\s*flex/s);
    assert.match(css, /\.stock-action-trigger:focus-visible,\s*\.stock-action-item:focus-visible\s*\{[^}]*outline/s);
    assert.match(css, /\.stock-action-trigger\s*\{[^}]*min-height:\s*44px/s);
});
