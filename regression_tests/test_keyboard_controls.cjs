const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const html = fs.readFileSync('static/index.html', 'utf8');
const start = html.indexOf('<div class="inventory-export-menu"');
const end = html.indexOf('<div class="inventory-filter-panel"', start);
const disclosure = html.slice(start, end);

function handler(attribute, scope) {
    const escaped = attribute.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const expression = disclosure.match(new RegExp(`${escaped}="([^"]*)"`))?.[1];
    assert.ok(expression, `Missing ${attribute} handler`);
    vm.runInNewContext(expression, scope);
}

test('Escape dismisses Export and restores its trigger without stealing focus when closed', () => {
    let focused = 0;
    const scope = {showExportMenu: true, $refs: {inventoryExportTrigger: {focus() { focused++; }}}};
    handler('@keydown.escape.stop', scope);
    assert.equal(scope.showExportMenu, false);
    assert.equal(focused, 1);
    handler('@keydown.escape.stop', scope);
    assert.equal(focused, 1);
});

test('Tab within Export keeps it open, while leaving the disclosure dismisses it', () => {
    const inside = {};
    const scope = {showExportMenu: true, $el: {contains: node => node === inside}, $event: {relatedTarget: inside}};
    handler('@focusout', scope);
    assert.equal(scope.showExportMenu, true);
    scope.$event.relatedTarget = {};
    handler('@focusout', scope);
    assert.equal(scope.showExportMenu, false);
});

test('every export choice closes the list and returns keyboard focus after invoking the action', () => {
    const choices = [...disclosure.matchAll(/<button type="button" class="inventory-export-menu__item" @click="([^"]*)"/g)];
    assert.equal(choices.length, 9);
    for (const [, expression] of choices) {
        const action = expression.match(/^(\w+)\(\)/)[1];
        const calls = [];
        const scope = {showExportMenu: true, [action]: () => calls.push(action)};
        vm.runInNewContext(expression, scope);
        assert.equal(scope.showExportMenu, false);
        assert.deepEqual(calls, [action]);
    }
    let focused = false;
    const panelClick = disclosure.match(/@click="(if \(\$event.target.closest[^\"]+)"/)[1];
    vm.runInNewContext(panelClick, {$event: {target: {closest: () => ({})}}, $refs: {inventoryExportTrigger: {focus() { focused = true; }}}});
    assert.equal(focused, true);
});

test('native CSV inputs remain keyboard reachable and the skip link has a focusable destination', () => {
    const files = [...html.matchAll(/<input type="file"[^>]*>/g)].map(match => match[0]);
    assert.equal(files.length, 3);
    for (const input of files) {
        assert.match(input, /class="file-upload-control"/);
        assert.doesNotMatch(input, /display:\s*none|tabindex="-1"|\shidden\b|aria-hidden="true"/);
    }
    assert.match(html, /class="skip-link" href="#workspace-content"/);
    assert.match(html, /<main id="workspace-content" tabindex="-1"/);
});

test('skip link focuses the current workspace without navigating through the page base', () => {
    // A normal fragment href resolves through <base> and drops notification
    // query parameters. Alpine must prevent navigation and focus this document.
    const link = html.match(/<a class="skip-link"[^>]*>/)?.[0];
    const expression = link?.match(/@click\.prevent="([^"]+)"/)?.[1];
    assert.ok(expression, 'Skip must prevent navigation through the document base');
    assert.match(html, /<main[^>]*x-ref="workspaceContent"/);
    const calls = [];
    const location = {href: 'https://example.test/static/index.html?store_id=7&inventory_id=42'};
    vm.runInNewContext(expression, {window: {location}, $refs: {workspaceContent: {
        focus() { calls.push('focus'); },
        scrollIntoView() { calls.push('scroll'); },
    }}});
    assert.deepEqual(calls, ['focus', 'scroll']);
    assert.equal(location.href, 'https://example.test/static/index.html?store_id=7&inventory_id=42');
});
