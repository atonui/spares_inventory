const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const staticDir = path.join(__dirname, '..', 'static');
const read = name => fs.readFileSync(path.join(staticDir, name), 'utf8');

function attributes(source) {
    const result = {};
    for (const match of source.matchAll(/([\w:-]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?/g)) {
        result[match[1].toLowerCase()] = match[2] ?? match[3] ?? match[4] ?? '';
    }
    return result;
}

function htmlTags(source) {
    const tags = [];
    let cursor = 0;
    while (cursor < source.length) {
        const start = source.indexOf('<', cursor);
        if (start < 0) break;
        if (source.startsWith('<!--', start)) {
            cursor = source.indexOf('-->', start + 4);
            if (cursor < 0) break;
            cursor += 3;
            continue;
        }
        let quote = null;
        let end = start + 1;
        for (; end < source.length; end += 1) {
            const char = source[end];
            if (quote) {
                if (char === quote) quote = null;
            } else if (char === '"' || char === "'") {
                quote = char;
            } else if (char === '>') {
                break;
            }
        }
        if (end >= source.length) break;
        const raw = source.slice(start + 1, end).trim();
        const match = /^([/!]?[\w:-]+)([\s\S]*)$/.exec(raw);
        if (match && !match[1].startsWith('!')) {
            tags.push({
                name: match[1].replace(/^\//, '').toLowerCase(),
                closing: match[1].startsWith('/'),
                attrs: attributes(match[2].replace(/\/$/, '')),
                start,
                end: end + 1,
            });
        }
        cursor = end + 1;
    }
    return tags;
}

function unlabelledControls(source, filename) {
    const labels = [];
    const controls = [];
    const openLabels = [];
    for (const tag of htmlTags(source)) {
        if (tag.name === 'label') {
            if (tag.closing) {
                const label = openLabels.pop();
                if (label) label.end = tag.end;
            } else {
                const label = {start: tag.start, end: source.length, forId: tag.attrs.for || null};
                labels.push(label);
                openLabels.push(label);
            }
        } else if (!tag.closing && ['input', 'select', 'textarea'].includes(tag.name)) {
            controls.push({tag: tag.name, attrs: tag.attrs, start: tag.start});
        }
    }
    const labelTargets = new Set(labels.map(label => label.forId).filter(Boolean));
    const missing = [];

    for (const control of controls) {
        const attrs = control.attrs;
        if (control.tag === 'input' && attrs.type?.toLowerCase() === 'hidden') continue;
        const wrapped = labels.some(label => label.start < control.start && control.start < label.end);
        const explicitlyNamed = attrs['aria-label'] || attrs[':aria-label'] || attrs['aria-labelledby'] || attrs[':aria-labelledby'];
        if (!wrapped && !explicitlyNamed && !(attrs.id && labelTargets.has(attrs.id))) {
            missing.push(`${filename}: ${attrs.id || attrs['x-model'] || attrs.name || control.tag}`);
        }
    }
    return missing;
}

function hexRgb(color) {
    const value = color.trim().toLowerCase();
    const named = {white: '#ffffff', black: '#000000'};
    const tokens = {'var(--brand-navy)': '#15263b', 'var(--brand-amber)': '#e9a23b', 'var(--brand-slate)': '#64748b', 'var(--brand-page)': '#f5f7fa', 'var(--brand-surface)': '#ffffff', 'var(--brand-border)': '#d8e0e8', 'var(--brand-focus)': '#15263b'};
    const hex = named[value] || tokens[value] || value;
    const short = /^#([0-9a-f]{3})$/i.exec(hex);
    const full = short ? [...short[1]].map(ch => ch + ch).join('') : /^#([0-9a-f]{6})$/i.exec(hex)?.[1];
    assert.ok(full, `Unsupported test color: ${color}`);
    return [0, 2, 4].map(offset => parseInt(full.slice(offset, offset + 2), 16) / 255);
}

function luminance(color) {
    const channels = hexRgb(color).map(channel => channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4);
    return channels[0] * 0.2126 + channels[1] * 0.7152 + channels[2] * 0.0722;
}

function contrast(foreground, background) {
    const values = [luminance(foreground), luminance(background)].sort((a, b) => b - a);
    return (values[0] + 0.05) / (values[1] + 0.05);
}

function declaration(css, selector, property) {
    const escaped = selector.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const rule = new RegExp(`(?:^|\\n)\\s*${escaped}\\s*\\{([^}]*)\\}`, 'm').exec(css);
    assert.ok(rule, `Missing CSS rule: ${selector}`);
    const value = new RegExp(`(?:^|;)\\s*${property}\\s*:\\s*([^;]+)`, 'i').exec(rule[1]);
    assert.ok(value, `Missing ${property} in ${selector}`);
    return value[1].trim();
}

function assertAa(label, foreground, background) {
    const ratio = contrast(foreground, background);
    assert.ok(ratio >= 4.5, `${label} contrast is ${ratio.toFixed(2)}:1; expected at least 4.5:1`);
}

test('visible form labels are programmatically associated with controls', () => {
    const pages = fs.readdirSync(staticDir).filter(name => name.endsWith('.html'));
    const missing = pages.flatMap(name => unlabelledControls(read(name), name));
    assert.deepEqual(missing, [], `Unlabelled controls:\n${missing.join('\n')}`);
});

test('inventory dialogs expose accessible names and modal semantics', () => {
    const tags = htmlTags(read('index.html'));
    const dialogs = tags.filter(tag => !tag.closing && tag.name === 'div' && tag.attrs.class?.split(/\s+/).includes('modal'));
    assert.equal(dialogs.length, 13, 'Expected all thirteen inventory dialogs');
    for (const dialog of dialogs) {
        assert.equal(dialog.attrs.role, 'dialog');
        assert.equal(dialog.attrs['aria-modal'], 'true');
        assert.ok(dialog.attrs.tabindex, 'Dialog should be programmatically focusable');
        const labelId = dialog.attrs['aria-labelledby'];
        assert.ok(labelId, 'Dialog should reference its visible title');
        assert.ok(tags.some(tag => !tag.closing && /^h[1-6]$/.test(tag.name) && tag.attrs.id === labelId), `Missing dialog title ${labelId}`);
    }
});

test('shared outlined buttons and destructive actions meet WCAG AA contrast', () => {
    assertAa('Brand navy text on pale neutral', '#15263B', '#F5F7FA');
    assertAa('Brand slate text on white', '#64748B', '#FFFFFF');
    const buttonCss = read('buttons.css');
    assertAa('Standard button label', '#15263B', '#FFFFFF');
    assertAa('Destructive button label', '#8A2828', '#FFFFFF');
    assert.match(buttonCss, /\.btn-danger[^{}]*\{[^}]*color:\s*#8A2828/s);
});

test('equipment due-soon and overdue summary text meets WCAG AA contrast', () => {
    const mainCss = read('mystyle.css');
    const background = declaration(mainCss, '.inventory-panel-heading', 'background');
    assertAa('Equipment due soon summary', declaration(mainCss, '.equipment-summary-due', 'color'), background);
    assertAa('Equipment overdue summary', declaration(mainCss, '.equipment-summary-overdue', 'color'), background);
});

test('workspace, report, and platform table headers meet WCAG AA contrast', () => {
    const mainCss = read('mystyle.css');
    const adminCss = read('superadmin.css');
    for (const [stylesheet, selector, backgroundSelector] of [
        [mainCss, '.stock-table th', '.stock-table th'],
        [mainCss, '.report-table-wrap th', '.report-table-wrap th'],
        [adminCss, '.tbl th', '.tbl th'],
    ]) {
        assertAa(
            `${selector} table header`,
            declaration(stylesheet, selector, 'color'),
            declaration(stylesheet, backgroundSelector, 'background'),
        );
    }
});

test('equipment calibration badges meet WCAG AA contrast in every state', () => {
    const mainCss = read('mystyle.css');
    const colors = {
        overdue: ['#991b1b', '#fee2e2'],
        urgent: ['#9a3412', '#fed7aa'],
        soon: ['#92400e', '#fef3c7'],
        ok: ['#065f46', '#d1fae5'],
        none: ['#334155', '#f1f5f9'],
    };
    for (const [state, [foreground, background]] of Object.entries(colors)) {
        const selector = `.equipment-calibration-status--${state}`;
        assert.equal(declaration(mainCss, selector, 'color'), foreground);
        assert.equal(declaration(mainCss, selector, 'background'), background);
        assertAa(`Equipment calibration ${state}`, foreground, background);
    }
});

test('selected navigation buttons retain a readable active state', () => {
    const buttonCss = read('buttons.css');
    const navigationCss = read('mystyle.css');
    assert.match(navigationCss, /\.workspace-sidebar \.sidebar-nav \.sidebar-nav-link\.is-active[^{}]*\{[^}]*color:\s*var\(--brand-navy\)/s);
    assert.match(buttonCss, /\.profile-tabs button\[aria-selected="true"\][^{}]*\{[^}]*color:\s*#FFFFFF/s);
});

test('platform-admin inline helper copy keeps readable contrast', () => {
    const adminHtml = read('superadmin.html');
    const lowContrast = [...adminHtml.matchAll(/color\s*:\s*#(?:888|aaa)\b/gi)];
    assert.equal(lowContrast.length, 0, `Found ${lowContrast.length} low-contrast inline helper colors`);
});

test('mobile movement history cards label every data cell', () => {
    const html = read('index.html');
    const heading = html.indexOf('id="movement-history-heading"');
    const tableStart = html.indexOf('<table', heading);
    const tableEnd = html.indexOf('</table>', tableStart);
    assert.ok(heading >= 0 && tableStart > heading && tableEnd > tableStart, 'Missing movement history table');
    const cells = [...html.slice(tableStart, tableEnd).matchAll(/<td\b([^>]*)>/g)];
    assert.deepEqual(cells.map(([, attrs]) => attributes(attrs)['data-label']), [
        'Date / time', 'Type', 'Part', 'Quantity', 'From store', 'To store', 'Work order', 'Recorded by', 'Transfer status'
    ]);
});

test('dialogs remain scrollable within the mobile viewport', () => {
    const css = read('mystyle.css');
    assert.ok(/\.modal-content\s*\{[^}]*max-height:\s*calc\(100dvh\s*-\s*2rem\)/s.test(css), 'Dialog should fit the dynamic viewport height');
    assert.equal(declaration(css, '.modal-content', 'overflow-y'), 'auto');
    assert.equal(declaration(css, '.modal-content', 'overscroll-behavior'), 'contain');
});

test('all date and date-time fields share mobile sizing', () => {
    const html = read('index.html');
    const adminHtml = read('superadmin.html');
    assert.equal([...html.matchAll(/type="date"/g)].length, 10, 'Inventory page should expose six history filters and four equipment dates');
    assert.equal([...adminHtml.matchAll(/type="date"/g)].length, 2, 'Platform audit should expose both date filters');
    assert.equal([...adminHtml.matchAll(/type="datetime-local"/g)].length, 2, 'Announcement controls should expose both date-time fields');

    const css = read('mystyle.css');
    assert.ok(/@media\s*\(max-width:\s*768px\)[\s\S]*?input\[type="date"\]\s*,\s*input\[type="datetime-local"\]\s*\{[^}]*box-sizing:\s*border-box;[^}]*width:\s*100%;[^}]*min-width:\s*0;[^}]*min-height:\s*48px;[^}]*font-size:\s*16px;/s.test(css), 'Date controls should share full-width, touch-sized mobile rules');
    const adminCss = read('superadmin.css');
    assert.ok(/@media\s*\(max-width:\s*768px\)[\s\S]*?\.audit-filters\s+input\[type="date"\]\s*\{[^}]*min-height:\s*48px;[^}]*font-size:\s*16px;/s.test(adminCss), 'Platform audit date filters should keep the shared mobile touch size');
});

test('platform organization table becomes labeled cards on mobile', () => {
    const html = read('superadmin.html');
    const start = html.indexOf('<table class="organizations-table">');
    const end = html.indexOf('</table>', start);
    assert.ok(start >= 0 && end > start, 'Missing organization table');
    const table = html.slice(start, end);
    assert.deepEqual([...table.matchAll(/<td\b[^>]*data-label="([^"]+)"/g)].map(([, label]) => label), [
        'Name', 'Slug', 'Status', 'Created'
    ]);
    const css = read('superadmin.css');
    assert.ok(/@media\s*\(max-width:\s*768px\)[\s\S]*?\.organizations-table[^}]*display:\s*block/s.test(css), 'Organization table should switch to a mobile card layout');
    assert.ok(/\.organizations-table\s+td::before\s*\{[^}]*content:\s*attr\(data-label\)/s.test(css), 'Mobile values should retain visible field labels');
});

test('active session table becomes labeled cards on mobile', () => {
    const html = read('superadmin.html');
    const sessionsTab = html.indexOf("<div x-show=\"tab==='sessions'\">");
    const start = html.indexOf('<table class="tbl sessions-table">', sessionsTab);
    const end = html.indexOf('</table>', start);
    assert.ok(sessionsTab >= 0 && start > sessionsTab && end > start, 'Missing active sessions table');
    const table = html.slice(start, end);
    assert.deepEqual([...table.matchAll(/<td\b[^>]*data-label="([^"]+)"/g)].map(([, label]) => label), [
        'User', 'Role', 'IP Address', 'Last Activity', 'Expires', 'Browser', 'Action'
    ]);
    const css = read('superadmin.css');
    assert.ok(/@media\s*\(max-width:\s*768px\)[\s\S]*?\.sessions-table[^}]*display:\s*block/s.test(css), 'Active sessions should switch to a mobile card layout');
    assert.ok(/\.sessions-table\s+td::before\s*\{[^}]*content:\s*attr\(data-label\)/s.test(css), 'Mobile session values should retain visible field labels');
});

test('platform user table becomes labeled cards on mobile', () => {
    const html = read('superadmin.html');
    const usersTab = html.indexOf("<div x-show=\"tab==='users'\">");
    const start = html.indexOf('<table class="tbl users-table">', usersTab);
    const end = html.indexOf('</table>', start);
    assert.ok(usersTab >= 0 && start > usersTab && end > start, 'Missing platform users table');
    const table = html.slice(start, end);
    assert.deepEqual([...table.matchAll(/<td\b[^>]*data-label="([^"]+)"/g)].map(([, label]) => label), [
        'Name', 'Email', 'Role', 'Territory', 'Failed Logins', 'Last Login', 'Status', 'Account Actions', 'Reset Password'
    ]);
    const css = read('superadmin.css');
    assert.ok(/@media\s*\(max-width:\s*768px\)[\s\S]*?\.users-table[^}]*display:\s*block/s.test(css), 'Platform users should switch to a mobile card layout');
    assert.ok(/\.users-table\s+td::before\s*\{[^}]*content:\s*attr\(data-label\)/s.test(css), 'Mobile user values should retain visible field labels');
});

test('platform audit entries become labeled cards on mobile', () => {
    const html = read('superadmin.html');
    const section = html.slice(html.indexOf("x-show=\"tab==='audit'\""), html.indexOf('class="audit-pagination"'));
    const start = section.indexOf('<table class="audit-table tbl">');
    const end = section.indexOf('</table>', start);
    assert.ok(start >= 0 && end > start, 'Missing audit table');
    const table = section.slice(start, end);
    assert.deepEqual([...table.matchAll(/<td\b[^>]*data-label="([^"]+)"/g)].map(([, label]) => label), [
        'Time', 'Action', 'Resource', 'Status', 'Details'
    ]);
    const css = read('superadmin.css');
    assert.ok(/@media\s*\(max-width:\s*768px\)[\s\S]*?\.audit-table[^}]*display:\s*block/s.test(css), 'Audit table should switch to a mobile card layout');
    assert.ok(/\.audit-table\s+td::before\s*\{[^}]*content:\s*attr\(data-label\)/s.test(css), 'Mobile audit values should retain visible field labels');
});

test('locked account table becomes labeled cards on mobile without losing selection or unlock actions', () => {
    const html = read('superadmin.html');
    const accountsTab = html.indexOf("<div x-show=\"tab==='accounts'\">");
    const start = html.indexOf('<table class="tbl locked-accounts-table">', accountsTab);
    const end = html.indexOf('</table>', start);
    assert.ok(accountsTab >= 0 && start > accountsTab && end > start, 'Missing locked accounts table');
    const table = html.slice(start, end);
    assert.deepEqual([...table.matchAll(/<td\b[^>]*data-label="([^"]+)"/g)].map(([, label]) => label), [
        'Select', 'Name', 'Email', 'Role', 'Failed Attempts', 'Locked Until', 'Action'
    ]);
    assert.match(table, /x-model="selectedLocked"/, 'Locked account selection should remain available');
    assert.match(table, /@click="unlock\(u\)"/, 'Per-account unlock action should remain available');
    const css = read('superadmin.css');
    assert.ok(/@media\s*\(max-width:\s*768px\)[\s\S]*?\.locked-accounts-table[^}]*display:\s*block/s.test(css), 'Locked accounts should switch to a mobile card layout');
    assert.ok(/\.locked-accounts-table\s+td::before\s*\{[^}]*content:\s*attr\(data-label\)/s.test(css), 'Mobile locked account values should retain visible field labels');
});

test('remaining fixed inventory tables become labeled mobile cards and keep row actions', () => {
    const html = read('index.html');
    const cases = [
        {
            marker: '<!-- All Parts Panel -->',
            labels: ['Part Number', 'Description', 'Category', 'Unit Cost', 'Quantity'],
        },
        {
            marker: '<section x-show="showArchivedPanel',
            labels: ['Type', 'Record', 'Archived', 'Action'],
            action: 'restoreArchivedRecord(record)',
        },
        {
            marker: '<!-- Store Management Panel (Admin Only) -->',
            labels: ['Name', 'Type', 'Location', 'Assigned To', 'Actions'],
            action: 'deleteStore(store.id, store.name)',
        },
        {
            marker: '<!-- All Stores Panel -->',
            labels: ['Store Name', 'Type', 'Location', 'Assigned To', 'Total Items', 'Actions'],
            action: 'viewStoreInventory(store)',
        },
    ];

    for (const {marker, labels, action} of cases) {
        const section = html.indexOf(marker);
        const start = html.indexOf('<table class="inventory-reference-table">', section);
        const end = html.indexOf('</table>', start);
        assert.ok(section >= 0 && start > section && end > start, `Missing table after ${marker}`);
        const table = html.slice(start, end);
        assert.deepEqual([...table.matchAll(/<td\b[^>]*data-label="([^"]+)"/g)].map(([, label]) => label), labels);
        if (action) assert.ok(table.includes(action), `Missing row action ${action}`);
    }

    const css = read('mystyle.css');
    assert.ok(/@media\s*\(max-width:\s*768px\)[\s\S]*?\.inventory-reference-table,\s*\.inventory-reference-table tbody\s*\{[^}]*display:\s*block/s.test(css), 'Fixed inventory tables should switch to mobile cards');
    assert.ok(/\.inventory-reference-table\s+td::before\s*\{[^}]*content:\s*attr\(data-label\)/s.test(css), 'Mobile inventory values should retain field labels');
    assert.ok(/\.inventory-reference-table\s+td\[data-label="Actions?"\]\s+\.btn\s*\{[^}]*min-height:\s*44px/s.test(css), 'Row actions should retain mobile touch size');
    assert.match(read('superadmin.html'), /class="tbl" x-show="queryResult\?\.rows\?\.length > 0"/, 'Dynamic query results should retain their separate scrollable table');
    assert.match(html, /href="mystyle\.css\?v=20261023-mobile-menu-visibility-v3"/, 'Header stylesheet changes should use a fresh cache version');
});
