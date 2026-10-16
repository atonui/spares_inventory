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
    const hex = named[value] || value;
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
    assert.equal(dialogs.length, 7, 'Expected the seven inventory dialogs');
    for (const dialog of dialogs) {
        assert.equal(dialog.attrs.role, 'dialog');
        assert.equal(dialog.attrs['aria-modal'], 'true');
        assert.ok(dialog.attrs.tabindex, 'Dialog should be programmatically focusable');
        const labelId = dialog.attrs['aria-labelledby'];
        assert.ok(labelId, 'Dialog should reference its visible title');
        assert.ok(tags.some(tag => !tag.closing && /^h[1-6]$/.test(tag.name) && tag.attrs.id === labelId), `Missing dialog title ${labelId}`);
    }
});

test('primary, success, warning, and consume actions meet WCAG AA contrast', () => {
    const mainCss = read('mystyle.css');
    const adminCss = read('superadmin.css');
    const primaryBg = declaration(mainCss, '.btn', 'background');
    const primaryFg = declaration(mainCss, '.btn', 'color');
    const successBg = declaration(mainCss, '.btn-success', 'background');
    const warningBg = declaration(mainCss, '.btn-warning', 'background');
    const disabledBg = declaration(mainCss, '.btn:disabled', 'background');
    const disabledFg = declaration(mainCss, '.btn:disabled', 'color');
    const greenBg = declaration(adminCss, '.btn-green', 'background');
    const greenFg = declaration(adminCss, '.btn-green', 'color');
    const greenDisabledBg = declaration(adminCss, '.btn-green:disabled', 'background');
    const greenDisabledFg = declaration(adminCss, '.btn-green:disabled', 'color');
    const amberBg = declaration(adminCss, '.btn-amber', 'background');
    const amberFg = declaration(adminCss, '.btn-amber', 'color');
    const adminTextSelectors = ['.sidebar-brand p', '.sidebar-footer a', '.tbl th', '.stat-lbl', '.cfg-desc', '.cfg-unit', '.empty', '.qa-sub'];
    const indexHtml = read('index.html');
    const consumeText = indexHtml.indexOf('<span x-show="!loading">Consume Part</span>');
    const consumeStart = indexHtml.lastIndexOf('<button', consumeText);
    const consumeEnd = indexHtml.indexOf('>', consumeStart);
    assert.ok(consumeText >= 0 && consumeStart >= 0 && consumeEnd > consumeStart, 'Missing consume action button');
    const consumeButtonAttrs = attributes(indexHtml.slice(consumeStart + '<button'.length, consumeEnd));
    const consumeStyle = Object.fromEntries(consumeButtonAttrs.style.split(';').map(item => {
        const [key, ...value] = item.split(':');
        return [key?.trim().toLowerCase(), value.join(':').trim()];
    }).filter(([key, value]) => key && value));
    const consumeBg = consumeStyle.background || consumeStyle['background-color'];
    const consumeFg = consumeStyle.color;

    assertAa('Primary action', primaryFg, primaryBg);
    assertAa('Primary action hover', primaryFg, declaration(mainCss, '.btn:hover', 'background'));
    const inventoryHoverFg = declaration(mainCss, '.inventory-controls .btn:hover', 'color');
    const replenishmentHoverFg = declaration(mainCss, '.replenishment-panel .btn:hover', 'color');
    assert.equal(inventoryHoverFg, '#ffffff');
    assert.equal(replenishmentHoverFg, '#ffffff');
    assertAa('Inventory control hover action', inventoryHoverFg, declaration(mainCss, '.inventory-controls .btn:hover', 'background'));
    assertAa('Replenishment hover action', replenishmentHoverFg, declaration(mainCss, '.replenishment-panel .btn:hover', 'background'));
    assertAa('Success action', primaryFg, successBg);
    assertAa('Success action hover', primaryFg, declaration(mainCss, '.btn-success:hover', 'background'));
    assertAa('Warning action', declaration(mainCss, '.btn-warning', 'color'), warningBg);
    assertAa('Warning action hover', declaration(mainCss, '.btn-warning:hover', 'color'), declaration(mainCss, '.btn-warning:hover', 'background'));
    assertAa('Disabled action', disabledFg, disabledBg);
    assert.equal(declaration(mainCss, '.inventory-controls .btn:disabled', 'opacity'), '1');
    assert.equal(declaration(mainCss, '.replenishment-panel .btn:disabled', 'opacity'), '1');
    assertAa('Green platform-admin action', greenFg, greenBg);
    assertAa('Green platform-admin hover action', greenFg, declaration(adminCss, '.btn-green:hover', 'background'));
    assertAa('Disabled platform-admin action', greenDisabledFg, greenDisabledBg);
    assertAa('Amber platform-admin action', amberFg, amberBg);
    assertAa('Amber platform-admin hover action', amberFg, declaration(adminCss, '.btn-amber:hover', 'background'));
    assertAa('Consume action', consumeFg, consumeBg);
    for (const selector of adminTextSelectors) {
        const foreground = declaration(adminCss, selector, 'color');
        const background = /\.tbl th/.test(selector) ? declaration(adminCss, selector, 'background') : '#ffffff';
        assertAa(`${selector} helper text`, foreground, background);
    }
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
