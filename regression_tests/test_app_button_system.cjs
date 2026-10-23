const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const styleVersion = '20261023-app-button-system-v1';
const buttonCss = fs.readFileSync('static/buttons.css', 'utf8');

test('every app page loads the shared button system after its page styles', () => {
    const pages = fs.readdirSync('static').filter(name => name.endsWith('.html'));
    for (const page of pages) {
        const html = fs.readFileSync(path.join('static', page), 'utf8');
        const buttonLink = html.indexOf(`buttons.css?v=${styleVersion}`);
        assert.notEqual(buttonLink, -1, `${page} must load the shared button stylesheet`);
        const head = html.slice(0, html.indexOf('</head>'));
        const lastStyleLink = Math.max(...Array.from(head.matchAll(/<link rel="stylesheet"/g), match => match.index));
        assert.ok(buttonLink > lastStyleLink, `${page} must load shared button rules after its page styles`);
    }
});

test('action buttons share outlined neutral geometry and interaction states', () => {
    const baseRule = buttonCss.slice(0, buttonCss.indexOf(':hover:not(:disabled)'));
    assert.match(baseRule, /button:not\(\.nav-item, \.stock-action-item, \.inventory-export-menu__item, \.stock-action-trigger, \.qa-btn\)/);
    assert.match(baseRule, /min-height:\s*40px/);
    assert.match(baseRule, /border:\s*1px solid var\(--brand-border/);
    assert.match(baseRule, /background:\s*var\(--brand-surface/);
    assert.match(baseRule, /color:\s*var\(--brand-navy/);
    assert.match(buttonCss, /:hover:not\(:disabled\)[\s\S]*?background:\s*var\(--brand-page/);
    assert.match(buttonCss, /:disabled\s*\{[^}]*cursor:\s*not-allowed/);
    assert.match(buttonCss, /:focus-visible\s*\{[^}]*outline:/);
    assert.match(buttonCss, /@media\s*\(max-width:\s*768px\)[\s\S]*?min-height:\s*44px/);
});

test('semantic danger and selected navigation remain identifiable without filled action buttons', () => {
    const dangerRules = buttonCss.slice(buttonCss.indexOf('button.btn.btn-danger'), buttonCss.indexOf('/* Navigation'));
    assert.match(dangerRules, /border-color:\s*#D7A5A5/);
    assert.match(dangerRules, /color:\s*#8A2828/);
    assert.match(buttonCss, /:hover:not\(:disabled\)\s*\{[^}]*background:\s*#FFF7F7/s);
    assert.match(buttonCss, /\.inventory-nav \.btn\.is-active/);
    assert.match(buttonCss, /\.profile-tabs button\[aria-selected="true"\]/);
    assert.doesNotMatch(dangerRules.slice(0, dangerRules.indexOf(':hover')), /background:\s*(?:#|var\(--brand-(?:navy|amber)\))/);
});
