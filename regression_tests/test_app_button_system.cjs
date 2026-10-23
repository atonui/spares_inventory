const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const styleVersion = '20261023-app-button-system-v1';
const buttonCss = fs.readFileSync('static/buttons.css', 'utf8');
const typographyVersion = '20261023-font-scale-v1';

test('every app page loads button and typography systems after its page styles', () => {
    const pages = fs.readdirSync('static').filter(name => name.endsWith('.html'));
    for (const page of pages) {
        const html = fs.readFileSync(path.join('static', page), 'utf8');
        const buttonLink = html.indexOf(`buttons.css?v=${styleVersion}`);
        const typographyLink = html.indexOf(`typography.css?v=${typographyVersion}`);
        assert.notEqual(buttonLink, -1, `${page} must load the shared button stylesheet`);
        assert.notEqual(typographyLink, -1, `${page} must load the shared typography stylesheet`);
        const head = html.slice(0, html.indexOf('</head>'));
        const stylesheetLinks = Array.from(head.matchAll(/<link rel="stylesheet" href="([^"]+)"/g));
        assert.ok(buttonLink < typographyLink, `${page} must load typography after button rules`);
        assert.match(stylesheetLinks.at(-1)?.[1] || '', /typography\.css\?v=20261023-font-scale-v1$/, `${page} must load typography after its page styles`);
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

test('shared typography uses the SaaS scale and mobile heading sizes', () => {
    const typographyCss = fs.readFileSync('static/typography.css', 'utf8');
    assert.match(typographyCss, /--font-sans:\s*Inter,\s*ui-sans-serif,\s*system-ui/);
    assert.match(typographyCss, /--type-dashboard-body:\s*0\.9375rem/);
    assert.match(typographyCss, /--type-data:\s*0\.875rem/);
    assert.match(typographyCss, /--type-caption:\s*0\.75rem/);
    assert.match(typographyCss, /--type-h2:\s*clamp\(1\.5rem,\s*2\.7vw,\s*2\.25rem\)/);
    assert.match(typographyCss, /--type-h3:\s*clamp\(1\.125rem,\s*1\.6vw,\s*1\.5rem\)/);
    assert.match(typographyCss, /--type-hero:\s*clamp\(3rem,\s*5vw,\s*3\.75rem\)/);
    assert.match(typographyCss, /h1\s*\{[^}]*letter-spacing:\s*-0\.02em/s);
    assert.match(typographyCss, /h2\s*\{[^}]*letter-spacing:\s*-0\.01em/s);
    assert.match(typographyCss, /line-height:\s*1\.55/);
    assert.match(typographyCss, /@media\s*\(max-width:\s*768px\)[\s\S]*?login-intro h1\s*\{[^}]*font-size:\s*clamp\(2rem,\s*8vw,\s*2\.25rem\)/);
});
