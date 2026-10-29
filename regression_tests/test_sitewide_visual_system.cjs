const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');

const css = fs.readFileSync('static/mystyle.css', 'utf8');
const loginCss = fs.readFileSync('static/login.css', 'utf8');
const profileCss = fs.readFileSync('static/profile.css', 'utf8');
const superadminCss = fs.readFileSync('static/superadmin.css', 'utf8');

function rule(selector, source = css) {
    const start = source.indexOf(selector);
    assert.notEqual(start, -1, `missing CSS rule for ${selector}`);
    const open = source.indexOf('{', start);
    const close = source.indexOf('}', open);
    assert.ok(open > start && close > open, `invalid CSS rule for ${selector}`);
    return source.slice(open + 1, close);
}

test('shared scale includes the approved larger type and spacing steps', () => {
    assert.ok(/--type-xl:\s*1\.5rem/.test(css), 'shared type scale must define --type-xl as 1.5rem');
    assert.ok(/--space-5:\s*1\.25rem/.test(css), 'shared spacing scale must define --space-5 as 1.25rem');
});

test('shared focus and reduced-motion rules apply across the workspace', () => {
    assert.ok(/:where\(button,\s*input,\s*select,\s*textarea,\s*a,\s*summary\):focus-visible\s*\{[^}]*outline:\s*3px solid var\(--brand-focus\)/s.test(css), 'shared focus rule must use the brand focus token');
    assert.ok(/@media\s*\(prefers-reduced-motion:\s*reduce\)/.test(css), 'shared stylesheet must honor reduced-motion preference');
    assert.ok(/prefers-reduced-motion:\s*reduce\)[\s\S]*?transition-duration:\s*0\.01ms/.test(css), 'reduced motion must minimize transitions');
});

test('workspace panel rules use shared spacing and surface tokens', () => {
    const heading = rule('.inventory-panel-heading');
    assert.match(heading, /gap:\s*var\(--space-5\)/);
    assert.match(heading, /padding:\s*var\(--space-5\) var\(--space-6\)/);
    const appSurfaces = css.match(/body\s*>\s*\[x-data="inventoryApp\(\)"\]\s*\.header,[\s\S]*?\.stat-card\s*\{([^}]*)\}/);
    assert.ok(appSurfaces, 'workspace surfaces must share one shell rule');
    assert.match(appSurfaces[1], /background:\s*var\(--brand-surface\)/);
    assert.match(appSurfaces[1], /border:\s*1px solid var\(--brand-border\)/);
    const tableHeader = rule('.stock-table th');
    assert.match(tableHeader, /color:\s*var\(--brand-navy\)/);
    assert.match(tableHeader, /font-size:\s*var\(--type-xs\)/);
    assert.match(tableHeader, /text-transform:\s*uppercase/);
});

test('workspace tables keep responsive data labels and bounded report overflow', () => {
    assert.match(css, /\.stock-table\s+td::before\s*\{[^}]*content:\s*attr\(data-label\)/s);
    assert.match(css, /\.report-table-wrap\s*\{[^}]*overflow-x:\s*auto/s);
    assert.match(css, /\.consumption-report-table\s+td::before\s*\{[^}]*content:\s*attr\(data-label\)/s);
});

test('account pages use shared surface and control tokens', () => {
    assert.match(rule('.login-field', loginCss), /margin-bottom:\s*var\(--space-5\)/);
    assert.match(rule('.login-field input', loginCss), /border-radius:\s*var\(--radius-control/);

    const profileShell = rule('.profile-shell', profileCss);
    assert.match(profileShell, /border-radius:\s*var\(--radius-surface\)/);
    assert.match(profileShell, /box-shadow:\s*var\(--shadow-surface\)/);
    const profileButton = rule('.profile-page button', profileCss);
    assert.match(profileButton, /border-radius:\s*var\(--radius-control\)/);
    assert.match(profileButton, /min-height:\s*var\(--control-height\)/);
    const profileDetails = rule('.profile-details', profileCss);
    assert.match(profileDetails, /gap:\s*var\(--space-5\)/);
    assert.match(profileDetails, /padding:\s*var\(--space-5\)/);
});

test('superadmin uses shared surface and control tokens', () => {
    assert.match(rule('.sidebar', superadminCss), /background:\s*var\(--brand-surface\)/);
    assert.match(rule('.panel', superadminCss), /border-radius:\s*var\(--radius-surface\)/);
    assert.match(rule('.panel-header', superadminCss), /padding:\s*var\(--space-3\) var\(--space-4\)/);
    const tableHeader = rule('.tbl th', superadminCss);
    assert.match(tableHeader, /font-size:\s*var\(--type-xs\)/);
    assert.match(tableHeader, /text-transform:\s*uppercase/);
    assert.match(superadminCss, /:where\(button,\s*select,\s*input,\s*textarea,\s*a,\s*summary\):focus-visible\s*\{[^}]*outline:\s*3px solid var\(--brand-focus\)/s);
});

test('every page cache-busts the updated site-wide stylesheets', () => {
    const versions = {
        'mystyle.css': '20261029-keyboard-controls',
        'login.css': '20261023-approved-brand-v1',
        'profile.css': '20261023-app-button-system-v1',
        'superadmin.css': '20261029-platform-support-v1',
    };
    const pages = fs.readdirSync('static').filter(name => name.endsWith('.html'));
    for (const page of pages) {
        const source = fs.readFileSync(`static/${page}`, 'utf8');
        for (const stylesheet of Object.keys(versions)) {
            const href = new RegExp(`href=["'][^"']*${stylesheet}\\?v=([^"']+)["']`).exec(source);
            if (href) assert.equal(href[1], versions[stylesheet], `${page} must load the updated ${stylesheet}`);
        }
    }
});
