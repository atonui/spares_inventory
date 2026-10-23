const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const html = fs.readFileSync('static/index.html', 'utf8');
const css = fs.readFileSync('static/mystyle.css', 'utf8');

test('authenticated app uses a labeled sidebar and a separate content column', () => {
  assert.match(html, /class="workspace-layout"/);
  assert.match(html, /@keydown\.escape\.window="[^"]*mobileNavigationOpen[^"]*">\s*<aside/);
  assert.match(html, /<aside[^>]*class="workspace-sidebar"/);
  assert.match(html, /class="container workspace-main"/);
  assert.match(html, /class="sidebar-brand"[^>]*>[^<]*<img[^>]*><span[^>]*>Spares Tracker<\/span>/s);
  assert.match(html, /<nav class="inventory-nav sidebar-nav" id="primary-navigation"[^>]*aria-label="Main navigation"/);
  for (const destination of ['inventory', 'stores', 'replenishment', 'reports', 'parts', 'equipment', 'movements']) {
    assert.match(html, new RegExp(`class="sidebar-nav-link[^"]*"[^>]*href="#${destination}"`), `missing ${destination} destination`);
  }
  assert.match(css, /\.workspace-layout\s*\{[^}]*grid-template-columns:\s*\d+px minmax\(0,\s*1fr\)/s);
});

test('management links are visible as a labeled section without a disclosure control', () => {
  assert.match(html, /<section class="sidebar-management"[^>]*x-show="\['owner','admin','superadmin'\]\.includes\(currentUser\?\.role\)"/);
  assert.match(html, /<h2[^>]*>Management<\/h2>/);
  for (const destination of ['archived', 'users', 'manage-stores', 'manage-parts', 'activity-log', 'store-types']) {
    assert.match(html, new RegExp(`class="sidebar-nav-link[^"]*"[^>]*href="#${destination}"`), `missing management ${destination} destination`);
  }
  assert.doesNotMatch(html, /class="btn sidebar-nav-link/);
  assert.match(css, /\.sidebar-nav-link\.is-active[^{}]*\{[^}]*color:\s*var\(--brand-navy\)/s);
  assert.doesNotMatch(html, /<details class="management-menu"|<summary>Management<\/summary>/);
});

test('narrow layouts get an accessible drawer trigger, dismiss control, and focus behavior', () => {
  const menuTrigger = html.match(/<button[^>]*class="mobile-nav-toggle"[^>]*>[\s\S]*?<\/button>/)?.[0];
  assert.ok(menuTrigger, 'mobile navigation trigger should exist');
  assert.match(menuTrigger, /:aria-label="mobileNavigationOpen \? 'Close main navigation' : 'Open main navigation'"/);
  assert.match(menuTrigger, /aria-controls="primary-navigation"[^>]*:aria-expanded="mobileNavigationOpen"/);
  assert.match(menuTrigger, /<span class="mobile-nav-icon" aria-hidden="true"><span><\/span><span><\/span><span><\/span><\/span>/);
  assert.doesNotMatch(menuTrigger, /<svg|>\s*Menu\s*</);
  assert.match(css, /\.mobile-nav-toggle\s*\{[^}]*width:\s*44px[^}]*height:\s*44px/s);
  assert.match(css, /\.mobile-nav-icon\s*\{[^}]*width:\s*20px[^}]*height:\s*14px[^}]*flex-direction:\s*column/s);
  assert.match(css, /\.mobile-nav-icon\s*>\s*span\s*\{[^}]*height:\s*2px[^}]*background-color:\s*currentColor/s);
  assert.match(html, /@keydown\.escape\.window=.*mobileNavigationOpen/);
  assert.match(html, /class="sidebar-backdrop"[^>]*x-show="mobileNavigationOpen"/);
  assert.match(html, /@click="mobileNavigationOpen = !mobileNavigationOpen; if \(mobileNavigationOpen\) \$nextTick\(\(\) => \$refs\.firstNavigationLink\.focus\(\)\)"/);
  assert.match(html, /:inert="window\.matchMedia\('\(max-width: 1024px\)'\)\.matches && !mobileNavigationOpen"/);
  assert.match(html, /@keydown\.tab="if \(mobileNavigationOpen\) trapNavigationFocus\(\$event, \$el\)"/);
  assert.match(html, /class="container workspace-main" :inert="window\.matchMedia\('\(max-width: 1024px\)'\)\.matches && mobileNavigationOpen"/);
  assert.match(css, /@media\s*\(max-width:\s*1024px\)[\s\S]*?\.workspace-sidebar\s*\{[^}]*position:\s*fixed/);
  assert.match(css, /\.workspace-sidebar\.is-open\s*\{[^}]*transform:\s*translateX\(0\)/);
  assert.match(css, /\.sidebar-backdrop\s*\{[^}]*position:\s*fixed/);
});

test('drawer focus wraps from its first and last visible controls', () => {
  const expression = html.match(/x-data="(\{ mobileNavigationOpen: false, trapNavigationFocus\(event, drawer\) \{[\s\S]*?\}\s*\})"/)[1];
  const first = { focused: false, getClientRects: () => [{}], focus() { this.focused = true; } };
  const last = { focused: false, getClientRects: () => [{}], focus() { this.focused = true; } };
  const hidden = { focused: false, getClientRects: () => [], focus() { this.focused = true; } };
  const document = { activeElement: first };
  const state = vm.runInNewContext(`(${expression})`, { document });
  const drawer = { querySelectorAll: () => [first, hidden, last] };
  let prevented = false;
  state.trapNavigationFocus({ shiftKey: true, preventDefault() { prevented = true; } }, drawer);
  assert.equal(prevented, true);
  assert.equal(last.focused, true);
  document.activeElement = last;
  prevented = false;
  state.trapNavigationFocus({ shiftKey: false, preventDefault() { prevented = true; } }, drawer);
  assert.equal(prevented, true);
  assert.equal(first.focused, true);
});

test('store filter remains backed by the minimal store option shape and shows names only', () => {
  const select = html.slice(html.indexOf('id="inventory-store"'), html.indexOf('</select>', html.indexOf('id="inventory-store"')));
  assert.match(select, /x-for="store in storeOptions"/);
  assert.match(select, /x-text="store\.name"/);
  assert.doesNotMatch(select, /store\.(?:type|location)/);
  const app = fs.readFileSync('static/js/inventory/application-core.js', 'utf8');
  assert.match(app, /this\.apiCall\('\/store-options'\)/);
});
