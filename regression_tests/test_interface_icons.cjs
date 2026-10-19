const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');

const pages = ['index', 'superadmin', 'profile'];
const read = name => fs.readFileSync(`static/${name}`, 'utf8');
const buttons = html => [...html.matchAll(/<button\b(?:[^>"']|"[^"]*"|'[^']*')*>[\s\S]*?<\/button>/g)].map(m => m[0]);
const opening = element => element.match(/^<(?:button|svg)\b(?:[^>"']|"[^"]*"|'[^']*')*>/)[0];

// Removing a shared stylesheet or navigation icon must fail, even if other icons remain.
test('all application navigation uses the shared local icon set', () => {
  for (const page of pages) {
    const html = read(`${page}.html`);
    assert.match(html, /href="icons\.css\?v=[^"]+"/);
    const navigation = page === 'index' ? html.match(/<nav class="inventory-nav"[\s\S]*?<\/nav>/)[0]
      : page === 'superadmin' ? html.match(/<nav aria-label="Superadmin navigation"[\s\S]*?<\/nav>/)[0]
      : html.match(/<div class="profile-tabs"[\s\S]*?<\/div>/)[0];
    for (const button of buttons(navigation)) assert.match(button, /<svg\b/);
  }
});

// A broken symbol URL renders an empty icon; a missing aria-hidden creates duplicate names.
test('every decorative icon resolves to a local symbol and stays out of accessible names', () => {
  assert.ok(fs.existsSync('static/icons.svg'), 'shared sprite must exist');
  const sprite = read('icons.svg');
  const ids = [...sprite.matchAll(/<symbol\b[^>]*id="([^"]+)"/g)].map(m => m[1]);
  assert.equal(new Set(ids).size, ids.length, 'symbol IDs must be unique');
  assert.ok(ids.length > 10);
  assert.doesNotMatch(sprite, /<(?:script|foreignObject|image)\b|\bon\w+=/i);
  for (const page of pages) {
    const html = read(`${page}.html`);
    const icons = [...html.matchAll(/<svg\b[^>]*class="ui-icon[^"]*"[^>]*>[\s\S]*?<\/svg>/g)];
    assert.ok(icons.length > 0, `${page} must have icons`);
    for (const [svg] of icons) {
      assert.match(opening(svg), /aria-hidden="true"/);
      assert.match(opening(svg), /focusable="false"/);
      const reference = svg.match(/<use href="icons\.svg\?v=[^"#]+#([^"]+)"/);
      assert.ok(reference, 'icons must use the versioned local sprite');
      assert.ok(ids.includes(reference[1]), `unknown icon ${reference[1]}`);
    }
    for (const button of buttons(html).filter(b => b.includes('class="ui-icon'))) {
      assert.doesNotMatch(opening(button), /\sx-text=/, 'Alpine must not erase the SVG');
    }
  }
});

test('offset icon accents use the Spares Tracker amber layer and fresh sprite URLs', () => {
  const sprite = read('icons.svg');
  for (const id of ['box', 'store', 'plus', 'chart', 'filter', 'search']) {
    const symbol = sprite.match(new RegExp(`<symbol\\b[^>]*id="${id}"[^>]*>([\\s\\S]*?)<\\/symbol>`));
    assert.ok(symbol, `missing ${id} icon`);
    assert.match(symbol[1], /fill="#E9A23B"[^>]*transform="translate\(1\.6 1\.6\)"/, `${id} needs an offset amber accent`);
  }
  for (const file of fs.readdirSync('static').filter(name => name.endsWith('.html'))) {
    const html = read(file);
    for (const reference of html.matchAll(/icons\.svg\?v=[^"#]+#(?:[\w-]+)/g)) {
      assert.match(reference[0], /^icons\.svg\?v=20261019-icon-pack-v3#/, `${file} must request the updated icon sprite`);
    }
  }
  const inventory = read('index.html');
  assert.match(inventory, /<label for="inventory-search">\s*<svg class="ui-icon" aria-hidden="true" focusable="false"><use href="icons\.svg\?v=20261019-icon-pack-v3#search"><\/use><\/svg>\s*Find stock<\/label>/);
  assert.match(inventory, /<label for="store-stock-search">\s*<svg class="ui-icon" aria-hidden="true" focusable="false"><use href="icons\.svg\?v=20261019-icon-pack-v3#search"><\/use><\/svg>\s*Find stock in this store<\/label>/);
});

test('the updated icon pack has dedicated icons for matching equipment and platform navigation', () => {
  const sprite = read('icons.svg');
  for (const id of ['download', 'unlock', 'sessions', 'secconfig', 'broadcast', 'console', 'audit', 'equipment', 'history']) {
    const symbol = sprite.match(new RegExp(`<symbol\\b[^>]*id="${id}"[^>]*>([\\s\\S]*?)<\\/symbol>`));
    assert.ok(symbol, `missing updated ${id} icon`);
    assert.match(symbol[1], /fill="#E9A23B"[^>]*transform="translate\(1\.6 1\.6\)"/, `${id} needs its offset amber layer`);
  }

  const index = read('index.html');
  const admin = read('superadmin.html');
  assert.match(index, new RegExp('#equipment"><\\/use><\\/svg> Equipment'));
  assert.match(index, new RegExp('#history"><\\/use><\\/svg> Movement history'));
  assert.match(index, new RegExp('#audit"><\\/use><\\/svg> Activity log'));
  assert.match(admin, new RegExp('#sessions"><\\/use><\\/svg><\\/span> Active Sessions'));
  assert.match(admin, new RegExp('#secconfig"><\\/use><\\/svg><\\/span> Security Config'));
  assert.match(admin, new RegExp('#console"><\\/use><\\/svg><\\/span> SQL Console'));
  assert.match(admin, new RegExp('#audit"><\\/use><\\/svg><\\/span> Audit Log'));
  for (const file of ['index.html', 'profile.html', 'superadmin.html']) {
    assert.match(read(file), /icons\.svg\?v=20261019-icon-pack-v3/);
  }
});

test('profile, clear filters, and open-in-new-window icons retain distinct meanings', () => {
  const sprite = read('icons.svg');
  for (const id of ['logout', 'refresh', 'profile', 'clearfilters', 'open']) {
    const symbol = sprite.match(new RegExp(`<symbol\\b[^>]*id="${id}"[^>]*>([\\s\\S]*?)<\\/symbol>`));
    assert.ok(symbol, `missing ${id} icon`);
    assert.match(symbol[1], /fill="#E9A23B"[^>]*transform="translate\(1\.6 1\.6\)"/, `${id} needs its offset amber layer`);
  }

  const index = read('index.html');
  const profile = read('profile.html');
  const admin = read('superadmin.html');
  assert.match(index, new RegExp('#profile"><\\/use><\\/svg> Profile'));
  assert.match(profile, new RegExp('#profile"><\\/use><\\/svg> Profile'));
  for (const button of buttons(index).concat(buttons(admin))) {
    if (/Clear filters/.test(button)) assert.match(button, /#clearfilters/);
  }
  assert.equal(buttons(index).filter(button => /Clear filters/.test(button)).length, 3);
  assert.equal(buttons(admin).filter(button => /Clear filters/.test(button)).length, 3);
  const openStore = buttons(index).find(button => button.includes('Open store'));
  assert.ok(openStore);
  assert.doesNotMatch(openStore, /#open/);
});

// Icon-only actions need contextual names, mouse tooltips and touch/keyboard affordances.
test('compact utilities keep accessible names and consequential actions keep visible labels', () => {
  let utilities = 0;
  for (const page of pages) {
    for (const button of buttons(read(`${page}.html`))) {
      if (opening(button).includes('ui-icon-only')) {
        utilities++;
        const label = opening(button).match(/aria-label="([^"]+)"/);
        const title = opening(button).match(/title="([^"]+)"/);
        assert.ok(label && title);
        assert.equal(label[1], title[1]);
        assert.match(label[1], /^(Refresh|Close) /);
      }
      if (/>\s*(?:Delete|Restore|Dispatch)\s*</.test(button)) assert.doesNotMatch(opening(button), /ui-icon-only/);
    }
  }
  assert.ok(utilities >= 3);
  const css = read('icons.css');
  assert.match(css, /min-width:\s*44px/);
  assert.match(css, /min-height:\s*44px/);
  assert.match(css, /:focus-visible/);
});

test('label-based CSV imports and the final dispatch action also have icons', () => {
  const html = read('index.html');
  const imports = [...html.matchAll(/<label\b(?:[^>"']|"[^"]*"|'[^']*')*>[\s\S]*?<\/label>/g)]
    .map(m => m[0]).filter(label => label.includes('type="file"'));
  assert.equal(imports.length, 3);
  for (const label of imports) {
    assert.ok(label.includes('#upload'), 'CSV import control needs upload icon');
    assert.ok(label.includes('Import CSV'), 'import label remains visible');
  }
  const dispatch = buttons(html).find(b => /<span[^>]*>Dispatch<\/span>/.test(b));
  assert.ok(dispatch.includes('#transfer'), 'dispatch submit needs movement icon');
});
