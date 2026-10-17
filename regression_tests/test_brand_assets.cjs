const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');

const read = path => fs.readFileSync(path, 'utf8');
const pngSize = path => {
  const data = fs.readFileSync(path);
  assert.equal(data.subarray(0, 8).toString('hex'), '89504e470d0a1a0a', `${path} must be a PNG`);
  return [data.readUInt32BE(16), data.readUInt32BE(20)];
};

test('brand palette tokens and source logo variants are present', () => {
  const css = read('static/mystyle.css');
  for (const [token, value] of Object.entries({
    '--brand-navy': '#15263B', '--brand-amber': '#E9A23B', '--brand-slate': '#64748B',
    '--brand-page': '#F5F7FA', '--brand-surface': '#FFFFFF',
  })) assert.match(css, new RegExp(`${token}:\\s*${value}`, 'i'));

  const horizontal = read('static/brand/source/logo-horizontal.svg');
  assert.match(horizontal, /<text\b[^>]*>SparesFlow<\/text>/);
  const icon = read('static/brand/source/logo-icon.svg');
  assert.doesNotMatch(icon, /<text\b/i);
  assert.match(icon, /#E9A23B/i);
  assert.match(read('static/index.html'), /<span>SparesFlow<\/span>/);
  assert.match(read('static/superadmin.html'), /<h2>SparesFlow<\/h2>/);
});

test('favicon and platform icons are exported at expected sizes', () => {
  assert.deepEqual(pngSize('static/brand/generated/app-icon-1024.png'), [1024, 1024]);
  assert.deepEqual(pngSize('static/brand/generated/app-icon-512.png'), [512, 512]);
  assert.deepEqual(pngSize('static/brand/generated/favicon-16.png'), [16, 16]);
  assert.deepEqual(pngSize('static/brand/generated/favicon-32.png'), [32, 32]);
  assert.deepEqual(pngSize('static/brand/generated/favicon-48.png'), [48, 48]);
  assert.deepEqual(pngSize('mobile/assets/icon.png'), [1024, 1024]);
  for (const name of ['android-icon-foreground.png', 'android-icon-background.png', 'android-icon-monochrome.png']) {
    assert.deepEqual(pngSize(`mobile/assets/${name}`), [432, 432]);
  }
  assert.deepEqual(pngSize('mobile/assets/favicon.png'), [48, 48]);
  assert.ok(fs.existsSync('static/brand/generated/favicon.ico'));
});

test('mobile display branding leaves technical identifiers unchanged', () => {
  const config = JSON.parse(read('mobile/app.json')).expo;
  assert.equal(config.name, 'SparesFlow');
  assert.equal(config.slug, 'inventory-management-mobile');
  assert.equal(config.ios.bundleIdentifier, 'com.atonui.inventory');
  assert.equal(config.android.package, 'com.atonui.inventory');
  assert.equal(config.scheme, 'inventory-management');
  assert.equal(config.android.adaptiveIcon.backgroundColor, '#15263B');
});
