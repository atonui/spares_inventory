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
    '--brand-slate-on-page': '#475569',
    '--brand-page': '#F5F7FA', '--brand-surface': '#FFFFFF',
  })) assert.match(css, new RegExp(`${token}:\\s*${value}`, 'i'));

  const logo = read('static/brand/source/logo-color.svg');
  assert.match(logo, /<text\b[^>]*>Spares Tracker<\/text>/);
  assert.match(logo, /Abstract S-shaped tracking route/);
  const mark = read('static/brand/source/mark-color.svg');
  assert.doesNotMatch(mark, /<text\b/i);
  assert.match(mark, /#15263B/i);
  assert.match(mark, /#E9A23B/i);
  const index = read('static/index.html');
  assert.match(index, /<title>Spares Tracker/);
  assert.match(index, /<a[^>]*class="header-brand"[^>]*href="\/"[^>]*>[\s\S]*?<span>Spares Tracker<\/span>[\s\S]*?<\/a>/);
  assert.match(index, /src="brand\/source\/mark-color\.svg"/);
  assert.match(index, /src="brand\/source\/logo-white\.svg"/);
  assert.match(index, /href="mystyle\.css\?v=20261031-keyboard-controls"/, 'Header styles must use a fresh stylesheet cache key');
  assert.match(index, /href="login\.css\?v=20261023-approved-brand-v1"/, 'Sign-in styles must use a fresh stylesheet cache key');
  assert.match(index, /rel="icon" type="image\/png" sizes="32x32" href="brand\/generated\/favicon-32\.png"/);
  assert.match(read('static/superadmin.html'), /Spares Tracker/);
  assert.match(read('static/brand/source/favicon.svg'), /<title id="title">Spares Tracker favicon<\/title>/);
  for (const page of ['forgot_password.html', 'reset_password.html', 'email_change_confirmation.html', 'profile.html', 'accept_invitation.html']) {
    assert.match(read('static/' + page), /Spares Tracker/);
  }
  for (const page of ['index.html', 'forgot_password.html', 'reset_password.html', 'email_change_confirmation.html', 'superadmin.html', 'profile.html', 'accept_invitation.html']) {
    assert.match(read('static/' + page), /brand\/generated\/favicon-32\.png/);
  }
});

test('favicon and platform icons are exported at expected sizes', () => {
  assert.deepEqual(pngSize('static/brand/generated/app-icon-1024.png'), [1024, 1024]);
  assert.deepEqual(pngSize('static/brand/generated/app-icon-512.png'), [512, 512]);
  assert.deepEqual(pngSize('static/brand/generated/favicon.png'), [32, 32]);
  assert.deepEqual(pngSize('static/brand/generated/favicon-16.png'), [16, 16]);
  assert.deepEqual(pngSize('static/brand/generated/favicon-32.png'), [32, 32]);
  assert.deepEqual(pngSize('static/brand/generated/favicon-48.png'), [48, 48]);
  assert.deepEqual(pngSize('static/brand/generated/apple-touch-icon.png'), [180, 180]);
  assert.ok(fs.existsSync('static/brand/generated/favicon.ico'));
});

test('brand text and primary controls keep accessible contrast', () => {
  const luminance = hex => {
    const channels = hex.slice(1).match(/../g).map(value => parseInt(value, 16) / 255)
      .map(value => value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4);
    return channels[0] * 0.2126 + channels[1] * 0.7152 + channels[2] * 0.0722;
  };
  const ratio = (first, second) => {
    const [high, low] = [luminance(first), luminance(second)].sort((a, b) => b - a);
    return (high + 0.05) / (low + 0.05);
  };
  assert.ok(ratio('#15263B', '#FFFFFF') >= 4.5, 'Navy text on white must meet WCAG AA');
  assert.ok(ratio('#64748B', '#FFFFFF') >= 4.5, 'Slate text on white must meet WCAG AA');
  assert.ok(ratio('#475569', '#F5F7FA') >= 4.5, 'Supporting text on pale neutral must meet WCAG AA');
  assert.ok(ratio('#15263B', '#E9A23B') >= 4.5, 'Navy text on amber must meet WCAG AA');
  assert.ok(ratio('#E9A23B', '#FFFFFF') < 4.5, 'Amber must not be used as normal text on white');
});
