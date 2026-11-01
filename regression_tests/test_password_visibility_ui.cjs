const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const pages = ['index.html','login.html','accept_invitation.html','reset_password.html','profile.html','superadmin.html'];

test('all web password fields have accessible show controls and shared assets', () => {
  const ids = [];
  for (const page of pages) {
    const pageIds = [];
    const html = fs.readFileSync(`static/${page}`, 'utf8');
    assert.match(html, /js\/shared\/password-visibility\.js\?v=20261101-password-icons/);
    assert.match(html, /password-visibility\.css\?v=20261101-password-icons/);
    for (const match of html.matchAll(/<input\b(?=[^>]*\btype="password")(?=[^>]*\bid="([^"]+)")[^>]*>/g)) {
      const id = match[1]; ids.push(id); pageIds.push(id);
      const control = new RegExp(`<button\\b(?=[^>]*data-password-visibility)(?=[^>]*aria-controls="${id}")(?=[^>]*aria-label="Show password")(?=[^>]*aria-pressed="false")[^>]*>\\s*<svg\\b(?=[^>]*class="password-visibility-icon")(?=[^>]*aria-hidden="true")[^>]*>[\\s\\S]*?<\\/svg>\\s*<\\/button>`);
      assert.match(html, control, `${page} #${id} needs a labeled toggle`);
      assert.match(html, new RegExp(`<div class="password-field-control">\\s*${match[0].replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*<button`), `${page} #${id} should align with its toggle`);
    }
    assert.equal(new Set(pageIds).size, pageIds.length, `${page} password field IDs must be unique`);
  }
  assert.equal(ids.length, 12);
});

test('reset recovery link targets the shipped forgot password page', () => {
  const html = fs.readFileSync('static/reset_password.html', 'utf8');
  assert.match(html, /href="\/static\/forgot_password\.html"/);
  assert.doesNotMatch(html, /href="\/forgot-password"/);
});

test('password visibility control toggles type and accessible state', () => {
  let clickHandler;
  const input = {type:'password'};
  const classes = new Set();
  const button = {attrs:{'aria-controls':'secret','aria-pressed':'false','aria-label':'Show password'},classList:{toggle(name,enabled){if(enabled)classes.add(name);else classes.delete(name)},contains(name){return classes.has(name)}},getAttribute(name){return this.attrs[name]},setAttribute(name,value){this.attrs[name]=value}};
  const doc = {addEventListener(name,handler){assert.equal(name,'click');clickHandler=handler},getElementById(id){return id==='secret'?input:null}};
  vm.runInNewContext(fs.readFileSync('static/js/shared/password-visibility.js','utf8'), {document:doc});
  const event = {target:{closest(selector){assert.equal(selector,'[data-password-visibility]');return button}}};
  clickHandler(event);
  assert.equal(input.type,'text'); assert.equal(button.attrs['aria-pressed'],'true'); assert.equal(button.attrs['aria-label'],'Hide password'); assert.equal(button.classList.contains('is-visible'),true);
  clickHandler(event);
  assert.equal(input.type,'password'); assert.equal(button.attrs['aria-pressed'],'false'); assert.equal(button.attrs['aria-label'],'Show password'); assert.equal(button.classList.contains('is-visible'),false);
});
