const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const {loadPageScripts} = require('./helpers/frontend.cjs');
const vm = require('node:vm');

test('SaaS profile directs email changes to the company administrator', () => {
    const html = fs.readFileSync('static/profile.html', 'utf8');
    const script = fs.readFileSync('static/js/pages/profile.js', 'utf8');
    const context = {console, Intl, Date, URLSearchParams, window: {location: {href: ''}}};
    vm.createContext(context);
    loadPageScripts('profile.html', context);
    const profile = context.profileManager();

    assert.match(html, /Ask your company owner or another administrator to change your sign-in email\./);
    assert.match(html, /Contact Spares Tracker support to change the company owner email\./);
    assert.doesNotMatch(html, /new-account-email|Send confirmation link|Cancel email change/);
    assert.doesNotMatch(script, /requestEmailChange|cancelEmailChange|\/api\/profile\/email-change/);
    assert.equal(typeof profile.requestEmailChange, 'undefined');
});
