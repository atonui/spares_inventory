const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const root = path.resolve(__dirname, '..');
const html = fs.readFileSync(path.join(root, 'static/login.html'), 'utf8');
const source = fs.readFileSync(path.join(root, 'static/js/pages/login.js'), 'utf8');
function setup(fetch, request) {
    const redirects = [];
    const c = vm.createContext({fetch, InventoryCsrf:{request}, window:{location:{replace:url=>redirects.push(url)}}});
    vm.runInContext(source,c);
    return {app:c.loginPage(),redirects};
}
test('login shell excludes inventory controllers and dashboard CSS',()=>{
    assert.doesNotMatch(html,/js\/inventory\/|inventoryApp\(|mystyle\.css|back-to-top\.css/);
    assert.match(html,/login-base\.css/);
    assert.match(html,/role="main" aria-labelledby="login-title"/);
    assert.match(html,/logo-white\.svg" alt="" width="720" height="180"/);
    assert.match(html,/autocomplete="current-password"/);
    assert.match(html,/loginForm\.remember_me/);
});
test('session cookie is checked on the server before redirecting',async()=>{
    const calls=[];
    const {app,redirects}=setup(async(url,options)=>{calls.push({url,options});return {ok:true,status:200}});
    await app.checkAuth();
    assert.deepEqual(redirects,['/static/index.html']);
    assert.equal(calls[0].options.credentials,'include');
    assert.equal(calls[0].options.cache,'no-store');
});
test('anonymous and failed session checks remain distinct',async()=>{
    for(const status of [401,503]) {
        const {app,redirects}=setup(async()=>({ok:false,status}));
        await app.checkAuth();
        assert.equal(app.authState,status===401?'anonymous':'error');
        assert.equal(redirects.length,0);
    }
});
test('sign-in preserves remember-me, uses shared CSRF and prevents duplicate submits',async()=>{
    let resolve;let calls=0;let payload;
    const {app,redirects}=setup(null,async(owner,url,options)=>{
        calls++;assert.equal(url,'/api/auth/login');payload=JSON.parse(options.body);
        return new Promise(r=>resolve=r);
    });
    app.loginForm={email:'test@example.test',password:'test-password',remember_me:true};
    const pending=app.login();await app.login();assert.equal(calls,1);
    resolve({ok:true});await pending;
    assert.equal(payload.remember_me,true);assert.equal(app.loginForm.password,'');
    assert.deepEqual(redirects,['/static/index.html']);
});
test('rejected sign-in retains form for retry without redirect',async()=>{
    const {app,redirects}=setup(null,async()=>({ok:false,status:401}));
    await app.login();assert.equal(app.error,'Invalid credentials');assert.equal(app.loading,false);
    assert.equal(redirects.length,0);
});

test('pending session check preserves card geometry without exposing an interactive form',()=>{
    assert.match(html, /class="login-shell login-pending"/);
    assert.doesNotMatch(html, /<section[^>]*x-show="authState === 'anonymous'"/);
    assert.match(html, /<form[^>]* inert :inert="authState !== 'anonymous'"/);
    assert.match(html, /class="login-session-status"/);
    assert.match(html, /rel="preload" href="fonts\/inter-latin\.woff2"/);
    const css=fs.readFileSync(path.join(root,'static/login-base.css'),'utf8');
    assert.match(css,/visibility: hidden/);
    assert.match(css,/aspect-ratio: 4 \/ 1/);
});
