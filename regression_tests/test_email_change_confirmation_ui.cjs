const fs=require('node:fs');
const path=require('node:path');
const {test}=require('node:test');
const assert=require('node:assert/strict');
const vm=require('node:vm');
const root=path.resolve(__dirname,'../static');
function setup(fetch){const c={console,URLSearchParams,fetch,window:{location:{search:'',hash:'#token=fixture-token-12345678901234567890',pathname:'/static/email_change_confirmation.html'}},history:{replaceState(...args){c.replaced=args;}}};vm.createContext(c);vm.runInContext(fs.readFileSync(path.join(root,'js/pages/email-change-confirmation.js'),'utf8'),c);return {c,app:c.emailChangeConfirmation()};}

test('confirmation waits for explicit action and removes token from visible URL',()=>{
 let calls=0;const {c,app}=setup(async()=>{calls++;});app.init();
 assert.equal(app.token,'fixture-token-12345678901234567890');assert.equal(calls,0);assert.equal(c.replaced[2],'/static/email_change_confirmation.html');
});

test('confirmation submits once, clears in-memory token, and reports success',async()=>{
 let calls=0,body;const {app}=setup(async(url,options)=>{calls++;body=JSON.parse(options.body);return {ok:true,json:async()=>({success:true,email:'new@example.test'})}});
 app.init();const first=app.confirm();const duplicate=app.confirm();await Promise.all([first,duplicate]);
 assert.equal(calls,1);assert.equal(body.token,'fixture-token-12345678901234567890');assert.equal(app.token,'');assert.equal(app.success,true);
});

test('confirmation does not persist the capability and page prevents referrer leakage',()=>{
 const script=fs.readFileSync(path.join(root,'js/pages/email-change-confirmation.js'),'utf8');
 const html=fs.readFileSync(path.join(root,'email_change_confirmation.html'),'utf8');
 assert.doesNotMatch(script,/localStorage|sessionStorage|sendBeacon/i);
 assert.match(html,/<meta[^>]+name=["']referrer["'][^>]+content=["']no-referrer["']/i);
 assert.doesNotMatch(html,/google-analytics|googletagmanager|segment\.com|hotjar/i);
});

