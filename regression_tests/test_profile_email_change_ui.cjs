const {loadPageScripts}=require('./helpers/frontend.cjs');
const {test}=require('node:test');
const assert=require('node:assert/strict');
const vm=require('node:vm');
function setup(fetch){const c={console,Intl,Date,URLSearchParams,fetch,window:{location:{href:''}}};vm.createContext(c);loadPageScripts('profile.html',c);return c.profileManager();}

test('SaaS profile loads only masked pending email-change status',async()=>{
 const calls=[];const p=setup(async url=>{calls.push(url);return {ok:true,json:async()=>url.endsWith('email-change-request')?{status:'pending',proposed_email:'n***@example.test',expires_at:'2026-10-17T12:00:00Z'}:{name:'Staff',email:'old@example.test',role:'engineer',saas_mode:true}}});
 await p.loadProfile();await p.loadEmailChangeStatus();
 assert.equal(p.profile.email,'old@example.test');assert.equal(p.pendingEmailChange.proposed_email,'n***@example.test');
 assert(calls.some(url=>url==='/api/profile/email-change-request'));
});

test('requesting a new email is separate from timezone and reports generic sent feedback',async()=>{
 const calls=[];const p=setup(async(url,options)=>{calls.push({url,options});return {ok:true,status:202,json:async()=>({message:'If the address can be used, a confirmation email has been sent.'})}});
 p.profile={email:'old@example.test',saas_mode:true};p.csrfToken='csrf';p.emailChangeDraft='new@example.test';p.displayTimezoneDraft='UTC';
 await p.requestEmailChange();
 assert.equal(calls[0].url,'/api/profile/email-change-requests');assert.deepEqual(JSON.parse(calls[0].options.body),{email:'new@example.test'});
 assert.match(p.emailChangeMessage,/confirmation email/i);assert.equal(p.profile.email,'old@example.test');assert.equal(p.displayTimezoneDraft,'UTC');
});

test('canceling pending email change refreshes status and prevents duplicate submits',async()=>{
 let finish,calls=0;const p=setup(()=>{calls++;return new Promise(resolve=>finish=resolve)});p.profile.saas_mode=true;p.csrfToken='csrf';p.pendingEmailChange={status:'pending',proposed_email:'n***@example.test'};
 const first=p.cancelEmailChange();const second=p.cancelEmailChange();assert.equal(calls,1);
 finish({ok:true,json:async()=>({success:true})});await Promise.all([first,second]);assert.equal(p.pendingEmailChange,null);
});

