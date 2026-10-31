const {loadPageScripts} = require('./helpers/frontend.cjs');
const {test}=require('node:test');
const assert=require('node:assert/strict');
const vm=require('node:vm');
function setup(fetch){
 const timers=[];
 const c={console,Intl,Date,URLSearchParams,Headers,fetch,setTimeout:(fn)=>timers.push(fn),window:{location:{href:''}}};
 vm.createContext(c);loadPageScripts('profile.html',c);
 return {p:c.profileManager(),c,timers};
}
const context={business_timezone:'Africa/Nairobi',display_timezone:'Africa/Nairobi',revision:1};
function ready(p){p.profile={name:'Fixture',email:'fixture@example.test',role:'admin',display_timezone:null};p.timezoneContext={...context};p.businessTimezoneDraft='Africa/Nairobi';p.csrfToken='test-only';}
test('temporary profile failure stays on page and retry loads the account',async()=>{
 let fail=true;const {p,c,timers}=setup(async()=>({ok:!fail,status:fail?503:200,json:async()=>({name:'Fixture',email:'fixture@example.test',role:'admin'})}));
 await p.loadProfile();assert.match(p.profileError,/load/i);assert.equal(p.profileLoaded,false);assert.equal(c.window.location.href,'');assert.equal(timers.length,0);
 fail=false;await p.loadProfile();assert.equal(p.profileLoaded,true);assert.equal(p.profileError,'');assert.equal(p.profile.name,'Fixture');
});
test('expired profile still redirects to the existing login page',async()=>{
 const {p,c}=setup(async()=>({ok:false,status:401}));await p.loadProfile();assert.equal(c.window.location.href,'/static/index.html');assert.equal(p.profileLoaded,false);
});
test('failed CSRF response disables writes and retry obtains a valid token',async()=>{
 let fail=true;const {p}=setup(async()=>({ok:!fail,status:fail?503:200,json:async()=>({csrf_token:fail?'rejected-token':'test-only'})}));
 await p.getCsrfToken();assert.equal(p.csrfToken,'');assert.match(p.csrfError,/retry/i);assert.equal(p.csrfLoading,false);
 fail=false;await p.getCsrfToken();assert.equal(p.csrfToken,'test-only');assert.equal(p.csrfError,'');
});
test('one preference save has its own pending and success feedback',async()=>{
 let resolve,calls=0;const {p}=setup(()=>{calls++;return new Promise(r=>resolve=r)});ready(p);p.displayTimezoneDraft='UTC';
 const save=p.saveDisplayTimezone();assert.equal(p.displayTimezoneSaving,true);assert.equal(p.businessTimezoneSaving,false);assert.equal(p.timezoneSaving,true);
 p.businessTimezoneDraft='UTC';await p.saveBusinessTimezone();assert.equal(calls,1);
 resolve({ok:true,json:async()=>({display_timezone:'UTC'})});await save;
 assert.equal(p.displayTimezoneSaving,false);assert.match(p.displayTimezoneMessage,/saved/i);assert.equal(p.businessTimezoneMessage,'');assert.equal(p.displayTimezoneDirty,false);
});
test('unchanged settings do not submit, and default reset sends null',async()=>{
 let calls=0,body;const {p}=setup(async(url,o)=>{calls++;body=JSON.parse(o.body);return {ok:true,json:async()=>({display_timezone:null})}});ready(p);
 await p.saveDisplayTimezone();await p.saveBusinessTimezone();assert.equal(calls,0);
 p.profile.display_timezone='UTC';p.displayTimezoneDraft='';assert.equal(p.displayTimezoneDirty,true);await p.saveDisplayTimezone();assert.equal(body.display_timezone,null);assert.equal(p.displayTimezoneDirty,false);
});
test('business revision conflict stays in its section and blocks duplicate retry',async()=>{
 let calls=0;const {p}=setup(async()=>{calls++;return {ok:false,status:409,json:async()=>({detail:'Refresh saved settings and retry.'})}});ready(p);p.displayTimezoneMessage='Display timezone saved.';p.businessTimezoneDraft='UTC';
 await p.saveBusinessTimezone();assert.match(p.businessTimezoneError,/Refresh/);assert.equal(p.displayTimezoneMessage,'Display timezone saved.');assert.equal(p.timezoneConflict,true);await p.saveBusinessTimezone();assert.equal(calls,1);
});
test('missing CSRF token prevents password and preference writes',async()=>{
 let calls=0;const {p}=setup(async()=>{calls++;});ready(p);p.csrfToken='';p.displayTimezoneDraft='UTC';p.businessTimezoneDraft='UTC';p.passwordForm={current_password:'fixture-old',new_password:'fixture-new',confirm_password:'fixture-new'};
 await p.saveDisplayTimezone();await p.saveBusinessTimezone();await p.changePassword();assert.equal(calls,0);
});
test('pending password change cannot submit twice',async()=>{
 let resolve,calls=0;const pending=new Promise(r=>resolve=r);const {p}=setup(()=>{calls++;return pending});ready(p);p.passwordForm={current_password:'fixture-old',new_password:'fixture-new',confirm_password:'fixture-new'};
 const save=p.changePassword();const duplicate=p.changePassword();try {assert.equal(calls,1);} finally {resolve({ok:false,json:async()=>({detail:'Fixture rejection'})});} await Promise.all([save,duplicate]);assert.equal(p.saving,false);assert.equal(p.error,'Fixture rejection');
});
test('expired security token on a write disables writes and offers token retry',async()=>{
 const {p}=setup(async()=>({ok:false,status:403,json:async()=>({detail:'Invalid CSRF token'})}));ready(p);p.displayTimezoneDraft='UTC';
 await p.saveDisplayTimezone();assert.equal(p.csrfToken,'');assert.match(p.csrfError,/retry/i);assert.match(p.displayTimezoneError,/CSRF/);
});
test('missing-token rejection exposes security recovery on the profile page',async()=>{
 const {p}=setup(async()=>({ok:false,status:403,json:async()=>({detail:'CSRF token missing'})}));ready(p);p.displayTimezoneDraft='UTC';await p.saveDisplayTimezone();assert.equal(p.csrfToken,'');assert.match(p.csrfError,/retry/i);
});
test('organization admin loads and saves mobile session duration within platform maximum',async()=>{
 const calls=[];let duration=48;
 const {p}=setup(async(url,options={})=>{
  calls.push({url,options});
  if(options.method==='PUT') {duration=JSON.parse(options.body).duration_hours;return {ok:true,json:async()=>({duration_hours:duration,max_duration_hours:72})};}
  return {ok:true,json:async()=>({duration_hours:duration,max_duration_hours:72})};
 });
 p.profile={saas_mode:true,role:'admin'};p.csrfToken='test-only';
 await p.loadMobileSessionPolicy();assert.equal(p.mobileSessionDurationDraft,48);assert.equal(p.mobileSessionPolicy.max_duration_hours,72);
 p.mobileSessionDurationDraft=24;await p.saveMobileSessionPolicy();
 assert.equal(calls[1].url,'/api/organization/mobile-session-policy');assert.equal(calls[1].options.method,'PUT');
 assert.deepEqual(JSON.parse(calls[1].options.body),{duration_hours:24});assert.equal(p.mobileSessionPolicy.duration_hours,24);
});
