const {test}=require('node:test');
const assert=require('node:assert/strict');
const vm=require('node:vm');
const fs=require('node:fs');
const {loadPageScripts}=require('./helpers/frontend.cjs');
function setup({stored=null,storageBlocked=false,fetch}={}) {
  const location={};const writes=[];
  const c=vm.createContext({Headers,FormData,URLSearchParams,Intl,setTimeout(){},console:{log(){},error(){}},fetch,
    localStorage:{getItem(){if(storageBlocked)throw Error('Storage blocked');return stored;},setItem(k,v){if(storageBlocked)throw Error('Storage blocked');writes.push([k,v]);},removeItem(){if(storageBlocked)throw Error('Storage blocked');}},window:{location}});
  loadPageScripts('index.html',c);const a=c.inventoryApp();let loads=0;
  a.getCsrfToken=async()=>{};a.loadAllData=async()=>loads++;
  return {a,c,location,writes,get loads(){return loads;}};
}
const response=(status,data)=>new Response(JSON.stringify(data),{status,headers:{'Content-Type':'application/json'}});
for(const mode of ['missing','malformed','stale','blocked'])test('valid session restores with '+mode+' user cache',async()=>{
  let requests=0;const s=setup({stored:mode==='malformed'?'{broken':mode==='stale'?JSON.stringify({id:99,role:'superadmin'}):null,storageBlocked:mode==='blocked',fetch:async()=>{requests++;return response(200,{id:7,role:'engineer'});}});
  await s.a.checkAuth();assert.equal(requests,1);assert.equal(s.a.isAuthenticated,true);assert.equal(s.a.authState,'authenticated');assert.equal(s.a.currentUser.id,7);assert.equal(s.a.currentUser.role,'engineer');assert.equal(s.loads,1);
});
test('restoration sends session cookies without a placeholder bearer token',async()=>{
  const s=setup({stored:JSON.stringify({id:7}),fetch:async(url,o)=>{assert.equal(url,'/api/me');assert.equal(o.credentials,'include');assert.equal(new Headers(o.headers).has('Authorization'),false);return response(200,{id:7});}});
  await s.a.checkAuth();assert.equal(s.a.isAuthenticated,true);
});
for(const mode of ['missing','stale','blocked'])test('expired session cannot be restored from '+mode+' cache',async()=>{
  let calls=0;const s=setup({stored:mode==='stale'?JSON.stringify({id:7}):null,storageBlocked:mode==='blocked',fetch:async()=>{calls++;return response(401,{detail:'Session expired'});}});
  await s.a.checkAuth();assert.equal(calls,1);assert.equal(s.a.isAuthenticated,false);assert.equal(s.a.authState,'anonymous');assert.equal(s.a.currentUser,null);assert.equal(s.loads,0);
});
test('session check failure is visible and retry can restore the valid cookie',async()=>{
  let online=false;const s=setup({fetch:async()=>{if(!online)throw Error('Offline');return response(200,{id:7});}});
  await s.a.checkAuth();assert.equal(s.a.isAuthenticated,false);assert.equal(s.a.authState,'error');assert.ok(s.a.error);online=true;const retry=s.a.checkAuth();assert.equal(s.a.authState,'checking');await retry;assert.equal(s.a.isAuthenticated,true);assert.equal(s.a.authState,'authenticated');assert.equal(s.a.error,'');
});
test('login is not shown until the server confirms the session is anonymous',async()=>{
  let finish;const s=setup({fetch:()=>new Promise(resolve=>{finish=resolve;})});
  assert.equal(s.a.authState,'checking');
  const pending=s.a.checkAuth();assert.equal(s.a.authState,'checking');
  const html=fs.readFileSync('static/index.html','utf8');
  assert.match(html,/<section x-show="authState === 'anonymous'" class="login-screen"/);
  assert.match(html,/authState === 'checking'[\s\S]*?Checking your session/);
  assert.match(html,/authState === 'error'[\s\S]*?Retry session check/);
  finish(response(401,{detail:'Session expired'}));await pending;
  assert.equal(s.a.authState,'anonymous');assert.equal(s.a.isAuthenticated,false);
});
test('inventory load failure does not erase a server-validated session',async()=>{
  const s=setup({stored:JSON.stringify({id:7}),fetch:async()=>response(200,{id:7})});s.a.loadAllData=async()=>{throw Error('Inventory offline');};
  await s.a.checkAuth();assert.equal(s.a.isAuthenticated,true);assert.equal(s.a.currentUser.id,7);assert.match(s.a.error,/Inventory offline/);
});
for(const remember of [false,true])test('login sends checkbox '+remember+' and tolerates unavailable user cache',async()=>{
  const s=setup({storageBlocked:true,fetch:async(url,o)=>{if(url==='/api/csrf-token')return response(200,{csrf_token:'fresh'});assert.equal(JSON.parse(o.body).remember_me,remember);return response(200,{user:{id:7}});}});
  s.a.loginForm.remember_me=remember;await s.a.login();assert.equal(s.a.isAuthenticated,true);assert.equal(s.a.authState,'authenticated');assert.equal(s.a.currentUser.id,7);assert.equal(s.loads,1);assert.equal(s.a.error,'');
});
test('logout finishes redirect even when user-cache removal is unavailable',async()=>{
  const s=setup({storageBlocked:true});s.a.currentUser={id:7};s.a.isAuthenticated=true;s.a.authState='authenticated';await s.a.logout({localOnly:true});assert.equal(s.a.isAuthenticated,false);assert.equal(s.a.authState,'anonymous');assert.equal(s.location.href,'/static/index.html');
});
for(const status of [200,401])test('late startup response '+status+' cannot overwrite a completed login',async()=>{
  let release;const s=setup({fetch:async(url)=>url==='/api/me'?new Promise(r=>release=r):url==='/api/csrf-token'?response(200,{csrf_token:'fresh'}):response(200,{user:{id:8}})});
  const pending=s.a.checkAuth();await s.a.login();release(response(status,{id:7}));await pending;assert.equal(s.a.currentUser.id,8);assert.equal(s.a.isAuthenticated,true);
});
test('failed remote logout preserves the authenticated user and allows retry',async()=>{
  const s=setup();s.a.currentUser={id:7};s.a.isAuthenticated=true;s.a.apiCall=async()=>{throw Error('Server unavailable');};
  await s.a.logout();assert.equal(s.a.currentUser.id,7);assert.equal(s.a.isAuthenticated,true);assert.equal(s.location.href,undefined);assert.match(s.a.error,/Logout failed/);
  s.a.apiCall=async()=>({success:true});await s.a.logout();assert.equal(s.a.currentUser,null);assert.equal(s.location.href,'/static/index.html');
});
