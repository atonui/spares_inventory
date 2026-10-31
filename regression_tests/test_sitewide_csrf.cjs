const {loadPageScripts} = require('./helpers/frontend.cjs');
const {test}=require('node:test');
const assert=require('node:assert/strict');
const vm=require('node:vm');
function setup(fetch){
 const c={console,Intl,Date,URLSearchParams,Headers,FormData,WeakMap,fetch,setTimeout:()=>{},localStorage:{removeItem(){}},window:{location:{href:''}},location:{href:''}};
 vm.createContext(c);loadPageScripts('index.html',c);
 loadPageScripts('superadmin.html',c);loadPageScripts('forgot_password.html',c);
 return c;
}
const response=(status,data)=>({status,ok:status>=200&&status<300,json:async()=>data,clone:()=>response(status,data)});
for(const surface of ['inventory','superadmin']){
 function app(c){return surface==='inventory'?c.inventoryApp():c.superPanel();}
 function write(a,opts={}){return surface==='inventory'?a.apiCall('/fixture',{method:'POST',body:'{}',...opts}):a.api('/fixture',{method:'POST',body:'{}',...opts});}
 test(`${surface}: failed token fetch prevents the mutation`,async()=>{
  const urls=[];const c=setup(async url=>{urls.push(url);return response(503,{csrf_token:'bad-response'});});const a=app(c);
  await assert.rejects(write(a),/security token/i);assert.deepEqual(urls,['/api/csrf-token']);assert.equal(a.csrfToken,'');
 });
 test(`${surface}: expiry refreshes once and preserves a multipart body`,async()=>{
  const calls=[];const c=setup(async(url,opts)=>{calls.push({url,opts});if(url.endsWith('/csrf-token'))return response(200,{csrf_token:'new'});return response(new Headers(opts.headers).get('X-CSRF-Token')==='new'?200:403,{detail:'Invalid CSRF token',saved:true});});const a=app(c);a.csrfToken='old';
  const body=new FormData();body.append('file','fixture');await write(a,{body,headers:{'X-CSRF-Token':'old','X-Fixture':'keep'}});
  assert.equal(calls.length,3);for(const call of calls.filter(x=>!x.url.endsWith('/csrf-token'))){assert.equal(call.opts.body,body);assert.equal(new Headers(call.opts.headers).get('Content-Type'),null);assert.equal(call.opts.credentials,'include');}assert.equal(new Headers(calls[2].opts.headers).get('X-CSRF-Token'),'new');
 });
 test(`${surface}: permissions and network failures never replay a write`,async()=>{
  let calls=0;const c=setup(async()=>{calls++;return response(403,{detail:'Admin required'});});const a=app(c);a.csrfToken='old';await assert.rejects(write(a),/Admin required/);assert.equal(calls,1);
  c.fetch=async()=>{calls++;throw Error('offline');};await assert.rejects(write(a),/offline/);assert.equal(calls,2);
 });
 test(`${surface}: repeated token rejection stops after one retry and invalidates it`,async()=>{
  let writes=0;const c=setup(async url=>url.endsWith('/csrf-token')?response(200,{csrf_token:'new'}):(writes++,response(403,{detail:'Invalid CSRF token'})));const a=app(c);a.csrfToken='old';await assert.rejects(write(a),/CSRF/);assert.equal(writes,2);assert.equal(a.csrfToken,'');
 });
 test(`${surface}: concurrent writes share token acquisition`,async()=>{
  const resolvers=[];let tokens=0,writes=0;const c=setup(async url=>url.endsWith('/csrf-token')?(tokens++,await new Promise(r=>resolvers.push(r))):(writes++,response(200,{saved:true})));const a=app(c);const pending=[write(a),write(a)];await Promise.resolve();for(const resolve of resolvers)resolve(response(200,{csrf_token:'new'}));await Promise.all(pending);assert.equal(tokens,1);assert.equal(writes,2);
 });
}
test('password recovery sends CSRF headers on both forms',async()=>{
 const calls=[];const c=setup(async(url,opts)=>{calls.push({url,opts});return response(200,url.endsWith('/csrf-token')?{csrf_token:'fixture'}:{});});
 const forgot=c.forgotPassword();forgot.email='fixture@example.test';await forgot.submitRequest();assert.equal(forgot.submitted,true);
 const reset=c.resetPassword();reset.token='fixture-reset';reset.newPassword=reset.confirmPassword='fixture-password';await reset.submitReset();assert.equal(reset.success,true);
 for(const call of calls.filter(x=>!x.url.endsWith('/csrf-token'))){assert.equal(new Headers(call.opts.headers).get('X-CSRF-Token'),'fixture');assert.equal(call.opts.credentials,'include');}
});
test('store import uses protected multipart requests',async()=>{
 const calls=[];const c=setup(async(url,opts)=>{calls.push({url,opts});return response(200,url.endsWith('/csrf-token')?{csrf_token:'fixture'}:{message:'Imported'});});const a=c.inventoryApp();a.loadStores=async()=>{};await a.importStores({target:{files:['fixture'],value:'fixture'}});
 const call=calls.find(x=>x.url.endsWith('/stores/bulk-import'));assert.equal(new Headers(call.opts.headers).get('X-CSRF-Token'),'fixture');assert.equal(call.opts.credentials,'include');
});
test('expired inventory session clears local state without recursive logout requests',async()=>{
 let calls=0;const c=setup(async()=>{calls++;if(calls>2)throw Error('recursive logout');return response(401,{});});const a=c.inventoryApp();a.csrfToken='fixture';await a.apiCall('/fixture',{method:'POST'});assert.equal(calls,1);assert.equal(a.isAuthenticated,false);assert.equal(c.window.location.href,'/static/index.html');
});
test('a rejected token is not reused when refreshing fails',async()=>{
 let writes=0;const c=setup(async url=>url.endsWith('/csrf-token')?response(503,{csrf_token:'unusable'}):(writes++,response(403,{detail:'Invalid CSRF token'})));const a=c.inventoryApp();a.csrfToken='old';await assert.rejects(a.apiCall('/fixture',{method:'POST'}),/security token/i);assert.equal(writes,1);assert.equal(a.csrfToken,'');
});
test('login acquires a token before sending credentials',async()=>{
 const calls=[];const c=setup(async(url,opts)=>{calls.push({url,opts});return response(url.endsWith('/csrf-token')?200:401,url.endsWith('/csrf-token')?{csrf_token:'fixture'}:{detail:'Invalid credentials'});});const a=c.inventoryApp();a.loginForm={email:'fixture@example.test',password:'test-only'};await a.login();assert.equal(calls.length,2);assert.equal(new Headers(calls[1].opts.headers).get('X-CSRF-Token'),'fixture');assert.equal(calls[1].opts.credentials,'include');assert.equal(a.loading,false);
});
test('concurrent expiry rejections share a refresh',async()=>{
 let refreshes=0;const c=setup(async(url,opts)=>url.endsWith('/csrf-token')?(refreshes++,response(200,{csrf_token:'new'})):response(new Headers(opts.headers).get('X-CSRF-Token')==='new'?200:403,{detail:'Invalid CSRF token'}));const a=c.inventoryApp();a.csrfToken='old';await Promise.all([a.apiCall('/a',{method:'POST'}),a.apiCall('/b',{method:'DELETE'})]);assert.equal(refreshes,1);
});
test('malformed token responses cannot authorise a write',async()=>{
 for(const data of [{csrf_token:' '},{csrf_token:42},{}]){
  let mutations=0;const c=setup(async url=>url.endsWith('/csrf-token')?response(200,data):(mutations++,response(200,{})));const a=c.inventoryApp();await assert.rejects(a.apiCall('/fixture',{method:'PATCH'}),/security token/i);assert.equal(mutations,0);
 }
});
test('token-service failure preserves an authenticated inventory session and read access',async()=>{
 const c=setup(async()=>response(503,{}));c.localStorage.getItem=()=>JSON.stringify({id:1});let removed=false;c.localStorage.removeItem=()=>{removed=true;};const a=c.inventoryApp();a.getCurrentUser=async()=>({id:1,role:'owner',is_platform_admin:false});let loaded=false;a.loadAllData=async()=>{loaded=true;};await a.checkAuth();assert.equal(a.isAuthenticated,true);assert.equal(removed,false);assert.equal(loaded,true);assert.match(a.error,/security token/i);
});

test('platform-only inventory session redirects without fetching tenant data or a CSRF token',async()=>{
 const c=setup(async()=>{throw Error('Tenant request must not run');});
 const redirects=[];c.window.location.replace=url=>redirects.push(url);
 const a=c.inventoryApp();a.getCurrentUser=async()=>({id:7,role:'platform_admin',is_platform_admin:true});
 a.loadAllData=async()=>{throw Error('Tenant data must not load');};
 await a.checkAuth();
 assert.deepEqual(redirects,['/static/superadmin.html']);
 assert.equal(a.isAuthenticated,false);
 assert.equal(a.error,'');
});
