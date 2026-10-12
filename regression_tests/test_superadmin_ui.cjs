const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const html=fs.readFileSync('static/superadmin.html','utf8');
function app(){const c={console,Date,URLSearchParams,Intl,setTimeout:()=>{},document:{activeElement:null},WeakMap};vm.createContext(c);vm.runInContext(fs.readFileSync('static/temporal.js','utf8'),c);vm.runInContext(html.match(/<script>\s*([\s\S]*?)<\/script>/)[1],c);const a=c.superPanel();a.timezoneContext={business_timezone:'Africa/Nairobi',display_timezone:'Africa/Nairobi',revision:1};a.auditTimezone='Africa/Nairobi';return a;}
for(const [section,method] of [['users','loadUsers'],['sessions','loadSessions'],['config','loadConfig']]) {
 test(`${section} distinguishes loading, failure and successful retry`,async()=>{
  const a=app();let release,calls=0;a.toast=()=>{};
  a.api=()=>{calls++;return new Promise(r=>release=r);};
  const pending=a[method]();
  assert.equal(a.panelLoads[section].loading,true);
  assert.equal(a.panelReady(section),false);
  await a[method]();assert.equal(calls,1);
  release(section==='config'?{}:[]);await pending;
  assert.equal(a.panelReady(section),true);
  a.api=async()=>{throw Error('offline');};await a[method]();
  assert.equal(a.panelLoads[section].loading,false);
  assert.equal(a.panelLoads[section].error,'offline');
  assert.equal(a.panelReady(section),false);
  a.api=async()=>section==='config'?{}:[];await a[method]();
  assert.equal(a.panelLoads[section].error,'');assert.equal(a.panelReady(section),true);
 });
}
test('loading one panel cannot clear another panel loading state',async()=>{
 const a=app();let release;a.api=path=>path.endsWith('/users')?new Promise(r=>release=r):Promise.resolve([]);
 const users=a.loadUsers();await a.loadSessions();
 assert.equal(a.panelLoads.users.loading,true);assert.equal(a.panelLoads.sessions.loading,false);
 release([]);await users;
});
test('settings cannot save before a successful load or during refresh',async()=>{
 const a=app();let writes=0,release;a.toast=()=>{};a.cfgVals.max_login_attempts='5';
 a.api=async()=>{writes++;};await a.saveConfig('max_login_attempts');assert.equal(writes,0);
 a.api=async()=>({});await a.loadConfig();
 a.api=()=>new Promise(r=>release=r);const refresh=a.loadConfig();
 await a.saveConfig('max_login_attempts');release({});await refresh;assert.equal(writes,0);
});
test('mobile navigation reaches every existing panel and loads its data',()=>{const a=app();for(const section of Object.keys(a.tabTitles)){let refreshed=false;a.refresh=()=>{refreshed=true;};a.selectSection(section);assert.equal(a.tab,section);assert.equal(refreshed,true);}a.selectSection('invalid');assert.notEqual(a.tab,'invalid');});
test('mobile menu and desktop buttons expose section names',()=>{assert.match(html,/aria-label="Superadmin section"/);assert.equal((html.match(/<button type="button" class="nav-item"/g)||[]).length,10);assert.match(html,/aria-current/);});
test('dialog traps focus in both directions',()=>{const a=app();let focused;const first={focus:()=>focused='first'},last={focus:()=>focused='last'};const el={querySelectorAll:()=>[first,last]};let prevented=false;const event={target:last,shiftKey:false,preventDefault:()=>prevented=true};a.trapDialogFocus(event,el);assert.equal(focused,'first');assert.equal(prevented,true);event.target=first;event.shiftKey=true;a.trapDialogFocus(event,el);assert.equal(focused,'last');});

test('dialog focuses a control once and restores the opener on close',()=>{const a=app();let focused=0,restored=0;const opener={isConnected:true,focus:()=>restored++};const c={console,Date,URLSearchParams,Intl,setTimeout:()=>{},document:{activeElement:opener},WeakMap};vm.createContext(c);vm.runInContext(html.match(/<script>\s*([\s\S]*?)<\/script>/)[1],c);const panel=c.superPanel();panel.$nextTick=fn=>fn();const el={querySelector:()=>({focus:()=>focused++})};panel.syncDialog(el,true);panel.syncDialog(el,true);assert.equal(focused,1);panel.syncDialog(el,false);assert.equal(restored,1);});
test('shared dialog lifecycle restores focus after the background stops being inert',()=>{
  let inert=false;
  const document={activeElement:null};
  const opener={isConnected:true,focus(){if(!inert)document.activeElement=this;}};
  document.activeElement=opener;
  const c={console,Date,URLSearchParams,Intl,setTimeout:()=>{},document,WeakMap};
  vm.createContext(c);vm.runInContext(html.match(/<script>\s*([\s\S]*?)<\/script>/)[1],c);
  const panel=c.superPanel(),ticks=[];
  panel.$nextTick=fn=>ticks.push(fn);
  const control={focus(){document.activeElement=this;}};
  const element={querySelector:()=>control};
  panel.syncDialog(element,true);
  inert=true;
  ticks.splice(0).forEach(fn=>fn());
  assert.equal(document.activeElement,control);
  panel.syncDialog(element,false);
  // Alpine clears the shell's inert binding after the dialog effect runs.
  inert=false;
  if(document.activeElement===control)document.activeElement=null;
  ticks.splice(0).forEach(fn=>fn());
  assert.equal(document.activeElement,opener);
});
test('role save has one request, preserves draft on failure, and clears busy state',async()=>{const a=app();const u={id:7,role:'engineer',_role:'manager'};let release,calls=0;a.toast=()=>{};a.api=async()=>{calls++;await new Promise(r=>release=r);return {message:'saved'};};const pending=a.changeRole(u);assert.equal(u._saving,true);await a.changeRole(u);assert.equal(calls,1);assert.equal(u.role,'engineer');release();await pending;assert.equal(u.role,'manager');assert.equal(u._saving,false);u._role='admin';a.api=async()=>{throw Error('offline');};await a.changeRole(u);assert.equal(u.role,'manager');assert.equal(u._role,'admin');assert.equal(u._error,'offline');});
test('confirmed action stays open while saving and preserves errors for retry',async()=>{const a=app();let calls=0,release;a.dlg={open:true,resolve:async()=>{calls++;await new Promise(r=>release=r);}};const pending=a.submitDialog();await a.submitDialog();assert.equal(calls,1);assert.equal(a.dlg.open,true);release();await pending;assert.equal(a.dlg.open,false);assert.equal(a.dialogBusy,false);a.dlg={open:true,resolve:async()=>{throw Error('offline');}};await a.submitDialog();assert.equal(a.dlg.open,true);assert.equal(a.dialogError,'offline');});
test('role selection waits for explicit Save and bulk logout stays in sessions',()=>{assert.doesNotMatch(html,/@change="changeRole\(u\)"/);assert.match(html,/@click="changeRole\(u\)"/);assert.doesNotMatch(html.split('<!-- /dashboard -->')[0],/@click="confirmLogoutAll\(\)"/);assert.match(html,/@click="confirmLogoutAll\(\)"/);});
test('logout confirmation makes no request until submitted and keeps server errors visible',async()=>{const a=app();let calls=0;a.api=async()=>{calls++;throw Error('server unavailable');};a.forceLogout({id:7,name:'Test User'});assert.equal(calls,0);assert.match(a.dlg.title,/Test User/);await a.submitDialog();assert.equal(calls,1);assert.equal(a.dlg.open,true);assert.equal(a.dialogError,'server unavailable');});
test('user filters combine search role and lock state without losing editable records',()=>{const a=app();const u={id:1,name:'Jane Smith',email:'jane@example.com',role:'engineer',_role:'manager',account_locked_until:'2999-01-01T00:00:00Z'};a.allUsers=[u,{id:2,name:'Other',email:null,role:'admin'}];a.userFilters={search:' JANE ',role:'engineer',status:'locked'};assert.equal(a.filteredUsers.length,1);assert.equal(a.filteredUsers[0],u);a.userFilters.role='manager';assert.equal(a.filteredUsers.length,0);a.userFilters={search:'',role:'',status:'active'};assert.equal(a.filteredUsers.length,1);});
test('session filters match email or IP and exclude invalid expired dates from upcoming expiry',()=>{const a=app();a.sessions=[{name:'Jane',email:'jane@example.com',role:'engineer',ip_address:'10.0.0.1',expires_at:new Date(Date.now()+3600000).toISOString()},{name:'Other',role:'admin',expires_at:'invalid'},{name:'Expired',role:'engineer',expires_at:'2020-01-01T00:00:00Z'}];a.sessionFilters={search:'10.0.0.1',role:'engineer',expiry:'soon'};assert.equal(a.filteredSessions.length,1);a.sessionFilters.search='';assert.equal(a.filteredSessions.length,1);a.sessionFilters.expiry='';assert.equal(a.filteredSessions.length,2);});
test('audit filters query full backend history and pagination preserves applied filters',async()=>{const a=app();a.auditFilters={start_date:'2026-10-05',end_date:'2026-10-05',action:'DB_BACKUP',status:'success'};a.api=async path=>{assert.match(path,/paginated=true/);assert.match(path,/limit=50/);assert.match(path,/action=DB_BACKUP/);return {rows:[{id:1}],total:101,actions:['DB_BACKUP']};};await a.loadAudit(50);assert.equal(a.auditOffset,50);assert.equal(a.auditTotal,101);a.api=async()=>{throw Error('offline');};await a.loadAudit();assert.equal(a.auditLog.length,0);assert.equal(a.auditError,'offline');});
test('audit dates show Nairobi independently of browser timezone',()=>{const a=app();assert.match(a.fmtAuditDate('2026-10-04T21:00:00Z'),/2026-10-05/);assert.match(a.fmtAuditDate('2026-10-04T21:00:00Z'),/00:00:00/);});
test('late audit response cannot overwrite a newer filter request',async()=>{const a=app();let first;a.api=()=>new Promise(r=>first=r);const pending=a.loadAudit();a.api=async()=>({rows:[{id:2}],total:1,actions:[]});await a.loadAudit();first({rows:[{id:1}],total:99,actions:[]});await pending;assert.equal(a.auditLog[0].id,2);assert.equal(a.auditTotal,1);});
for (const method of ['unlock','bulkUnlock','unlockSelected','saveConfig','saveAnnouncement','clearAnnouncement','submitPasswordReset']) {
 test(method+' prevents duplicate requests and exposes errors for retry',async()=>{
  const a=app();a.toast=()=>{};a.loadLocked=a.loadDashboard=a.loadConfig=a.loadAnnouncement=async()=>{};
  a.locked=[{id:7}];a.selectedLocked=[7];a.cfgVals.max_login_attempts='5';a.panelLoads.config.loaded=true;a.annForm={message:'Notice',level:'info'};
  a.resetModal={open:true,userId:7,password:'password123',confirm:'password123',error:''};
  let release,calls=0;a.api=async()=>{calls++;await new Promise(r=>release=r);return {message:'saved',unlocked_count:1};};
  const args=method==='unlock'?[{id:7}]:method==='saveConfig'?['max_login_attempts']:[];
  const pending=a[method](...args);
  assert.ok(Object.values(a.actionPending).some(Boolean));
  await a[method](...args);assert.equal(calls,1);release();await pending;
  assert.equal(Object.values(a.actionPending).some(Boolean),false);
  a.resetModal={open:true,userId:7,password:'password123',confirm:'password123',error:''};a.annForm.message='Notice';a.api=async()=>{throw Error('offline');};
  await a[method](...args);assert.ok(Object.values(a.actionErrors).includes('offline'));
 });
}
test('announcement removal cannot race a pending broadcast',async()=>{const a=app();a.toast=()=>{};a.loadAnnouncement=async()=>{};a.annForm.message='Notice';let release,calls=0;a.api=async()=>{calls++;await new Promise(r=>release=r);};const pending=a.saveAnnouncement();await a.clearAnnouncement();assert.equal(calls,1);release();await pending;});
test('reset validation makes no request and failed reset retains values for retry',async()=>{const a=app();let calls=0;a.api=async()=>{calls++;throw Error('offline');};a.resetModal={open:true,userId:7,password:'short',confirm:'short',error:''};await a.submitPasswordReset();assert.equal(calls,0);assert.match(a.resetModal.error,/8 characters/);a.resetModal.password=a.resetModal.confirm='password123';await a.submitPasswordReset();assert.equal(a.resetModal.open,true);assert.equal(a.resetModal.password,'password123');assert.equal(a.actionErrors.reset,'offline');});
