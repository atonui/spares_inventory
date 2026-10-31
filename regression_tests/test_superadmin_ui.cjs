const {loadPageScripts} = require('./helpers/frontend.cjs');
const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const html=fs.readFileSync('static/superadmin.html','utf8');
function app(){const c={console,Date,URLSearchParams,Intl,setTimeout:()=>{},document:{activeElement:null},WeakMap};vm.createContext(c);loadPageScripts('superadmin.html',c);const a=c.superPanel();a.timezoneContext={business_timezone:'Africa/Nairobi',display_timezone:'Africa/Nairobi',revision:1};a.auditTimezone='Africa/Nairobi';a.announcementReady=true;a.announcementTimezone='Africa/Nairobi';a.announcementTimezoneRevision=1;return a;}
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
test('mobile navigation reaches every available panel and loads its data',()=>{const a=app();a.me={saas_mode:false};for(const section of Object.keys(a.tabTitles).filter(key=>key!=='support')){let refreshed=false;a.refresh=()=>{refreshed=true;};a.selectSection(section);assert.equal(a.tab,section);assert.equal(refreshed,true);}a.me={saas_mode:true,is_platform_admin:true};a.supportSession={support_session_id:'support-a'};for(const section of ['dashboard','config','announcement','organizations','platformAdmins','platformAudit','support']){let refreshed=false;a.refresh=()=>{refreshed=true;};a.selectSection(section);assert.equal(a.tab,section);assert.equal(refreshed,true);}a.selectSection('invalid');assert.notEqual(a.tab,'invalid');});
test('mobile menu and desktop buttons expose section names',()=>{assert.match(html,/aria-label="Superadmin section"/);assert.equal((html.match(/<button type="button" class="nav-item"/g)||[]).length,17);assert.match(html,/aria-current/);});
test('legacy superadmin cannot navigate to the SaaS support workspace',()=>{const a=app();a.me={saas_mode:false};a.tab='dashboard';a.selectSection('support');assert.equal(a.tab,'dashboard');assert.match(html,/!me\?\.saas_mode && key!=='support'/);});
test('SaaS platform boot loads only platform data',async()=>{
 const a=app(),calls=[];
 a.getCsrf=async()=>calls.push('csrf');
 a.getMe=async()=>{a.me={saas_mode:true,is_platform_admin:true};calls.push('me');return true;};
 a.loadPlatformDashboard=async()=>calls.push('platform-dashboard');
  a.loadCurrentSupportSession=async()=>calls.push('support-current');
 a.loadOrganizations=async()=>calls.push('organizations');
 a.loadPlatformAudit=async()=>calls.push('platform-audit');
 a.loadPlatformAdmins=async()=>calls.push('platform-admins');
 a.loadTimezoneContext=async()=>assert.fail('legacy tenant timezone must not load');
 a.loadDashboard=async()=>assert.fail('legacy dashboard must not load');
 await a.init();
  assert.deepEqual(calls,['csrf','me','support-current','platform-dashboard','organizations','platform-audit','platform-admins']);
});
test('platform administrator list distinguishes loading, failure and successful retry',async()=>{
 const a=app();let release,calls=0;a.api=()=>{calls++;return new Promise(r=>release=r);};
 const pending=a.loadPlatformAdmins();assert.equal(a.platformAdminLoading,true);await a.loadPlatformAdmins();assert.equal(calls,1);
 release([{id:1,email:'platform@example.test',name:'Platform'}]);await pending;
 assert.equal(a.platformAdmins.length,1);assert.equal(a.platformAdminLoading,false);assert.equal(a.platformAdminError,'');
 a.api=async()=>{throw Error('offline');};await a.loadPlatformAdmins();assert.equal(a.platformAdminError,'offline');
 a.api=async()=>[{id:1,email:'platform@example.test',name:'Platform'}];await a.loadPlatformAdmins();assert.equal(a.platformAdminError,'');
});
test('grant platform admin requires confirmation and posts an exact email',async()=>{
 const a=app();a.me={id:2};a.toast=()=>{};a.platformAdminEmail='  Ops.Team@example.test  ';const calls=[];
 a.api=async(path,options)=>{calls.push([path,options.method,JSON.parse(options.body)]);return {success:true,created:true};};
 a.loadPlatformAdmins=async()=>calls.push('admins');
 a.requestPlatformAdminGrant();assert.equal(calls.length,0);assert.match(a.dlg.msg,/Ops.Team@example.test/);
 await a.submitDialog();
 assert.deepEqual(calls,[['/platform/admins','POST',{email:'Ops.Team@example.test'}],'admins']);
 assert.equal(a.platformAdminEmail,'');
});
test('platform admin revocation requires confirmation and hides self-removal action',async()=>{
 const a=app();a.me={id:2};a.toast=()=>{};const calls=[];a.api=async(path,options)=>{calls.push([path,options.method]);return {success:true};};a.loadPlatformAdmins=async()=>calls.push('admins');
 a.requestPlatformAdminRevoke({id:2,name:'Me',email:'me@example.test'});assert.equal(a.dlg.open,false);
 a.requestPlatformAdminRevoke({id:3,name:'Other',email:'other@example.test'});assert.equal(calls.length,0);assert.match(a.dlg.title,/Other/);
 await a.submitDialog();assert.deepEqual(calls,[['/platform/admins/3','DELETE'],'admins']);
 assert.match(html,/requestPlatformAdminRevoke\(admin\)/);assert.match(html,/Cannot revoke your own access/);
});
test('SaaS settings load and save use platform routes while SQLite keeps legacy routes',async()=>{
 const a=app(),paths=[];a.me={saas_mode:true};
 assert.ok(a.availableCfgMeta.mobile_session_max_duration_hours);
 a.api=async(path,options={})=>{paths.push([path,options.method||'GET']);return path.endsWith('/security-config')?{}:{success:true};};
 await a.loadConfig();a.panelLoads.config.loaded=true;a.cfgVals.max_login_attempts='8';await a.saveConfig('max_login_attempts');
 assert.deepEqual(paths,[['/platform/security-config','GET'],['/platform/security-config/max_login_attempts','PUT'],['/platform/security-config','GET']]);
 paths.length=0;a.me={saas_mode:false};a.api=async(path,options={})=>{paths.push([path,options.method||'GET']);return {};};
 await a.loadConfig();assert.deepEqual(paths,[['/superadmin/security-config','GET']]);
 assert.equal(a.availableCfgMeta.mobile_session_max_duration_hours,undefined);
 assert.match(html,/MFA and global password policy are not managed here/);
});
test('SaaS announcement management uses platform routes and accepts fixed UTC timezone revision',async()=>{
 const a=app(),paths=[];a.me={saas_mode:true};
 const manage={announcement:null,status:'none',business_timezone:'UTC',timezone_revision:0};
 a.api=async(path,options={})=>{paths.push([path,options.method||'GET',options.body&&JSON.parse(options.body)]);return path.endsWith('/manage')?manage:{success:true,revision:'new'};};
 await a.loadAnnouncement();assert.equal(a.announcementReady,true);assert.equal(a.announcementTimezone,'UTC');assert.equal(a.announcementTimezoneRevision,0);
 a.annForm={message:'Maintenance window',level:'warning',audience:'everyone',roles:[],starts_local:'',expires_local:'',dismissible:false};
 await a.saveAnnouncement();
 assert.equal(paths[0][0],'/platform/announcement/manage');
 assert.equal(paths[1][0],'/platform/announcement');assert.equal(paths[1][1],'POST');assert.equal(paths[1][2].timezone_revision,0);
 assert.equal(paths[2][0],'/platform/announcement/manage');
});
test('SaaS announcement removal uses platform route and SQLite removal remains compatible',async()=>{
 const a=app(),paths=[];a.me={saas_mode:true};a.announcementReady=true;a.savedAnnouncement={revision:'current'};
 a.api=async(path,options={})=>{paths.push([path,options.method]);return {success:true};};await a.clearAnnouncement();
 assert.deepEqual(paths,[['/platform/announcement?expected_revision=current','DELETE']]);
 paths.length=0;a.me={saas_mode:false};a.announcementReady=true;a.savedAnnouncement={revision:'legacy'};a.api=async(path,options={})=>{paths.push([path,options.method]);return {success:true};};await a.clearAnnouncement();
 assert.deepEqual(paths,[['/superadmin/announcement?expected_revision=legacy','DELETE']]);
});
test('SaaS platform admin section does not expose tenant identity search',()=>{
 const section=html.split('x-show="tab===\'platformAdmins\' && me?.saas_mode"')[1].split('x-show="tab===\'platformAudit\'')[0];
 assert.match(section,/Grant platform admin/);assert.match(section,/type="email"/);assert.match(section,/platformAdmins/);assert.doesNotMatch(section,/filteredUsers|allUsers|userFilters/);
});
test('SaaS navigation exposes only supported platform settings and announcement controls',()=>{
 const platform=html.split('x-show="me?.saas_mode && me?.is_platform_admin"')[1].split('</nav>')[0];
 assert.match(platform,/Security Settings/);assert.match(platform,/System Announcement/);
 assert.match(html,/\['dashboard','config','announcement','organizations','platformAdmins','platformAudit'\]/);
 assert.match(html,/key==='support' && supportSession/);
 assert.match(html,/Scheduled announcements use UTC/);
});
test('support start requires organization, reason, and password, then clears the password',async()=>{
 const a=app(),calls=[];a.me={saas_mode:true,is_platform_admin:true};a.toast=()=>{};
 const organization={id:'org-a',name:'Northwind'};a.openSupportStart(organization);
 assert.equal(a.supportStartOpen,true);assert.equal(a.supportStartOrg.id,'org-a');assert.equal(a.supportStartForm.current_password,'');
 a.supportStartForm={reason:'Investigate sign-in issue',current_password:'secret'};
 a.api=async(path,options)=>{calls.push([path,options.method,JSON.parse(options.body)]);return {support_session_id:'support-a',organization,reason:'Investigate sign-in issue',expires_at:new Date(Date.now()+60000).toISOString()};};
 await a.startSupportSession();
 assert.deepEqual(calls,[['/platform/support-sessions','POST',{organization_id:'org-a',reason:'Investigate sign-in issue',current_password:'secret'}]]);
 assert.equal(a.supportStartForm.current_password,'');assert.equal(a.tab,'support');assert.equal(a.supportSession.support_session_id,'support-a');
 a.supportStartForm={reason:'Investigate sign-in issue',current_password:'bad'};a.api=async()=>{throw Error('wrong password');};
 await a.startSupportSession();assert.equal(a.supportStartForm.current_password,'');assert.equal(a.supportStartError,'wrong password');
});
test('active support session restores into the workspace banner state',async()=>{
 const a=app();a.me={saas_mode:true};a.api=async()=>({support_session_id:'support-a',organization:{id:'org-a',name:'Northwind'},reason:'Investigate sign-in issue',expires_at:new Date(Date.now()+60000).toISOString()});
 await a.loadCurrentSupportSession();assert.equal(a.tab,'support');assert.equal(a.supportSession.organization.name,'Northwind');assert.match(html,/support-banner/);assert.match(html,/End support session/);
});
test('support lookups include the session identifier and never send a free-standing organization ID',async()=>{
 const a=app(),paths=[];a.tab='support';a.supportSession={support_session_id:'support-a'};a.supportLookupValue='VALUE-1';
 a.api=async path=>{paths.push(path);return {rows:[{id:1}]};};
 for(const kind of a.supportLookupKinds){a.supportLookupKind=kind.key;await a.loadSupportLookup();}
 assert.equal(paths.length,6);for(const path of paths){assert.match(path,/\/support-sessions\/support-a\//);assert.doesNotMatch(path,/organization_id=/);}
 assert.deepEqual(paths.map(path=>path.split('/').at(-1).split('?')[0]),Array.from(a.supportLookupKinds,kind=>kind.key));
 assert.ok(a.supportRows.length);a.clearSupportResults();assert.equal(a.supportRows.length,0);
});
test('terminal support response clears tenant data and returns to the platform console',async()=>{
 const a=app();a.me={saas_mode:true};a.tab='support';a.supportRows=[{email:'tenant@example.test'}];a.supportSession={support_session_id:'support-a'};a.supportLookupValue='user@example.test';a.toast=()=>{};
 a.api=async()=>{const error=Error('unavailable');error.status=404;throw error;};await a.loadSupportLookup();
 assert.equal(a.supportRows.length,0);assert.equal(a.supportSession,null);assert.equal(a.tab,'dashboard');
});
test('support workspace offers only fixed lookups and renders result values as text',()=>{
 const support=html.split('x-show="tab===\'support\' && me?.saas_mode && supportSession"')[1].split('x-show="tab===\'platformAdmins\'')[0];
 const script=fs.readFileSync('static/js/pages/superadmin.js','utf8');
 for(const key of ['accounts','inventory','work-orders','equipment','equipment-history','movements'])assert.ok(script.includes(`key:'${key}'`));
 assert.match(support,/x-text="entry\[1\]/);assert.doesNotMatch(support,/x-html=/);assert.match(script,/cache: 'no-store'/);
});
test('platform audit filters are encoded, paginated, and recoverable after failure',async()=>{
 const a=app();a.platformAuditFilters={actor_user_id:'7',organization_id:'org / id',action:'organization_created',result:'success',start_at:'2026-10-01T00:00:00Z',end_at:''};
 let path='';a.api=async value=>{path=value;return {rows:[{id:9}],total:101,offset:50};};
 await a.loadPlatformAudit(50);assert.match(path,/limit=50/);assert.match(path,/offset=50/);assert.match(path,/organization_id=org\+%2F\+id/);assert.equal(a.platformAuditRows[0].id,9);assert.equal(a.platformAuditTotal,101);
 a.api=async()=>{throw Error('offline');};await a.loadPlatformAudit(0);assert.equal(a.platformAuditRows.length,0);assert.equal(a.platformAuditError,'offline');assert.equal(a.platformAuditLoading,false);
 assert.match(html,/x-text="JSON.stringify\(event\.details \|\| \{\}\)"/);assert.doesNotMatch(html,/x-html="JSON.stringify\(event\.details/);
});
test('platform organization form sends name slug and owner invitation',async()=>{
 const a=app();a.toast=()=>{};a.organizationForm={name:'Acme Services',slug:'acme-services',owner_email:'owner@example.test'};
 const calls=[];a.api=async(path,options)=>{calls.push([path,options.method,JSON.parse(options.body)]);return {success:true};};
 a.loadOrganizations=async()=>calls.push('organizations');a.loadPlatformDashboard=async()=>calls.push('dashboard');
 await a.provisionOrganization();
 assert.deepEqual(calls,[['/platform/organizations','POST',{name:'Acme Services',slug:'acme-services',owner_email:'owner@example.test'}],'organizations','dashboard']);
 assert.deepEqual(JSON.parse(JSON.stringify(a.organizationForm)),{name:'',slug:'',owner_email:''});
});
test('platform organization directory sends search/status filters with bounded pagination and errors',async()=>{
 const a=app();a.organizationFilters={search:'Acme & Sons',status:'suspended'};let path='';
 a.api=async value=>{path=value;return {rows:[{id:'org-1',name:'Acme & Sons'}],total:31,limit:25,offset:25};};
 await a.loadOrganizations(25);assert.match(path,/search=Acme\+%26\+Sons/);assert.match(path,/status=suspended/);assert.match(path,/limit=25/);assert.match(path,/offset=25/);
 assert.equal(a.organizations[0].id,'org-1');assert.equal(a.organizationTotal,31);assert.equal(a.organizationOffset,25);
 a.api=async()=>{throw Error('offline');};await a.loadOrganizations(0);assert.equal(a.organizationError,'offline');assert.equal(a.organizationLoading,false);
});
test('organization suspension waits for a reason and confirms before posting',async()=>{
 const a=app();a.toast=()=>{};const org={id:'org-1',name:'Acme',is_active:true};const calls=[];
 a.api=async(path,options)=>{calls.push([path,options.method,JSON.parse(options.body)]);return {success:true,is_active:false,changed:true};};
 a.loadOrganizations=async()=>calls.push('organizations');a.loadPlatformDashboard=async()=>calls.push('dashboard');
 a.requestOrganizationStatus(org);assert.equal(a.dlg.open,true);assert.equal(a.dlg.reason_required,true);assert.equal(calls.length,0);
 a.dlg.reason='too short';await a.submitDialog();assert.equal(calls.length,0);assert.equal(a.dlg.open,true);assert.match(a.dialogError,/10/);
 a.dlg.reason='Customer requested suspension';await a.submitDialog();
 assert.deepEqual(calls,[['/platform/organizations/org-1/status','PUT',{action:'suspend',reason:'Customer requested suspension'}],'organizations','dashboard']);
 assert.equal(a.dlg.open,false);
});
test('organization directory shows lifecycle controls and aggregate-only operational fields',()=>{
 const directory=html.split("x-show=\"tab==='organizations' && me?.saas_mode\"")[1].split("x-show=\"tab==='platformAudit'")[0];
 assert.match(directory,/Active members/);assert.match(directory,/Invitation email/);assert.match(directory,/Pending/);assert.match(directory,/Failed/);
 assert.match(directory,/requestOrganizationStatus\(org\)/);assert.doesNotMatch(directory,/organization_users|inventory_rows/);
 assert.match(html,/x-model="dlg\.reason"/);
});
test('dialog traps focus in both directions and includes textareas',()=>{const a=app();let focused,selector;const first={focus:()=>focused='first'},last={focus:()=>focused='last'};const el={querySelectorAll:value=>{selector=value;return [first,last];}};let prevented=false;const event={target:last,shiftKey:false,preventDefault:()=>prevented=true};a.trapDialogFocus(event,el);assert.equal(focused,'first');assert.equal(prevented,true);assert.match(selector,/textarea:not\(\[disabled\]\)/);event.target=first;event.shiftKey=true;a.trapDialogFocus(event,el);assert.equal(focused,'last');});

test('dialog focuses a control once and restores the opener on close',()=>{const a=app();let focused=0,restored=0;const opener={isConnected:true,focus:()=>restored++};const c={console,Date,URLSearchParams,Intl,setTimeout:()=>{},document:{activeElement:opener},WeakMap};vm.createContext(c);loadPageScripts('superadmin.html',c);const panel=c.superPanel();panel.$nextTick=fn=>fn();const el={querySelector:()=>({focus:()=>focused++})};panel.syncDialog(el,true);panel.syncDialog(el,true);assert.equal(focused,1);panel.syncDialog(el,false);assert.equal(restored,1);});
test('shared dialog lifecycle restores focus after the background stops being inert',()=>{
  let inert=false;
  const document={activeElement:null};
  const opener={isConnected:true,focus(){if(!inert)document.activeElement=this;}};
  document.activeElement=opener;
  const c={console,Date,URLSearchParams,Intl,setTimeout:()=>{},document,WeakMap};
  vm.createContext(c);loadPageScripts('superadmin.html',c);
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
test('announcement loading exposes errors and successful retry clears them',async()=>{const a=app();a.api=async()=>{throw Error('offline')};await a.loadAnnouncement();assert.equal(a.announcementError,'offline');assert.equal(a.announcementLoading,false);a.api=async()=>({announcement:{message:'Notice',level:'info'},status:'active',business_timezone:'Africa/Nairobi',timezone_revision:1});await a.loadAnnouncement();assert.equal(a.announcementError,'');assert.equal(a.annForm.message,'Notice');});
test('broadcast writes wait while the current announcement is loading',async()=>{const a=app();let calls=0,release;a.api=()=>{calls++;return new Promise(r=>release=r)};const load=a.loadAnnouncement();a.saveAnnouncement();a.clearAnnouncement();assert.equal(calls,1);release({announcement:null});await load;});
test('announcement refresh cannot overwrite a pending removal',async()=>{const a=app();a.toast=()=>{};let calls=0,release;a.api=()=>{calls++;return new Promise(r=>release=r)};const removal=a.clearAnnouncement();a.loadAnnouncement();assert.equal(calls,1);release({success:true});await removal;assert.equal(a.announcement,null);});
