const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const {loadPageScripts} = require('./helpers/frontend.cjs');
const plain = v => JSON.parse(JSON.stringify(v));
const initial = {email:'',name:'',password:'',role:'engineer',territory:''};
const saved = {...initial,role:''};
const row = {id:42,email:'target@example.test',name:'Target',role:'admin',territory:null};
function setup({confirm=()=>true,fetch}={}) {
 const timers=[]; const c=vm.createContext({Headers,FormData,URLSearchParams,fetch,confirm,console:{log(){},error(){}},setTimeout(callback,delay){timers.push({callback,delay});}});
 loadPageScripts('index.html',c); const a=c.inventoryApp(); c.app=a; a.currentUser={id:1,role:'superadmin'}; return {a,c,timers};
}
const html=()=>fs.readFileSync('static/index.html','utf8');
const clicks=()=>[...html().matchAll(/@click="([^"]*)"/g)].map(m=>m[1]);
function fill(a,op='update'){a.editUser(row);a.userForm.password='new password';if(op==='create')a.editingUser=null;}
const response=(status,data)=>new Response(JSON.stringify(data),{status,headers:{'Content-Type':'application/json'}});
test('user management uses the shared responsive heading and retains its access/actions',()=>{
 const source=html();const start=source.indexOf('<!-- User Management Panel (Admin Only) -->');const end=source.indexOf('<!-- Equipment Management Panel -->',start);const panel=source.slice(start,end);
 assert.match(panel,/x-show="!loading && showUsersPanel && \['owner','admin','superadmin'\]\.includes\(currentUser\?\.role\)"/);
 assert.ok(panel.includes('class="inventory-panel-heading"'));
 assert.ok(panel.includes('class="inventory-panel-heading-content"'));
 assert.ok(panel.includes('class="inventory-panel-title">User Management</h3>'));
 assert.ok(panel.includes('class="inventory-panel-actions"'));
 assert.match(panel,/@click="editingUser = null; userForm = \{ email: '', name: '', password: '', role: 'engineer', territory: '' \}; showUserModal = true"/);
 assert.match(panel,/@click="closeAllPanels\(\)" aria-label="Close panel" title="Close panel"/);
 for(const action of ['x-for="user in users"','editUser(user)','deleteUser(user.id, user.name)','removeUser(user.id, user.name)','x-show="currentUser?.saas_mode"','resendInvitation(invitation.id)','cancelInvitation(invitation.id)']) assert.ok(panel.includes(action),action);
});
test('actual add/cancel/submit and email/password bindings retain create/edit mode',async()=>{
 const {a,c}=setup();fill(a);const add=clicks().find(e=>e.startsWith('editingUser = null; userForm ='));assert.ok(add);
 vm.runInContext('with(app){'+add+'}',c);assert.deepEqual(plain(a.userForm),initial);assert.equal(a.editingUser,null);assert.equal(a.showUserModal,true);
 const source=html();assert.match(source,/<input[^>]*x-model="userForm.email"[^>]*:disabled="!!editingUser"/);
 assert.match(source,/<input[^>]*x-model="userForm.name"[^>]*:required="editingUser \|\| !currentUser\?\.saas_mode"/,'name must be required for local account creation and edits, but optional for SaaS invitations');
 assert.match(source,/<input[^>]*x-model="userForm.password"[^>]*:required="!editingUser && !currentUser\?\.saas_mode"/,'password must be required only when creating a local account');
 const submit=[...source.matchAll(/@submit.prevent="([^"]*)"/g)].map(m=>m[1]).find(e=>e.includes('editingUser ? updateUser()')&&e.includes('inviteUser()'));assert.ok(submit);
 const calls=[];a.createUser=()=>calls.push('create');a.inviteUser=()=>calls.push('invite');a.updateUser=()=>calls.push('update');vm.runInContext('with(app){'+submit+'}',c);a.currentUser.saas_mode=true;vm.runInContext('with(app){'+submit+'}',c);a.editUser(row);vm.runInContext('with(app){'+submit+'}',c);assert.deepEqual(calls,['create','invite','update']);
 const form=a.userForm;assert.equal(form.password,'');assert.equal(form.territory,'');
 const cancel=clicks().find(e=>e==='showUserModal = false; editingUser = null;');assert.ok(cancel);vm.runInContext('with(app){'+cancel+'}',c);assert.equal(a.showUserModal,false);assert.equal(a.editingUser,null);assert.equal(a.userForm,form);
});
test('SaaS invite sends only email and company role, then reloads invitations',async()=>{
 const {a,timers}=setup();a.currentUser={id:1,role:'owner',saas_mode:true};a.userForm={email:'person@example.test',name:'ignored',password:'must-not-send',role:'manager',territory:'hidden'};
 const calls=[];a.apiCall=async(path,opts)=>{calls.push([path,opts.method,opts.body&&JSON.parse(opts.body)]);return {};};
 a.loadInvitations=async()=>calls.push('invitations');await a.inviteUser();
 assert.deepEqual(calls,[['/users/invitations','POST',{email:'person@example.test',role:'manager'}],'invitations']);
 assert.equal(a.showUserModal,false);assert.equal(a.userForm.email,'');assert.equal(a.successMessage,'Invitation queued for delivery. It expires in seven days.');assert.equal(timers[0].delay,3000);
});
test('pending invitation resend and cancel use scoped company routes',async()=>{
 const {a}=setup();const calls=[];a.loading=false;a.apiCall=async(path,opts)=>{calls.push([path,opts.method]);return [];};a.loadInvitations=async()=>calls.push('refresh');
 await a.resendInvitation(17);await a.cancelInvitation(17);
 assert.deepEqual(calls,[['/users/invitations/17/resend','POST'],'refresh',['/users/invitations/17','DELETE'],'refresh']);
});
test('company administrators manage verified email changes from the SaaS user editor',async()=>{
 const {a}=setup();
 a.currentUser={id:1,role:'owner',saas_mode:true};
 a.users=[{id:42,email:'target@example.test',name:'Target',role:'admin',territory:null}];
 a.editingUser=42;a.emailChangeDraft='new@example.test';
 const calls=[];
 a.apiCall=async(path,opts={})=>{
  calls.push([path,opts.method||'GET',opts.body?JSON.parse(opts.body):null]);
  if(!opts.method)return {status:'none'};
  if(opts.method==='POST')return {success:true,message:'Confirmation link sent.'};
  if(opts.method==='DELETE')return {success:true,message:'Pending email change canceled.'};
  return {};
 };
 assert.equal(a.canManageEditedEmail,true);
 await a.requestMemberEmailChange();
 assert.deepEqual(calls,[
  ['/users/42/email-change-requests','POST',{email:'new@example.test'}],
  ['/users/42/email-change-request','GET',null],
 ]);
 assert.equal(a.emailChangeDraft,'');
 assert.equal(a.emailChangeMessage,'Confirmation link sent.');
 a.pendingEmailChange={status:'pending'};
 await a.cancelMemberEmailChange();
 assert.deepEqual(calls.at(-1),['/users/42/email-change-request','DELETE',null]);
 assert.equal(a.pendingEmailChange,null);
});
test('SaaS email changes cannot target self or another administrator without owner authority',()=>{
 const {a}=setup();a.currentUser={id:1,role:'admin',saas_mode:true};
 a.users=[{id:1,role:'admin'},{id:2,role:'admin'},{id:3,role:'manager'},{id:4,role:'owner'}];
 a.editingUser=1;assert.equal(a.canManageEditedEmail,false);
 a.editingUser=2;assert.equal(a.canManageEditedEmail,false);
 a.editingUser=3;assert.equal(a.canManageEditedEmail,true);
 a.editingUser=4;assert.equal(a.canManageEditedEmail,false);assert.equal(a.editedEmailIsOwner,true);
 a.currentUser={id:5,role:'owner',saas_mode:true};a.editingUser=2;assert.equal(a.canManageEditedEmail,true);
});
test('email change controls are separate from account update and the owner gets the support path',()=>{
 const source=html();
 assert.match(source,/<section class="form-group" x-show="currentUser\?\.saas_mode && editingUser && canManageEditedEmail"[^>]*>[\s\S]*?requestMemberEmailChange\(\)/);
 assert.match(source,/Contact Spares Tracker support to change the company owner email\./);
 assert.match(source,/Ask another company administrator to change this email address\./);
});
for(const territory of ['', ' Kitale '])test('create keeps raw full form territory '+JSON.stringify(territory),async()=>{
 const {a,timers}=setup();fill(a,'create');a.userForm.territory=territory;const before=plain(a.userForm);const calls=[];
 a.apiCall=async(path,opts)=>{assert.equal(a.loading,true);calls.push([path,opts.method,JSON.parse(opts.body)]);return {};};
 a.loadUsers=async()=>{assert.deepEqual(plain(a.userForm),saved);assert.equal(a.showUserModal,false);assert.equal(timers.length,0);calls.push('users');};
 await a.createUser();assert.deepEqual(calls,[['/users','POST',before],'users']);assert.equal(a.successMessage,'User created successfully!');assert.equal(a.loading,false);assert.equal(timers[0].delay,3000);timers[0].callback();assert.equal(a.successMessage,'');
});
for(const territory of ['', ' Kitale '])for(const password of ['', 'changed', '  '])test('update preserves territory/password '+JSON.stringify([territory,password]),async()=>{
 const {a,timers}=setup();fill(a);a.userForm.territory=territory;a.userForm.password=password;let payload;
 a.apiCall=async(path,opts)=>{assert.equal(path,'/users/42');assert.equal(opts.method,'PUT');payload=JSON.parse(opts.body);return {};};
 a.loadUsers=async()=>{assert.deepEqual(plain(a.userForm),saved);assert.equal(a.editingUser,null);assert.equal(a.showUserModal,false);assert.equal(timers.length,0);};
 await a.updateUser();assert.deepEqual(payload,{name:'Target',role:'admin',territory:territory||null,...(password?{password}:{})});assert.equal(a.successMessage,'User updated successfully!');assert.equal(a.loading,false);assert.equal(timers[0].delay,3000);timers[0].callback();assert.equal(a.successMessage,'');
});
test('archive decline retains feedback, session and selection',async()=>{
 const prompts=[];const {a,timers}=setup({confirm(m){prompts.push(m);return false;}});a.error='old';a.successMessage='keep';a.selectedStore={id:42};const user=a.currentUser,selected=a.selectedStore;
 a.apiCall=async()=>assert.fail('no write');await a.deleteUser(42,'Target');assert.deepEqual(prompts,['Archive user Target? History will be preserved.']);assert.equal(a.error,'old');assert.equal(a.successMessage,'keep');assert.equal(a.currentUser,user);assert.equal(a.selectedStore,selected);assert.equal(timers.length,0);
});
test('remove member has a distinct confirmation and scoped mutation',async()=>{
 const calls=[];const {a,timers}=setup({confirm(m){calls.push(m);return true;}});
 a.apiCall=async(path,opts)=>{calls.push([path,opts.method]);return {message:'Company membership removed'};};
 a.loadUsers=async()=>calls.push('users');
 await a.removeUser(42,'Target');
 assert.deepEqual(calls,['Remove Target from this company? Their account and company history will remain.',['/users/42/remove','POST'],'users']);
 assert.equal(a.successMessage,'Company membership removed');assert.equal(a.loading,false);assert.equal(timers[0].delay,3000);
});
test('user actions expose separate reversible archive and company removal controls',()=>{
 const source=html();assert.match(source,/@click="deleteUser\(user\.id, user\.name\)"[^>]*>.*?Archive/s);
 assert.match(source,/@click="removeUser\(user\.id, user\.name\)"[^>]*>.*?Remove from company/s);
});
for(const open of [false,true])test('archive preserves session/selection and refresh order, panel '+open,async()=>{
 const calls=[];const {a,timers}=setup({confirm(m){calls.push(m);return true;}});a.showArchivedPanel=open;a.selectedStore={id:42};const selected=a.selectedStore,user=a.currentUser;
 a.apiCall=async(path,opts)=>{assert.equal(a.loading,true);calls.push([path,opts.method]);return {message:'Server archived'};};
 for(const [name,label] of [['loadUsers','users'],['loadInventory','inventory'],['loadArchivedRecords','archived']])a[name]=async()=>{assert.equal(a.currentUser,user);assert.equal(a.selectedStore,selected);assert.equal(timers.length,0);calls.push(label);};
 await a.deleteUser(42,'Target');assert.deepEqual(calls,['Archive user Target? History will be preserved.',['/users/42','DELETE'],'users','inventory',...(open?['archived']:[])]);assert.equal(a.successMessage,'Server archived');assert.equal(a.loading,false);assert.equal(timers[0].delay,3000);
});
for(const op of ['create','update','archive'])for(const stage of (op==='archive'?['write','users','inventory','archived']:['write','users']))test(op+' failure at '+stage+' retains prior or saved state',async()=>{
 const {a,timers}=setup();fill(a,op);a.showArchivedPanel=true;const form=a.userForm,user=a.currentUser;a.selectedStore={id:42};const selected=a.selectedStore;const calls=[];
 a.apiCall=async()=>{calls.push('write');if(stage==='write')throw Error('offline');return {message:'Archived'};};
 for(const [name,label] of [['loadUsers','users'],['loadInventory','inventory'],['loadArchivedRecords','archived']])a[name]=async()=>{calls.push(label);if(stage===label)throw Error('offline');};
 await a[op==='create'?'createUser':op==='update'?'updateUser':'deleteUser'](42,'Target');
 assert.equal(a.loading,false);assert.equal(timers.length,0);assert.equal(a.error,'Failed to '+(op==='archive'?'archive':op)+' user: offline');assert.equal(a.currentUser,user);assert.equal(a.selectedStore,selected);
 if(op!=='archive'&&stage!=='write'){assert.deepEqual(plain(a.userForm),saved);assert.equal(a.showUserModal,false);assert.equal(a.editingUser,null);}else{assert.equal(a.userForm,form);assert.equal(a.showUserModal,true);}
 const order=['write','users',...(op==='archive'?['inventory','archived']:[])];assert.deepEqual(calls,order.slice(0,order.indexOf(stage)+1));
});
for(const stage of ['inventory','archived'])test('core '+stage+' refresh failure is swallowed after successful user archive',async()=>{
 const {a,timers}=setup();a.showArchivedPanel=stage==='archived';a.selectedStore={id:42};const selected=a.selectedStore,user=a.currentUser;const calls=[];
 a.apiCall=async(path)=>{calls.push(path);if(path==='/users/42')return {message:'Archived'};if(stage==='inventory'&&path==='/inventory')throw Error('offline');if(stage==='archived'&&path.includes('include_archived'))throw Error('offline');return [];};
 await a.deleteUser(42,'Target');assert.equal(a.successMessage,'Archived');assert.equal(a.currentUser,user);assert.equal(a.selectedStore,selected);assert.equal(a.loading,false);assert.equal(timers[0].delay,3000);
 assert.equal(a.error,stage==='inventory'?'Inventory could not refresh. Retry or reload the page: offline':'Failed to load archived records: offline');assert.ok(calls.includes('/inventory'));
});
for(const role of ['owner','admin','superadmin','engineer'])test('core loadUsers preserves role check '+role,async()=>{
 const {a}=setup();a.currentUser.role=role;const calls=[];a.apiCall=async(path)=>{calls.push(path);return [{id:2}];};await a.loadUsers();assert.deepEqual(calls,role==='engineer'?[]:['/users']);assert.equal(a.users.length,role==='engineer'?0:1);
});
test('remove member uses the real JSON API and CSRF-protected POST',async()=>{
 const calls=[];const {a,timers}=setup({fetch:async(url,opts)=>{
  calls.push([url,opts.method]);
  if(url==='/api/csrf-token')return response(200,{csrf_token:'fresh'});
  assert.equal(url,'/api/users/42/remove');assert.equal(opts.method,'POST');assert.equal(opts.headers.get('Content-Type'),'application/json');
  assert.equal(opts.headers.get('X-CSRF-Token'),'fresh');return response(200,{message:'Company membership removed'});
 }});a.loadUsers=async()=>calls.push(['users']);
 await a.removeUser(42,'Target');assert.deepEqual(calls,[['/api/csrf-token',undefined],['/api/users/42/remove','POST'],['users']]);
 assert.equal(a.successMessage,'Company membership removed');assert.equal(a.loading,false);assert.equal(timers.length,1);
});
for(const mode of ['initial','retry','permission','token','retry_rejected'])test('real JSON API/CSRF user write '+mode,async()=>{
 const calls=[];let writes=0;const {a,timers}=setup({fetch:async(url,opts)=>{
  assert.equal(opts.credentials,'include');calls.push(url);
  if(url==='/api/csrf-token')return response(mode==='token'?503:200,{csrf_token:'fresh'});
  assert.equal(url,'/api/users/42');assert.equal(opts.method,'PUT');assert.equal(opts.headers.get('Content-Type'),'application/json');assert.deepEqual(JSON.parse(opts.body),{name:'Target',role:'admin',territory:null});writes++;
  if(mode==='permission')return response(403,{detail:'Admin required'});
  if(mode==='retry_rejected'||(mode==='retry'&&writes===1))return response(403,{detail:'Invalid CSRF token'});
  assert.equal(opts.headers.get('X-CSRF-Token'),'fresh');return response(200,{});
 }});fill(a);a.userForm.password='';if(mode!=='initial'&&mode!=='token')a.csrfToken='old';a.loadUsers=async()=>{};const form=a.userForm,user=a.currentUser;
 await a.updateUser();assert.equal(a.currentUser,user);assert.equal(a.loading,false);
 if(mode==='initial'||mode==='retry'){assert.deepEqual(plain(a.userForm),saved);assert.equal(timers.length,1);}else{assert.equal(a.userForm,form);assert.equal(a.editingUser,42);assert.equal(timers.length,0);assert.match(a.error,/Failed to update user:/);}
 assert.equal(writes,mode==='token'?0:mode==='retry'||mode==='retry_rejected'?2:1);
 assert.equal(calls.filter(u=>u==='/api/csrf-token').length,mode==='permission'?0:1);
});
test('navigation closes modal without clearing forms/other editing data; instances independent',()=>{
 const {a}=setup();fill(a);a.editingEquipment=7;a.editingStoreType=8;const form=a.userForm;a.openPanel('showUsersPanel');assert.equal(a.showUserModal,false);assert.equal(a.userForm,form);assert.equal(a.editingUser,42);assert.equal(a.editingEquipment,7);assert.equal(a.editingStoreType,8);
 const {a:b}=setup();assert.deepEqual(plain(b.userForm),initial);assert.equal(b.editingUser,null);assert.equal(b.showUserModal,false);
});
