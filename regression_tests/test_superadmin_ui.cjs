const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const html=fs.readFileSync('static/superadmin.html','utf8');
function app(){const c={console,Date,setTimeout:()=>{},document:{activeElement:null},WeakMap};vm.createContext(c);vm.runInContext(html.match(/<script>\s*([\s\S]*?)<\/script>/)[1],c);return c.superPanel();}
test('mobile navigation reaches every existing panel and loads its data',()=>{const a=app();for(const section of Object.keys(a.tabTitles)){let refreshed=false;a.refresh=()=>{refreshed=true;};a.selectSection(section);assert.equal(a.tab,section);assert.equal(refreshed,true);}a.selectSection('invalid');assert.notEqual(a.tab,'invalid');});
test('mobile menu and desktop buttons expose section names',()=>{assert.match(html,/aria-label="Superadmin section"/);assert.equal((html.match(/<button type="button" class="nav-item"/g)||[]).length,10);assert.match(html,/aria-current/);});
test('dialog traps focus in both directions',()=>{const a=app();let focused;const first={focus:()=>focused='first'},last={focus:()=>focused='last'};const el={querySelectorAll:()=>[first,last]};let prevented=false;const event={target:last,shiftKey:false,preventDefault:()=>prevented=true};a.trapDialogFocus(event,el);assert.equal(focused,'first');assert.equal(prevented,true);event.target=first;event.shiftKey=true;a.trapDialogFocus(event,el);assert.equal(focused,'last');});

test('dialog focuses a control once and restores the opener on close',()=>{const a=app();let focused=0,restored=0;const opener={isConnected:true,focus:()=>restored++};const c={console,Date,setTimeout:()=>{},document:{activeElement:opener},WeakMap};vm.createContext(c);vm.runInContext(html.match(/<script>\s*([\s\S]*?)<\/script>/)[1],c);const panel=c.superPanel();panel.$nextTick=fn=>fn();const el={querySelector:()=>({focus:()=>focused++})};panel.syncDialog(el,true);panel.syncDialog(el,true);assert.equal(focused,1);panel.syncDialog(el,false);assert.equal(restored,1);});
