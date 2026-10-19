const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');

const html=fs.readFileSync('static/index.html','utf8');
const css=fs.readFileSync('static/mystyle.css','utf8');

test('header account menu keeps profile, authorized superadmin, and logout actions',()=>{
  assert.match(html,/<div class="account-menu"[\s\S]*?@click\.outside="accountMenuOpen = false"/);
  assert.match(html,/@focusout="if \(!\$el\.contains\(\$event\.relatedTarget\)\) accountMenuOpen = false"/);
  assert.match(html,/<button[^>]*class="account-menu-trigger"[^>]*:aria-expanded="accountMenuOpen"[^>]*aria-controls="account-menu-panel"/);
  assert.match(html,/<div class="account-menu-panel" id="account-menu-panel"[^>]*x-show="accountMenuOpen"[^>]*x-cloak\b/);
  assert.match(html,/<a[^>]*href="\/static\/profile\.html"[^>]*>[^<]*<svg[\s\S]*?Profile<\/a>/);
  assert.match(html,/x-show="\(currentUser\?\.is_platform_admin \|\| currentUser\?\.role === 'superadmin'\)"[^>]*class="account-menu-item"[^>]*href="\/static\/superadmin\.html"/);
  assert.match(html,/<button[^>]*class="account-menu-item account-menu-signout"[^>]*@click="accountMenuOpen = false; logout\(\)"/);
  assert.match(html,/@keydown\.escape\.window="if \(accountMenuOpen\) \{ accountMenuOpen = false; \$refs\.accountMenuTrigger\.focus\(\) \}"/);
  assert.doesNotMatch(html,/class="header-actions"[\s\S]{0,1400}Logout[\s\S]{0,500}Profile[\s\S]{0,500}Superadmin/);
});

test('account menu keeps a discoverable label and usable touch targets on mobile',()=>{
  assert.match(css,/\.account-menu-trigger\s*\{[^}]*min-height:\s*44px/s);
  assert.match(css,/\.account-menu-item\s*\{[^}]*min-height:\s*44px/s);
  assert.doesNotMatch(css,/@media\s*\(max-width:\s*480px\)[\s\S]*?\.account-menu-label\s*\{[^}]*display:\s*none/s);
  assert.match(css,/@media\s*\(max-width:\s*768px\)[\s\S]*?\.header-actions\s*\{[^}]*width:\s*auto/s);
  assert.match(css,/@media\s*\(max-width:\s*480px\)[\s\S]*?\.account-menu-panel\s*\{[^}]*width:\s*min\(280px,\s*calc\(100vw\s*-\s*24px\)\)/s);
  assert.match(css,/@media\s*\(max-width:\s*480px\)[\s\S]*?\.account-menu-item\s*\{[^}]*min-height:\s*48px/s);
  assert.match(css,/\.account-menu-panel\s*\{[^}]*position:\s*absolute/s);
});
