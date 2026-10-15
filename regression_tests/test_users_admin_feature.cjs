const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const plain = value => JSON.parse(JSON.stringify(value));
const initial = {email: '', name: '', password: '', role: 'engineer', territory: ''};
const saved = {...initial, role: ''};
function setup(globals = {}) {
    const c = vm.createContext(globals);
    vm.runInContext(fs.readFileSync('static/js/shared/features.js', 'utf8'), c);
    const filename = 'static/js/inventory/users-admin.js';
    assert.ok(fs.existsSync(filename), 'users admin feature must exist');
    vm.runInContext(fs.readFileSync(filename, 'utf8'), c, {filename});
    return c;
}
test('user administration owns its invitation state and independent forms', () => {
    const c = setup();
    const a = c.usersAdminFeature(), b = c.usersAdminFeature();
    assert.deepEqual(Object.keys(a).sort(), ['userForm', 'showUserModal', 'editingUser', 'createUser', 'editUser', 'updateUser', 'deleteUser', 'invitations', 'invitationsLoading', 'loadInvitations', 'inviteUser', 'resendInvitation', 'cancelInvitation'].sort());
    assert.deepEqual(plain(a.userForm), initial);
    assert.equal(a.showUserModal, false);
    assert.equal(a.editingUser, null);
    a.userForm.role = 'admin'; a.showUserModal = true; a.editingUser = 42;
    assert.deepEqual(plain(b.userForm), initial);
    assert.equal(b.showUserModal, false); assert.equal(b.editingUser, null);
});
test('edit replaces form, clears password and retains role and territory fallback', () => {
    const c = setup(); const a = c.composeInventoryFeatures({}, c.usersAdminFeature());
    const original = a.userForm;
    a.userForm.password = 'unsaved';
    a.editUser({id: 42, email: 'user@example.test', name: 'Target', role: 'admin', territory: null});
    assert.notEqual(a.userForm, original);
    assert.deepEqual(plain(a.userForm), {email: 'user@example.test', name: 'Target', password: '', role: 'admin', territory: ''});
    assert.equal(a.editingUser, 42); assert.equal(a.showUserModal, true);
    a.editUser({id: 43, email: 'next@example.test', name: 'Next', role: 'engineer', territory: ' Kitale '});
    assert.equal(a.userForm.territory, ' Kitale '); assert.equal(a.editingUser, 43);
});
for (const operation of ['create', 'update', 'archive']) {
    test(`${operation} uses core providers with the composed receiver in original order`, async () => {
        const calls = []; let callback;
        const c = setup({confirm(message) { assert.equal(message, 'Archive user Target? History will be preserved.'); calls.push('confirm'); return true; },
            setTimeout(fn, delay) { calls.push(['timer', delay]); callback = fn; }});
        const a = c.composeInventoryFeatures({loading: false, error: 'old error', successMessage: 'old success', showArchivedPanel: true,
            async apiCall(path, options) { assert.equal(this, a); assert.equal(this.loading, true); assert.equal(this.error, ''); assert.equal(this.successMessage, '');
                calls.push(['write', path, options.method, options.body ? JSON.parse(options.body) : null]); return {message: 'Archived'}; },
            async loadUsers() { assert.equal(this, a); calls.push('users'); },
            async loadInventory() { assert.equal(this, a); calls.push('inventory'); },
            async loadArchivedRecords() { assert.equal(this, a); calls.push('archived'); },
        }, c.usersAdminFeature());
        a.userForm = {email: 'user@example.test', name: 'Target', password: 'password', role: 'admin', territory: ' Kitale '};
        a.editingUser = operation === 'create' ? null : 42; a.showUserModal = true;
        if (operation === 'archive') {
            await a.deleteUser(42, 'Target');
            assert.deepEqual(calls, ['confirm', ['write', '/users/42', 'DELETE', null], 'users', 'inventory', 'archived', ['timer', 3000]]);
            assert.equal(a.successMessage, 'Archived');
        } else {
            const body = operation === 'create' ? plain(a.userForm) : {name: 'Target', role: 'admin', territory: ' Kitale ', password: 'password'};
            await a[operation === 'create' ? 'createUser' : 'updateUser']();
            assert.deepEqual(calls, [['write', operation === 'create' ? '/users' : '/users/42', operation === 'create' ? 'POST' : 'PUT', body], 'users', ['timer', 3000]]);
            assert.equal(a.showUserModal, false); assert.equal(a.editingUser, null); assert.deepEqual(plain(a.userForm), saved);
        }
        assert.equal(a.loading, false); callback(); assert.equal(a.successMessage, '');
    });
}
