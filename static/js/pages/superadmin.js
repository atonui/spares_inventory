function superPanel() {
  return {
    actionPending: {},
    actionErrors: {},
    async runAction(key, operation) {
      if (this.actionPending[key]) return false;
      this.actionPending[key] = true;
      this.actionErrors[key] = '';
      try {
        await operation();
        return true;
      } catch (error) {
        this.actionErrors[key] = error.message || 'Action failed. Please retry.';
        return false;
      } finally {
        this.actionPending[key] = false;
      }
    },
    dialogBusy: false,
    dialogError: '',
    async submitDialog() {
      if (this.dialogBusy) return;
      this.dialogBusy = true;
      this.dialogError = '';
      try {
        await this.dlg.resolve();
        this.dlg.open = false;
      } catch (error) {
        this.dialogError = error.message || 'Action failed. Please retry.';
      } finally {
        this.dialogBusy = false;
      }
    },
    dialogFocus: new WeakMap(),
    selectSection(section) {
      if (!Object.hasOwn(this.tabTitles, section)) return;
      this.tab = section;
      this.refresh();
    },
    syncDialog(element, open) {
      if (open && !this.dialogFocus.has(element)) {
        this.dialogFocus.set(element, document.activeElement);
        this.$nextTick(() => {
          if (this.dialogFocus.has(element))
            (element.querySelector('button:not([disabled]), input:not([disabled])') || element).focus();
        });
      } else if (!open && this.dialogFocus.has(element)) {
        const previous = this.dialogFocus.get(element);
        this.dialogFocus.delete(element);
        // Wait for Alpine to remove the shell's inert binding before focusing it.
        this.$nextTick(() => {
          if (!this.dialogFocus.has(element) && previous?.isConnected) previous.focus();
        });
      }
    },
    trapDialogFocus(event, element) {
      const controls = Array.from(element.querySelectorAll('button:not([disabled]), input:not([disabled]), select:not([disabled]), a[href]'));
      if (!controls.length) { event.preventDefault(); element.focus(); return; }
      const first = controls[0], last = controls[controls.length - 1];
      if (event.shiftKey && (event.target === first || event.target === element)) {
        event.preventDefault(); last.focus();
      } else if (!event.shiftKey && (event.target === last || event.target === element)) {
        event.preventDefault(); first.focus();
      }
    },
    tab: 'dashboard',
    loading: false,
    apiUrl: '/api',
    csrfToken: '',
    me: null,

    tabTitles: {
      dashboard: 'Dashboard',    accounts: 'Locked Accounts',
      sessions:  'Active Sessions', config: 'Security Config',
      users:     'All Users',    tables: 'Database Tables',
      query:     'SQL Console',  maintenance: 'Maintenance',
      announcement: 'System Announcement', audit: 'Audit Log',
    },

    // data stores
    dashboard: {},
    locked: [], selectedLocked: [],
    sessions: [],
    panelLoads: {
      users: { loading: false, loaded: false, error: '' },
      sessions: { loading: false, loaded: false, error: '' },
      config: { loading: false, loaded: false, error: '' },
    },
    panelReady(section) {
      const state = this.panelLoads[section];
      return state.loaded && !state.loading && !state.error;
    },
    async loadPanel(section, operation) {
      const state = this.panelLoads[section];
      if (state.loading) return;
      state.loading = true;
      state.error = '';
      try {
        await operation();
        state.loaded = true;
      } catch (error) {
        state.error = error.message || 'Unable to load data. Please retry.';
      } finally {
        state.loading = false;
      }
    },
    secConfig: {}, cfgVals: {},
    userFilters: { search: '', role: '', status: '' },
    sessionFilters: { search: '', role: '', expiry: '' },
    matchesIdentity(record, search) {
      const query = search.trim().toLowerCase();
      return !query || [record.name, record.email, record.ip_address].some(value => String(value || '').toLowerCase().includes(query));
    },
    get filteredUsers() {
      return this.allUsers.filter(user => this.matchesIdentity(user, this.userFilters.search)
        && (!this.userFilters.role || user.role === this.userFilters.role)
        && (!this.userFilters.status || this.isLocked(user) === (this.userFilters.status === 'locked')));
    },
    get filteredSessions() {
      const now = Date.now();
      return this.sessions.filter(session => {
        const expiry = this.utcTimestamp(session.expires_at);
        return this.matchesIdentity(session, this.sessionFilters.search)
          && (!this.sessionFilters.role || session.role === this.sessionFilters.role)
          && (!this.sessionFilters.expiry || (expiry > now && expiry <= now + 86400000));
      });
    },
    utcTimestamp(value) {
      return InventoryTime.parseInstant(value);
    },
    timezoneContext: null, timezoneError: '', timezoneLoading: false,
    async loadTimezoneContext() {
      if(this.timezoneLoading)return;
      this.timezoneLoading=true;this.timezoneError='';
      try {const data=await this.api('/timezone-context');if(!validTimezoneContext(data))throw Error('Timezone settings are unavailable.');this.timezoneContext=data;}
      catch(error){this.timezoneContext=null;this.timezoneError=error.message;}
      finally{this.timezoneLoading=false;}
    },
    allUsers: [],
    dbTables: {},
    sqlInput: 'SELECT * FROM users LIMIT 20',
    queryResult: null,
    restoreFile: null,
    vacuumResult: null, purgeResult: null, purgeDays: 90,
    auditLog: [], auditTotal: 0, auditOffset: 0, auditActions: [], auditError: '', auditLoading: false,
    auditRequest: 0, auditTimezone: null,
    auditFilters: { start_date: '', end_date: '', action: '', status: '' },
    announcement: null,
    annForm: { message: '', level: 'info' },

    toasts: [],
    dlg: { open: false, title: '', msg: '', action: '', resolve: () => {} },

    resetModal: { open: false, userId: null, userName: '', password: '', confirm: '', error: '' },

    cfgMeta: {
      max_login_attempts:        { label: 'Max Login Attempts',     desc: 'Consecutive failures before account lockout',      unit: 'attempts', min: 1, max: 100  },
      lockout_duration_minutes:  { label: 'Lockout Duration',       desc: 'How long an account stays locked after failure',   unit: 'minutes',  min: 1, max: 1440 },
      session_duration_hours:    { label: 'Session Duration',       desc: 'Normal login session lifetime',                   unit: 'hours',    min: 1, max: 720  },
      remember_me_duration_days: { label: '"Remember Me" Duration', desc: 'Session lifetime when remember-me is checked',    unit: 'days',     min: 1, max: 365  },
    },

    // ── Boot ──────────────────────────────────────────────────
    async init() {
      await this.getCsrf();
      await this.getMe();
      await this.loadTimezoneContext();
      await this.loadDashboard();
      await this.loadAnnouncement();
    },

    refresh() {
      const loaders = {
        dashboard: () => this.loadDashboard(),
        accounts:  () => this.loadLocked(),
        sessions:  () => this.loadSessions(),
        config:    () => this.loadConfig(),
        users:     () => this.loadUsers(),
        tables:    () => this.loadTables(),
        audit:     () => this.loadAudit(),
        announcement: () => this.loadAnnouncement(),
      };
      (loaders[this.tab] || (() => this.loadDashboard()))();
    },

    // add these two methods alongside your other methods:
openResetModal(u) {
    if (this.actionPending.reset) return;
    this.actionErrors.reset = '';
    this.resetModal = {
        open: true,
        userId: u.id,
        userName: u.name,
        password: '',
        confirm: '',
        error: '',
    };
},

async submitPasswordReset() {
    if (this.actionPending.reset) return;
    this.resetModal.error = '';
    this.actionErrors.reset = '';

    if (this.resetModal.password.length < 8) {
        this.resetModal.error = 'Password must be at least 8 characters.';
        return;
    }
    if (this.resetModal.password !== this.resetModal.confirm) {
        this.resetModal.error = 'Passwords do not match.';
        return;
    }

    return this.runAction('reset', async () => {
        const r = await this.api(`/superadmin/users/${this.resetModal.userId}/reset-password`, {
            method: 'POST',
            body: JSON.stringify({
                user_id: this.resetModal.userId,
                new_password: this.resetModal.password,
            }),
        });
        this.toast(r.message, 'ok');
        this.resetModal.open = false;
        this.resetModal.password = '';
        this.resetModal.confirm = '';
    });
},

    // ── Auth helpers ──────────────────────────────────────────
    async getCsrf() {
      try { await InventoryCsrf.token(this, this.apiUrl); }
      catch (e) { this.toast(e.message, 'danger'); }
    },

    async getMe() {
      try {
        const r = await fetch(`${this.apiUrl}/me`, { credentials: 'include' });
        if (r.status === 401) { location.href = '/static/index.html'; return; }
        this.me = await r.json();
        if (this.me.role !== 'superadmin') {
          this.toast('Access denied — superadmin role required.', 'danger');
          setTimeout(() => location.href = '/static/index.html', 2000);
        }
      } catch { location.href = '/static/index.html'; }
    },

    async api(path, opts = {}) {
      const headers = { ...opts.headers };
      if (!(opts.body instanceof FormData)) headers['Content-Type'] = 'application/json';
      const r = await InventoryCsrf.request(this, `${this.apiUrl}${path}`, { ...opts, headers }, this.apiUrl);
      if (r.status === 401) { location.href = '/static/index.html'; throw new Error('Unauthenticated'); }
      if (!r.ok) { const e = await r.json().catch(() => ({})); throw new Error(e.detail || `HTTP ${r.status}`); }
      if (r.status === 204) return null;
      return r.json();
    },

    // ── Toast ──────────────────────────────────────────────────
    toast(msg, type = 'ok') {
      const id = Date.now();
      this.toasts.push({ id, msg, type });
      setTimeout(() => this.toasts = this.toasts.filter(t => t.id !== id), 3500);
    },

    // ── Dashboard ──────────────────────────────────────────────
    async loadDashboard() {
      this.loading = true;
      try { this.dashboard = await this.api('/superadmin/dashboard'); }
      catch (e) { this.toast(e.message, 'danger'); }
      finally { this.loading = false; }
    },

    // ── Locked accounts ────────────────────────────────────────
    async loadLocked() {
      this.loading = true;
      try { this.locked = await this.api('/superadmin/locked-accounts'); this.selectedLocked = []; }
      catch (e) { this.toast(e.message, 'danger'); }
      finally { this.loading = false; }
    },

    async unlock(u) {
      return this.runAction('unlock', async () => {
        const r = await this.api('/superadmin/unlock-account', {
          method: 'POST', body: JSON.stringify({ user_id: u.id }),
        });
        this.toast(r.message, 'ok');
        await this.loadLocked(); await this.loadDashboard();
      });
    },

    async bulkUnlock() {
      if (!this.locked.length) return;
      return this.runAction('unlock', async () => {
        const r = await this.api('/superadmin/unlock-accounts/bulk', {
          method: 'POST', body: JSON.stringify({ user_ids: this.locked.map(u => u.id) }),
        });
        this.toast(`Unlocked ${r.unlocked_count} account(s)`, 'ok');
        await this.loadLocked(); await this.loadDashboard();
      });
    },

    async unlockSelected() {
      if (!this.selectedLocked.length) return;
      return this.runAction('unlock', async () => {
        const r = await this.api('/superadmin/unlock-accounts/bulk', {
          method: 'POST', body: JSON.stringify({ user_ids: this.selectedLocked }),
        });
        this.toast(`Unlocked ${r.unlocked_count} account(s)`, 'ok');
        await this.loadLocked(); await this.loadDashboard();
      });
    },

    toggleAll(e) {
      this.selectedLocked = e.target.checked ? this.locked.map(u => u.id) : [];
    },

    isLocked(u) {
      return Boolean(u.account_locked_until && this.utcTimestamp(u.account_locked_until) > Date.now());
    },

    // ── Sessions ───────────────────────────────────────────────
    async loadSessions() {
      return this.loadPanel('sessions', async () => {
        this.sessions = await this.api('/superadmin/sessions');
      });
    },

    forceLogout(u) {
      if (this.dialogBusy) return;
      this.dialogError = '';
      this.dlg = {
        open: true,
        title: `Force logout ${u.name || u.email}?`,
        msg: 'All active sessions for this user will be terminated immediately.',
        action: 'Force Logout',
        resolve: async () => {
          try {
            const r = await this.api('/superadmin/sessions/force-logout', {
              method: 'POST', body: JSON.stringify({ user_id: u.user_id || u.id }),
            });
            this.toast(`Terminated ${r.sessions_terminated} session(s)`, 'ok');
            await this.loadSessions();
          } catch (e) { throw e; }
        },
      };
    },

    confirmLogoutAll() {
      if (this.dialogBusy) return;
      this.dialogError = '';
      this.dlg = {
        open: true,
        title: 'Force logout ALL users?',
        msg: 'Every active session except yours will be terminated immediately. Users will need to log in again.',
        action: 'Logout Everyone',
        resolve: async () => {
          try {
            const r = await this.api('/superadmin/sessions/force-logout-all', { method: 'POST' });
            this.toast(`Terminated ${r.sessions_terminated} session(s)`, 'ok');
            await this.loadSessions(); await this.loadDashboard();
          } catch (e) { throw e; }
        },
      };
    },

    // ── Security config ────────────────────────────────────────
    async loadConfig() {
      return this.loadPanel('config', async () => {
        this.secConfig = await this.api('/superadmin/security-config');
        for (const k of Object.keys(this.cfgMeta))
          this.cfgVals[k] = this.secConfig[k]?.setting_value ?? '';
      });
    },

    async saveConfig(key) {
      if (!this.panelReady('config')) return;
      const val = this.cfgVals[key];
      if (!val) { this.toast('Please enter a value', 'warn'); return; }
      return this.runAction('config:' + key, async () => {
        await this.api(`/superadmin/security-config/${key}`, {
          method: 'PUT', body: JSON.stringify({ value: String(val) }),
        });
        this.toast(`${key} updated to ${val}`, 'ok');
        await this.loadConfig();
      });
    },

    // ── Users ──────────────────────────────────────────────────
    async loadUsers() {
      return this.loadPanel('users', async () => {
        this.allUsers = (await this.api('/superadmin/users')).map(u => ({ ...u, _role: u.role, _saving: false, _error: '' }));
      });
    },

    async changeRole(u) {
      if (u._saving || u._role === u.role) return;
      const requestedRole = u._role;
      u._saving = true;
      u._error = '';
      try {
        const r = await this.api(`/superadmin/users/${u.id}/role`, {
          method: 'PUT', body: JSON.stringify({ role: requestedRole }),
        });
        this.toast(r.message, 'ok');
        u.role = requestedRole;
      } catch (e) { u._error = e.message; }
      finally { u._saving = false; }
    },

    // ── DB Tables ──────────────────────────────────────────────
    async loadTables() {
      this.loading = true;
      try { this.dbTables = await this.api('/superadmin/database/tables'); }
      catch (e) { this.toast(e.message, 'danger'); }
      finally { this.loading = false; }
    },

    // ── SQL ────────────────────────────────────────────────────
    async runQuery() {
      if (!this.sqlInput.trim()) return;
      this.loading = true; this.queryResult = null;
      try {
        this.queryResult = await this.api('/superadmin/database/query', {
          method: 'POST', body: JSON.stringify({ sql: this.sqlInput }),
        });
      } catch (e) { this.toast(e.message, 'danger'); }
      finally { this.loading = false; }
    },

    // ── Maintenance ────────────────────────────────────────────
    backupDB() {
      const a = document.createElement('a');
      a.href = `${this.apiUrl}/superadmin/database/backup`;
      a.click();
      this.toast('Backup download started', 'ok');
    },

    async restoreDB() {
      if (!this.restoreFile || !confirm('Replace the entire live database with this file? Changes since the backup will be overwritten.')) return;
      this.loading = true;
      try {
        const data = new FormData(); data.append('file', this.restoreFile);
        const result = await this.api('/superadmin/database/restore', {method:'POST',body:data});
        alert(result.message + '\nPrevious database saved as: ' + result.backup_name);
        location.href = '/static/index.html';
      } catch (e) { this.toast(e.message, 'danger'); }
      finally { this.loading = false; }
    },

    vacuumDB() {
      if (this.dialogBusy) return;
      this.dialogError = '';
      this.dlg = {
        open: true, title: 'Run VACUUM?',
        msg: 'This defragments the database and reclaims unused space. Takes a few seconds.',
        action: 'Run VACUUM',
        resolve: async () => {
          this.loading = true;
          try {
            this.vacuumResult = await this.api('/superadmin/database/vacuum', { method: 'POST' });
            this.toast(`Saved ${this.fmtBytes(this.vacuumResult.saved_bytes)}`, 'ok');
            await this.loadDashboard();
          } catch (e) { throw e; }
          finally { this.loading = false; }
        },
      };
    },

    purgeLogs() {
      const days = parseInt(this.purgeDays) || 0;
      if (this.dialogBusy) return;
      this.dialogError = '';
      this.dlg = {
        open: true,
        title: days === 0 ? 'Purge All General Logs?' : `Purge Logs Older Than ${days} Days?`,
        msg: days === 0
          ? 'This permanently deletes general logs. Stock audit evidence is retained. This cannot be undone.'
          : `This deletes general logs older than ${days} days. Stock audit evidence is retained. This cannot be undone.`,
        action: 'Purge',
        resolve: async () => {
          this.loading = true;
          try {
            this.purgeResult = await this.api(
              `/superadmin/database/logs/purge?days=${days}`, { method: 'DELETE' }
            );
            this.toast(
              `Deleted ${this.purgeResult.activity_logs_deleted + this.purgeResult.system_logs_deleted} entries`,
              'ok'
            );
            await this.loadDashboard();
          } catch (e) { throw e; }
          finally { this.loading = false; }
        },
      };
    },

    // ── Announcement ───────────────────────────────────────────
    async loadAnnouncement() {
      try {
        const r = await this.api('/superadmin/announcement');
        this.announcement = r.announcement;
        if (this.announcement) {
          this.annForm.message = this.announcement.message;
          this.annForm.level   = this.announcement.level;
        }
      } catch {}
    },

    async saveAnnouncement() {
      return this.runAction('announcement', async () => {
        await this.api('/superadmin/announcement', {
          method: 'POST', body: JSON.stringify(this.annForm),
        });
        this.toast('Announcement broadcast!', 'ok');
        await this.loadAnnouncement();
      });
    },

    async clearAnnouncement() {
      return this.runAction('announcement', async () => {
        await this.api('/superadmin/announcement', { method: 'DELETE' });
        this.announcement = null;
        this.annForm = { message: '', level: 'info' };
        this.toast('Announcement cleared', 'ok');
      });
    },

    // ── Audit ──────────────────────────────────────────────────
    async loadAudit(offset = 0) {
      const request = ++this.auditRequest;
      this.auditLoading = true; this.auditError = '';
      const query = new URLSearchParams({paginated:'true', limit:'50', offset:String(offset)});
      for (const [key,value] of Object.entries(this.auditFilters)) if (value) query.set(key,value);
      try {
        const result = await this.api('/superadmin/audit-log?' + query);
        if (request !== this.auditRequest) return;
        this.auditTimezone=result.timezone;
        this.auditLog = result.rows; this.auditTotal = result.total;
        this.auditActions = result.actions; this.auditOffset = offset;
      } catch (error) {
        if (request !== this.auditRequest) return;
        this.auditLog = []; this.auditTotal = 0; this.auditOffset = 0;
        this.auditError = error.message;
      } finally {
        if (request === this.auditRequest) this.auditLoading = false;
      }
    },
    fmtAuditDate(value) {
      return InventoryTime.formatInstant(value,this.auditTimezone);
    },

    // ── Helpers ────────────────────────────────────────────────
    fmtBytes(b) {
      if (!b && b !== 0) return '—';
      if (b < 1024)        return b + ' B';
      if (b < 1048576)     return (b / 1024).toFixed(1) + ' KB';
      return (b / 1048576).toFixed(2) + ' MB';
    },

    fmtDate(d) { return d ? InventoryTime.formatInstant(d,this.timezoneContext?.display_timezone) : '—'; },

    parseUA(ua) {
      if (!ua) return '—';
      if (ua.includes('Chrome'))  return 'Chrome';
      if (ua.includes('Firefox')) return 'Firefox';
      if (ua.includes('Safari'))  return 'Safari';
      if (ua.includes('Edge'))    return 'Edge';
      return ua.slice(0, 25);
    },
  };
}
