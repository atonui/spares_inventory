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
        if (this.dlg.reason_required && String(this.dlg.reason || '').trim().length < 10) {
          this.dialogError = 'Enter a reason of at least 10 characters.';
          return;
        }
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
      if (section === 'support' && !this.me?.saas_mode) return;
      if (this.me?.saas_mode) {
        const allowed = ['dashboard','config','announcement','organizations','platformAdmins','platformAudit'];
        if (section === 'support' && this.supportSession) allowed.push('support');
        if (!allowed.includes(section)) return;
      }
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
      const controls = Array.from(element.querySelectorAll('button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), a[href]'));
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
      organizations: 'Organizations', platformAdmins: 'Platform Admins', platformAudit: 'Platform Audit',
      support: 'Customer Support',
    },

    // data stores
    dashboard: {},
    organizations: [],
    organizationTotal: 0, organizationLimit: 25, organizationOffset: 0,
    organizationLoading: false, organizationError: '',
    organizationFilters: { search: '', status: 'all' },
    platformAuditRows: [], platformAuditTotal: 0, platformAuditOffset: 0,
    platformAuditLoading: false, platformAuditError: '',
    platformAuditFilters: { actor_user_id: '', organization_id: '', action: '', result: '', start_at: '', end_at: '' },
    organizationForm: { name: '', slug: '', owner_email: '' },
    supportSession: null, supportNow: Date.now(), supportExpiryTimer: null,
    supportStartOrg: null, supportStartOpen: false, supportStartPending: false,
    supportStartError: '', supportStartForm: { reason: '', current_password: '' },
    supportLookupKind: 'accounts', supportLookupValue: '', supportRows: [],
    supportLoading: false, supportError: '', supportRequest: 0, supportHasSearched: false,
    supportLookupKinds: [
      { key:'accounts', label:'Account access', placeholder:'Exact email address', param:'email' },
      { key:'inventory', label:'Inventory and parts', placeholder:'Exact part number', param:'query' },
      { key:'work-orders', label:'Work orders', placeholder:'Exact work order number', param:'query' },
      { key:'equipment', label:'Equipment', placeholder:'Exact serial number', param:'query' },
      { key:'equipment-history', label:'Equipment history', placeholder:'Exact serial number', param:'query' },
      { key:'movements', label:'Movements and transfers', placeholder:'Exact part number', param:'query' },
    ],
    platformAdmins: [], platformAdminLoading: false, platformAdminError: '', platformAdminEmail: '',
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
    announcement: null, announcementLoading: false, announcementError: '',
    savedAnnouncement: null, announcementReady: false, announcementConflict: false,
    announcementStatus: 'none', announcementTimezone: '', announcementTimezoneRevision: null,
    annForm: {message:'',level:'info',audience:'everyone',roles:[],starts_local:'',expires_local:'',dismissible:false},
    announcementPublishNow: true, announcementHasExpiry: false,

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
      if (!await this.getMe()) return;
      if (this.me?.saas_mode) {
        await this.loadCurrentSupportSession();
        await this.loadPlatformDashboard();
        await this.loadOrganizations();
        await this.loadPlatformAudit();
        await this.loadPlatformAdmins();
        return;
      }
      await this.loadTimezoneContext();
      await this.loadDashboard();
      await this.loadAnnouncement();
    },

    refresh() {
      const loaders = {
        dashboard: () => this.loadDashboard(),
        support: () => this.loadCurrentSupportSession(),
        organizations: () => this.loadOrganizations(),
        platformAdmins: () => this.loadPlatformAdmins(),
        platformAudit: () => this.loadPlatformAudit(),
        accounts:  () => this.loadLocked(),
        sessions:  () => this.loadSessions(),
        config:    () => this.loadConfig(),
        users:     () => this.loadUsers(),
        tables:    () => this.loadTables(),
        audit:     () => this.loadAudit(),
        announcement: () => this.openAnnouncement(),
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
        if (!this.me.is_platform_admin && this.me.role !== 'superadmin') {
          this.toast('Access denied — platform administrator access required.', 'danger');
          setTimeout(() => location.href = '/static/index.html', 2000);
          return false;
        }
        return true;
      } catch { location.href = '/static/index.html'; return false; }
    },

    async api(path, opts = {}) {
      const headers = { ...opts.headers };
      if (!(opts.body instanceof FormData)) headers['Content-Type'] = 'application/json';
      const supportRequest = path.startsWith('/platform/support-sessions');
      const r = await InventoryCsrf.request(this, `${this.apiUrl}${path}`, {
        ...opts, headers, ...(supportRequest ? { cache: 'no-store' } : {}),
      }, this.apiUrl);
      if (r.status === 401) {
        const error = new Error('Unauthenticated'); error.status = 401;
        if (!path.startsWith('/platform/support-sessions')) location.href = '/static/index.html';
        throw error;
      }
      if (!r.ok) { const e = await r.json().catch(() => ({})); const error = new Error(e.detail || `HTTP ${r.status}`); error.status=r.status; throw error; }
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

    async loadPlatformDashboard() {
      this.loading = true;
      try { this.dashboard = await this.api('/platform/dashboard'); }
      catch (e) { this.toast(e.message, 'danger'); }
      finally { this.loading = false; }
    },

    async loadOrganizations(offset = this.organizationOffset) {
      if (this.organizationLoading) return;
      const query = new URLSearchParams({
        limit: String(this.organizationLimit), offset: String(offset),
        status: this.organizationFilters.status,
      });
      if (this.organizationFilters.search.trim()) query.set('search', this.organizationFilters.search.trim());
      this.organizationLoading = true;
      this.organizationError = '';
      try {
        const data = await this.api(`/platform/organizations?${query.toString()}`);
        this.organizations = Array.isArray(data.rows) ? data.rows : [];
        this.organizationTotal = Number.isInteger(data.total) ? data.total : 0;
        this.organizationOffset = data.offset || 0;
      } catch (error) {
        this.organizations = [];
        this.organizationTotal = 0;
        this.organizationError = error.message || 'Unable to load organizations.';
      } finally {
        this.organizationLoading = false;
      }
    },

    openSupportStart(org) {
      if (!this.me?.saas_mode || !this.me?.is_platform_admin || !org?.id) return;
      this.supportStartOrg = org;
      this.supportStartForm = { reason: '', current_password: '' };
      this.supportStartError = '';
      this.supportStartOpen = true;
    },

    async startSupportSession() {
      if (this.supportStartPending || !this.supportStartOrg) return;
      const reason = String(this.supportStartForm.reason || '').trim();
      const password = String(this.supportStartForm.current_password || '');
      if (reason.length < 10 || reason.length > 500 || !password) {
        this.supportStartError = 'Enter a reason of 10–500 characters and confirm your password.';
        this.supportStartForm.current_password = '';
        return;
      }
      this.supportStartPending = true;
      this.supportStartError = '';
      try {
        const data = await this.api('/platform/support-sessions', {
          method: 'POST',
          body: JSON.stringify({ organization_id: this.supportStartOrg.id, reason, current_password: password }),
        });
        this.clearSupportResults();
        this.supportSession = data;
        this.supportStartOpen = false;
        this.tab = 'support';
        this.supportNow = Date.now();
        this.scheduleSupportExpiry();
      } catch (error) {
        this.supportStartError = error.message || 'Unable to start support session.';
      } finally {
        this.supportStartForm.current_password = '';
        this.supportStartPending = false;
      }
    },

    async loadCurrentSupportSession() {
      if (!this.me?.saas_mode) return;
      try {
        const data = await this.api('/platform/support-sessions/current');
        this.supportSession = data || null;
        if (this.supportSession) {
          this.supportNow = Date.now();
          this.tab = 'support';
          this.scheduleSupportExpiry();
        } else {
          this.clearSupportSession();
          if (this.tab === 'support') this.tab = 'dashboard';
        }
      } catch (error) {
        this.clearSupportSession();
        if (this.tab === 'support' || error.status === 401 || error.status === 403) this.tab = 'dashboard';
      }
    },

    scheduleSupportExpiry() {
      if (this.supportExpiryTimer) clearTimeout(this.supportExpiryTimer);
      this.supportExpiryTimer = setTimeout(() => {
        this.supportNow = Date.now();
        if (!this.supportSession) return;
        if (this.supportNow >= Date.parse(this.supportSession.expires_at)) {
          this.clearSupportSession();
          this.tab = 'dashboard';
          this.toast('Support session expired. Tenant data was cleared.', 'danger');
          return;
        }
        this.scheduleSupportExpiry();
      }, 1000);
    },

    supportTimeRemaining() {
      if (!this.supportSession) return '';
      const seconds = Math.max(0, Math.ceil((Date.parse(this.supportSession.expires_at) - this.supportNow) / 1000));
      return `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, '0')}`;
    },

    clearSupportResults() {
      this.supportRequest++;
      this.supportRows = [];
      this.supportError = '';
      this.supportLoading = false;
      this.supportLookupValue = '';
      this.supportHasSearched = false;
    },

    clearSupportSession() {
      if (this.supportExpiryTimer) clearTimeout(this.supportExpiryTimer);
      this.supportExpiryTimer = null;
      this.supportSession = null;
      this.clearSupportResults();
    },

    handleTerminalSupportError(error) {
      if (![401,403,404].includes(error?.status)) return false;
      this.clearSupportSession();
      this.tab = 'dashboard';
      this.toast('Support session is no longer available. Tenant data was cleared.', 'danger');
      return true;
    },

    async endSupportSession() {
      if (!this.supportSession || this.supportLoading) return;
      const id = this.supportSession.support_session_id;
      this.supportLoading = true;
      try {
        await this.api(`/platform/support-sessions/${encodeURIComponent(id)}`, { method: 'DELETE' });
        this.clearSupportSession();
        this.tab = 'dashboard';
        this.toast('Support session ended.', 'ok');
      } catch (error) {
        if (!this.handleTerminalSupportError(error)) this.supportError = error.message || 'Unable to end support session.';
      } finally {
        this.supportLoading = false;
      }
    },

    async loadSupportLookup() {
      if (!this.supportSession || this.supportLoading) return;
      const kind = this.supportLookupKinds.find(item => item.key === this.supportLookupKind);
      const value = String(this.supportLookupValue || '').trim();
      const maximum = kind?.key === 'accounts' ? 254 : 100;
      if (!kind || !value || value.length > maximum) {
        this.supportRows = [];
        this.supportError = `Enter a lookup value of 1–${maximum} characters.`;
        return;
      }
      const request = ++this.supportRequest;
      this.supportLoading = true;
      this.supportError = '';
      this.supportRows = [];
      this.supportHasSearched = true;
      try {
        const query = new URLSearchParams({ [kind.param]: value });
        const result = await this.api(`/platform/support-sessions/${encodeURIComponent(this.supportSession.support_session_id)}/${kind.key}?${query.toString()}`);
        if (request === this.supportRequest && this.tab === 'support')
          this.supportRows = Array.isArray(result.rows) ? result.rows : [];
      } catch (error) {
        if (request !== this.supportRequest) return;
        if (!this.handleTerminalSupportError(error)) this.supportError = error.message || 'Unable to load support results.';
      } finally {
        if (request === this.supportRequest) this.supportLoading = false;
      }
    },

    requestOrganizationStatus(org) {
      if (this.dialogBusy) return;
      const action = org.is_active ? 'suspend' : 'reactivate';
      const label = org.is_active ? 'Suspend' : 'Reactivate';
      this.dialogError = '';
      this.dlg = {
        open: true,
        title: `${label} ${org.name}?`,
        msg: org.is_active
          ? 'Tenant access will be blocked for all members while the organization is suspended.'
          : 'Members will regain tenant access after the organization is reactivated.',
        action: `${label} organization`,
        button_class: org.is_active ? 'btn-red' : 'btn-green',
        reason_required: true,
        reason: '',
        resolve: async () => {
          await this.api(`/platform/organizations/${encodeURIComponent(org.id)}/status`, {
            method: 'PUT',
            body: JSON.stringify({ action, reason: this.dlg.reason.trim() }),
          });
          this.toast(`Organization ${action === 'suspend' ? 'suspended' : 'reactivated'}.`, 'ok');
          await this.loadOrganizations(this.organizationOffset);
          await this.loadPlatformDashboard();
        },
      };
    },

    async loadPlatformAdmins() {
      if (this.platformAdminLoading) return;
      this.platformAdminLoading = true;
      this.platformAdminError = '';
      try {
        const rows = await this.api('/platform/admins');
        this.platformAdmins = Array.isArray(rows) ? rows : [];
      } catch (error) {
        this.platformAdmins = [];
        this.platformAdminError = error.message || 'Unable to load platform administrators.';
      } finally {
        this.platformAdminLoading = false;
      }
    },

    requestPlatformAdminGrant() {
      if (this.dialogBusy || this.actionPending.platformAdminGrant) return;
      const email = String(this.platformAdminEmail || '').trim();
      if (!email) {
        this.actionErrors.platformAdminGrant = 'Enter the exact email address of an existing account.';
        return;
      }
      this.actionErrors.platformAdminGrant = '';
      this.dlg = {
        open: true,
        title: 'Grant platform administrator access?',
        msg: `Grant global platform administration to the existing account ${email}? This does not create an account.`,
        action: 'Grant access',
        button_class: 'btn-green',
        resolve: async () => {
          if (!await this.grantPlatformAdmin(email)) throw new Error(this.actionErrors.platformAdminGrant || 'Unable to grant access.');
        },
      };
    },

    async grantPlatformAdmin(email) {
      return this.runAction('platformAdminGrant', async () => {
        const result = await this.api('/platform/admins', {
          method: 'POST', body: JSON.stringify({ email }),
        });
        this.platformAdminEmail = '';
        this.toast(result.created ? 'Platform administrator access granted.' : 'That account already has platform administrator access.', 'ok');
        await this.loadPlatformAdmins();
      });
    },

    requestPlatformAdminRevoke(admin) {
      if (admin.id === this.me?.id || this.dialogBusy || this.actionPending[`platformAdminRevoke:${admin.id}`]) return;
      this.dlg = {
        open: true,
        title: `Revoke access from ${admin.name || admin.email}?`,
        msg: `This removes platform-wide administrator access from ${admin.email}. Their tenant membership, if any, is unchanged.`,
        action: 'Revoke access',
        button_class: 'btn-red',
        resolve: async () => {
          const key = `platformAdminRevoke:${admin.id}`;
          if (!await this.revokePlatformAdmin(admin)) throw new Error(this.actionErrors[key] || 'Unable to revoke access.');
        },
      };
    },

    async revokePlatformAdmin(admin) {
      const key = `platformAdminRevoke:${admin.id}`;
      return this.runAction(key, async () => {
        await this.api(`/platform/admins/${encodeURIComponent(admin.id)}`, { method: 'DELETE' });
        this.toast(`Platform administrator access revoked for ${admin.email}.`, 'ok');
        await this.loadPlatformAdmins();
      });
    },

    async loadPlatformAudit(offset = 0) {
      if (this.platformAuditLoading) return;
      const request = new URLSearchParams({ limit: '50', offset: String(offset) });
      for (const [key, value] of Object.entries(this.platformAuditFilters)) {
        if (String(value).trim()) request.set(key, String(value).trim());
      }
      this.platformAuditLoading = true;
      this.platformAuditError = '';
      try {
        const data = await this.api(`/platform/audit-events?${request.toString()}`);
        this.platformAuditRows = Array.isArray(data.rows) ? data.rows : [];
        this.platformAuditTotal = Number.isInteger(data.total) ? data.total : 0;
        this.platformAuditOffset = data.offset || 0;
      } catch (error) {
        this.platformAuditRows = [];
        this.platformAuditError = error.message || 'Unable to load platform audit events.';
      } finally {
        this.platformAuditLoading = false;
      }
    },

    async provisionOrganization() {
      const form = this.organizationForm;
      if (!form.name.trim() || !form.slug.trim() || !form.owner_email.trim()) return;
      return this.runAction('provisionOrganization', async () => {
        await this.api('/platform/organizations', {
          method: 'POST',
          body: JSON.stringify({
            name: form.name.trim(),
            slug: form.slug.trim(),
            owner_email: form.owner_email.trim(),
          }),
        });
        this.organizationForm = { name: '', slug: '', owner_email: '' };
        this.organizationFilters = { search: '', status: 'all' };
        this.toast('Organization created and owner invitation queued.', 'ok');
        await this.loadOrganizations(0);
        await this.loadPlatformDashboard();
      });
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
        const path = this.me?.saas_mode ? '/platform/security-config' : '/superadmin/security-config';
        this.secConfig = await this.api(path);
        for (const k of Object.keys(this.cfgMeta))
          this.cfgVals[k] = this.secConfig[k]?.setting_value ?? '';
      });
    },

    async saveConfig(key) {
      if (!this.panelReady('config')) return;
      const val = this.cfgVals[key];
      if (!val) { this.toast('Please enter a value', 'warn'); return; }
      return this.runAction('config:' + key, async () => {
        const path = this.me?.saas_mode ? `/platform/security-config/${key}` : `/superadmin/security-config/${key}`;
        await this.api(path, {
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
    announcementFormFor(notice) {
      return {message:notice?.message || '',level:notice?.level || 'info',audience:notice?.audience || 'everyone',roles:[...(notice?.roles || [])],
        starts_local:InventoryAnnouncementTime.localInput(notice?.starts_at,this.announcementTimezone),
        expires_local:InventoryAnnouncementTime.localInput(notice?.expires_at,this.announcementTimezone),dismissible:notice?.dismissible || false};
    },
    openAnnouncement() {
      if (!this.announcementReady && !this.announcementConflict) return this.loadAnnouncement();
    },
    async loadAnnouncement(afterWrite = false) {
      if (this.announcementLoading || (this.actionPending.announcement && !afterWrite)) return;
      this.announcementLoading = true; this.announcementError = ''; this.announcementReady=false;
      try {
        const path = this.me?.saas_mode ? '/platform/announcement/manage' : '/superadmin/announcement/manage';
        const r = await this.api(path);
        const minRevision = this.me?.saas_mode ? 0 : 1;
        if (!InventoryTime.isValidZone(r.business_timezone) || !Number.isInteger(r.timezone_revision) || r.timezone_revision<minRevision) throw Error('Announcement timezone metadata unavailable');
        this.announcementTimezone=r.business_timezone;this.announcementTimezoneRevision=r.timezone_revision;
        this.savedAnnouncement=r.announcement;this.announcement=r.announcement;
        this.announcementStatus=r.status;this.annForm=this.announcementFormFor(r.announcement);
        this.announcementPublishNow=!r.announcement?.starts_at;this.announcementHasExpiry=!!r.announcement?.expires_at;
        this.announcementConflict=false;this.announcementReady=true;this.actionErrors.announcement='';
      } catch (error) { this.announcementError = error.message; }
      finally { this.announcementLoading = false; }
    },
    async saveAnnouncement() {
      if (this.announcementLoading || !this.announcementReady || this.announcementConflict) return;
      return this.runAction('announcement', async () => {
        if (this.annForm.audience==='roles' && !this.annForm.roles.length) throw Error('Select at least one role');
        if (!this.announcementPublishNow && !this.annForm.starts_local) throw Error('Select a start time');
        if (this.announcementHasExpiry && !this.annForm.expires_local) throw Error('Select an expiry time');
        try {
          const path = this.me?.saas_mode ? '/platform/announcement' : '/superadmin/announcement';
          await this.api(path, {method:'POST',body:JSON.stringify({...this.annForm,
            starts_local:this.announcementPublishNow?null:this.annForm.starts_local,
            expires_local:this.announcementHasExpiry?this.annForm.expires_local:null,
            timezone_revision:this.announcementTimezoneRevision,expected_revision:this.savedAnnouncement?.revision || null})});
        } catch(error) {if(error.status===409)this.announcementConflict=true;throw error;}
        this.toast('Announcement saved. Saving resets previous dismissals.', 'ok');
        await this.loadAnnouncement(true);
      });
    },
    async clearAnnouncement() {
      if (this.announcementLoading || !this.announcementReady || this.announcementConflict) return;
      return this.runAction('announcement', async () => {
        const query=this.savedAnnouncement?.revision?'?expected_revision='+encodeURIComponent(this.savedAnnouncement.revision):'';
        const path = this.me?.saas_mode ? '/platform/announcement' : '/superadmin/announcement';
        try {await this.api(path+query,{method:'DELETE'});}
        catch(error) {if(error.status===409)this.announcementConflict=true;throw error;}
        this.announcement=null;this.savedAnnouncement=null;this.announcementStatus='none';this.announcementError='';
        this.annForm=this.announcementFormFor(null);this.announcementPublishNow=true;this.announcementHasExpiry=false;
        this.toast('Announcement removed', 'ok');
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
