function profileManager() {
    return {
        activeTab: 'profile',
        loading: true,
        profileRequestBusy: false,
        profileLoaded: false,
        profileError: '',
        saving: false,
        error: '',
        successMessage: '',
        csrfToken: '',
        csrfLoading: false,
        csrfError: '',
        profile: {name: '', email: '', role: '', territory: '', display_timezone: null},
        passwordForm: {current_password: '', new_password: '', confirm_password: ''},
        passwordStrength: '',
        timezoneContext: null,
        timezoneLoading: false,
        timezoneError: '',
        timezoneConflict: false,
        displayTimezoneDraft: '',
        businessTimezoneDraft: '',
        displayTimezoneSaving: false,
        businessTimezoneSaving: false,
        displayTimezoneError: '',
        businessTimezoneError: '',
        displayTimezoneMessage: '',
        businessTimezoneMessage: '',

        get timezoneSaving() { return this.displayTimezoneSaving || this.businessTimezoneSaving; },
        get displayTimezoneDirty() { return this.displayTimezoneDraft !== (this.profile.display_timezone || ''); },
        get businessTimezoneDirty() { return Boolean(this.timezoneContext && this.businessTimezoneDraft !== this.timezoneContext.business_timezone); },
        get canManageBusinessTimezone() { return ['owner','admin','superadmin'].includes(this.profile.role); },
        get detectedTimezone() {
            const zone=Intl.DateTimeFormat().resolvedOptions().timeZone;
            return InventoryTime.isValidZone(zone) ? zone : '';
        },
        get timezoneOptions() {
            const list=typeof Intl.supportedValuesOf==='function' ? Intl.supportedValuesOf('timeZone') : ['Africa/Nairobi','Africa/Lagos','America/New_York','Europe/London','Asia/Kathmandu'];
            return [...new Set(['UTC',...list,this.timezoneContext?.business_timezone,this.profile.display_timezone,this.detectedTimezone].filter(zone=>InventoryTime.isValidZone(zone)))].sort();
        },
        setActiveTab(tab, focus=false) {
            if (!['profile','password'].includes(tab) || this.saving || this.timezoneSaving) return;
            this.activeTab=tab;
            if (focus) this.$nextTick(()=>document.getElementById('profile-tab-'+tab)?.focus());
        },
        async init() {
            await Promise.all([this.getCsrfToken(),this.loadProfile()]);
            if (this.profileLoaded) await this.loadTimezoneContext();
        },
        async retryProfile() {
            await this.loadProfile();
            if (this.profileLoaded) await this.loadTimezoneContext();
        },
        async getCsrfToken() {
            if (this.csrfLoading || this.saving || this.timezoneSaving) return;
            this.csrfLoading=true;this.csrfError='';this.csrfToken='';
            try {
                const response=await fetch('/api/csrf-token',{credentials:'include'});
                if (!response.ok) throw Error('Security token unavailable');
                const data=await response.json();
                if (typeof data.csrf_token!=='string' || !data.csrf_token) throw Error('Security token unavailable');
                this.csrfToken=data.csrf_token;
            } catch (_) {
                this.csrfError='Saving is unavailable. Retry to reload the security token.';
            } finally { this.csrfLoading=false; }
        },
        async loadProfile() {
            if (this.profileRequestBusy) return;
            this.profileRequestBusy=true;this.loading=true;this.profileError='';this.profileLoaded=false;
            try {
                const response=await fetch('/api/profile',{credentials:'include'});
                if (!response.ok) {
                    if (response.status===401) {window.location.href='/static/index.html';return;}
                    throw Error('Profile unavailable');
                }
                const data=await response.json();
                this.profile={name:data.name,email:data.email,role:data.role,territory:data.territory || '',display_timezone:data.display_timezone || null};
                this.profileLoaded=true;
            } catch (_) {
                this.profileError='Your profile could not be loaded. Retry when your connection is ready.';
            } finally {this.loading=false;this.profileRequestBusy=false;}
        },
        async loadTimezoneContext() {
            if (this.timezoneLoading || this.timezoneSaving || this.saving) return;
            this.timezoneLoading=true;this.timezoneError='';
            try {
                const response=await fetch('/api/timezone-context',{credentials:'include'});
                if (!response.ok) throw Error('Timezone settings could not be loaded. Retry.');
                const data=await response.json();
                if (!validTimezoneContext(data)) throw Error('Timezone settings are unavailable. Retry.');
                this.timezoneContext=data;this.businessTimezoneDraft=data.business_timezone;
                this.displayTimezoneDraft=this.profile.display_timezone || '';
                this.timezoneConflict=false;
                this.displayTimezoneError='';this.businessTimezoneError='';
                this.displayTimezoneMessage='';this.businessTimezoneMessage='';
            } catch (error) {this.timezoneContext=null;this.timezoneError=error.message;}
            finally {this.timezoneLoading=false;}
        },
        clearDisplayTimezoneFeedback() {this.displayTimezoneError='';this.displayTimezoneMessage='';},
        clearBusinessTimezoneFeedback() {if (!this.timezoneConflict) this.businessTimezoneError='';this.businessTimezoneMessage='';},
        handleSecurityRejection(response, data) {
            if (response.status === 403 && ['Invalid CSRF token', 'CSRF token missing'].includes(data.detail)) {
                this.csrfToken = '';
                this.csrfError = 'Saving is unavailable. Retry to reload the security token.';
            }
        },
        async saveDisplayTimezone() {
            if (this.timezoneSaving || this.saving || this.timezoneLoading || this.csrfLoading || !this.csrfToken || !this.timezoneContext || !this.displayTimezoneDirty) return;
            this.displayTimezoneSaving=true;this.clearDisplayTimezoneFeedback();
            try {
                const response=await fetch('/api/profile',{method:'PUT',credentials:'include',headers:{'Content-Type':'application/json','X-CSRF-Token':this.csrfToken},body:JSON.stringify({display_timezone:this.displayTimezoneDraft || null})});
                const data=await response.json();
                this.handleSecurityRejection(response, data);
                if (!response.ok) throw Error(typeof data.detail==='string' ? data.detail : 'Display timezone could not be saved.');
                this.profile.display_timezone=data.display_timezone;
                this.timezoneContext.display_timezone=data.display_timezone || this.timezoneContext.business_timezone;
                this.displayTimezoneMessage='Display timezone saved.';
            } catch (error) {this.displayTimezoneError=error.message;}
            finally {this.displayTimezoneSaving=false;}
        },
        async saveBusinessTimezone() {
            if (this.timezoneSaving || this.saving || this.timezoneLoading || this.csrfLoading || !this.csrfToken || this.timezoneConflict || !this.timezoneContext || !this.canManageBusinessTimezone || !this.businessTimezoneDirty) return;
            this.businessTimezoneSaving=true;this.clearBusinessTimezoneFeedback();
            try {
                const response=await fetch('/api/organisation/timezone',{method:'PUT',credentials:'include',headers:{'Content-Type':'application/json','X-CSRF-Token':this.csrfToken},body:JSON.stringify({timezone:this.businessTimezoneDraft,expected_revision:this.timezoneContext.revision})});
                const data=await response.json();
                this.handleSecurityRejection(response, data);
                if (!response.ok) {if(response.status===409)this.timezoneConflict=true;throw Error(typeof data.detail==='string' ? data.detail : 'Business timezone could not be saved.');}
                if (!validTimezoneContext(data)) throw Error('Reload settings to verify the saved timezone.');
                this.timezoneContext=data;
                this.businessTimezoneMessage='Organisation timezone saved. Refresh open reports to use it.';
            } catch (error) {this.businessTimezoneError=error.message;}
            finally {this.businessTimezoneSaving=false;}
        },
        async changePassword() {
            if (this.saving || this.timezoneSaving || this.csrfLoading || !this.csrfToken) return;
            this.error='';this.successMessage='';
            if (this.passwordForm.new_password!==this.passwordForm.confirm_password) {this.error='Passwords do not match';return;}
            if (this.passwordForm.new_password.length<8) {this.error='Password must be at least 8 characters long';return;}
            this.saving=true;
            try {
                const response=await fetch('/api/profile/change-password',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json','X-CSRF-Token':this.csrfToken},body:JSON.stringify({current_password:this.passwordForm.current_password,new_password:this.passwordForm.new_password})});
                const data=await response.json();
                this.handleSecurityRejection(response, data);
                if (response.ok) {
                    this.successMessage=data.message+' Redirecting to login…';
                    this.passwordForm={current_password:'',new_password:'',confirm_password:''};this.passwordStrength='';
                    localStorage.removeItem('currentUser');
                    setTimeout(()=>{window.location.href='/static/index.html';},2000);
                } else {this.error=typeof data.detail==='string' ? data.detail : 'Password could not be changed.';}
            } catch (_) {this.error='Password could not be changed. Check your connection and retry.';}
            finally {this.saving=false;}
        },
        checkPasswordStrength() {
            const password=this.passwordForm.new_password;
            let strength=0;
            if (password.length>=8) strength++;
            if (password.match(/[a-z]/) && password.match(/[A-Z]/)) strength++;
            if (password.match(/\d/)) strength++;
            if (password.match(/[^a-zA-Z\d]/)) strength++;
            this.passwordStrength=strength<=2 ? 'strength-weak' : strength===3 ? 'strength-medium' : 'strength-strong';
        }
    };
}
