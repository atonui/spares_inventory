function loginPage() {
    return {
        authState: 'checking',
        loading: false,
        error: '',
        csrfToken: '',
        loginForm: {email: '', password: '', remember_me: false},
        async redirectAuthenticatedUser() {
            const response = await fetch('/api/me', {credentials: 'include', cache: 'no-store'});
            if (!response.ok) throw Error('Unable to check your session. Retry.');
            const user = await response.json();
            const isTenantlessPlatformAdmin = user.is_platform_admin && user.role === 'platform_admin';
            window.location.replace(isTenantlessPlatformAdmin ? '/static/superadmin.html' : '/static/index.html');
        },
        async checkAuth() {
            if (this.loading) return;
            this.authState = 'checking';
            this.error = '';
            try {
                const response = await fetch('/api/me', {credentials: 'include', cache: 'no-store'});
                if (response.status === 401) { this.authState = 'anonymous'; return; }
                if (!response.ok) throw Error('Unable to check your session. Retry.');
                const user = await response.json();
                const isTenantlessPlatformAdmin = user.is_platform_admin && user.role === 'platform_admin';
                window.location.replace(isTenantlessPlatformAdmin ? '/static/superadmin.html' : '/static/index.html');
            } catch (error) {
                this.authState = 'error';
                this.error = error.message;
            }
        },
        async login() {
            if (this.loading) return;
            this.loading = true;
            this.error = '';
            try {
                const response = await InventoryCsrf.request(this, '/api/auth/login', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(this.loginForm)
                });
                if (!response.ok) {
                    throw Error(response.status === 401 ? 'Invalid credentials' : 'Unable to sign in. Please retry.');
                }
                this.loginForm.password = '';
                await this.redirectAuthenticatedUser();
            } catch (error) {
                this.error = error.message;
            } finally {
                this.loading = false;
            }
        }
    };
}
