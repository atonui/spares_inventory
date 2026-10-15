function acceptInvitation() {
    return {
        organizationId: '',
        token: '',
        name: '',
        password: '',
        busy: false,
        complete: false,
        error: '',
        message: '',
        csrfToken: '',

        init() {
            const params = new URLSearchParams(window.location.search);
            this.organizationId = params.get('organization_id') || '';
            this.token = params.get('token') || '';
            // Keep the bearer token only in page memory; don't leave it in browser history.
            window.history.replaceState({}, document.title, window.location.pathname);
        },

        async submit() {
            if (this.busy || !this.token || !this.organizationId) return;
            this.busy = true;
            this.error = '';
            try {
                const response = await InventoryCsrf.request(this, '/api/invitations/accept', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        organization_id: this.organizationId,
                        token: this.token,
                        name: this.name,
                        password: this.password,
                    }),
                });
                const data = await response.json().catch(() => ({}));
                if (!response.ok) throw new Error(data.detail || 'Invitation could not be accepted.');
                this.message = 'Your account is ready. Sign in to continue.';
                this.complete = true;
                this.password = '';
                this.token = '';
                this.organizationId = '';
            } catch (error) {
                this.error = error.message || 'Invitation could not be accepted.';
            } finally { this.busy = false; }
        },
    };
}
