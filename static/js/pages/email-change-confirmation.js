function emailChangeConfirmation() {
    return {
        token: '',
        loading: false,
        submitted: false,
        success: false,
        error: '',
        init() {
            const fragment = typeof window !== 'undefined' ? window.location.hash : '';
            this.token = new URLSearchParams(fragment.replace(/^#/, '')).get('token') || '';
            if (typeof history !== 'undefined' && typeof window !== 'undefined') {
                history.replaceState(null, '', window.location.pathname);
            }
            if (!this.token || this.token.length < 20 || this.token.length > 200) {
                this.token = '';
                this.error = 'This confirmation link is invalid or expired. Request a new email change from your profile.';
            }
        },
        async confirm() {
            if (this.loading || this.submitted || !this.token) return;
            this.loading = true;
            this.submitted = true;
            this.error = '';
            const token = this.token;
            this.token = '';
            try {
                const response = await fetch('/api/auth/email-change/confirm', {
                    method: 'POST',
                    credentials: 'omit',
                    cache: 'no-store',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({token}),
                });
                const data = await response.json();
                if (!response.ok || data.success !== true) {
                    this.error = response.status === 400
                        ? 'This confirmation link is invalid or expired. Request a new email change from your profile.'
                        : response.status === 409
                            ? 'That address can no longer be used. Sign in with your current address and try another.'
                            : 'The email change could not be completed. Sign in with your current address and try again later.';
                    return;
                }
                this.success = true;
            } catch (_) {
                this.error = 'The email change could not be confirmed. Sign in with your current address and request a new link.';
            } finally {
                this.loading = false;
            }
        },
    };
}

if (typeof document !== 'undefined' && typeof document.addEventListener === 'function') {
    document.addEventListener('DOMContentLoaded', () => {
        const app = emailChangeConfirmation();
        const confirmButton = document.getElementById('confirm-email-change');
        const pending = document.getElementById('email-change-pending');
        const success = document.getElementById('email-change-success');
        const error = document.getElementById('email-change-error');
        const message = document.getElementById('email-change-message');
        app.init();
        const render = () => {
            if (pending) pending.hidden = !app.token || app.submitted;
            if (confirmButton) {
                confirmButton.disabled = app.loading || app.submitted || !app.token;
                confirmButton.textContent = app.loading ? 'Confirming…' : 'Confirm email change';
            }
            if (success) success.hidden = !app.success;
            if (error) {
                error.hidden = !app.error;
                error.textContent = app.error;
            }
            if (message && app.success) message.textContent = 'Your email address has been updated. A security notice will be sent to your previous address.';
        };
        if (confirmButton) confirmButton.addEventListener('click', async () => { await app.confirm(); render(); });
        render();
    });
}
