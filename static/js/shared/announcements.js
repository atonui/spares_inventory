// Public notices are independent of account/page controllers.
function siteAnnouncementBanner() {
    return {
        announcement: null, error: '', loading: false, timer: null, visibilityHandler: null,
        init() {
            this.load();
            this.timer = setInterval(() => {
                if (document.visibilityState !== 'hidden') this.load();
            }, 60000);
            this.visibilityHandler = () => {
                if (document.visibilityState !== 'hidden') this.load();
            };
            document.addEventListener('visibilitychange', this.visibilityHandler);
        },
        destroy() {
            clearInterval(this.timer);
            document.removeEventListener('visibilitychange', this.visibilityHandler);
        },
        async load() {
            if (this.loading) return;
            this.loading = true;
            try {
                const response = await fetch('/api/superadmin/announcement', {credentials: 'same-origin', cache: 'no-store'});
                if (!response.ok) throw Error('Announcement request failed');
                const data = await response.json();
                const notice = data.announcement;
                if (notice !== null && (!notice || typeof notice.message !== 'string' || !['info','warning','danger'].includes(notice.level))) {
                    throw Error('Invalid announcement');
                }
                this.announcement = notice;
                this.error = '';
            } catch {
                this.error = 'Announcement updates are unavailable. The last loaded notice may be out of date.';
            } finally { this.loading = false; }
        },
    };
}
