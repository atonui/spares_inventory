// One token acquisition per component; only explicit CSRF rejection permits a replay.
const InventoryCsrf = (() => {
    const pending = new WeakMap();
    const isWrite = method => !['GET', 'HEAD', 'OPTIONS'].includes((method || 'GET').toUpperCase());
    const rejected = (response, data) => response.status === 403 &&
        ['Invalid CSRF token', 'CSRF token missing'].includes(data?.detail);

    async function token(owner, base = '/api') {
        if (owner.csrfToken) return owner.csrfToken;
        if (pending.has(owner)) return pending.get(owner);
        const request = (async () => {
            try {
                const response = await fetch(`${base}/csrf-token`, {credentials: 'include', cache: 'no-store'});
                if (!response.ok) throw new Error('Security token unavailable');
                const data = await response.json();
                if (typeof data.csrf_token !== 'string' || !data.csrf_token.trim()) throw new Error('Security token unavailable');
                owner.csrfToken = data.csrf_token;
                return owner.csrfToken;
            } catch (_) {
                owner.csrfToken = '';
                throw new Error('Unable to load the security token. Please retry.');
            }
        })();
        pending.set(owner, request);
        try {return await request;} finally {pending.delete(owner);}
    }

    async function request(owner, url, options = {}, base = '/api') {
        const headers = new Headers(options.headers);
        const config = {...options, credentials: 'include', headers};
        if (!isWrite(options.method)) return fetch(url, config);
        const used = await token(owner, base);
        headers.set('X-CSRF-Token', used);
        let response = await fetch(url, config);
        if (response.status !== 403) return response;
        // Clone so normal error handling can still consume the response body.
        const data = await response.clone().json().catch(() => ({}));
        if (!rejected(response, data)) return response;
        if (owner.csrfToken === used) owner.csrfToken = '';
        const fresh = await token(owner, base);
        headers.set('X-CSRF-Token', fresh);
        response = await fetch(url, config);
        if (response.status === 403) {
            const retryData = await response.clone().json().catch(() => ({}));
            if (rejected(response, retryData) && owner.csrfToken === fresh) owner.csrfToken = '';
        }
        return response;
    }
    return {token, request};
})();
