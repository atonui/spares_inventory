export type NativeUser = {
  id: number;
  email: string;
  name: string;
  role: string;
  territory: string | null;
  is_platform_admin?: boolean;
  saas_mode?: boolean;
};

export type InventoryRow = {
  id: number;
  part_id: number;
  store_id: number;
  part_number: string;
  description: string;
  store_name: string;
  store_type: string;
  quantity: number;
  min_threshold: number;
  is_allocated: boolean;
  work_order: string | null;
};

export type NativeSession = {
  access_token: string;
  refresh_token: string;
  expires_at: string;
};

export type NativeLogin = NativeSession & {
  success: true;
  token_type: 'Bearer';
  user: NativeUser;
};

type InventoryPage = {
  items: InventoryRow[];
  page: {limit: number; next_cursor: string | null};
};

export type SessionStore = {
  getSession(): Promise<NativeSession | null>;
  setSession(session: NativeSession): Promise<void>;
  clearSession(): Promise<void>;
};

export class ApiError extends Error {
  readonly status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

type ApiClientOptions = {
  baseUrl: string;
  fetchImpl?: typeof fetch;
  sessionStore?: SessionStore;
  requestIdFactory?: () => string;
};

function safeMessage(payload: unknown, fallback: string): string {
  if (!payload || typeof payload !== 'object') return fallback;
  if ('error' in payload) {
    const error = (payload as {error?: {detail?: unknown}}).error;
    if (error && typeof error.detail === 'string' && error.detail.trim()) return error.detail;
  }
  if ('detail' in payload) {
    const detail = (payload as {detail?: unknown}).detail;
    if (typeof detail === 'string' && detail.trim()) return detail;
  }
  return fallback;
}

function makeRequestId(): string {
  return `mobile_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 12)}`;
}

export function createApiClient({
  baseUrl,
  fetchImpl = fetch,
  sessionStore,
  requestIdFactory = makeRequestId,
}: ApiClientOptions) {
  const root = baseUrl.trim().replace(/\/+$/, '');
  let refreshInFlight: Promise<NativeSession> | null = null;

  async function request<T>(
    path: string,
    {token, method = 'GET', body, extraHeaders = {}}: {
      token?: string;
      method?: string;
      body?: unknown;
      extraHeaders?: Record<string, string>;
    } = {},
  ): Promise<T> {
    if (!/^https:\/\//i.test(root)) {
      throw new ApiError('The mobile API server is not configured with an HTTPS URL.', 0);
    }
    const headers: Record<string, string> = {Accept: 'application/json', ...extraHeaders};
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    if (token) headers.Authorization = `Bearer ${token}`;
    const response = await fetchImpl(`${root}${path}`, {
      method,
      headers,
      credentials: 'omit',
      cache: 'no-store',
      ...(body === undefined ? {} : {body: JSON.stringify(body)}),
    });

    let payload: unknown = null;
    try {
      payload = await response.json();
    } catch {
      if (response.ok) throw new ApiError('The server returned an unreadable response.', response.status);
    }
    if (!response.ok) {
      throw new ApiError(safeMessage(payload, `Request failed (${response.status}).`), response.status);
    }
    return payload as T;
  }

  async function refresh(refreshToken: string, requestId = requestIdFactory()): Promise<NativeSession> {
    const options = {
      method: 'POST',
      body: {refresh_token: refreshToken},
      extraHeaders: {'X-Request-ID': requestId},
    };
    const send = async () => {
      const result = await request<NativeSession & {success: boolean; token_type: string}>(
        '/api/v1/auth/native/refresh', options,
      );
      if (result.token_type !== 'Bearer' || !result.access_token || !result.refresh_token || !result.expires_at) {
        throw new ApiError('The server returned an invalid session response.', 0);
      }
      return {access_token: result.access_token, refresh_token: result.refresh_token, expires_at: result.expires_at};
    };
    try {
      return await send();
    } catch (reason) {
      // The backend caches a refresh response for this request ID so a lost
      // response can be replayed without consuming the rotated credential.
      if (!(reason instanceof TypeError)) throw reason;
      return send();
    }
  }

  async function rotateSession(rejected: NativeSession): Promise<NativeSession> {
    if (!sessionStore) throw new ApiError('Your session is unavailable. Please sign in again.', 401);
    const latest = await sessionStore.getSession();
    if (!latest) throw new ApiError('Your session expired. Please sign in again.', 401);
    // Another request may already have rotated this pair while this request
    // was in flight. Reuse its result instead of replaying the old refresh token.
    if (latest.access_token !== rejected.access_token) return latest;

    if (!refreshInFlight) {
      refreshInFlight = (async () => {
        const renewed = await refresh(latest.refresh_token);
        const nextSession: NativeSession = {
          access_token: renewed.access_token,
          refresh_token: renewed.refresh_token,
          expires_at: renewed.expires_at,
        };
        await sessionStore.setSession(nextSession);
        return nextSession;
      })().finally(() => { refreshInFlight = null; });
    }

    try {
      return await refreshInFlight;
    } catch (reason) {
      if (reason instanceof ApiError && [401, 403].includes(reason.status)) {
        await sessionStore.clearSession();
      }
      throw reason;
    }
  }

  async function authenticated<T>(operation: (accessToken: string) => Promise<T>): Promise<T> {
    if (!sessionStore) throw new ApiError('Please sign in to continue.', 401);
    const session = await sessionStore.getSession();
    if (!session?.access_token || !session.refresh_token || !session.expires_at) {
      throw new ApiError('Please sign in to continue.', 401);
    }
    try {
      return await operation(session.access_token);
    } catch (reason) {
      if (!(reason instanceof ApiError) || reason.status !== 401) throw reason;
      const renewed = await rotateSession(session);
      return operation(renewed.access_token);
    }
  }

  return {
    async login({email, password, rememberMe = false}: {email: string; password: string; rememberMe?: boolean}) {
      const {csrf_token: csrfToken} = await request<{csrf_token: string}>('/api/v1/csrf-token');
      if (!csrfToken) throw new ApiError('The server did not provide a security token.', 0);
      const result = await request<NativeLogin>('/api/v1/auth/native/login', {
        method: 'POST',
        body: {email: email.trim(), password, remember_me: rememberMe},
        extraHeaders: {'X-CSRF-Token': csrfToken},
      });
      if (result.token_type !== 'Bearer' || !result.access_token || !result.refresh_token || !result.expires_at) {
        throw new ApiError('The server returned an invalid session response.', 0);
      }
      return result;
    },
    refresh,
    getSession() {
      return sessionStore?.getSession() ?? Promise.resolve(null);
    },
    saveSession(session: NativeSession) {
      if (!sessionStore) throw new ApiError('Secure session storage is unavailable.', 0);
      return sessionStore.setSession({
        access_token: session.access_token,
        refresh_token: session.refresh_token,
        expires_at: session.expires_at,
      });
    },
    clearSession() {
      return sessionStore?.clearSession() ?? Promise.resolve();
    },
    getMe() {
      return authenticated(token => request<NativeUser>('/api/v1/me', {token}));
    },
    async getInventory(): Promise<InventoryRow[]> {
      return authenticated(async token => {
        const rows: InventoryRow[] = [];
        const seenCursors = new Set<string>();
        let cursor: string | null = null;
        do {
          const query: string = cursor === null ? '?limit=50' : `?limit=50&cursor=${encodeURIComponent(cursor)}`;
          const page: InventoryPage = await request<InventoryPage>(`/api/v1/inventory${query}`, {token});
          if (!Array.isArray(page.items) || !page.page || !('next_cursor' in page.page)) {
            throw new ApiError('The server returned an invalid inventory response.', 0);
          }
          rows.push(...page.items);
          cursor = page.page.next_cursor;
          if (cursor !== null) {
            if (seenCursors.has(cursor)) throw new ApiError('The server returned a repeated inventory cursor.', 0);
            seenCursors.add(cursor);
          }
        } while (cursor !== null);
        return rows;
      });
    },
    logout() {
      return authenticated(async token => {
        const result = await request<{success: boolean}>('/api/v1/auth/logout', {token, method: 'POST'});
        if (result.success) await sessionStore?.clearSession();
        return result;
      });
    },
  };
}
