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

export type NativeLogin = {
  success: true;
  token_type: 'Bearer';
  access_token: string;
  expires_at: string;
  user: NativeUser;
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
};

function safeMessage(payload: unknown, fallback: string): string {
  if (payload && typeof payload === 'object' && 'detail' in payload) {
    const detail = (payload as {detail?: unknown}).detail;
    if (typeof detail === 'string' && detail.trim()) return detail;
  }
  return fallback;
}

export function createApiClient({baseUrl, fetchImpl = fetch}: ApiClientOptions) {
  const root = baseUrl.trim().replace(/\/+$/, '');

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

  return {
    async login({email, password, rememberMe = false}: {email: string; password: string; rememberMe?: boolean}) {
      const {csrf_token: csrfToken} = await request<{csrf_token: string}>('/api/csrf-token');
      if (!csrfToken) throw new ApiError('The server did not provide a security token.', 0);
      const result = await request<NativeLogin>('/api/auth/native/login', {
        method: 'POST',
        body: {email: email.trim(), password, remember_me: rememberMe},
        extraHeaders: {'X-CSRF-Token': csrfToken},
      });
      if (result.token_type !== 'Bearer' || !result.access_token) {
        throw new ApiError('The server returned an invalid session response.', 0);
      }
      return result;
    },
    getMe(token: string) {
      return request<NativeUser>('/api/me', {token});
    },
    getInventory(token: string) {
      return request<InventoryRow[]>('/api/inventory', {token});
    },
    logout(token: string) {
      return request<{success: boolean}>('/api/auth/logout', {token, method: 'POST'});
    },
  };
}

export const api = createApiClient({
  baseUrl: process.env.EXPO_PUBLIC_API_URL || '',
});
