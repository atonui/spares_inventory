import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createApiClient, ApiError} from '../src/api/client.ts';

function jsonResponse(data, status = 200) {
  return {ok: status >= 200 && status < 300, status, json: async () => data};
}

test('native login obtains a CSRF token before sending credentials', async () => {
  const calls = [];
  const client = createApiClient({
    baseUrl: 'https://inventory.example/',
    fetchImpl: async (url, options) => {
      calls.push({url, options});
      return calls.length === 1
        ? jsonResponse({csrf_token: 'csrf-value'})
        : jsonResponse({success: true, token_type: 'Bearer', access_token: 'opaque-secret', refresh_token: 'refresh-secret', expires_at: '2026-10-16T00:00:00Z', user: {id: 7}});
    },
  });

  const session = await client.login({email: 'member@example.test', password: 'correct horse', rememberMe: true});

  assert.equal(calls[0].url, 'https://inventory.example/api/v1/csrf-token');
  assert.equal(calls[1].url, 'https://inventory.example/api/v1/auth/native/login');
  assert.equal(calls[1].options.headers['X-CSRF-Token'], 'csrf-value');
  assert.deepEqual(JSON.parse(calls[1].options.body), {email: 'member@example.test', password: 'correct horse', remember_me: true});
  assert.equal(calls[0].options.credentials, 'omit');
  assert.equal(calls[1].options.credentials, 'omit');
  assert.equal(session.refresh_token, 'refresh-secret');
});

test('authenticated requests send the server session only as a bearer header', async () => {
  const calls = [];
  const session = {access_token: 'opaque-secret', refresh_token: 'refresh-secret', expires_at: '2026-10-17T00:15:00Z'};
  const client = createApiClient({
    baseUrl: 'https://inventory.example',
    sessionStore: {
      async getSession() { return session; },
      async setSession() {},
      async clearSession() {},
    },
    fetchImpl: async (url, options) => {
      calls.push({url, options});
      if (url.includes('/inventory')) return jsonResponse({items: [], page: {limit: 50, next_cursor: null}});
      return jsonResponse({success: true});
    },
  });

  await client.getMe();
  await client.getInventory();
  await client.logout();

  assert.deepEqual(calls.map(call => call.url), [
    'https://inventory.example/api/v1/me',
    'https://inventory.example/api/v1/inventory?limit=50',
    'https://inventory.example/api/v1/auth/logout',
  ]);
  for (const call of calls) {
    assert.equal(call.options.headers.Authorization, 'Bearer opaque-secret');
    assert.equal(call.options.credentials, 'omit');
  }
  assert.equal(calls[2].options.method, 'POST');
});

test('API failures retain status and a safe server message', async () => {
  const client = createApiClient({
    baseUrl: 'https://inventory.example',
    fetchImpl: async () => jsonResponse({error: {status: 401, code: 'unauthenticated', detail: 'Invalid credentials', request_id: 'req_1'}}, 401),
  });

  await assert.rejects(client.login({email: 'member@example.test', password: 'wrong'}), error => {
    assert.ok(error instanceof ApiError);
    assert.equal(error.status, 401);
    assert.equal(error.message, 'Invalid credentials');
    return true;
  });
});

test('native refresh sends the refresh credential and a stable request ID', async () => {
  const calls = [];
  const client = createApiClient({
    baseUrl: 'https://inventory.example',
    requestIdFactory: () => 'refresh_attempt_1',
    fetchImpl: async (url, options) => {
      calls.push({url, options});
      return jsonResponse({success: true, token_type: 'Bearer', access_token: 'access-2', refresh_token: 'refresh-2', expires_at: '2026-10-17T00:15:00Z'});
    },
  });

  const refreshed = await client.refresh('refresh-1');

  assert.equal(calls[0].url, 'https://inventory.example/api/v1/auth/native/refresh');
  assert.equal(calls[0].options.headers['X-Request-ID'], 'refresh_attempt_1');
  assert.equal(calls[0].options.credentials, 'omit');
  assert.deepEqual(JSON.parse(calls[0].options.body), {refresh_token: 'refresh-1'});
  assert.equal(refreshed.access_token, 'access-2');
  assert.equal(refreshed.refresh_token, 'refresh-2');
});

test('native refresh retries a lost response with the same request ID', async () => {
  const requestIds = [];
  let attempts = 0;
  const client = createApiClient({
    baseUrl: 'https://inventory.example',
    requestIdFactory: () => 'same_refresh_attempt',
    fetchImpl: async (_url, options) => {
      attempts += 1;
      requestIds.push(options.headers['X-Request-ID']);
      if (attempts === 1) throw new TypeError('Network response was lost');
      return jsonResponse({success: true, token_type: 'Bearer', access_token: 'access-2', refresh_token: 'refresh-2', expires_at: '2026-10-17T00:15:00Z'});
    },
  });

  await client.refresh('refresh-1');

  assert.equal(attempts, 2);
  assert.deepEqual(requestIds, ['same_refresh_attempt', 'same_refresh_attempt']);
});

test('native refresh rejects incomplete rotated credentials', async () => {
  const client = createApiClient({
    baseUrl: 'https://inventory.example',
    fetchImpl: async () => jsonResponse({success: true, token_type: 'Bearer', access_token: 'access-2'}),
  });

  await assert.rejects(client.refresh('refresh-1'), error => {
    assert.ok(error instanceof ApiError);
    assert.equal(error.status, 0);
    assert.match(error.message, /invalid session response/i);
    return true;
  });
});

test('inventory follows opaque next cursors until the final page', async () => {
  const calls = [];
  const client = createApiClient({
    baseUrl: 'https://inventory.example',
    sessionStore: {
      async getSession() { return {access_token: 'access-1', refresh_token: 'refresh-1', expires_at: '2026-10-17T00:15:00Z'}; },
      async setSession() {},
      async clearSession() {},
    },
    fetchImpl: async (url, options) => {
      calls.push({url, options});
      return calls.length === 1
        ? jsonResponse({items: [{id: 1}], page: {limit: 50, next_cursor: 'opaque / cursor'}})
        : jsonResponse({items: [{id: 2}], page: {limit: 50, next_cursor: null}});
    },
  });

  const rows = await client.getInventory();

  assert.deepEqual(rows.map(row => row.id), [1, 2]);
  assert.match(calls[0].url, /^https:\/\/inventory\.example\/api\/v1\/inventory\?/);
  assert.match(calls[1].url, /cursor=opaque%20%2F%20cursor/);
  assert.equal(calls[1].options.headers.Authorization, 'Bearer access-1');
});

test('a 401 rotates and securely persists the session pair before retrying once', async () => {
  const calls = [];
  let savedSession = {access_token: 'access-1', refresh_token: 'refresh-1', expires_at: '2026-10-17T00:00:00Z'};
  const sessionStore = {
    async getSession() { return savedSession; },
    async setSession(session) { savedSession = session; },
    async clearSession() { savedSession = null; },
  };
  const client = createApiClient({
    baseUrl: 'https://inventory.example',
    sessionStore,
    requestIdFactory: () => 'attempt_one',
    fetchImpl: async (url, options) => {
      calls.push({url, options});
      if (url.endsWith('/me') && options.headers.Authorization === 'Bearer access-1') {
        return jsonResponse({error: {status: 401, code: 'unauthenticated', detail: 'Expired', request_id: 'req_1'}}, 401);
      }
      if (url.endsWith('/auth/native/refresh')) {
        return jsonResponse({success: true, token_type: 'Bearer', access_token: 'access-2', refresh_token: 'refresh-2', expires_at: '2026-10-17T00:15:00Z'});
      }
      return jsonResponse({id: 7, email: 'member@example.test', name: 'Member', role: 'manager', territory: null});
    },
  });

  const user = await client.getMe();

  assert.equal(user.id, 7);
  assert.deepEqual(savedSession, {access_token: 'access-2', refresh_token: 'refresh-2', expires_at: '2026-10-17T00:15:00Z'});
  assert.deepEqual(calls.map(call => call.url.split('/api/v1')[1]), [
    '/me', '/auth/native/refresh', '/me',
  ]);
  assert.equal(calls[1].options.headers['X-Request-ID'], 'attempt_one');
  assert.equal(calls[2].options.headers.Authorization, 'Bearer access-2');
});

test('saving a login stores only the credential pair and expiry', async () => {
  let savedSession;
  const client = createApiClient({
    baseUrl: 'https://inventory.example',
    sessionStore: {
      async getSession() { return savedSession ?? null; },
      async setSession(session) { savedSession = session; },
      async clearSession() { savedSession = null; },
    },
  });

  await client.saveSession({
    success: true,
    token_type: 'Bearer',
    access_token: 'access-1',
    refresh_token: 'refresh-1',
    expires_at: '2026-10-17T00:15:00Z',
    user: {id: 7, email: 'member@example.test', name: 'Member', role: 'manager', territory: null},
  });

  assert.deepEqual(savedSession, {
    access_token: 'access-1',
    refresh_token: 'refresh-1',
    expires_at: '2026-10-17T00:15:00Z',
  });
});

test('concurrent 401 responses share one refresh rotation', async () => {
  let savedSession = {access_token: 'access-1', refresh_token: 'refresh-1', expires_at: '2026-10-17T00:00:00Z'};
  let refreshCount = 0;
  const client = createApiClient({
    baseUrl: 'https://inventory.example',
    sessionStore: {
      async getSession() { return savedSession; },
      async setSession(session) { savedSession = session; },
      async clearSession() { savedSession = null; },
    },
    fetchImpl: async (url, options) => {
      if (url.endsWith('/me') && options.headers.Authorization === 'Bearer access-1') {
        return jsonResponse({error: {status: 401, code: 'unauthenticated', detail: 'Expired', request_id: 'req_1'}}, 401);
      }
      if (url.endsWith('/auth/native/refresh')) {
        refreshCount += 1;
        await new Promise(resolve => setTimeout(resolve, 5));
        return jsonResponse({success: true, token_type: 'Bearer', access_token: 'access-2', refresh_token: 'refresh-2', expires_at: '2026-10-17T00:15:00Z'});
      }
      return jsonResponse({id: 7, email: 'member@example.test', name: 'Member', role: 'manager', territory: null});
    },
  });

  await Promise.all([client.getMe(), client.getMe()]);

  assert.equal(refreshCount, 1);
  assert.equal(savedSession.refresh_token, 'refresh-2');
});

test('an invalid refresh credential clears the stored pair', async () => {
  let savedSession = {access_token: 'access-1', refresh_token: 'refresh-1', expires_at: '2026-10-17T00:00:00Z'};
  const client = createApiClient({
    baseUrl: 'https://inventory.example',
    sessionStore: {
      async getSession() { return savedSession; },
      async setSession(session) { savedSession = session; },
      async clearSession() { savedSession = null; },
    },
    fetchImpl: async (url, options) => url.endsWith('/me')
      ? jsonResponse({error: {status: 401, code: 'unauthenticated', detail: 'Expired', request_id: 'req_1'}}, 401)
      : jsonResponse({error: {status: 401, code: 'unauthenticated', detail: 'Invalid refresh', request_id: 'req_2'}}, 401),
  });

  await assert.rejects(client.getMe(), error => error instanceof ApiError && error.status === 401);
  assert.equal(savedSession, null);
});

test('a transient refresh service failure preserves the stored pair for retry', async () => {
  const savedSession = {access_token: 'access-1', refresh_token: 'refresh-1', expires_at: '2026-10-17T00:00:00Z'};
  const client = createApiClient({
    baseUrl: 'https://inventory.example',
    sessionStore: {
      async getSession() { return savedSession; },
      async setSession() {},
      async clearSession() { throw new Error('must retain credentials on a transient failure'); },
    },
    fetchImpl: async url => url.endsWith('/me')
      ? jsonResponse({error: {status: 401, code: 'unauthenticated', detail: 'Expired', request_id: 'req_1'}}, 401)
      : jsonResponse({error: {status: 503, code: 'service_unavailable', detail: 'Try again', request_id: 'req_2'}}, 503),
  });

  await assert.rejects(client.getMe(), error => error instanceof ApiError && error.status === 503);
  assert.equal(savedSession.refresh_token, 'refresh-1');
});

test('a failed explicit logout keeps the stored pair for retry', async () => {
  const savedSession = {access_token: 'access-1', refresh_token: 'refresh-1', expires_at: '2026-10-17T00:15:00Z'};
  const client = createApiClient({
    baseUrl: 'https://inventory.example',
    sessionStore: {
      async getSession() { return savedSession; },
      async setSession() {},
      async clearSession() { throw new Error('must not clear on server failure'); },
    },
    fetchImpl: async () => jsonResponse({error: {status: 503, code: 'service_unavailable', detail: 'Try again', request_id: 'req_1'}}, 503),
  });

  await assert.rejects(client.logout(), error => error instanceof ApiError && error.status === 503);
});

test('an unconfigured server URL fails closed before sending credentials', async () => {
  let requested = false;
  const client = createApiClient({baseUrl: '', fetchImpl: async () => { requested = true; return jsonResponse({}); }});

  await assert.rejects(client.login({email: 'member@example.test', password: 'secret'}), error => {
    assert.ok(error instanceof ApiError);
    assert.equal(error.status, 0);
    assert.match(error.message, /HTTPS URL/);
    return true;
  });
  assert.equal(requested, false);
});
