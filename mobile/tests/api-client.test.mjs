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
        : jsonResponse({success: true, token_type: 'Bearer', access_token: 'opaque-secret', expires_at: '2026-10-16T00:00:00Z', user: {id: 7}});
    },
  });

  await client.login({email: 'member@example.test', password: 'correct horse', rememberMe: true});

  assert.equal(calls[0].url, 'https://inventory.example/api/csrf-token');
  assert.equal(calls[1].url, 'https://inventory.example/api/auth/native/login');
  assert.equal(calls[1].options.headers['X-CSRF-Token'], 'csrf-value');
  assert.deepEqual(JSON.parse(calls[1].options.body), {email: 'member@example.test', password: 'correct horse', remember_me: true});
  assert.equal(calls[0].options.credentials, 'omit');
  assert.equal(calls[1].options.credentials, 'omit');
});

test('authenticated requests send the server session only as a bearer header', async () => {
  const calls = [];
  const client = createApiClient({
    baseUrl: 'https://inventory.example',
    fetchImpl: async (url, options) => { calls.push({url, options}); return jsonResponse([]); },
  });

  await client.getMe('opaque-secret');
  await client.getInventory('opaque-secret');
  await client.logout('opaque-secret');

  assert.deepEqual(calls.map(call => call.url), [
    'https://inventory.example/api/me',
    'https://inventory.example/api/inventory',
    'https://inventory.example/api/auth/logout',
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
    fetchImpl: async () => jsonResponse({detail: 'Invalid credentials'}, 401),
  });

  await assert.rejects(client.login({email: 'member@example.test', password: 'wrong'}), error => {
    assert.ok(error instanceof ApiError);
    assert.equal(error.status, 401);
    assert.equal(error.message, 'Invalid credentials');
    return true;
  });
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
