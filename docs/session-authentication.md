# Session persistence and Remember me

Login sends the Remember me checkbox as a boolean. The server reads current
Superadmin configuration when creating each session:

| Login choice | Setting | Default |
| --- | --- | --- |
| Unchecked | session_duration_hours | 24 hours |
| Checked | remember_me_duration_days | 30 days |

Both choices create persistent HTTPOnly cookies, with Max-Age matching the database
session lifetime. The cookie uses Secure in production, SameSite=Lax and Path=/.
Unchecked means the shorter configured lifetime; it does not mean browser-close
logout. Changing configuration affects future logins, not existing session expiry.
Sessions have a fixed expiry: normal activity does not extend it.

On startup, the inventory page validates the session cookie through /api/me using
credentials and bypassing the browser cache. Local storage contains only an optional
user display cache; absent, corrupt or unavailable storage cannot block a valid
remembered session or prove that an expired session is valid. Server-returned user
identity replaces stale cached metadata. Login and logout continue to work if user
cache writes fail. Authentication errors remain distinct from inventory load errors.

A startup response that completes after login/logout cannot restore an old identity
or clear a newer login. Session-check failures are visible and can be retried by
reloading. A failed remote logout preserves the signed-in state and displays an
error; confirmed logout revokes the session and removes the cookie. Expiry,
revocation, account archiving and password changes invalidate remembered sessions.

Verification uses disposable databases, real HTTPS test-client cookie/session
flows, and shipped-page JavaScript. Coverage includes configured/default lifetimes,
exact expiry boundaries, invalidation, missing/blocked storage, stale responses,
and logout retry. Live signed-in browser acceptance remains pending while browser
credential protection blocks access.

## Native API clients

The API also supports native Android and iPhone clients on the PostgreSQL SaaS
runtime. Browser authentication remains an HTTP-only `session_token` cookie and
continues to require CSRF tokens for unsafe requests.

Native clients first request a CSRF token from `GET /api/csrf-token`, then send
it with `POST /api/auth/native/login` in `X-CSRF-Token`. Login uses the existing
password verification, account lockout, login rate limit, and configured session
lifetimes. It does not set a session cookie. A successful response has this
shape:

```json
{
  "success": true,
  "token_type": "Bearer",
  "access_token": "<opaque-session-credential>",
  "expires_at": "<UTC ISO 8601 instant>",
  "user": {
    "id": 123,
    "email": "person@example.com",
    "name": "Person",
    "role": "engineer",
    "territory": null
  }
}
```

The credential is a high-entropy opaque session secret, not a JWT. Store it only
in iOS Keychain or Android Keystore-backed secure storage. Send it on authenticated
API requests as `Authorization: Bearer <access_token>`. The credential carries no
tenant or role claims: the server resolves the user's active session, company
membership, permissions, expiry, and revocation state from PostgreSQL.

PostgreSQL stores only the credential's SHA-256 hash. The raw native credential
is returned only in the successful native-login response. It is not returned by
profile or session-list endpoints and is never placed in URLs or logs.

Validated Bearer requests may omit `X-CSRF-Token` on authenticated unsafe
requests because the credential is explicitly sent in the Authorization header.
Cookie-authenticated writes still require CSRF. Login, password reset, and
invitation acceptance remain CSRF-protected. A request carrying both a session
cookie and a Bearer credential is rejected with `401`.

Native logout uses `POST /api/auth/logout` and revokes the same server-side
session; the app should then delete its locally stored credential. Expired
sessions require signing in again. There is no refresh-token endpoint in this
API slice. OpenAPI documents both the browser cookie and opaque Bearer schemes.
Native login is unavailable on the legacy SQLite runtime.
