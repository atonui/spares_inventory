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
