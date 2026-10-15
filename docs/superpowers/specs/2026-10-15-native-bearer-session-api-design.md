# Native Bearer Authentication on Server-Side Sessions

## Purpose

Prepare the SaaS API for future native Android and iPhone clients without changing the browser application's authentication contract. The web app continues to authenticate with an HTTP-only session cookie and CSRF protection. Native clients authenticate with an opaque bearer credential that resolves to the same server-managed session, tenant membership, permissions, expiry, and revocation state.

This is API groundwork only. It does not build a mobile app, change production configuration, or migrate production data.

## Current State

- PR #136 is merged on `main` as `99386c041a3310c119f96377dbc76274b6447f81`.
- The API is FastAPI and exposes tenant-aware JSON endpoints. Its OpenAPI metadata reports version `1.0.0`; current route paths are under `/api` and are not URL-versioned.
- PostgreSQL authentication resolves the active session, organization membership, company role, and platform-admin status from server-side records. Tenant transactions derive RLS context from that principal.
- Login currently creates an opaque random session token, stores it in `sessions.session_token`, and returns it to the browser as an HTTP-only cookie. The raw token is currently stored in PostgreSQL.
- `get_current_user` accepts the cookie. Many route handlers also read that cookie directly when revalidating writes, recording activity, or identifying the current session.
- State-changing routes use the existing signed CSRF token dependency. The CORS configuration already permits the `Authorization` and `X-CSRF-Token` headers.
- The current SQLite deployment remains supported separately from the PostgreSQL SaaS runtime.

## Goals

1. Keep browser login, cookie behavior, CSRF protection, logout, and existing endpoint response shapes compatible.
2. Add a native login flow that returns a one-time opaque bearer credential and uses the existing server-side session lifecycle.
3. Resolve both cookie and bearer credentials through one authentication and transaction-revalidation path.
4. Hash session credentials at rest in PostgreSQL. Return the raw native credential only at successful native login; never log or include it in URLs or ordinary responses.
5. Preserve tenant isolation: organization and company role continue to come only from the resolved server-side principal, never from client-supplied claims or identifiers.
6. Make authentication schemes and errors explicit in OpenAPI and document the native client contract without starting mobile implementation.

## Non-Goals

- Native Android or iPhone UI, app-store packaging, or mobile-specific business features.
- JWTs, OAuth providers, API keys, stateless authorization claims, or a separate refresh-token system.
- Changing existing `/api` paths or introducing `/api/v1` route aliases in this slice.
- Changing tenant membership rules, role permissions, platform-admin access, or the PostgreSQL tenant model.
- Removing CSRF from browser-cookie requests.
- Changing the legacy SQLite deployment or its existing session storage as part of the SaaS PostgreSQL work.

## Authentication Design

### Web client

The existing login endpoint and response remain unchanged. The server sets the HTTP-only `session_token` cookie with the current secure, same-site, and expiry settings. Cookie-authenticated unsafe requests continue to require `X-CSRF-Token`. Existing web logout and session-management behavior remains supported.

### Native clients

Add a dedicated `POST /api/auth/native/login` endpoint using the existing login request fields and the existing password verification, lockout, rate-limit, and active-account rules. A successful response returns the user summary plus:

```json
{
  "token_type": "Bearer",
  "access_token": "<opaque-random-session-credential>",
  "expires_at": "<UTC ISO 8601 instant>"
}
```

The credential is a high-entropy random secret, not a JWT. The server stores only its SHA-256 hash in the PostgreSQL session record. The client sends it as `Authorization: Bearer <credential>` and stores it only in platform-protected storage (Android Keystore-backed storage or Apple Keychain). Native logout revokes the same server session; the client then deletes its local credential. No access or refresh token is placed in ordinary app preferences.

The native session uses existing configured session durations, including the existing remember-me option. There is no separate refresh endpoint in the first API-auth slice; after expiry, the client signs in again. The raw credential is never returned by session-list or profile endpoints.

### Shared session resolution

Introduce a shared request credential resolver used by `get_current_user`, read transactions, write transactions, activity logging, and current-session comparisons. It accepts either the `session_token` cookie or a syntactically valid Bearer header. If both are present, fail closed with `401` rather than choosing one silently.

All PostgreSQL session checks look up the SHA-256 hash, then verify active status, expiration, archived-account status, and current organization membership using the existing server-side rules. Role, organization ID, and platform-admin status are never accepted from a token or request body. Existing tenant RLS setup remains transaction-local and is based on the resolved principal.

Replace direct route-level cookie reads used for authenticated database work with the shared resolver. This includes the existing transaction-time session revalidation, session activity tracking, session listing/revocation, and audit attribution. A request may not authenticate as one identity and then revalidate or audit as another.

### CSRF and transport selection

- Cookie-authenticated browser mutations retain the current CSRF requirement.
- Authenticated Bearer requests may omit CSRF because the credential is sent explicitly in the `Authorization` header and is not an ambient browser cookie. A CSRF exemption is allowed only after the bearer credential has been validated; merely supplying an `Authorization` header is not enough.
- Login, password-reset, invitation-acceptance, and other unauthenticated state-changing routes do not receive a Bearer-based CSRF exemption.
- Requests that mix a session cookie and Bearer credential fail with `401`, so a bearer header cannot silently turn a cookie-authenticated request into a CSRF-exempt request.

The native login endpoint continues to use the existing login CSRF protection. A native client obtains a CSRF token through the existing no-store CSRF endpoint and sends it on login. This keeps the login-CSRF defense and browser behavior intact.

## PostgreSQL Migration and Secret Handling

Add a new checksummed PostgreSQL migration after version 4; do not edit applied migration files. Move PostgreSQL session lookup to a unique `session_token_hash` (or an equivalently named hash column) and stop persisting raw credentials. The migration must hash existing active session values transactionally so current valid sessions continue to work. It must clear any obsolete raw session credential stored on the PostgreSQL user row and prevent new raw-token writes there.

SHA-256 is suitable because session credentials are generated with high entropy; password hashing algorithms are not used for these random tokens. Keep the hash lookup indexed and unique. If the migration cannot preserve existing sessions safely, stop and produce a reviewed rollout plan rather than silently invalidating accounts.

Do not log `Authorization`, cookie values, raw credentials, or login response bodies. Ensure request and error logging redact these values. Require HTTPS for deployed SaaS endpoints. Keep the current SQLite branch behavior unchanged in this slice; native login is enabled only for the PostgreSQL SaaS runtime.

## OpenAPI and Client Contract

- Add an HTTP Bearer security scheme describing opaque, server-managed session credentials. Document that the credential is not a JWT and that tenant context is inferred server-side.
- Document the native login response and the existing logout/session endpoints for bearer use.
- Document `401` for missing, malformed, expired, inactive, or conflicting credentials; `403` for an authenticated identity without the required company membership or role; and existing validation responses for invalid request bodies.
- Preserve existing paths and schemas used by the web UI. Route versioning remains a separate decision; OpenAPI metadata version `1.0.0` is not treated as a promise that paths are versioned.

## Testing and Acceptance

PostgreSQL integration tests must prove:

1. Browser login still sets the HTTP-only cookie and does not return a bearer credential in JSON.
2. Native login returns one opaque bearer credential, honors the same lockout/rate-limit/session-expiry rules, and never sets or requires a session cookie.
3. A valid bearer credential authenticates the same user and tenant principal as its session record; client-supplied tenant IDs or role claims have no effect.
4. Cookie and bearer credentials use the same transaction-time revalidation. Revoking a session, changing a password, archiving an account, expiring a session, or removing tenant membership prevents subsequent bearer requests.
5. Native bearer requests can perform authorized writes without CSRF, while cookie-authenticated writes still fail without a valid CSRF token. Login and other unauthenticated mutation endpoints remain CSRF-protected.
6. Invalid Bearer credentials cannot bypass CSRF, mixed cookie/Bearer requests fail closed, and platform-admin-only status still does not grant tenant inventory access.
7. Raw credentials are not persisted in PostgreSQL after migration, included in ordinary API responses, URLs, logs, or audit details. Existing active sessions remain usable after the migration.
8. Existing SQLite authentication and CSRF regressions remain unchanged and passing.
9. The OpenAPI document declares the Bearer scheme and accurately documents the native login contract without changing existing web contracts.

Use the existing GitHub Actions PostgreSQL service for integration verification. No local PostgreSQL installation is required.

## Delivery Sequence

1. Review and approve this design.
2. Write and review an implementation plan covering the PostgreSQL token-hash migration, shared credential resolution, native login, bearer-aware CSRF behavior, OpenAPI, and tests.
3. Implement on a fresh branch from merged `main`. Keep the web app and native app source unchanged.
4. Verify against the PostgreSQL CI service and the complete existing Python/JavaScript regression suites.
5. Only after this API/auth contract is merged and documented, begin separate native mobile design and implementation for Android and iPhone.
