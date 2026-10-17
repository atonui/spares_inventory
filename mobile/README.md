# Inventory Management mobile app

The native client is built with Expo and React Native for Android and iOS. The
first slice supports invitation-only sign-in, server-backed session validation,
logout, and tenant-scoped inventory browsing.

## Run locally

```sh
npm install
npx expo start
```

Install Expo Go on a phone and scan the development QR code. For a local or
staging backend, set `EXPO_PUBLIC_API_URL` before starting Expo. It must be an
HTTPS URL. The API URL is deliberately unset by default: the production service
is still on the legacy SQLite runtime, where native login is disabled. Set the
production URL only after the PostgreSQL SaaS cutover is approved and complete.
Use `.env.example` as the starting point; do not commit credentials or real
environment values.

## Session handling

- The client uses the versioned `/api/v1` native API. Login first requests a
  CSRF token, then calls `/api/v1/auth/native/login`.
- The opaque access and refresh credentials are stored together as one value
  with `expo-secure-store`; both are sent only through the appropriate HTTPS
  request (`Authorization: Bearer` for protected calls, refresh token in the
  refresh request body). The app does not use browser cookies.
- On a protected request's `401`, the client rotates the credential pair at
  `/api/v1/auth/native/refresh`, persists the new pair, then retries the
  protected request once. A lost refresh response is retried with the same
  `X-Request-ID` so the server can return its cached rotation response.
- Expired or revoked refresh credentials clear the local session. Transient
  errors keep it available for a retry.
- Startup validates the session through `/api/v1/me`; PostgreSQL remains
  authoritative for tenant membership, expiry, and revocation. Inventory
  loading follows `next_cursor` until all pages are read.
- Logout calls `/api/v1/auth/logout` before clearing local credentials. If the
  server cannot confirm logout, the app keeps the credential pair and reports
  the failure so the user can retry.

## Verify

```sh
npm run test:api
npm run typecheck
npm run lint
npx expo-doctor
```

Store builds use EAS Build profiles in `eas.json`. Store submission still
requires the owner's Apple and Google developer accounts, signing setup, and
final device acceptance.
