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

- Native login requests a CSRF token, then calls `/api/auth/native/login`.
- The opaque bearer credential is stored with `expo-secure-store` and sent only
  in the `Authorization` header. The app does not use browser cookies.
- Startup validates the stored session through `/api/me`; PostgreSQL remains
  authoritative for tenant membership, expiry, and revocation.
- Logout calls `/api/auth/logout` before deleting the local credential. If the
  server cannot confirm logout, the app keeps the credential and reports the
  failure so the user can retry.

## Verify

```sh
npm run test:api
npm run typecheck
npx expo-doctor
```

Store builds use EAS Build profiles in `eas.json`. Store submission still
requires the owner's Apple and Google developer accounts, signing setup, and
final device acceptance.
