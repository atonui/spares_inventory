# Mobile Session Security Policy

## Intent

Give each Spares Tracker account exactly one active native mobile session and let company administrators set its absolute lifetime. Platform superadmins set the upper limit for all organisations.

## Goals

- A completed pairing or native mobile login revokes any earlier active mobile session for that user, including its refresh credentials.
- The mobile session lifetime is read from the user’s organisation setting; platform administrators control the maximum allowed value.
- Organisation administrators can view and change the duration in Account settings. Values are integer hours from 1 through the current platform maximum.
- Shortening an organisation’s duration immediately clamps or revokes its existing mobile session(s); web sessions are unaffected.
- All pairing, refresh, and setting changes remain server-enforced and auditable.

## Non-goals

- Changing web login or remember-me session policy.
- Supporting multiple phones or a device-count exception.
- Changing the mobile app authentication protocol or introducing JWTs.

## Approaches considered

1. Mark native sessions explicitly, serialize all native login and pairing replacements on the account row, and enforce one active native session with a PostgreSQL partial unique index. Keep duration in organization settings. This reuses the existing session and refresh credential tables; it is the selected approach.
2. Add a separate mobile-session table and credential protocol. This duplicates the existing session authority and is rejected.
3. Enforce one session only in the app. This cannot prevent concurrent credentials or API calls and is rejected.

## Policy

- Platform key `mobile_session_max_duration_hours` defaults to 720 hours (30 days), bounded 1–720.
- Organisation setting `mobile_session_duration_hours` defaults to 720 hours and must be between 1 and the platform maximum.
- Pairing and native login create an absolute expiry from the effective organization duration. The account-row lock serializes both entry points; prior native sessions and their refresh credentials are revoked atomically. Browser sessions remain active.
- When the organization shortens the duration, existing mobile sessions are clamped to `created_at + new duration`; expired sessions and refresh credentials are revoked immediately.
- Reducing the platform maximum clamps organisation settings and active mobile session deadlines to the new maximum.

## Constraints

- PostgreSQL schema changes are append-only and registered as migration v19.
- Existing two-minute one-time pairing credentials and desktop approval remain unchanged.
- Never expose raw session credentials in settings or paired-device responses.
