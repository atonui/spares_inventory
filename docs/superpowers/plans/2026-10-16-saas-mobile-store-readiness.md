# SaaS Mobile and Store Readiness Plan

**Status:** Planning addendum. The SaaS backend milestones through native bearer authentication are merged. Store readiness is not complete. Keep the approved SaaS sequence; use these checks as acceptance gates for the native iOS and Android clients.

**Goal:** Make the existing invitation-only SaaS API safe and predictable for native clients, then prepare a reviewable iOS and Android release without weakening tenant or production security.

**Current native client:** `mobile/` contains an Expo/React Native starter with invitation-only sign-in, session validation, logout, and inventory browsing. It uses `expo-secure-store`. It currently needs a new login after session expiry; it is not store-ready.

## Merged SaaS Sequence and Native Readiness Gaps

| SaaS milestone (preserve this order) | Merged baseline | Native client check / remaining gap |
| --- | --- | --- |
| PostgreSQL tenant foundation — PR #135 (foundation work began in #134) | PostgreSQL schema, tenant context, and RLS are in the repository. | Keep tenant identity derived from the authenticated server-side principal. Native requests must not choose a company by sending a tenant ID. Add cross-tenant contract tests for every native API resource. |
| Tenant-scoped users, invitations, organization settings, and platform-admin separation — PR #136 | Invitation-only onboarding and separated company/platform operations are implemented. | Document which tenant-scoped operations are available to each company role. Specify stable errors and prevent platform-admin privileges from becoming implicit tenant access. Define member departure and account/tenant deletion behavior before adding deletion actions. |
| SQLite importer and operational runbook — PR #136 | Import tooling and cutover/operations documentation are present. | Add a separate synthetic review environment and reproducible demo seed/reset procedure. The reviewer account must use ordinary authentication and tenant authorization; never add a production bypass or use production customer data. |
| Native bearer session API — PRs #137 and #138 | Native login issues opaque credentials backed by server-side PostgreSQL sessions; session credentials are hash-stored and revocable. The browser keeps cookie + CSRF auth. | There is no refresh endpoint: the client signs in again after expiry. OpenAPI metadata says `1.0.0`, but the route paths are unversioned `/api/...`; that metadata alone is not a versioned contract. No shared error or pagination contract is defined for native clients. |
| Native client and store release — existing starter in `mobile/` | Sign-in, `/api/me` session validation, logout, and inventory browsing exist. | Do not expand the client surface or submit to stores until the API, renewal, deletion, privacy, payment, and reviewer-access gates below are complete. |

## Required Follow-on Gates

### Gate 1 — Versioned Native API Contract

- [ ] Adopt a URL-versioned native surface, recommended as `/api/v1`, while preserving current web paths during migration. Reuse the same authorization and business services; do not fork tenant rules between web and native handlers.
- [ ] Publish and maintain OpenAPI for the versioned surface, including request/response examples, authentication, authorization, rate limits, and deprecation/compatibility rules. Treat the contract version separately from the app package version.
- [ ] Define a stable error envelope with HTTP status, machine-readable `code`, safe user-facing `detail`, and a request/correlation ID. Cover authentication, authorization, validation, conflict, rate limiting, and server errors. Keep secrets and sensitive tenant data out of errors.
- [ ] Define bounded pagination for list endpoints (default and maximum page size, stable ordering, continuation behavior, and optional totals only where needed). Document which collection endpoints are paginated and how clients recover from expired cursors.
- [ ] State that tenant scope comes only from the authenticated server-side membership and transaction-local RLS context. Ignore or reject client-supplied tenant IDs on ordinary company routes. Define explicit platform-admin routes separately.
- [ ] Add contract tests for versioned paths, errors, pagination, role checks, tenant isolation, and backwards compatibility with the current web client. Generate the OpenAPI document in CI and fail on unreviewed breaking changes.

### Gate 2 — Native Session Renewal and Revocation

- [ ] Record a reviewed session design before implementation. Recommended design: short-lived opaque access credentials plus longer-lived, single-use rotating refresh credentials, both bound to a server-side session family and stored only as hashes server-side.
- [ ] Rotate refresh credentials atomically. Detect reuse of an already-rotated credential and revoke the associated session family. Define absolute and idle expiry, refresh rate limits, device/session listing, and behavior when the device clock is wrong.
- [ ] Keep the refresh credential in iOS Keychain / Android Keystore-backed storage through the platform secure-storage library; keep access credentials in memory where practical. Never place credentials in ordinary preferences, analytics, crash reports, URLs, or logs.
- [ ] Make logout and server-side revocation invalidate subsequent API calls. Revoke sessions on password reset/change, account deletion, membership removal, company suspension/deletion, administrator force-logout, and detected refresh-token reuse. Test each path against the same session authority.
- [ ] Preserve browser cookie + CSRF behavior. A native bearer header must not create a CSRF exemption for cookie-authenticated or unauthenticated requests.
- [ ] Add PostgreSQL integration tests for rotation, concurrent refresh, replay, expiry, logout, force logout, and tenant membership changes; add iOS and Android client tests for secure persistence and renewal failure recovery.

### Gate 3 — Member Departure, Account Deletion, and Tenant Deletion

- [ ] Write the product/data-retention rules before adding UI or endpoints. The three actions must be distinct:
  - **Leave/remove a company member:** remove that person's membership and revoke their sessions; retain the company's tenant data. Since v1 permits one company per account, define whether the person may retain a non-member identity and how they can be invited again. Require ownership transfer before an owner leaves.
  - **Delete a user's account:** provide a clearly labeled, confirmed in-app action and a public web deletion-request page for people who cannot sign in. Verify control of the account before acting. Delete or anonymize personal data according to the approved retention rules while preserving only records that must be retained, with those exceptions disclosed.
  - **Delete a company/tenant:** a separate owner-authorized request that affects the organization's data and members, not a side effect of one user's account deletion. Require reauthentication, explain impact, provide an export opportunity and a defined cancellation/grace period, then revoke all tenant sessions and apply documented deletion, backup-retention, and legal-hold rules.
- [ ] Define the last-owner and active-invitation behavior, confirmation wording, audit trail, support escalation, deletion completion notification, and request status tracking.
- [ ] Implement the authenticated in-app account action and public request page/API. The public page must not disclose whether an email or company exists and must not delete data based on an unverified request.
- [ ] Test member removal, self-deletion, owner transfer, whole-tenant deletion, failed verification, duplicate requests, and cross-tenant attempts. Confirm account deletion never silently deletes the tenant.

### Gate 4 — Privacy and Secure Data Handling

- [ ] Inventory personal, company, and operational data collected by the API and app, including fields in inventory/work orders, invitation data, audit logs, telemetry, crash reports, analytics, and every third-party SDK. Record purpose, retention, processors, and deletion behavior.
- [ ] Publish a reachable privacy policy and support contact before store submission. Keep it consistent with actual server and client behavior, not just planned behavior.
- [ ] Complete Apple App Privacy disclosures and Google Play Data safety declarations from the verified inventory, including data handled by SDKs. Recheck declarations whenever dependencies or collection behavior changes.
- [ ] Keep native permissions minimal. The current starter declares no camera, location, contacts, microphone, or photo-library permissions; add a permission only when a shipped feature requires it, request it at the point of use, explain the reason, and test denial paths.
- [ ] Require HTTPS; keep bearer/refresh credentials in platform secure storage; keep server secrets out of app bundles; redact credentials and sensitive user/company data from logs; verify access controls for backups, analytics, crash reports, and support tooling.
- [ ] Add a release checklist that compares the final binary's SDKs and permission declarations with the privacy policy and both stores' disclosures.

### Gate 5 — Subscription and Payment Decision

- [ ] Before any paywall, checkout, subscription-management, or purchase flow is designed, record the business decision: who pays (company or individual), what is sold, billing cadence, trial/cancellation/refund rules, and whether the mobile app is a login-only companion or sells digital subscriptions.
- [ ] For the chosen model and each target storefront/region, verify current Apple and Google payment rules, including any applicable business/enterprise service treatment, external-purchase options, and required store billing. Record links and review date with the decision.
- [ ] Keep purchase UI and payment SDKs out of the native app until this decision and the applicable store policy review are approved. If the initial app is a companion, document how users learn about access without adding an unreviewed payment workaround.

### Gate 6 — Isolated App Review Demo

- [ ] Provision a dedicated review/staging environment with a separate database, storage, credentials, mail configuration, and monitoring from production. Use synthetic data only and disable external side effects such as real customer email.
- [ ] Seed one demo company and a least-privileged reviewer account that can exercise the app's reviewable features through the normal invitation-only login and tenant authorization flow. Do not grant platform-admin access unless a separately reviewed platform-admin app feature requires it.
- [ ] Make the seed/reset command refuse production configuration. Add tests that prove the demo company, reviewer credentials, and sample records cannot be created in or connected to the production database.
- [ ] Put reviewer sign-in steps and credentials only in the stores' private review/access fields or approved secret-management workflow, never in source control, app binaries, public docs, or customer production data. Keep access valid during review and rotate it afterward.
- [ ] Document the seed/reset owner, reset cadence, test-data content, credentials rotation, environment health check, and reviewer support contact in the operational runbook.

### Gate 7 — Store Submission and Device Acceptance

- [ ] Complete iOS and Android release builds with production API configuration, signing, privacy links, account-deletion link, reviewer access instructions, screenshots, support contact, and accurate store metadata.
- [ ] Test invitation-only sign-in, refresh/revocation, tenant isolation, account deletion, user departure, and empty/error/offline states on supported physical iOS and Android devices and OS versions.
- [ ] Verify store-specific accessibility, layout, system back behavior, network failure handling, and secure logout. Do not submit until the isolated reviewer account and demo tenant have been smoke-tested on both platforms.
- [ ] Recheck the official store policies below at submission time; policies and exceptions can change.

## Readiness Rule

The API/mobile foundation is ready for broader native feature work when Gates 1 and 2 pass. A store submission additionally requires Gates 3 through 7. The SaaS remains invitation-only; review access is isolated to synthetic data and cannot bypass production authentication or tenant isolation.

## Official Store Guidance (reviewed 2026-10-16)

- Apple account deletion: <https://developer.apple.com/help/app-review/guideline-reference/5-1-1-account-deletion/>
- Apple App Review information: <https://developer.apple.com/help/app-store-connect/manage-submissions-to-app-review/overview-of-submitting-for-review/>
- Apple privacy and data use: <https://developer.apple.com/app-store/user-privacy-and-data-use/>
- Apple App Store Review Guidelines: <https://developer.apple.com/app-store/review/guidelines/>
- Google Play account deletion: <https://support.google.com/googleplay/android-developer/answer/13327111>
- Google Play review access and declarations: <https://support.google.com/googleplay/android-developer/answer/9859455>
- Google Play Data safety: <https://support.google.com/googleplay/android-developer/answer/10787469>
- Google Play Payments policy: <https://support.google.com/googleplay/android-developer/answer/10281818>
- Google Play billing system: <https://support.google.com/googleplay/android-developer/answer/1072599>
