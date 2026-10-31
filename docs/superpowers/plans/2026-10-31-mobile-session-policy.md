# Mobile Session Policy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enforce one active mobile session per account and add an organisation-controlled mobile session lifetime capped by platform policy.

**Architecture:** Add migration v19 with organization duration and platform cap defaults, explicitly mark native sessions, and enforce one active native session per account with a partial unique index. Native login and pairing completion lock the user, revoke existing mobile sessions and refresh credentials, and create one session using the effective duration. Organization and platform settings APIs validate limits and shorten existing mobile sessions transactionally; profile and superadmin settings UIs expose the controls.

**Tech Stack:** FastAPI, Pydantic, PostgreSQL/psycopg, existing Alpine.js profile and superadmin pages, pytest and Node regression tests.

**Spec:** `docs/superpowers/specs/2026-10-31-mobile-session-policy-design.md`

## Global Constraints

- Platform maximum defaults to 720 hours and is bounded 1–720.
- Organisation duration defaults to 720 hours and is bounded 1–platform maximum.
- Pairing approval stays required; pairing token expiry remains two minutes. Native password login uses the same one-session and expiry policy.
- Only mobile sessions are revoked or shortened; web sessions remain unaffected.
- Migration history is immutable; add v19 only.

## Review Focus

- Two simultaneous pairing completions for one user: user-row locking serializes revocation and creation; only one mobile session remains active.
- Invalid or stale organisation duration: API returns 400/422 and performs no write.
- Platform cap lowered below configured organisation values: organisation settings and device deadlines are clamped.
- Session deadline passes during refresh: refresh is rejected and session revoked.
- Tenant boundary or non-admin caller: cannot read or change another organisation’s policy.

---

### Task 1: Persist platform and organisation mobile-session policy

**Files:** Create `backend/postgres_migrations/v0019_mobile_session_policy.py`; modify `backend/postgres_migrations/registry.py`; test `regression_tests/test_postgres_migrations.py`.

- [ ] Add migration v19 that adds checked `organization_settings.mobile_session_duration_hours` default 720 and inserts the system setting `mobile_session_max_duration_hours=720`.
- [ ] Register migration and add assertions for the schema and defaults.
- [ ] Run focused migration tests.

### Task 2: Enforce one session and effective expiry

**Files:** Modify `backend/routes/auth.py`; add/update `regression_tests/test_mobile_session_policy.py`.

- [ ] Add PostgreSQL-backed tests proving native login and completed pairing replace a prior mobile session and refresh credential while leaving web sessions active.
- [ ] Prove the new session expiry uses organisation duration and the platform cap.
- [ ] Implement account-row locked replacement for both native login paths, plus a database uniqueness guard.
- [ ] Run focused pairing/session tests.

### Task 3: Add admin APIs and immediate policy changes

**Files:** Modify `backend/routes/organization_settings.py`, `backend/routes/platform_settings.py`, `backend/schemas/organization_settings.py`; test `regression_tests/test_tenant_organization_settings.py`, `regression_tests/test_platform_settings.py`.

- [ ] Add tests for admin-only reads/writes, revision conflicts, cap validation, and clamping existing mobile sessions.
- [ ] Add organisation setting API with integer-hour validation and platform cap enforcement.
- [ ] Add platform max to supported security config and clamp organisation policy plus active mobile-session expiry when reduced.
- [ ] Run focused API tests.

### Task 4: Surface the controls

**Files:** Modify `static/profile.html`, `static/js/pages/profile.js`, `static/profile.css`, generated minified CSS if required; modify `static/js/pages/superadmin.js`, `static/superadmin.html`; update relevant UI regression tests.

- [ ] Add organisation-admin duration control with current maximum, save/loading/error/conflict states.
- [ ] Add platform max duration to the existing security configuration panel.
- [ ] Add UI tests proving controls are visible to eligible roles and send the expected API requests.
- [ ] Run frontend regression checks and CSS asset check.

### Task 5: Verify and publish

- [ ] Run focused pytest tests, full backend regression suite, frontend CJS suite, Python compilation, and `git diff --check`.
- [ ] Review migration RLS/grants and sensitive session handling.
- [ ] Commit changes and open a PR targeting `main`; do not deploy or merge.
