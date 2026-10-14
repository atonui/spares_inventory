# Announcement Controls Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking. Preserve the established native implementation workflow, with one fresh final whole-branch reviewer.

**Goal:** Give the single announcement role audiences, scheduling, expiry and optional dismissal.

**Architecture:** Keep the existing single JSON notice, add a focused announcement service and a dismissal-table migration. Separate privileged management metadata from audience-filtered banner reads; extend the shared banner and superadmin editor without modifying unrelated inventory features.

**Tech Stack:** FastAPI, SQLite explicit migrations, classic JavaScript/AlpineJS and existing UTC/IANA timezone utilities; no new dependencies.

**Spec:** `docs/superpowers/specs/2026-10-14-announcement-controls-design.md` (approved).

## Global Constraints

- One saved announcement; no multiple notices, store targeting or per-user targeting.
- Audiences: everyone, authenticated, roles; exact roles engineer, manager, admin, superadmin.
- Existing notices remain public, immediate, without expiry and non-dismissible.
- Start inclusive, expiry exclusive; UTC storage, organisation-local editor inputs.
- Reject DST gaps/folds and changed organisation-timezone revisions.
- Every save creates a new opaque revision and resets dismissals.
- Protected writes retain current-session revalidation, superadmin checks and CSRF.
- Anonymous dismissal is browser-local; authenticated dismissal is per account across devices.
- No production setting/broadcast writes during tests; do not circumvent browser restrictions.

## Review Focus

1. A revoked session or changed role must not obtain restricted text from a cached response (Task 2).
2. A timezone change or DST transition must not silently move a scheduled notice (Task 2).
3. A delayed response or account switch must not restore dismissed/expired/ineligible text (Task 4).
4. An older backup must upgrade correctly; v1–v5 migration checksums stay unchanged (Task 1).
5. Two superadmin tabs must not silently overwrite each other's notice or lose drafts (Task 3).

## Interface and file map

Create `backend/services/announcements.py` for notice normalization, scheduling,
eligibility and persistence. Keep HTTP wiring in `backend/routes/superadmin.py` and
request validation in `backend/schemas/superadmin.py`. Create migration
`backend/migrations/v0006_announcement_dismissals.py`; update the registry and
version-aware validation, never existing migration files.

Extend `static/js/pages/superadmin.js` and `static/superadmin.html` for controls.
Extend `static/js/shared/announcements.js`, all five banner snippets and
`static/announcements.css` for dismissal/expiry/error states. Add
`static/js/shared/announcement-time.js` only to superadmin for formatting UTC
instants as organisation-local datetime inputs. Update actual script-manifest
expectations and asset versions in the same commit as each new dependency.

### Task 1: Dismissal storage and backward-compatible notice model

**Files:** new migration/service; `backend/migrations/registry.py`,
`backend/migrations/validation.py`, `backend/temporal_manifest.py`;
`regression_tests/test_announcement_service.py`, migration/restore/temporal tests.

**Interfaces:**
- `normalize_notice(payload: dict | None) -> dict | None`: legacy defaults and stable legacy revision; normalized keys revision, message, level, set_at, audience, roles, starts_at, expires_at, dismissible.
- `load_notice(conn) -> dict | None`: current JSON record, no auth or commit ownership.
- `save_notice(conn, notice: dict, *, actor_id: int, expected_revision: str | None) -> dict`: conflict 409 on mismatch; creates UUID revision and clears obsolete dismissals.
- `remove_notice(conn, *, expected_revision: str) -> None`: revision-aware delete/cleanup.
- `dismiss_notice(conn, *, user_id: int, revision: str, now) -> None`: idempotent current-revision dismissal; caller owns authentication/eligibility checks and transaction.

- [x] Write service/migration tests: `test_legacy_notice_defaults_are_stable` asserts public/immediate/no-expiry/non-dismissible and a stable revision; `test_save_revision_resets_dismissals` asserts new revision and no stale rows; `test_migration_v6_idempotent` asserts unique `(user_id, revision)` and user FK; `test_old_backup_upgrades_without_changing_notice` asserts existing payload/stock rows survive.
- [x] Run `python -m pytest regression_tests/test_announcement_service.py regression_tests/test_database_migrations.py regression_tests/test_database_restore.py -q`; observe failures for missing v6/service.
- [x] Implement the table `(user_id INTEGER NOT NULL REFERENCES users(id), revision TEXT NOT NULL, dismissed_at TEXT NOT NULL, PRIMARY KEY(user_id,revision))` and v6 validation. Extend schema reference/unknown-object checks with version awareness so earlier migration validation accepts the additive table while v6 requires it. Register dismissal timestamps and optional schedule JSON instants for current temporal validation without changing v5 checksums.
- [x] Implement normalization and borrowed-connection service functions; retain missing-record behavior and reject corrupt saved restricted metadata rather than defaulting it to public.
- [x] Rerun focused tests; update exact latest-version assertions from 5 to 6 where appropriate, preserving legacy migration evidence. Commit the storage/model boundary.

### Task 2: Audience filtering, schedule conversion and protected dismissal API

**Files:** announcement service, superadmin routes/schemas;
`regression_tests/test_announcement_api.py`, `test_announcement_schedule.py`,
`test_superadmin_router.py`, `test_session_write_routes.py`, `test_sitewide_csrf.py`.

**Interfaces:**
- `resolve_local_instant(value: str | None, *, zone: str) -> datetime | None`: strict ISO local datetime, unique UTC round-trip across both folds; reject gaps or multiple distinct instants.
- `notice_status(notice, *, now) -> str`: scheduled/active/expired using inclusive start/exclusive expiry.
- `eligible_notice(conn, notice, *, viewer, now) -> dict | None`: current role, schedule and account dismissal.
- `GET /api/superadmin/announcement`: `{announcement: filtered_notice_or_null, dismissal_mode: 'account'|'browser'}`; no-store on success and errors, never restricted metadata when denied.
- `GET /api/superadmin/announcement/manage`: superadmin-only `{announcement: saved_notice_or_null, status, business_timezone, timezone_revision}`.
- Save body retains message/level, adds `audience`, `roles`, `starts_local`, `expires_local`, `timezone_revision`, `dismissible`, `expected_revision`. Default audience everyone/empty roles/no schedule/non-dismissible; expected revision null only when no saved notice exists. API values use the same names throughout tests/editor.
- `DELETE /api/superadmin/announcement?expected_revision=...`: protected revision-aware removal.
- `POST /api/superadmin/announcement/dismiss` body `{revision}`: authenticated CSRF write, eligibility/dismissibility/revision checked under the writer lock.

- [x] Write table-driven HTTP tests for anonymous plus all four roles against every audience, role changes, expired/revoked/archived accounts, public fallback only for authentication 401, no restricted text in denied responses and no-store headers. Add stale revision 409, CSRF, revoked-after-initial-auth and cross-account dismissal tests.
- [x] Write schedule tests for exact start/expiry, blank start, no expiry, invalid expiry ordering/already-expired save, timezone revision 409, Nairobi conversion, New York gap `2026-03-08T02:30` and fold `2026-11-01T01:30` rejection.
- [x] Run `python -m pytest regression_tests/test_announcement_api.py regression_tests/test_announcement_schedule.py -q`; observe missing-interface/behavior failures.
- [x] Implement optional banner-session resolution using the existing session validator on a borrowed transaction and current DB role; catch only authentication 401 for anonymous fallback. Propagate DB/infrastructure errors. Add protected management read; save resolves the organisation context and canonical UTC times; reject malformed audiences/roles and stale expected revisions.
- [x] Implement dismissal under authenticated transaction; non-dismissible/ineligible requests fail 403, stale revisions fail 409 and repeats succeed. Reads omit dismissed notices; management read ignores dismissal.
- [x] Rerun API/service/session/CSRF tests and update intentional old OpenAPI/schema/public-read expectations. Commit the server boundary.

### Task 3: Superadmin controls and conflict-preserving editor

**Files:** editor JS/HTML; new announcement-time helper;
`regression_tests/test_superadmin_ui.cjs`, `test_announcement_editor.cjs`,
`test_frontend_entrypoints.cjs` and current asset references.

**Interfaces:** `InventoryAnnouncementTime.localInput(instant, zone) -> string`
formats canonical UTC as `YYYY-MM-DDTHH:mm:ss` in the named IANA zone; never
converts local input through the browser timezone. Editor `loadAnnouncement`
uses management metadata and keeps `savedAnnouncement`, `annForm`, schedule
status and timezone revision separate. Save/remove send expected revision.

- [x] Add failing shipped-editor tests for all audience controls, required role selection, local schedule round trips across different device zones, existing/public legacy defaults, expired saved notice still editable, loaded timezone gating and retained draft on conflict.
- [x] Add a two-editor test: both load revision A, first saves B, second receives 409 and preserves its draft until explicit reload. Test read/write races, management load failure/Retry and pending duplicate saves/removals.
- [x] Run `node --test regression_tests/test_announcement_editor.cjs regression_tests/test_superadmin_ui.cjs regression_tests/test_frontend_entrypoints.cjs`; verify intended RED failures.
- [x] Implement controls for audience/roles, publish-now versus scheduled start, optional expiry and dismissal; add organisation-zone labels and Scheduled/Active/Expired summary. Explain that saving resets dismissals. Preserve message limits/severity and accessible loading/error states.
- [x] Load the time helper before the editor; update cache versions/manifest assertions together. Keep conflict drafts separate from saved preview, block writes until metadata loads, and allow explicit reload after conflict.
- [x] Rerun focused tests, syntax/diff checks and commit the editor boundary.

### Task 4: Banner dismissal, expiry and account-safe refresh

**Files:** shared banner JS/CSS and all five HTML snippets;
`regression_tests/test_announcements_ui.cjs`, `test_announcement_delivery.cjs`.

**Interfaces:** banner consumes Task 2 filtered result/revision/expiry/dismissal mode.
Authenticated dismissal obtains CSRF with the existing shared helper and POSTs
`{revision}`; ensure every page loads that helper, including profile. Anonymous
markers use `inventory:announcement:dismissed:<revision>` and contain no message.
Keep a monotonic request generation to reject stale completions.

- [x] Write failing tests for optional Dismiss visibility, account POST success/failure, anonymous storage failure, anonymous-to-authenticated transition, account switches and a delayed GET arriving after dismissal/removal/newer revision.
- [x] Write clock-controlled expiry tests: hide at exact expiry, no-expiry stays visible, long-delay timer re-arms within browser timeout limits; hidden/restored pages refresh. Verify teardown clears every timer/listener and restricted stale notices clear on eligibility-check failure.
- [x] Run `node --test regression_tests/test_announcement_delivery.cjs regression_tests/test_announcements_ui.cjs`; observe behavior failures.
- [x] Implement dismissal/expiry state and request-generation guards. Use server dismissal mode so anonymous markers never suppress account responses. Recheck UTC expiry when rendering/resuming; retain visible Retry/errors, but never preserve role-targeted stale content after revalidation failure.
- [x] Update five snippets with accessible Dismiss/pending/error controls; maintain plain-text rendering and responsive vertical layout. Shared CSRF/helper dependencies are explicit, deferred and versioned. Rerun focused tests and commit delivery changes.

### Task 5: Whole-system verification, review and publication

**Files:** `docs/site-announcements.md`, `docs/frontend-organisation.md`, spec/plan status and any remaining regression expectations.

- [x] Document one-notice semantics, exact-role targeting, public information limits, expiry/polling latency, account/browser dismissal, republishing/reset and migration rollback constraints. A schema rollback requires a compatible backup; do not claim git revert removes v6 safely.
- [x] Run `python -m pytest -q`, `node --test regression_tests/*.cjs`, all active JS syntax checks and `git diff --check`. Record fresh results; investigate every failure. Confirm v1–v5 migration bytes unchanged and unrelated stock/auth workflows remain covered.
- [x] Request one fresh independent whole-branch review, emphasizing audience leaks, session transitions, DST/clock boundaries, concurrent edits and restore validation. Fix Critical/Important findings and rerun affected/full checks as warranted.
- [x] Publish the branch and PR automatically as previously authorized. Verify remote base and exact published/tested tree equality; do not merge the PR.
- [ ] After owner merge, confirm migration/deployment state and public asset/anonymous endpoint behavior without production mutations. Report signed-in desktop/mobile verification separately while browser protection remains blocked.

## Execution handoff

Preserve native implementation in this session, then one fresh final reviewer.
The owner reviews this written plan before implementation. No production code has
been changed for announcement controls at the planning stage.

Final verification: 896 Python tests and 697 JavaScript tests pass. Active JS syntax checks and whitespace checks pass; published v1–v5 migrations remain unchanged. Fresh review completed and both Important findings fixed with regression tests. Publication follows under standing authorization; post-merge/live signed-in gates remain pending.

Published PR: https://github.com/atonui/spares_inventory/pull/126. GitHub implementation tree equals tested local tree 104aa282a0692e7de87e1f4dd254bf022136bac8. This publication record is a documentation-only follow-up.
