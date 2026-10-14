# User Administration Frontend Extraction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Preserve Native execution with one fresh final whole-branch review. Steps use checkbox tracking.

**Goal:** Give inventory user create/edit/archive state and methods one feature owner without changing behavior.

**Architecture:** `usersAdminFeature()` supplies the user form, editing ID, modal flag and four existing methods. A new v12 inventory entrypoint composes it with current features. Authentication/current-user state, user data/loading, navigation, shared feedback and archive listing/restoration remain core providers.

**Tech Stack:** Existing classic JavaScript, AlpineJS 3.13.0, Node VM regressions, FastAPI and pytest. No new dependencies or build step.

**Spec:** `docs/superpowers/specs/2026-10-13-frontend-organisation-design.md` (owner-approved architecture).

**Status:** Owner approved; implementation and verification complete. Fresh final review approved without findings. Native execution retained; automatic publication authorized.

## Global Constraints

- Retain current screens, Alpine bindings, permissions, requests, authentication, CSRF recovery, timezone handling, stock workflows and exports.
- The owner merges; this work does not deploy or modify production data.
- Standing owner authorization permits publishing inventory branches and PRs after checks/review pass; publish automatically and report the link without requesting publication approval again.
- No bundler, package installation, runtime dependency, framework migration or server change.
- No HTML redesign, CSS reorganisation, new feature, endpoint, database migration or unrelated bug fix.
- Preserve global factories, the flat Alpine application, property descriptors/getters, method `this`, enumerability and fresh instance state. Reject duplicate ownership through the existing composer.
- Freeze `static/script.js` and historical inventory controllers through v11 byte-for-byte. V11 blob SHA: `8264fed6ef3d84fc8dac1ec410f38e2b1044729b`.
- Existing helpers/features and other four HTML pages remain byte-identical; index changes only script references. No backend, database, CSS or dependency changes; retain the activity-log null-actor fix.
- Move defaults and method bodies unchanged. Preserve payload asymmetry, feedback, resets, refresh order, timers, loading/error and shared CSRF handling. Do not add guards, validation, role normalization or password/email changes.
- Browser/mobile verification remains pending under the existing credential-session limitation; do not reset or route around it.

## Ownership and Interfaces

Create `static/js/inventory/users-admin.js` exposing `usersAdminFeature(): object`, owning exactly seven properties:

| Kind | Properties |
| --- | --- |
| State | `userForm: {email:'', name:'', password:'', role:'engineer', territory:''}`, `showUserModal: false`, `editingUser: null` |
| Methods | `createUser()`, `editUser(user)`, `updateUser()`, `deleteUser(userId, userName)` |

Providers consumed through composed `this`: `loading`, `error`, `successMessage`, `apiCall(endpoint, options?)`, `loadUsers()`, `loadInventory(options?)`, `showArchivedPanel`, `loadArchivedRecords()`. External dependencies: confirm, setTimeout and existing JSON behavior. Core `loadUsers()` retains its admin/superadmin role check; shared API/CSRF remains the mutation transport. Do not extract `users`, `currentUser`, login/profile flows, permissions, archive listing/restoration or equipment/store-type administration.

Create retains POST `/users` with `JSON.stringify(this.userForm)`, including email/password and raw territory. Success sets `User created successfully!`, closes the modal and resets the form to all blanks **including role** before `loadUsers()`, then schedules the existing 3,000 ms success timer. Preserve the distinction between the initial/create-button role `engineer` and the post-save reset role `''`. Create itself does not reset `editingUser`; existing HTML initializes create mode.

Edit records the row ID, replaces the form with email/name/role, blank password and `user.territory || ''`, and opens the modal. Update retains PUT `/users/${editingUser}` with only name, role and `territory || null`; email is omitted and password is included only when truthy. Preserve untrimmed values. Success sets `User updated successfully!`, closes the modal, clears editing ID, resets the form to all blanks and loads users before its 3,000 ms timer. Write failures retain the form/mode; post-write refresh failures retain already-reset/saved state. Preserve `Failed to create/update user: ` wording and final loading release.

Archive retains `Archive user ${userName}? History will be preserved.` confirmation and DELETE `/users/${userId}`. Decline returns before modifying loading or feedback. Success copies the server message and refreshes users → inventory → archived records only if the archive panel is open, then schedules a 3,000 ms success timer. Preserve `Failed to archive user: ` wording, current selected-store behavior, and core refresh-error handling, including swallowed inventory/archive refresh errors. Do not add statistics/store/equipment refreshes or change current-user/session state locally.

Create `static/js/pages/inventory-v12.js` from v11, remove only the seven owned properties and add a fresh user-admin feature to composition. Preserve all 265 application properties/descriptors/defaults/method/getter sources. Index local order: temporal, audit, csrf, time-context, features, reports, replenishment, stock-counts, stock-imports, transfer-receipts, stock-dispatch, stock-entry, stock-consumption, parts-admin, stores-admin, users-admin, inventory-v12. All local references defer with `?v=20261013-frontend-12`, followed by unchanged Alpine CDN.

## Review Focus

1. Create/edit mode and actual HTML bindings preserve the initial engineer role versus blank post-save role, disabled edit email and optional edit password behavior.
2. Create/update payload asymmetry preserves raw territory on creation, null blank territory on update, email omission and truthy-only password inclusion without trimming.
3. Archive decline/success/failure preserves session/selection state, confirmation, users → inventory → optional archived refresh order and existing swallowed-refresh handling.
4. Real API/CSRF remains role-aware and cookie-authenticated; only explicit CSRF rejection replays once, permission failures do not replay and token failures prevent mutation.
5. Fresh forms, composed receivers, cached v11/active v12 equivalence and frozen modules/markup remain correct; authentication and equipment/store-type administration are untouched.

---

### Task 1: Extract and wire user administration

**Create:** `static/js/inventory/users-admin.js`, `static/js/pages/inventory-v12.js`, `regression_tests/test_users_admin_feature.cjs`, `regression_tests/test_users_admin_ui.cjs`.

**Modify:** `static/index.html`, `regression_tests/test_frontend_entrypoints.cjs`, `docs/frontend-organisation.md`.

**Interfaces:** Produce the seven properties above; consume exact core providers through composed receivers. Keep HTML, authentication, browsing and other modules unchanged.

- [x] **Step 1: Baseline.** Run `node --test regression_tests/*.cjs` and `/workspace/scratch/22e193396fd5/timezone-venv/bin/python -m pytest -q` on merged PR112 (`ff1adf4`). Expected: 355 Node and 830 Python tests pass. Record v11 frozen hash and application contract before production edits.
- [x] **Step 2: Isolated contracts RED and prior behavior.** Write exact-seven-keys/defaults/fresh-form tests and composed-provider receiver/order tests for create/update/archive. Assert edit replaces form, clears password and preserves raw role/territory fallback. Run `node --test regression_tests/test_users_admin_feature.cjs`; expected missing-module failure. Write Step 6 shipped behavior tests now and run on unchanged v11; expected all pass before moving code.
- [x] **Step 3: Extraction GREEN.** Copy three defaults and four method bodies verbatim into `usersAdminFeature()`. Run isolated tests; expected pass without body rewrites/new providers.
- [x] **Step 4: Entrypoint contracts RED.** Expect exact v12 manifest/cache key and user-admin factory on index only. Add cached-v11 construction with original manifest/frozen SHA, no user-admin dependency, and compare all 265 descriptors/defaults/method/getter sources. Extend frozen-controller guard through two-digit v11. Run `node --test regression_tests/test_frontend_entrypoints.cjs`; expected manifest/factory failures before wiring.
- [x] **Step 5: Wiring GREEN.** Copy v11 to v12, remove only owned properties, compose a fresh user-admin feature and update index script references. Run isolated/entrypoint tests; expected all pass, cached v11 self-contained.
- [x] **Step 6: Shipped behavior GREEN.** Rerun established UI tests through shipped v12 references. Execute actual add/cancel and submit expressions; assert create role engineer, edit disables email/password is optional, cancel clears mode, and navigation closes modal while preserving form/other editing data. Cover create raw full payload, edit password clearing, update blank/present territory and blank/nonempty/whitespace password (email omitted; whitespace remains truthy), reset-before-refresh and exact timer. Archive decline retains feedback/session/selection; confirmed open/closed archive cases assert exact order and unchanged session/selection. Reject each write and relevant refresh provider; check retained form/mode or saved/reset state, error wording/loading and no timer on caught failure. Use actual core loadInventory/loadArchivedRecords failure behavior to preserve swallowed errors. Through real core apiCall/CSRF, assert credentials, JSON payload/header, initial token and one explicit-rejection replay, permission/token failures, and admin/superadmin versus engineer loadUsers behavior. Assert independent forms. Run `node --test regression_tests/test_users_admin_feature.cjs regression_tests/test_users_admin_ui.cjs regression_tests/test_frontend_entrypoints.cjs regression_tests/test_sitewide_csrf.cjs`; expected all pass.
- [x] **Step 7: Verify and document.** Update active controller, ownership/providers and frozen compatibility guide; update plan status consistently. Run both full suites, `node --check` on new production files and `git diff --check`; expected all pass. Validate exact extraction, frozen controllers/features/helpers/other pages/backend byte-identical and non-script index markup unchanged. Report rendered browser checks pending.
- [x] **Step 8: Review and publication.** One fresh final whole-branch reviewer checks the approved spec/plan and five Review Focus areas. Fix Critical/Important findings with RED→GREEN and full verification; record Minor findings. Commit, publish automatically and open one PR under standing authorization; require remote tree equality with tested local source and report the link. Owner merges; no production writes.

## Plan self-review

This is one mutation/form-state boundary with explicit providers and preserved transport. User data and session ownership remain core. Initial versus post-save role defaults and create/update email/password/territory asymmetry are intentional compatibility behavior. All five review-focus areas have explicit test coverage. No other administration boundary is included. Architecture is approved; this implementation plan is owner-approved, with Native execution retained and publication already authorized.

## Execution evidence

Baseline: 355 JavaScript and 830 Python tests passed. Five isolated tests failed on the missing module; all 31 shipped behavior cases passed on unchanged v11. Entrypoint RED had two expected manifest/factory failures. Final targeted suite: 83 passed; full suites: 392 JavaScript and 830 Python passed. Runtime restart removed the old virtualenv interpreter link; restoring it to the same Python 3.12.14 runtime reused installed packages without dependency changes. Baseline Python was rerun on the prior tree identical to merged PR112; final Python passed on the extracted branch. Syntax, diff, exact extraction, 249 frozen tracked files and non-script markup checks passed. Fresh final reviewer independently verified the branch and approved without findings. Rendered browser/mobile verification remains pending under the existing access limitation. Publication follows under standing owner authorization; the owner merges.
