# Store-Type Administration Frontend Extraction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Preserve Native execution with one fresh final whole-branch review. Steps use checkbox tracking.

**Goal:** Give store-type create/edit/delete-or-deactivate state and methods one feature owner without changing behavior.

**Architecture:** `storeTypesAdminFeature()` supplies the form, editing ID, modal flag and four existing methods. A new v13 inventory controller composes it with current features. Store-type data/loading, store data/loading, navigation and shared API/feedback remain core providers.

**Tech Stack:** Existing classic JavaScript, AlpineJS 3.13.0, Node VM regressions, FastAPI and pytest. No new dependencies or build step.

**Spec:** `docs/superpowers/specs/2026-10-13-frontend-organisation-design.md` (owner-approved architecture).

**Status:** Owner approved; implementation and verification complete. Fresh final review approved without findings. Native execution retained; automatic publication authorized.

## Global Constraints

- Retain current screens, Alpine bindings, permissions, requests, authentication, CSRF recovery, timezone handling, stock workflows and exports.
- Owner merges; no deployment or production data changes. Standing owner authorization permits automatically publishing verified inventory branches/PRs without another publication question.
- No bundler, package installation, runtime dependency, framework migration, HTML redesign, CSS reorganisation, new feature, endpoint, migration or unrelated bug fix.
- Preserve global factories and the flat Alpine application; use existing descriptor-preserving composition with duplicate-owner rejection, fresh state and composed method receivers.
- Freeze `static/script.js` and historical inventory controllers through v12 byte-for-byte. V12 blob SHA: `e1eb475af20aab48886967706412185183417dd7`.
- Existing helpers/features and other four HTML pages remain byte-identical. Index changes only script references. No backend/database/dependency changes; preserve the activity-log null-actor fix.
- Copy defaults and method bodies unchanged, including payload asymmetry, parsing/fallback, resets, feedback, refresh order, timers and current swallowed loader errors. Do not normalize, validate or add guards.
- Rendered browser/mobile verification remains pending under the existing credential-session limitation; do not reset or route around it.

## Ownership and Interfaces

Create `static/js/inventory/store-types-admin.js` exposing `storeTypesAdminFeature(): object`, owning exactly seven properties:

| Kind | Properties |
| --- | --- |
| State | `storeTypeForm: {type_code:'', type_name:'', description:'', display_order:0, is_active:true}`, `showStoreTypeModal:false`, `editingStoreType:null` |
| Methods | `createStoreType()`, `editStoreType(storeType)`, `updateStoreType()`, `deleteStoreType(typeId,typeName)` |

Providers consumed through composed `this`: `loading`, `error`, `successMessage`, `apiCall(endpoint, options?)`, `loadStoreTypes()`, `loadStores()`. External dependencies: confirm, setTimeout, parseInt and JSON. Store-type/store data, loaders, role checks, navigation, store administration, authentication and equipment remain with existing owners.

Create retains POST `/store-types` with raw type_code/type_name/description and `parseInt(display_order) || 0`; is_active is omitted. Success sets `Store type created successfully!`, closes modal and resets to `{type_code:'',type_name:'',description:'',display_order:0}` **without is_active**, then loads store types and schedules the 3,000 ms success timer. Create itself does not clear editing ID; HTML initializes create mode.

Edit records ID, replaces the form with type_code/type_name, `description || ''`, raw display_order and is_active, and opens the modal. Update retains PUT `/store-types/${editingStoreType}` with type_name/description, the same order conversion and is_active; type_code is omitted. Success sets `Store type updated successfully!`, closes modal, clears editing ID and resets to the same four-field form, then loads store types → stores before its 3,000 ms timer. Preserve failed-write form/mode and post-write refresh-failure reset/saved state.

Delete/deactivate retains exact confirmation `Are you sure you want to delete/deactivate store type '${typeName}'?`, DELETE `/store-types/${typeId}`, server message, store-type-only refresh and 3,000 ms timer. Decline returns before changing loading/feedback. Keep existing `Failed to create/update/delete store type: ` wording and finally loading release. Preserve actual loadStoreTypes swallowed errors and loadStores rejected errors; do not add store/statistics refreshes or change selection/session state.

Create `static/js/pages/inventory-v13.js` from v12, removing only seven properties and composing a fresh feature after users administration. Preserve all 265 descriptors/defaults/method/getter sources. Index local order remains unchanged through users-admin, followed by store-types-admin and inventory-v13. All local references defer with `?v=20261014-frontend-13`; remote Alpine 3.13.0 unchanged.

## Review Focus

1. Initial/add/edit/post-save forms preserve is_active true, edited false, and omission after reset; actual HTML create/edit/cancel/submit/disabled-code bindings and navigation retain current behavior.
2. Create/update payload asymmetry preserves omitted fields, raw description and parseInt/fallback for zero, negatives, fractional strings, blanks and invalid strings.
3. Confirmation/delete-or-deactivate server feedback, store-type-only delete refresh and store-types → stores update refresh remain unchanged; no session/selection mutation.
4. Write and refresh failures retain form/mode or already-saved/reset state as appropriate; actual swallowed loadStoreTypes errors and loading/timers remain unchanged. Shared JSON API/CSRF preserves credentials and one explicit-rejection replay; token/permission failures prevent writes/replays appropriately.
5. Fresh forms/composed receivers, cached v12/active v13 equivalence and frozen modules/markup remain correct; store/user/equipment administration and authentication remain untouched.

---

### Task 1: Extract and wire store-type administration

**Create:** `static/js/inventory/store-types-admin.js`, `static/js/pages/inventory-v13.js`, `regression_tests/test_store_types_admin_feature.cjs`, `regression_tests/test_store_types_admin_ui.cjs`.

**Modify:** `static/index.html`, `regression_tests/test_frontend_entrypoints.cjs`, `docs/frontend-organisation.md`.

**Interfaces:** Produce seven properties above; consume exact core providers through composed receivers. Preserve other ownership and HTML bindings.

- [x] **Step 1: Baseline.** On merged PR113 (`9d85ca3`), run `node --test regression_tests/*.cjs` and `/workspace/scratch/22e193396fd5/timezone-venv/bin/python -m pytest -q`. Expected 392 Node/830 Python pass. Record frozen v12 hash/application contract before production changes.
- [x] **Step 2: Isolated RED and prior behavior.** Write exact-seven-key/default/fresh-form/edit-replacement tests and composed-provider receiver/order cases. Run isolated suite; expected missing-module failures. Write Step 6 shipped tests now and run unchanged v12; expected pass before moving code.
- [x] **Step 3: Extraction GREEN.** Copy three defaults/four bodies verbatim into `storeTypesAdminFeature()`. Run isolated tests; expected pass without new providers or body rewrites.
- [x] **Step 4: Entrypoint RED.** Expect exact v13 manifest/cache and inventory-only factory. Add cached-v12 construction using original scripts and frozen SHA with no new factory; compare all 265 descriptors/defaults/function/getter sources. Extend historical-controller guard through v12. Run entrypoint suite; expected manifest/factory failures before wiring.
- [x] **Step 5: Wiring GREEN.** Copy v12 to v13, remove only seven owned properties, add composition and update index references. Run isolated/entrypoint suites; expected pass, cached v12 remains self-contained.
- [x] **Step 6: Shipped behavior GREEN.** Rerun v12-established tests through shipped v13. Execute actual add/cancel/submit bindings; assert code disabled only in edit and navigation preserves form/editing data. Cover initial/add is_active, edited false/null description, reset omission. Create/update order cases 0, -2, '3.9', '', 'invalid' pin parseInt/fallback and raw descriptions/omitted fields. Confirm exact payload, reset-before-refresh, order and timer. Decline preserves feedback/session/selection; confirmed delete retains server message and refreshes store types only. Reject each write/relevant refresh provider and assert preserved or saved/reset form/mode, failure wording/loading/no timer; exercise actual swallowed loader errors. Through real API/CSRF assert JSON headers/credentials, initial token, one explicit-rejection replay, permission failure and token failure. Assert instance isolation. Run `node --test regression_tests/test_store_types_admin_feature.cjs regression_tests/test_store_types_admin_ui.cjs regression_tests/test_frontend_entrypoints.cjs regression_tests/test_sitewide_csrf.cjs`; expected all pass.
- [x] **Step 7: Verify/document.** Update active/frozen controllers and ownership/provider guide, plan approval/status consistently. Run full Node/Python suites, syntax checks and `git diff --check`; expected pass. Validate exact extraction, frozen tracked files, backend/other pages and non-script index markup unchanged. Report browser verification pending.
- [x] **Step 8: Review/publication.** One fresh final whole-branch reviewer checks approved spec/plan and all five Review Focus areas. Fix Critical/Important findings RED→GREEN and verify; record Minor findings. Commit, publish branch/PR automatically and require remote tree equals tested local source. Report PR link; owner merges, no production writes.

## Plan self-review

One mutation/form-state boundary, with explicit core providers. is_active omission after saves and create/update payload differences are preserved compatibility behavior. All five review-focus areas have concrete tests. Equipment remains a later boundary because calibration, transfer and history share selectedEquipment. Architecture is approved; this plan is owner-approved, with Native execution retained and publication already authorized.

## Execution evidence

Baseline: 392 JavaScript and 830 Python tests passed. Five isolated tests failed on the missing module; 29 shipped behavior cases passed on unchanged v12. Entrypoint RED had two expected manifest/factory failures. Final targeted suite: 82 passed; full suites: 427 JavaScript and 830 Python passed (final Python on the extracted store-types-admin worktree). Syntax, diff, exact extraction, 254 frozen tracked files and non-script markup checks passed. Fresh final reviewer independently verified the branch and approved without findings. Browser/mobile verification remains pending under the existing access limitation. Publication follows standing authorization; owner merges.
