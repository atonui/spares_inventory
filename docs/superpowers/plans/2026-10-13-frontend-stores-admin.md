# Store Administration Frontend Extraction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Preserve Native execution with one fresh final whole-branch review. Steps use checkbox tracking.

**Goal:** Give store create/edit/archive and CSV administration one feature owner without changing existing behavior.

**Architecture:** `storesAdminFeature()` supplies the store form, editing ID, modal flag and six existing methods. A new v11 inventory entrypoint composes it with current features. Store/user/type data, browsing, archive listing, authentication, CSRF and shared feedback remain core providers.

**Tech Stack:** Existing classic JavaScript, AlpineJS 3.13.0, Node VM regressions, FastAPI and pytest. No new dependencies or build step.

**Spec:** `docs/superpowers/specs/2026-10-13-frontend-organisation-design.md` (owner-approved architecture).

**Status:** Owner approved; implementation and verification complete. Fresh final review approved without findings. Native execution retained; automatic publication authorized.

## Global Constraints

- Retain current screens, Alpine bindings, permissions, requests, authentication, CSRF recovery, timezone handling, stock workflows and exports.
- The owner merges; this work does not deploy or modify production data.
- The owner has authorized publishing future inventory branches and PRs after checks/review pass; publish automatically and report the link without requesting publication approval again.
- No bundler, package installation, runtime dependency, framework migration or server change.
- No HTML redesign, CSS reorganisation, new feature, endpoint, database migration or unrelated bug fix.
- Keep existing global factory names so HTML expressions do not change.
- Feature factories return fresh state for every application instance.
- Compose property descriptors, rather than spreading getter-bearing objects.
- Reject duplicate property ownership instead of silently allowing a later feature to overwrite an earlier one.
- Preserve method `this`, getter access, property enumerability and instance isolation.
- Freeze `static/script.js` and historical inventory controllers through v10 byte-for-byte. V10 blob SHA: `150ca58feedd23f30790935c3fd35df5741aad52`.
- Existing helpers and all inventory features remain byte-identical. Other four HTML pages remain byte-identical; index changes only script references.
- Preserve field fallback/conversion, feedback, form resets, refresh order, timers, loading/error and URL lifecycle. Do not add submission guards, normalize inputs, change archive rules or rewrite multipart/CSRF logic. Core refresh-error handling remains unchanged.
- No backend, database, CSS or dependency changes; retain the PR107 activity-log fix.

## Ownership and Interfaces

Create `static/js/inventory/stores-admin.js` exposing `storesAdminFeature(): object`, owning exactly nine properties:

| Kind | Properties |
| --- | --- |
| State | `storeForm: {name:'', type:'customer_site', location:'', assigned_user_id:''}`, `showStoreModal: false`, `editingStore: null` |
| Methods | `createStore()`, `editStore(store)`, `updateStore()`, `deleteStore(storeId, storeName)`, `importStores(event)`, `downloadStoreTemplate()` |

Move all three defaults and six method bodies unchanged from v10. Allocate fresh forms per application. Preserve `deleteStore` as the existing public name though it archives. Existing HTML initializes/cancels create/edit state; core navigation still closes the modal through the composed application.

Providers accessed through composed `this`: `loading`, `error`, `successMessage`, `apiCall(endpoint, options?)`, `loadStores()`, `loadStats()`, `loadInventory(options?)`, `selectedStore`, `storeInventory`, `showStoreInventoryPanel`, `showArchivedPanel`, `loadArchivedRecords()`. Browser dependencies: confirm, setTimeout, FormData/File, Blob/URL/document and existing parseInt/JSON behavior. CSRF remains inside the core API helper: do not add a direct token prefetch to store import.

Create retains POST `/stores` with unchanged name/type, location or null and assigned-user integer or null. Success sets `Store created successfully!`, closes/resets the form before stores → stats refresh, then a 3,000 ms message timer. Edit replaces the form with row values, falling back to blank location/assignment with the existing `||` expressions, records ID and opens the modal. Update retains PUT `/stores/${editingStore}` and conversions; success clears modal/editing ID and resets form before stores → inventory → stats refresh and its 3,000 ms timer. Preserve write-failure form/mode and post-write refresh-failure saved/reset state/error wording.

Archive retains `Archive store ${storeName}? History will be preserved.` confirmation, DELETE `/stores/${storeId}` and server message. After a successful write, if selected-store ID strictly equals the target ID, immediately clear `selectedStore`, `storeInventory` and `showStoreInventoryPanel` before refresh. Other stores, including equal names with different IDs, remain selected. Refresh stores → stats → inventory and, if the archived panel is open, archived records; then schedule a 3,000 ms timer. Declining/write failure must not clear selection. Post-write refresh failure retains any already-cleared selection.

CSV import returns immediately if no file is selected. Otherwise retain multipart POST `/stores/bulk-import` with `file` through real `apiCall`. Copy the server message and, when nonempty errors exist, set `Some errors occurred:\n` plus newline-joined errors. Refresh only stores, then clear input and schedule the existing 5,000 ms callback clearing both success and error. Token/write/refresh failures retain input and existing feedback behavior; do not add statistics refresh or move input clearing into finally. Shared API/CSRF helpers preserve cookie credentials and one replay only on explicit CSRF rejection.

Template retains exact CSV `name,type,location,assigned_user_email\nSample Store,customer_site,Sample Location,user@example.com`, text/csv Blob, object URL, anchor click and filename `stores_import_template.csv`, with unchanged URL lifecycle.

Keep store browsing/data/getters/exports, user lookup/data, store-type administration/data, archive listing/restoration and all other feature modules with their current owners. Do not extract `editingStoreType` or `showStoreTypeModal` with similarly named store fields.

Create `static/js/pages/inventory-v11.js` from v10, remove only nine owned properties and add a fresh store-admin feature to composition. Preserve all 265 application properties/descriptors/defaults/method/getter sources. Index local order: temporal, audit, shared csrf, shared time-context, shared features, reports, replenishment, stock-counts, stock-imports, transfer-receipts, stock-dispatch, stock-entry, stock-consumption, parts-admin, stores-admin, inventory-v11. All local references defer with `?v=20261013-frontend-11`, followed by unchanged Alpine CDN.

## Review Focus

1. Create/edit mode, optional location/assignment and custom store types preserve exact payload/fallback/reset behavior and direct HTML/navigation bindings.
2. Archive clears only the selected target by ID, preserves unrelated equal-name stores, and retains confirmation/refresh order and failure state.
3. CSV import preserves server message/row errors, store-only refresh, delayed input reset and the callback clearing both feedback fields.
4. Real multipart/CSRF retains file content, cookie credentials and absent JSON Content-Type; explicit CSRF rejection may replay once, permission/token failures do not authorize a write/replay.
5. Fresh forms/template APIs, cached v10/active v11 equivalence and frozen modules/markup remain correct; store-type administration is untouched.

---

### Task 1: Extract and wire store administration

**Create:** `static/js/inventory/stores-admin.js`, `static/js/pages/inventory-v11.js`, `regression_tests/test_stores_admin_feature.cjs`, `regression_tests/test_stores_admin_ui.cjs`.

**Modify:** `static/index.html`, `regression_tests/test_frontend_entrypoints.cjs`, `docs/frontend-organisation.md`.

**Interfaces:** Produce nine properties; consume exact core providers through composed receivers. HTML, browsing, store types and other modules remain unchanged.

- [x] **Step 1: Baseline.** Run `node --test regression_tests/*.cjs` and `/workspace/scratch/22e193396fd5/timezone-venv/bin/python -m pytest -q` on merged PR111. Expected: 314 Node and 830 Python tests pass. Record frozen v10 hash and application contract before editing production files.
- [x] **Step 2: Isolated contracts RED and prior behavior.** Assert exact nine keys/defaults and independent forms; edit preserves custom type and assigned ID, blanks null location/assignment and replaces the form. Compose real feature with core providers and verify their `this` receivers and distinct create/update/archive/import sequences. Mock only Blob/URL/document for exact template CSV/type/filename/click; use real Node FormData/File for upload. Run `node --test regression_tests/test_stores_admin_feature.cjs`. Expected: fail on missing module. Also write Step 6 shipped cases now and run on v10; expected all pass before the move.
- [x] **Step 3: Extraction GREEN.** Move defaults/six bodies unchanged into `storesAdminFeature()`. Run isolated tests. Expected: pass without new providers or body rewrites.
- [x] **Step 4: Entrypoint contracts RED.** Expect exact v11 manifest/cache key and store-admin factory on index only. Add cached-v10 construction with original scripts/frozen SHA and compare all 265 descriptors/defaults/method/getter sources. Extend frozen-controller regression guard through v10, including the two-digit version. Run `node --test regression_tests/test_frontend_entrypoints.cjs`. Expected: fail on still-v10 manifest/factory before wiring.
- [x] **Step 5: Wiring GREEN.** Copy v10 to v11, remove only owned properties, compose a fresh store-admin feature and update index references. Run isolated/entrypoint tests. Expected: all pass; cached v10 does not require the new factory.
- [x] **Step 6: Shipped behavior GREEN.** Rerun v10-established `test_stores_admin_ui.cjs` cases on v11. Cover actual add/cancel bindings, edit fallbacks/custom type, create/update location and assigned-user payloads, reset-before-refresh and exact 3,000 ms timer. Archive decline retains feedback/selection; confirmed archive with selected target versus different ID/equal name, panel closed/open, verifies clear-before-refresh and exact ordering. Write/each relevant refresh rejection preserve form/mode/selected-store or saved/cleared state as appropriate and avoid timers. CSV no-file and success with/without row errors preserves server message, refreshes stores only, clears input after refresh and clears both feedback fields after 5,000 ms; failures retain input. Real API/CSRF fetch fixtures test initial token, explicit rejection/retry, same FormData/File contents, credentials and no JSON Content-Type, plus token and permission failure. Verify navigation closes store modal without mutating store-type form/editing data and form isolation. Run `node --test regression_tests/test_stores_admin_ui.cjs regression_tests/test_stores_admin_feature.cjs regression_tests/test_frontend_entrypoints.cjs regression_tests/test_sitewide_csrf.cjs`. Expected: all pass through shipped-page references.
- [x] **Step 7: Verify and document.** Update ownership/providers, active controller and frozen compatibility guide; update plan approval/completion text consistently. Run both full suites, `node --check` on new production files and `git diff --check`; expected all pass. Require v10/v11 equivalence, frozen controllers/other features/helpers/pages/backend byte-identical and index non-script markup identical. Report rendered browser verification as pending under the existing access limitation.
- [x] **Step 8: Review and publication.** One fresh final whole-branch reviewer checks approved spec/plan and all five Review Focus areas. Fix Critical/Important findings with RED→GREEN and full verification; record Minor findings. Commit, publish the verified branch and open one PR under standing owner authorization; verify remote tree matches tested local source and report PR link. Owner merges; no production writes.

## Plan self-review

Store administration owns mutation/form state, not browsing, type definitions or user lookup. The selected-store invalidation after archive is an intentional cross-owner write; core owns those browsing fields. CSV import has different refresh/error/timer semantics from parts import and remains copied unchanged. All five review-focus areas have explicit coverage. This boundary plan and its architecture are owner-approved; approval/status text tracks execution. Publication needs no additional conversational approval under the owner's standing instruction.

## Execution evidence

Baseline: 314 JavaScript and 830 Python tests passed. Seven isolated tests failed on the missing module; all 33 shipped behavior cases passed on unchanged v10. Entrypoint RED had two expected manifest/factory failures. Final targeted suite: 86 passed; full suites: 355 JavaScript and 830 Python passed. Syntax, diff, exact extraction, frozen files and non-script markup checks passed. Fresh final reviewer independently verified the branch and approved with no findings. Rendered browser verification remains pending under the existing access limitation. Publication follows under standing owner authorization; the owner merges.
