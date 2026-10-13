# Parts Catalog Administration Frontend Extraction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Preserve Native execution with one fresh final whole-branch review. Steps use checkbox tracking.

**Goal:** Give parts-catalog editing, archiving and CSV administration one feature owner without changing existing behavior.

**Architecture:** `partsAdminFeature()` supplies the part form, editing ID, modal flag and six existing methods. A new v10 inventory entrypoint composes it with current features; catalog data/loaders, archived-record browsing, authentication, CSRF and shared feedback remain core providers.

**Tech Stack:** Existing classic JavaScript, AlpineJS 3.13.0, Node VM regressions, FastAPI and pytest. No new dependencies or build step.

**Spec:** `docs/superpowers/specs/2026-10-13-frontend-organisation-design.md` (owner-approved architecture).

**Status:** Implemented and verified; fresh final review cleared publication. Native execution retained; standing publication authorization applies.

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
- Freeze `static/script.js` and historical inventory controllers through v9 byte-for-byte. V9 blob SHA: `a99571ce0ea040130fb44a76c9e4b2d4c2fc5825`.
- Existing helpers and all inventory features remain byte-identical. Other four HTML pages remain byte-identical; index changes only script references.
- Preserve parsing, reset timing, refresh order, messages, loading/error and URL lifecycle semantics. Do not add submission guards, normalize inputs, change archive rules, or rewrite multipart/CSRF logic. Existing core refresh-error handling remains unchanged.
- No backend, database, CSS or dependency changes; retain the PR107 activity-log fix.

## Ownership and Interfaces

Create `static/js/inventory/parts-admin.js` exposing `partsAdminFeature(): object`, owning exactly nine properties:

| Kind | Properties |
| --- | --- |
| State | `partForm: {part_number:'', description:'', category:'', unit_cost:''}`, `showPartModal: false`, `editingPart: null` |
| Methods | `createPart()`, `editPart(part)`, `updatePart()`, `deletePart(partId, partNumber)`, `importParts(event)`, `downloadPartTemplate()` |

Move all three defaults and six method bodies unchanged from v9. Each application gets a fresh form. Preserve `deletePart` as the existing public method name although it archives records. Core navigation still closes the feature-owned modal; existing HTML initializes/cancels create/edit state directly.

Providers accessed through composed `this`: `loading`, `error`, `successMessage`, `csrfToken`, `getCsrfToken()`, `apiCall(endpoint, options?)`, `loadParts()`, `loadInventory(options?)`, `loadStats()`, `showArchivedPanel`, `loadArchivedRecords()`. Browser dependencies remain `confirm`, `setTimeout`, FormData/File, Blob/URL/document, console and existing parseFloat/JSON behavior. Do not bind methods to the isolated feature object.

Create retains POST `/parts` with unchanged strings and parseFloat unit cost; success closes/reset form before parts → stats refresh and a 3,000 ms timer. Edit replaces the form with exact row values, stores its ID and opens the modal. Update retains PUT `/parts/${editingPart}`; success closes/reset form and editing ID before parts → inventory → stats refresh and a 3,000 ms timer. Preserve zero unit cost, write-failure input state and post-write refresh-failure saved/reset state/error wording.

Archive retains `Archive part ${partNumber}? History will be preserved.` confirmation, DELETE `/parts/${partId}`, server message, parts → stats → inventory refresh, optional archived-record refresh when that panel is open, and the 3,000 ms timer. Declining confirmation does not mutate shared state or send requests.

CSV import returns immediately with no selected file. Otherwise retain the initial token acquisition when absent, multipart POST `/parts/bulk-import` with `file`, exact added/skipped message and conditional console message, parts → stats refresh, then input clearing and a 5,000 ms timer. Preserve the shared API helper's multipart detection and one replay on explicit CSRF rejection. Token/write/refresh failures retain the existing input value and error/feedback behavior; do not move input clearing into finally.

Template retains exact CSV `part_number,description,category,unit_cost\nSAMPLE-001,Sample Part Description,Sample Category,99.99`, text/csv Blob, object URL, anchor click and filename `parts_import_template.csv`, with unchanged URL lifecycle.

Keep core `parts`, `loadParts()`, read-only catalog panels/getters/exports, stock-entry picker and all other feature modules unchanged. Keep generic archive listing/restoration, users/stores administration and store CSV template/import in core.

Create `static/js/pages/inventory-v10.js` from v9, remove only the nine owned properties and add a fresh parts-admin feature to composition. Preserve all 265 application descriptors/defaults/method/getter sources. Index local order: temporal, audit, shared csrf, shared time-context, shared features, reports, replenishment, stock-counts, stock-imports, transfer-receipts, stock-dispatch, stock-entry, stock-consumption, parts-admin, inventory-v10. All local references defer with `?v=20261013-frontend-10`, followed by unchanged Alpine CDN.

## Review Focus

1. Create/edit mode, zero cost, form replacement/reset and direct HTML/navigation bindings retain their exact payload and state semantics.
2. Archive confirmation and optional archived-panel refresh preserve history wording, permissions and request/refresh ordering.
3. Real multipart CSV import acquires/retries CSRF safely, preserves file content/body, sets no JSON Content-Type and retains authenticated cookie behavior.
4. Token/write/refresh failures preserve existing form/input/feedback state and avoid later refreshes/timers; successful input reset remains after refresh.
5. Fresh forms and template browser APIs remain correct; cached v9/active v10 contracts and frozen modules/markup stay equivalent.

---

### Task 1: Extract and wire parts administration

**Create:** `static/js/inventory/parts-admin.js`, `static/js/pages/inventory-v10.js`, `regression_tests/test_parts_admin_feature.cjs`, `regression_tests/test_parts_admin_ui.cjs`.

**Modify:** `static/index.html`, `regression_tests/test_frontend_entrypoints.cjs`, `docs/frontend-organisation.md`.

**Interfaces:** Produce the nine properties; consume the exact core providers without wrappers. Navigation, stock-entry catalog access and HTML remain unchanged.

- [x] **Step 1: Baseline.** Run `node --test regression_tests/*.cjs` and `/workspace/scratch/22e193396fd5/timezone-venv/bin/python -m pytest -q` on merged PR110. Expected: 276 Node and 830 Python tests pass. Record frozen v9 hash and application contract before editing production files.
- [x] **Step 2: Isolated contracts RED and prior behavior.** Assert exact nine keys/defaults and independent forms. Assert edit replaces form without losing zero cost. Compose real feature with core providers and verify all provider `this` receivers and distinct create/update/archive/import ordering. Use real Node FormData/File for upload where available; mock only Blob/URL/document for the template's exact CSV/type/filename/click. Run `node --test regression_tests/test_parts_admin_feature.cjs`. Expected: fail on missing feature. Also write Step 6 shipped cases now and run on v9 before moving production code; expected all pass to establish existing behavior.
- [x] **Step 3: Extraction GREEN.** Move all defaults and six method bodies unchanged into `partsAdminFeature()`. Run isolated tests. Expected: pass without new providers, wrappers or body rewrites.
- [x] **Step 4: Entrypoint contracts RED.** Expect exact v10 manifest/cache key and parts-admin factory on index only. Add cached-v9 construction with original scripts/frozen SHA and compare all 265 application properties/descriptors/defaults/method/getter sources. Extend the frozen-controller regression guard through v9. Run `node --test regression_tests/test_frontend_entrypoints.cjs`. Expected: fail on still-v9 index manifest/factory before wiring.
- [x] **Step 5: Wiring GREEN.** Copy v9 to v10, remove only owned properties, compose a fresh admin feature and update index references. Run isolated and entrypoint tests. Expected: pass; cached v9 does not require the new factory.
- [x] **Step 6: Shipped behavior GREEN.** Rerun the v9-established `test_parts_admin_ui.cjs` cases on v10. Cover actual add/cancel HTML bindings, edit/zero cost, create/update exact payloads and resets before their distinct refresh sequences; decline archive preserving feedback, confirmed archive with panel closed/open, and exact timers. Cover multipart upload with missing/present token and no file; use real `apiCall` and CSRF helper with a fetch fixture to test explicit token rejection/retry, unchanged FormData/File content, cookie credentials and absent JSON Content-Type. Token failure prevents writes; mutation and each relevant refresh-stage rejection preserve current form/input/reset state and avoid timers. Verify added/skipped summary/input clearing only after success; navigation closure and form isolation. Run `node --test regression_tests/test_parts_admin_ui.cjs regression_tests/test_parts_admin_feature.cjs regression_tests/test_frontend_entrypoints.cjs regression_tests/test_sitewide_csrf.cjs`. Expected: all pass through real shipped-page references.
- [x] **Step 7: Verify and document.** Update ownership/providers, active controller and frozen compatibility guide. Run both full suites, `node --check` on both new production files and `git diff --check`; expected all pass. Require v9/v10 equivalence, frozen controllers/other features/helpers/pages/backend byte-identical and index non-script markup identical. Report rendered browser checks as pending under the existing access limitation.
- [x] **Step 8: Review and publication.** One fresh final whole-branch reviewer checks approved spec/plan and all five Review Focus areas. Fix Critical/Important findings with RED→GREEN and full verification; record Minor findings. Commit, publish the verified branch and open one PR under the owner's standing publication authorization; verify remote tree matches tested local source and report the PR link. Owner merges; no production writes.

## Plan self-review

This boundary owns catalog administration actions/form state, not catalog reads or stock selection. Archive browsing/restoration remains generic core behavior. CSV multipart and shared CSRF providers are preserved rather than duplicated; real-helper tests exercise that interface. Each review-focus condition has explicit coverage. The existing approved architecture supplies the spec; the owner approved this boundary plan before implementation. Publishing needs no additional conversational approval under the owner's standing instruction.

## Verification result

830 Python tests and 314 JavaScript tests pass. Both new production files pass syntax checks; whitespace checks pass. All 265 application descriptors/defaults/method/getter sources match v9. Fresh final review found no Critical or Important issues, passed 82 focused tests and the full Node suite, and confirmed frozen files/backend unchanged with index changes limited to script references. Its minor observation about stale approval wording was addressed during final documentation status updates. Browser verification remains pending under the existing access limitation. Publish the verified branch/PR under standing owner authorization and verify remote tree equality. Owner merges.
