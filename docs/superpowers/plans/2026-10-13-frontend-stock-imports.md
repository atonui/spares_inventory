# Stock CSV Imports Frontend Extraction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Preserve Native execution with one fresh final whole-branch review.

**Goal:** Give stock-balance CSV parsing, preview and duplicate resolution one feature owner without changing existing behaviour.

**Architecture:** `stockImportsFeature()` supplies fresh import state and existing methods to the descriptor composer. A new v5 inventory entrypoint composes the feature with core, reports, replenishment and counts; historical entrypoints retain their original dependency graphs.

**Tech Stack:** Existing classic JavaScript, AlpineJS 3.13.0, FastAPI static hosting, Node VM tests and pytest; no new dependencies/build step.

**Spec:** `docs/superpowers/specs/2026-10-13-frontend-organisation-design.md`

**Status:** Implemented and verified; fresh final review found no issues. Owner authorized publication; ready for owner merge.

## Global Constraints

- Retain current screens, Alpine bindings, permissions, requests, authentication, CSRF recovery, timezone handling, stock workflows and exports.
- The owner merges; this work does not deploy or modify production data.
- No bundler, package installation, runtime dependency, framework migration or server change.
- No HTML redesign, CSS reorganisation, new feature, endpoint, database migration or unrelated bug fix.
- Keep existing global factory names so HTML expressions do not change.
- Feature factories return fresh state for every application instance.
- Compose property descriptors, rather than spreading getter-bearing objects.
- Reject duplicate property ownership instead of silently allowing a later feature to overwrite an earlier one.
- Preserve method `this`, getter access, property enumerability and instance isolation.
- Preserve all historical controllers byte-for-byte: `static/script.js`, `static/js/pages/inventory.js`, `inventory-v2.js`, `inventory-v3.js`, `inventory-v4.js`. V4 blob SHA: `fcb9d4dd8d520e096908ef550850ccd45bb7b149`.
- Index loads only `static/js/pages/inventory-v5.js`; other four pages remain unchanged. All local index scripts defer with `?v=20261013-frontend-5`, followed by the unchanged Alpine CDN script.
- Reports, replenishment, counts and shared helpers remain unchanged. Catalog `importParts(event)`, store administration `importStores(event)`, transfer receipts and stock entry remain core responsibilities for later boundaries.

## Ownership and Interfaces

Create `static/js/inventory/stock-imports.js` exposing `stockImportsFeature(): object`, with exactly thirteen properties:

| Kind | Properties |
| --- | --- |
| State | `showDuplicateResolutionModal`, `csvDuplicates`, `storeConflicts`, `pendingImportData` |
| Methods | `getImportPreview()`, `getResolutionSummary()`, `setAllCsvDuplicates(action)`, `setAllStoreConflicts(action)`, `setAllActions(action)`, `cancelDuplicateResolution()`, `processDuplicateResolution()`, `importPartsToStore(event, storeId)`, `downloadStoreImportTemplate()` |

Move defaults and method bodies unchanged from v4. `getImportPreview()` returns rows shaped `{partNumber, quantity, action, currentQuantity}`; summary returns `{willAdd, willUpdate, willSkip}`. Pending data remains `{parsedRows, storeId}`, with parsed rows `{partNumber, quantity}`. Preserve duplicate/conflict objects and their existing action precedence.

Core providers consumed through composed `this`: `loading`, `error`, `successMessage`, `parts`, `inventory`, `selectedStore`, `storeInventory`, `loadParts()`, `apiCall(endpoint, options?, onTimeContext?)`, `loadInventory(options?)`, `loadStats()`. External dependencies remain browser File `.text()`, Blob, URL, document, Map, Number and JSON. Do not bind methods to the isolated feature object.

Preserve BOM stripping, two-column quoted CSV parsing, exact headers, 1,000-row limit, zero/nonnegative safe-integer validation, catalog checks, store-ID filtering and exclusion of work-order balances. Preview makes no write. Confirmation retains the single `/inventory/import-balances` POST with `{store_id, rows}` and each row's `{part_number, quantity, expected_quantity}`. Success closes/reset the preview before inventory refresh, selected-store filtering and stats refresh. Write failures retain the preview; post-save refresh failures retain the current cleared state and existing error wording. Do not silently fix those semantics in this refactor.

Create `static/js/pages/inventory-v5.js` from v4, remove only the thirteen owned properties, and compose core with reports, replenishment, counts and imports. Keep `viewStoreInventory(store)`, `addStockToStore(store)` and `filterPartsForSelection()` in core. No new public application keys or modal focus behaviour.

Index local order: `temporal.js`, `audit.js`, `js/shared/csrf.js`, `js/shared/time-context.js`, `js/shared/features.js`, `js/inventory/reports.js`, `js/inventory/replenishment.js`, `js/inventory/stock-counts.js`, `js/inventory/stock-imports.js`, `js/pages/inventory-v5.js`. Script references are the only markup changes.

## Review Focus

1. CSV validation and file lifecycle: BOM/quoted headers and zero work; invalid or excessive rows do not open a preview; processed inputs reset so the same file can be selected again.
2. Duplicate resolution: first/tally/skip choices and summary stay reactive; unresolved rows, unsafe combined quantities and all-skipped imports prevent writes.
3. Store isolation: identical store names and work-order rows do not affect the target balance; duplicate existing balances block preview.
4. Save lifecycle and concurrency: one exact batch, shared busy guards, successful refresh order, retained write-failure state and current post-save refresh-failure behaviour.
5. Fresh factories and cached v4 HTML: arrays/pending data remain independent; template download uses existing browser APIs; both dependency graphs construct equivalent applications.

---

### Task 1: Extract and wire stock imports

**Create:** `static/js/inventory/stock-imports.js`, `static/js/pages/inventory-v5.js`, `regression_tests/test_stock_imports_feature.cjs`.
**Modify:** `static/index.html`, `regression_tests/test_frontend_entrypoints.cjs`, `regression_tests/test_stock_import_ui.cjs`, `docs/frontend-organisation.md`.
**Interfaces:** Consume/produce the thirteen properties and providers above; reuse all existing feature modules and composer unchanged.

- [x] **Step 1: Baseline.** Run full Node/Python suites on merged PR104. Record v4 hash and all application keys/descriptors/defaults/method/getter sources for comparison.
- [x] **Step 2: Write isolated feature tests and observe RED.** Load the new feature with the real composer. Assert the exact thirteen keys, defaults `false`, `[]`, `[]`, `null`, independent mutable state, and providers accessed through composed `this`. Assert first/tally/skip preview rows and exact summary counts; cancellation resets only owned import state. Mock Blob/URL/document and assert the exact CSV template, filename, click and URL revocation. Initial failure must be the missing feature.
- [x] **Step 3: Move owned state/methods and observe GREEN.** Copy the defaults and nine bodies unchanged, preserving parser, payloads, messages and browser APIs. Run the isolated tests; no wrappers, parsing rewrite or lifecycle changes.
- [x] **Step 4: Write entrypoint expectations and observe RED.** Expect the exact v5 manifest/cache key and import factory on index only. Add cached-v4 construction coverage using its original script list and frozen blob SHA. Retain all earlier compatibility contracts. Current index must fail the new manifest expectation before wiring.
- [x] **Step 5: Compose v5 and wire index.** Remove only owned defaults/methods from the copied core, compose a fresh import feature, update script references and extend the active-regression guard through frozen v4. Retain all 265 public properties and descriptors.
- [x] **Step 6: Exercise shipped-page imports.** Retain existing preview, malformed quantity, unresolved duplicate, store-ID, exact batch and failed inventory-read regressions. Add BOM/quoted headers with zero; 1,000 accepted versus 1,001 rejected rows; invalid columns/unknown catalog parts clearing preview; duplicate existing balances rejected while work-order balances are excluded; processed input reset. Add first/tally/skip summary, unsafe tally and all-skipped no-write cases. Assert loading guards block concurrent import/save, cancellation clears owned state, one exact POST precedes inventory and stats refresh, selected-store refresh uses IDs, write failure retains preview, and post-save refresh failure preserves existing state/message. Confirm separate app state remains independent.
- [x] **Step 7: Verify and document.** Run `node --test regression_tests/*.cjs`, `/workspace/scratch/22e193396fd5/timezone-venv/bin/python -m pytest -q`, `node --check` on both new production files and `git diff --check`; require all passing. Compare all v5 application defaults/descriptors/method/getter sources with v4; require equivalence. Verify historical files and other features are unchanged and markup outside scripts is identical. Update ownership/providers/active controller/compatibility policy in the guide. Report rendered browser verification as pending while access remains blocked.
- [x] **Step 8: Fresh final review and publish.** One fresh whole-branch reviewer checks the approved spec/plan and five Review Focus conditions. Fix Critical/Important findings with RED→GREEN and full verification. Publish one PR with its remote tree verified against the tested local tree. Owner merges; no production writes.

## Self-review

The boundary owns stock-balance CSV import, not catalog/store administration imports. All nine methods and four defaults have one owner; shared loading and refresh providers deliberately remain core. The plan preserves existing error and refresh semantics rather than adding behaviour changes. Each Review Focus condition has explicit isolated or shipped-page coverage. A new versioned controller protects cached v4 HTML; historical asset retirement remains a separate decision.

## Verification result

826 Python tests and 195 JavaScript tests pass. Both new production files pass syntax checks; whitespace checks pass. All 265 application properties/descriptors/defaults/method/getter sources match v4. Historical controllers, existing features/helpers and other pages remain byte-identical; index changes only script references. Fresh final review checked all five Review Focus areas and found no Critical, Important or Minor issues. Rendered browser verification remains pending under the existing access limitation. The owner explicitly authorized publication after final verification and review. Owner merges the PR.
