# Stock Entry and Adjustment Frontend Extraction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Preserve Native execution with one fresh final whole-branch review. Steps use checkbox tracking.

**Goal:** Give stock entry, manual quantity adjustment and the add-stock part picker one feature owner without changing existing behavior.

**Architecture:** `stockEntryFeature()` supplies the add/edit forms, modal flags, addition busy flag, part-picker state and six existing methods. A new v8 inventory entrypoint composes it with current features. Catalog and selected-store data remain core providers; navigation and existing HTML keep accessing the flat composed application.

**Tech Stack:** Existing classic JavaScript, AlpineJS 3.13.0, Node VM regressions, FastAPI and pytest. No new dependencies or build step.

**Spec:** `docs/superpowers/specs/2026-10-13-frontend-organisation-design.md` (owner-approved architecture).

**Status:** Implemented and verified; fresh final review found no issues. Owner authorized publication; prepared for owner merge. Native execution retained.

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
- Freeze `static/script.js` and historical inventory controllers through v7 byte-for-byte. V7 blob SHA: `62ef53d129f439b75beda38f08604fd326c160ce`.
- Existing helpers, reports, replenishment, counts, imports, receipts and dispatch remain byte-identical. Other four HTML pages remain byte-identical; index changes only script references.
- Preserve exact numeric conversion, feedback, form/reset timing, timer behavior and refresh order. Add uses `addingStock`, adjustment uses shared `loading`; do not introduce new validation or submission guards. Core inventory refresh retains its existing loading and swallowed-error behavior.
- Preserve the activity-log fix from PR107. No backend, database, CSS or dependency changes.

## Ownership and Interfaces

Create `static/js/inventory/stock-entry.js` exposing `stockEntryFeature(): object`, owning exactly thirteen properties:

| Kind | Properties |
| --- | --- |
| State | `addingStock: false`, `addForm: {part_id:'', store_id:'', quantity:'', work_order_number:''}`, `editForm: {inventory_id:'', new_quantity:''}`, `showAddModal: false`, `showEditModal: false`, `partSearchTerm: ''`, `filteredPartsForSelection: []` |
| Methods | `addStockToStore(store)`, `filterPartsForSelection()`, `selectPart(part)`, `addStock()`, `editItem(item)`, `updateStock()` |

Move all seven defaults and six method bodies unchanged from v7. Each instance allocates fresh forms and picker array. After opening/filtering, the picker may deliberately reference the core `parts` array; preserve that aliasing rather than cloning it. The modal's local Alpine `showSuggestions` state remains in existing HTML.

Core providers consumed through composed `this`: `parts`, `loading`, `error`, `successMessage`, `selectedStore`, `apiCall(endpoint, options?)`, `loadInventory(options?)`, `loadStats()`, `loadEquipmentStats()`, `viewStoreInventory(store)`. External dependency: `setTimeout(callback, delay)` and existing Number/parseInt/JSON behavior.

`addStockToStore(store)` retains its form object, selects the store ID, blanks part/quantity/work order/search, assigns the full catalog to picker results and opens the modal. Search remains case-insensitive across part number, description and category; empty search references the full catalog. Selection retains the part ID and exact `part_number + ' - ' + description` search label.

`addStock()` retains POST `/inventory/add`, unchanged part/store values, numeric `Number(quantity)` and work-order value or null. On success it sets `Stock added successfully`, closes/reset the add form and search before inventory → statistics → equipment statistics refresh; it then calls core `viewStoreInventory(selectedStore)` when selected. Schedule the existing 3,000 ms success-message reset only after refreshes. Always release `addingStock`. Preserve retained form/modal on write failure and reset state/existing error wording on post-write refresh failure.

`editItem(item)` retains its form object and sets ID/current quantity before opening the modal. `updateStock()` retains PUT `/inventory/update` with parseInt conversions, zero quantity support, `Stock updated successfully!`, close/reset before inventory → statistics refresh and the existing 3,000 ms timer. Preserve its write/refresh failure behavior and shared-loading lifecycle.

Keep `viewStoreInventory(store)`, store browsing, catalog data/loaders and core `openPanel(panelName)` unchanged. Navigation still closes both feature-owned modals; HTML continues to write/cancel their form state without new handlers. Consumption, dispatch and physical-count workflows stay with their current owners.

Create `static/js/pages/inventory-v8.js` from v7, removing only these thirteen properties and adding a fresh stock-entry feature to the existing composition. Preserve all 265 application properties/descriptors/defaults/method/getter sources.

Index local order: temporal, audit, shared csrf, shared time-context, shared features, reports, replenishment, stock-counts, stock-imports, transfer-receipts, stock-dispatch, stock-entry, inventory-v8. All local references defer with `?v=20261013-frontend-8`, followed by the unchanged Alpine CDN script.

## Review Focus

1. Store/part selection, blank search and case-insensitive picker filtering preserve form reset, catalog aliasing and local Alpine bindings.
2. Addition and adjustment preserve their distinct payload conversions, optional work-order behavior and zero adjustment without shifting validation into this refactor.
3. Write failures retain input/modal state; post-write refresh failures retain existing saved/reset state, error wording and timer behavior.
4. Composed provider receivers, addition's equipment-statistics refresh and selected-store reopening by ID remain correct; navigation still closes both modals.
5. Fresh forms/picker arrays remain independent; cached v7 and active v8 retain equivalent application contracts and correct deferred dependencies.

---

### Task 1: Extract and wire stock entry/adjustment

**Create:** `static/js/inventory/stock-entry.js`, `static/js/pages/inventory-v8.js`, `regression_tests/test_stock_entry_feature.cjs`, `regression_tests/test_stock_entry_ui.cjs`.

**Modify:** `static/index.html`, `regression_tests/test_frontend_entrypoints.cjs`, `docs/frontend-organisation.md`.

**Interfaces:** Produce the thirteen properties above; consume the exact core providers without wrappers. Navigation, browsing and HTML remain unchanged callers.

- [x] **Step 1: Baseline.** Run `node --test regression_tests/*.cjs` and `/workspace/scratch/22e193396fd5/timezone-venv/bin/python -m pytest -q` on merged PR108. Expected: 231 Node and 830 Python tests pass. Record v7 hash and application contract before editing production files.
- [x] **Step 2: Isolated contracts RED and prior behavior.** Assert the exact thirteen owned keys/defaults, independent forms/picker arrays and composed provider `this`. Verify add-store opener retains the form object/reset fields/catalog reference; filtering covers case-insensitive part number/description/category, empty search and no matches; selecting a part sets exact ID/label. Verify edit opener retains its form object and supports zero. Run `node --test regression_tests/test_stock_entry_feature.cjs`. Expected: fail on missing feature. Also write the shipped behavior cases specified in Step 6 now and run them against v7 before the move; expected all pass, establishing existing behavior.
- [x] **Step 3: Extraction GREEN.** Move seven defaults and six method bodies unchanged into `stockEntryFeature()`. Run isolated tests. Expected: all pass, without wrappers, new validation or provider additions.
- [x] **Step 4: Entrypoint contracts RED.** Expect the exact v8 index manifest/cache key and stock-entry factory on index only. Add cached-v7 startup with original scripts/frozen SHA and compare all 265 descriptors/defaults/method/getter sources. Extend the frozen-controller regression guard through v7. Run `node --test regression_tests/test_frontend_entrypoints.cjs`. Expected: fail on the unchanged v7 index manifest/factory before wiring.
- [x] **Step 5: Wiring GREEN.** Copy v7 to v8, remove only owned properties, compose a fresh entry feature and update index references. Run isolated and entrypoint tests. Expected: pass; cached v7 does not require the new factory.
- [x] **Step 6: Shipped behavior GREEN.** Rerun the v7-established `test_stock_entry_ui.cjs` cases on shipped v8. Cover add payload with string IDs/numeric quantity and blank versus present work order; adjustment payload with parsed string ID/quantity including zero; deferred writes showing correct busy flags and retained pre-save forms; success close/reset/search timing before exact refresh order and 3,000 ms callback. For add, use real `viewStoreInventory()` to test selected-store reopening and duplicate store names with different IDs; also cover no selected store. Cover write rejection and each refresh-stage rejection preserving current form/modal/feedback state and avoiding the timer, plus real core inventory-refresh swallowed-error/loading behavior. Exercise real picker methods and core navigation closure; verify instance isolation. Run `node --test regression_tests/test_stock_entry_ui.cjs regression_tests/test_stock_entry_feature.cjs regression_tests/test_frontend_entrypoints.cjs` and `/workspace/scratch/22e193396fd5/timezone-venv/bin/python -m pytest regression_tests/test_stock_safety.py::test_add_stock_form_sends_numeric_quantity -q`. Expected: all pass through real shipped-page references.
- [x] **Step 7: Verify and document.** Update ownership, providers/cross-feature calls, active controller and frozen compatibility guide. Run both full suites, `node --check` on both new production files, and `git diff --check`; expected all pass. Require v7/v8 application equivalence, historical controllers/features/helpers/other pages/backend byte-identical, index non-script markup identical. Report rendered browser checks as pending under the existing access limitation.
- [x] **Step 8: Review and publication.** One fresh final whole-branch reviewer checks the approved spec/plan and all five Review Focus areas. Fix Critical/Important findings with RED→GREEN and full verification; record Minor findings. Commit and publish one PR only after publication authorization, verifying the remote tree matches tested local source. Owner merges; no production writes.

## Plan self-review

The boundary owns the add/edit workflows and add-stock picker state together; catalog and store browsing remain data providers. Existing HTML and navigation still access the same flat application properties. Each of the five review-focus areas has explicit coverage, including the Python test's embedded Node harness. Existing busy flags, refresh failures and catalog aliasing are specified rather than silently improved. This plan implements the next boundary under the approved frontend architecture and awaits owner review.

## Verification result

830 Python tests and 259 JavaScript tests pass. Both new production files pass syntax checks; whitespace checks pass. All 265 application properties/descriptors/defaults/method/getter sources match v7. Fresh final review found no Critical, Important or Minor issues, independently passed the full Node suite and embedded Python/Node numeric-add regression, and checked 26 existing files unchanged with index changes limited to script references. Backend files are unchanged. Browser verification remains pending under the existing access limitation. The owner authorized publication after verification and final review. The remote source tree must match the tested local source; owner merges the PR.
