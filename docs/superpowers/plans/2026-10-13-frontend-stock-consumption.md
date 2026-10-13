# Stock Consumption Frontend Extraction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Preserve Native execution with one fresh final whole-branch review. Steps use checkbox tracking.

**Goal:** Give stock consumption and its work-order form one feature owner while preserving existing behavior.

**Architecture:** `stockConsumptionFeature()` supplies the consumption form, modal flag and two existing methods. A new v9 inventory entrypoint composes it with current features; API/history/dashboard refreshes and inventory/selected-store data remain core providers.

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
- Freeze `static/script.js` and historical inventory controllers through v8 byte-for-byte. V8 blob SHA: `469bebef2d610aca63fb36050b90d1e1941003c4`.
- Existing helpers, reports, replenishment, counts, imports, receipts, dispatch and stock entry remain byte-identical. Other four HTML pages remain byte-identical; index changes only script references.
- Preserve current parsing/trimming, feedback, modal/form reset, refresh order, timer and error semantics. Do not add validation or a method-level duplicate-submit guard; existing HTML validation/disabled controls remain unchanged. Core inventory/dashboard refresh semantics remain unchanged.
- No backend, database, CSS or dependency changes; retain the PR107 activity-log fix.

## Ownership and Interfaces

Create `static/js/inventory/stock-consumption.js` exposing `stockConsumptionFeature(): object`, owning exactly four properties:

| Kind | Properties |
| --- | --- |
| State | `showConsumeModal: false`, `consumeForm: {inventory_id:'', part_number:'', description:'', store_name:'', available_quantity:0, quantity:'', work_order_number:'', notes:''}` |
| Methods | `consumeItem(item)`, `consumeStock()` |

Move both defaults and method bodies unchanged from v8. Every instance allocates a fresh form. `consumeItem(item)` replaces that form with the item's ID/part/description/store/available quantity, quantity 1 and blank work-order/notes before opening the modal. It must work after the existing HTML cancel operation clears the form to `{}`.

`consumeStock()` retains POST `/inventory/consume` with parsed integer inventory ID/quantity, trimmed work-order text and unchanged notes or null. Success copies the server message, closes the modal and resets the form to `{}` before inventory → movements → dashboard refresh. It then filters selected-store balances by ID when a store is selected, and schedules the existing 5,000 ms success-message reset. Preserve write-failure form/modal state and post-write refresh-failure saved/reset state, message and error wording. Shared loading is released in the existing finally block; core inventory refresh can clear it before later providers, as before.

Consumed providers through composed `this`: `loading`, `error`, `successMessage`, `inventory`, `selectedStore`, `storeInventory`, `apiCall(endpoint, options?)`, `loadInventory(options?)`, `loadMovements()`, `refreshDashboard()`. External dependency: `setTimeout(callback, delay)` and existing parseInt/JSON/String.trim behavior.

Keep core `refreshDashboard()` and its parallel statistics/equipment-statistics refresh unchanged; keep history methods/data, store browsing, navigation and the unrelated `workOrders` data field in core. Existing HTML form bindings, direct cancellation and click-outside behavior remain unchanged. Do not add consumption-modal closure to navigation or new focus behavior.

Create `static/js/pages/inventory-v9.js` from v8, removing only the four owned properties and adding a fresh consumption feature to existing composition. Preserve all 265 application descriptors/defaults/method/getter sources.

Index local order: temporal, audit, shared csrf, shared time-context, shared features, reports, replenishment, stock-counts, stock-imports, transfer-receipts, stock-dispatch, stock-entry, stock-consumption, inventory-v9. All local references defer with `?v=20261013-frontend-9`, followed by the unchanged Alpine CDN script.

## Review Focus

1. Opening another stock row or reopening after cleared-form cancellation replaces all item metadata and clears old work-order/notes.
2. Parsed quantity/ID, trimmed work-order and blank versus present notes retain existing request semantics and server validation.
3. Write rejection retains input/modal; post-write refresh rejection preserves the existing saved/reset state, stops later refreshes and does not schedule the timer.
4. Composed provider receivers, real dashboard refresh and selected-store ID filtering preserve ordering and store isolation.
5. Form instances stay independent; cached v8 and active v9 remain equivalent with correct deferred dependencies and unchanged existing modules/markup.

---

### Task 1: Extract and wire stock consumption

**Create:** `static/js/inventory/stock-consumption.js`, `static/js/pages/inventory-v9.js`, `regression_tests/test_stock_consumption_feature.cjs`, `regression_tests/test_stock_consumption_ui.cjs`.

**Modify:** `static/index.html`, `regression_tests/test_frontend_entrypoints.cjs`, `docs/frontend-organisation.md`.

**Interfaces:** Produce the four owned properties; consume exact core providers without wrappers. Existing HTML remains the caller of opening/submission/cancellation.

- [x] **Step 1: Baseline.** Run `node --test regression_tests/*.cjs` and `/workspace/scratch/22e193396fd5/timezone-venv/bin/python -m pytest -q` on merged PR109. Expected: 259 Node and 830 Python tests pass. Record frozen v8 hash and application contract before editing production files.
- [x] **Step 2: Isolated contracts RED and prior behavior.** Assert exact sorted keys `consumeForm`, `consumeItem`, `consumeStock`, `showConsumeModal`, exact defaults and independent forms. Assert opener replaces form with complete metadata, quantity 1 and blank work-order/notes even after form `{}`. Compose real feature with core providers, asserting each `this` receiver and exact POST/refresh/timer order. Run `node --test regression_tests/test_stock_consumption_feature.cjs`. Expected: fail on missing feature. Also write the shipped behavior cases in Step 6 now and run them on v8; expected all pass, establishing current behavior before the move.
- [x] **Step 3: Extraction GREEN.** Move both defaults and two method bodies unchanged into `stockConsumptionFeature()`. Run isolated tests. Expected: pass without wrappers or body rewrites.
- [x] **Step 4: Entrypoint contracts RED.** Expect the exact v9 index manifest/cache key and consumption factory only on index. Add cached-v8 construction with its original scripts/frozen SHA and compare all 265 properties/descriptors/defaults/method/getter sources. Extend the frozen-controller regression guard through v8. Run `node --test regression_tests/test_frontend_entrypoints.cjs`. Expected: fail on still-v8 manifest/factory before wiring.
- [x] **Step 5: Wiring GREEN.** Copy v8 to v9, remove only owned properties, compose a fresh consumption feature and update index references. Run isolated and entrypoint tests. Expected: all pass; cached v8 does not require the new factory.
- [x] **Step 6: Shipped behavior GREEN.** Rerun the v8-established `test_stock_consumption_ui.cjs` cases on shipped v9. Cover opener metadata/defaults/reopening and form independence; string ID/quantity, trimmed work order, blank/present notes, and exact POST. A deferred write retains form/modal and shared loading. Success closes/empties form before inventory → movements → dashboard; use real `refreshDashboard()` with traced statistics/equipment providers, and verify selected-store filtering with identically named stores/different IDs versus no selected store. Verify exact 5,000 ms timer/callback. Write rejection retains form/modal; rejection at each refresh stage preserves saved/cleared state/error/server message, stops later providers and avoids the timer. Pin real core inventory-refresh swallowed-error/loading behavior. Run `node --test regression_tests/test_stock_consumption_ui.cjs regression_tests/test_stock_consumption_feature.cjs regression_tests/test_frontend_entrypoints.cjs`. Expected: all pass through real shipped-page references.
- [x] **Step 7: Verify and document.** Update ownership, providers, active controller and frozen compatibility guide. Run both full suites, `node --check` on both new production files and `git diff --check`; expected all pass. Require v8/v9 contract equivalence, historical controllers/other features/helpers/pages/backend byte-identical and index non-script markup identical. Report rendered browser checks as pending under the existing access limitation.
- [x] **Step 8: Review and publication.** One fresh final whole-branch reviewer checks the approved spec/plan and all five Review Focus areas. Fix Critical/Important findings with RED→GREEN and full verification; record Minor findings. Commit and publish one PR only after publication authorization, verifying remote source tree matches tested local source. Owner merges; no production writes.

## Plan self-review

Consumption owns its form and lifecycle together; history/dashboard providers remain core. The unused work-order collection is not part of the consumption form boundary. Each review-focus condition has explicit tests. Existing cancellation, navigation, timer and loading/error semantics remain specified rather than silently improved. This plan implements the next boundary under the approved frontend architecture and awaits owner review.

## Verification result

830 Python tests and 276 JavaScript tests pass. Both new production files pass syntax checks; whitespace checks pass. All 265 application properties/descriptors/defaults/method/getter sources match v8. Fresh final review found no Critical, Important or Minor issues and independently verified every existing static file except index unchanged, with index changes limited to script references. Backend files are unchanged. The cancel-binding and real-dashboard tests preserve reopening and completion before filtering/timer scheduling. Browser verification remains pending under the existing access limitation. The owner authorized publication after verification and final review. The remote source tree must match the tested local source; owner merges the PR.
