# Physical Stock Counts Frontend Extraction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Preserve Native execution with one fresh final whole-branch review.

**Goal:** Give physical-count entry, preview/confirmation and count-dialog focus handling one feature owner without changing inventory behaviour.

**Architecture:** `stockCountsFeature()` supplies fresh count state and its existing methods to the descriptor composer. The active v4 entrypoint composes core, reports, replenishment and counts; older entrypoints retain their original dependency graphs.

**Tech Stack:** Existing classic JavaScript, AlpineJS 3.13.0, FastAPI static hosting, Node VM tests and pytest; no new dependencies/build step.

**Spec:** `docs/superpowers/specs/2026-10-13-frontend-organisation-design.md`

**Status:** Approved by the owner; implemented and reviewed. Publication is recorded in PR metadata.

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
- Preserve all previous controllers byte-for-byte: `static/script.js`, `static/js/pages/inventory.js`, `inventory-v2.js`, `inventory-v3.js`. V3 blob SHA: `2bbb4df29f9ec3f5d403a59e8bb90f26cca10ca8`.
- New index loads only `static/js/pages/inventory-v4.js`; other four pages remain unchanged. No historical controller loads alongside the active controller.
- Index local scripts defer with `?v=20261013-frontend-4`; unchanged Alpine CDN script follows local dependencies.
- Reports, replenishment, shared composer, imports and transfer execution remain unchanged. This work reorganises the existing count workflow rather than altering correction or concurrency rules.

## Ownership and Interfaces

Create `static/js/inventory/stock-counts.js` exposing `stockCountsFeature(): object`, with exactly thirteen properties:

| Kind | Properties |
| --- | --- |
| State | `stockCount`, `stockCountPreview`, `stockCountBusy`, `stockCountTrigger` |
| Methods | `startStockCount(store, trigger=null)`, `previewStockCount()`, `editStockCount()`, `focusStockCountDialog()`, `restoreStockCountFocus()`, `restartStockCount()`, `cancelStockCount()`, `trapStockCountFocus(event, dialog)`, `confirmStockCount()` |

Move the four defaults and the contiguous nine-method block unchanged. Preserve the actual opener element reference in `stockCountTrigger`; do not serialize or clone DOM references. Sheet rows still receive fresh blank counted quantities/reasons using the current row-copy logic. Keep all prompts, busy guards, validation, signed-token payloads and status messages unchanged.

Core providers consumed through composed `this`: `error`, `successMessage`, `apiCall(endpoint, options?, onTimeContext?)`, `loadInventory(options?)`, `loadStats()`, `selectedStore`, `storeInventory`, `inventory`. Alpine supplies `$nextTick` and `$refs.stockCountDialog` on the composed application; count methods must not be bound to the isolated feature object. External dependencies remain Number/String/JSON, browser `confirm` and DOM focus APIs.

Count confirmation retains its existing order: confirm acknowledgement, set busy, POST signed preview token, mark saved and clear count/preview, set success text, refresh inventory, refresh selected-store rows by store ID, refresh stats, then clear busy and restore opener focus. Failed writes retain count/preview and refocus the dialog. A refresh failure after saving retains the existing saved-versus-not-saved error distinction. Do not change any existing core refresh/error semantics or add a logout reset.

Create `static/js/pages/inventory-v4.js`: remove the thirteen owned properties from its v3 core, then return `composeInventoryFeatures(core, consumptionReportsFeature(), replenishmentFeature(), stockCountsFeature())`. No new public application keys. Existing HTML count bindings/dialog markup stay identical.

Index local order: `temporal.js`, `audit.js`, `js/shared/csrf.js`, `js/shared/time-context.js`, `js/shared/features.js`, `js/inventory/reports.js`, `js/inventory/replenishment.js`, `js/inventory/stock-counts.js`, `js/pages/inventory-v4.js`. Script references are the only markup changes.

## Review Focus

1. Blank versus zero entries: blanks remain omitted, zero remains a valid submitted count, and corrections still require reasons.
2. Confirmation concurrency: signed preview payload/acknowledgement and busy guards prevent duplicate submissions; a declined prompt causes no write.
3. Alpine receiver/focus: dialog focus uses injected refs/nextTick; opener restoration waits for busy clearing and rendering; tab trapping remains unchanged.
4. Confirmation refresh: selected-store rows refresh by store ID, success/write-failure/refresh-failure paths retain existing state/messages and focus behaviour.
5. Fresh instances and cached v3 HTML: count state/opener references remain independent and both old/new dependency lists construct working applications.

---

### Task 1: Extract and wire physical stock counts

**Create:** `static/js/inventory/stock-counts.js`, `static/js/pages/inventory-v4.js`, `regression_tests/test_stock_counts_feature.cjs`.
**Modify:** `static/index.html`, `regression_tests/test_frontend_entrypoints.cjs`, `regression_tests/test_stock_counts_ui.cjs`, `docs/frontend-organisation.md`.
**Interfaces:** Consume/produce exactly the thirteen properties and providers above; reuse composer/reports/replenishment unchanged.

- [x] **Step 1: Baseline.** Run full Node/Python suites on merged PR103. Record v3 hash and full inventory descriptor shape; preserve all historical controllers.
- [x] **Step 2: Write isolated feature tests and observe RED.** Load the new feature with the real composer. Assert exact thirteen-key ownership/defaults and independent sheet/preview/busy/opener state. Supply core/Alpine providers on the composed object: start a sheet, submit zero while omitting blank entries, verify exact signed-preview payload and method receivers. Use a queued `$nextTick` fixture to prove dialog and opener focus resolve through the composed object and opener restoration follows busy clearing. Initial failure is missing feature implementation.
- [x] **Step 3: Move owned state/methods and observe GREEN.** Copy existing defaults and nine method bodies unchanged, including prompt text, DOM selection and focus logic. Run isolated tests; no bound wrappers or alternate focus implementation.
- [x] **Step 4: Write new entrypoint expectations and observe RED.** Change only index to the exact v4 dependency order/cache key; expose the count factory on index only. Add cached-v3 VM coverage with its original dependency list, count-sheet construction/defaults and v3 blob hash. Preserve all earlier compatibility contracts/other-page manifests. The current index must fail the new expectation before wiring.
- [x] **Step 5: Compose v4 and wire index.** Remove owned defaults/methods from core, add a fresh count feature, update only script references and extend the active-regression guard to forbid frozen v3. Preserve public keys/descriptors and all other method/getter sources.
- [x] **Step 6: Exercise shipped-page count lifecycle.** Retain existing count tests for blanks/zero, validation, exact payloads, duplicate-click blocking, declined confirmation, cancellation, restart/recount, no-control tab trapping and queued focus. Extend successful confirmation to verify selected-store refresh uses IDs, core inventory/stats providers run in order, and focus is restored after rendering/busy clearing. Cover write failure retaining preview and refresh failure after successful save preserving the existing message/focus path. Assert a second composed app retains independent state and trigger reference.
- [x] **Step 7: Verify and document.** Run full Python/Node suites, syntax checks for both new files, staged-whitespace checks and frozen-file comparisons. Independently compare every v4 application default/descriptor/method/getter with v3. Verify markup outside scripts is unchanged and shared feature modules were not modified. Update guide ownership/providers/active entrypoint/compatibility policy; record browser rendering unverified if access remains blocked.
- [ ] **Step 8: Fresh final review and publish.** One fresh reviewer checks the approved spec/plan and all five Review Focus conditions. Fix Critical/Important findings with RED→GREEN and full verification. Publish one PR whose remote tree matches the tested local tree; owner merges/deploys. No live count, stock or settings writes.

## Self-review

Ownership includes the opener reference and all focus methods. The provider contract includes Alpine magic properties and selected-store refresh rather than treating count logic as isolated from its dialog. Existing signed-token/acknowledgement/concurrency rules are preserved. Each review condition has isolated or shipped-page coverage. Cached-controller retention follows the approved policy; its cost is another historical file until a separately reviewed retirement policy.

**Execution record:** 826 Python tests and 176 JavaScript tests pass; syntax/staged-whitespace checks pass. Fresh review confirmed all 265 application properties/descriptors/defaults/method/getter sources match v3. Two explicitly planned edge-case tests absent from earlier coverage were added: declined confirmation and no-control focus trapping. Historical controllers/core refresh behaviour stay unchanged; rendered browser focus remains unverified.
