# Stock Dispatch Frontend Extraction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Preserve Native execution with one fresh final whole-branch review. Steps use checkbox tracking.

**Goal:** Give the stock-dispatch form and submission workflow one feature owner without changing existing behavior.

**Architecture:** `stockDispatchFeature()` supplies the transfer form, modal flag and two existing methods. A new v7 inventory entrypoint composes it with existing features; replenishment continues to call its opener and update the composed form, while navigation continues to close its modal.

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
- Freeze `static/script.js` and historical inventory controllers through v6 byte-for-byte. V6 blob SHA: `1ea6022d24ad4c5b3d332c7bd557bc09026d35e2`.
- Existing helpers, reports, replenishment, counts, imports and receipts remain byte-identical. Other four HTML pages remain byte-identical; index changes only script references.
- Preserve current numeric parsing, form-reset timing, messages, refresh order and loading semantics. `transferStock()` currently has no method-level duplicate-submit guard; this extraction does not add one. HTML retains its existing disabled submit button and validation attributes.
- Preserve the activity-log fix from merged PR107; no backend files change.

## Ownership and Interfaces

Create `static/js/inventory/stock-dispatch.js` exposing `stockDispatchFeature(): object`, owning exactly four properties:

| Kind | Properties |
| --- | --- |
| State | `transferForm: {inventory_id:'', to_store_id:'', quantity:''}`, `showTransferModal: false` |
| Methods | `transferItem(item)`, `transferStock()` |

Move defaults and both method bodies unchanged from v6. `transferItem(item)` retains the existing form object, resets `replenishment=false` and `max_quantity=null`, sets the inventory ID, quantity 1 and blank destination, then opens the modal. Replenishment writes its destination, quantity, maximum and mode after invoking this opener; do not change that sequence or bind the method to the isolated feature.

`transferStock()` retains its single POST `/inventory/transfer` with parsed integer inventory/destination/quantity fields and optional `{replenishment:true}`. On success, copy the server message, close the modal and replace the form with the initial three-field shape before refreshing inventory, statistics and pending transfers in that order. Schedule the existing 3,000 ms success-message reset only after those refreshes. Preserve write-failure form/modal state and existing post-write refresh-failure wording/state. Core inventory refresh retains its existing swallowed-error and loading behavior.

Consumed providers through composed `this`: `loading`, `error`, `successMessage`, `apiCall(endpoint, options?)`, core `loadInventory(options?)`, core `loadStats()`, receipt feature `loadPendingTransfers()`. Browser dependency: `setTimeout(callback, delay)`; existing parseInt and JSON behavior remains unchanged.

Intentional cross-feature writes: replenishment modifies the dispatch form, core `openPanel(panelName)` sets `showTransferModal=false`, and existing HTML updates/cancels the modal. Their bodies and markup remain unchanged. Equipment transfers and all other stock forms stay with their current owners.

Create `static/js/pages/inventory-v7.js` from v6, remove only the four owned properties, and add a fresh stock-dispatch feature to composition. Preserve all 265 application properties/descriptors/defaults/method/getter sources.

Index local order: temporal, audit, shared csrf, shared time-context, shared features, reports, replenishment, stock-counts, stock-imports, transfer-receipts, stock-dispatch, inventory-v7. All local scripts defer and use `?v=20261013-frontend-7`, followed by the unchanged Alpine CDN script.

## Review Focus

1. Manual dispatch after replenishment review clears mode/maximum/destination and does not retain stale form values.
2. Replenishment still refreshes/revalidates its plan before populating the dispatched form; stale suggestions never open it.
3. Ordinary versus replenishment payloads, server messages and refresh/timer order remain unchanged, including write and post-write refresh failures.
4. Composed receiver/provider access and navigation modal closure work; forms are independent between application instances.
5. Cached v6 and active v7 construct equivalent applications, with correct script order and unchanged prior feature implementations.

---

### Task 1: Extract and wire stock dispatch

**Create:** `static/js/inventory/stock-dispatch.js`, `static/js/pages/inventory-v7.js`, `regression_tests/test_stock_dispatch_feature.cjs`, `regression_tests/test_stock_dispatch_ui.cjs`.

**Modify:** `static/index.html`, `regression_tests/test_frontend_entrypoints.cjs`, `docs/frontend-organisation.md`.

**Interfaces:** Produce the four properties above; consume the shared core providers and receipt loader without wrappers. Replenishment and navigation remain unchanged callers.

- [x] **Step 1: Baseline.** Run `node --test regression_tests/*.cjs` and `/workspace/scratch/22e193396fd5/timezone-venv/bin/python -m pytest -q` on merged PR107. Expected: 216 Node and 830 Python tests pass. Record v6 hash and application contract before editing production files.
- [x] **Step 2: Isolated contracts RED.** Assert exact sorted keys `showTransferModal`, `transferForm`, `transferItem`, `transferStock`; default modal false and exactly three blank form fields; independent forms across instances. Assert manual opener retains its form object while setting ID/quantity/destination and clearing replenishment mode/maximum. Compose real receipt and dispatch features with core providers, asserting provider `this` is the application and exact POST/refresh order. Run `node --test regression_tests/test_stock_dispatch_feature.cjs`. Expected: fail because the new feature is missing. Also write the shipped behavior cases specified in Step 6 now and run them against shipped v6 before any production move; expected: all pass, establishing the pre-extraction behavior.
- [x] **Step 3: Extraction GREEN.** Move both defaults and method bodies unchanged into `stockDispatchFeature()`. Run isolated tests. Expected: pass with no new provider or body rewrite.
- [x] **Step 4: Entrypoint contracts RED.** Expect the exact v7 manifest/cache key and dispatch factory only on index. Add cached-v6 construction with its original scripts/frozen SHA and comparison of all 265 application properties/descriptors/defaults/method/getter sources. Extend the frozen-controller regression guard through v6. Run `node --test regression_tests/test_frontend_entrypoints.cjs`. Expected: fail on the unchanged v6 index manifest/factory.
- [x] **Step 5: Wiring GREEN.** Copy v6 to v7, remove only owned properties, compose a fresh dispatch feature and update index references. Run isolated and entrypoint tests. Expected: pass; cached v6 does not require the new dispatch factory.
- [x] **Step 6: Shipped behavior.** Rerun the `test_stock_dispatch_ui.cjs` cases established on v6 in Step 2 against shipped v7. Cover normal string-field integer payload versus replenishment payload, shared feedback/loading during a deferred POST, success close/reset before inventory → stats → real pending-transfer loader, and the 3,000 ms timer callback. Verify write rejection retains form/modal; refresh rejection after successful write retains reset form/closed modal/server message and sets existing error wording without scheduling the timer. Exercise real inventory refresh swallowed-error/loading semantics. Assert manual opener after replenishment clears mode/maximum; real replenishment review still fills the dispatch form with no POST, and core navigation closes the modal. Check independent forms. Run `node --test regression_tests/test_stock_dispatch_ui.cjs regression_tests/test_replenishment.cjs regression_tests/test_replenishment_feature.cjs regression_tests/test_transfer_receipts_ui.cjs`. Expected: all pass, including existing stale-plan/no-write contracts.
- [x] **Step 7: Verify and document.** Update ownership, providers, cross-feature calls, active controller and frozen-file guide. Run both full suites, `node --check` on both new production files, and `git diff --check`; expected all pass. Require v6/v7 contract equivalence, historical controllers/other features/pages/backend byte-identical and index non-script markup identical. Report rendered browser checks as pending under the existing access limitation.
- [x] **Step 8: Review and publication.** One fresh final whole-branch reviewer checks the approved spec/plan and all five Review Focus areas. Fix Critical/Important findings with RED→GREEN and full verification; record Minor findings. Commit and publish one PR only after publication authorization, verifying the remote tree matches tested local source. Owner merges; no production writes.

## Plan self-review

Dispatch and receipts are separate owners connected by the existing pending-transfer loader. Replenishment owns its planning state and uses the composed dispatch interface; navigation deliberately closes the shared modal. All review-focus areas have explicit tests. Existing parsing, refresh errors and loading behavior remain unchanged. This plan implements the next boundary under the approved frontend architecture and awaits owner review.

## Verification result

830 Python tests and 231 JavaScript tests pass. Both new production files pass syntax checks; whitespace checks pass. All 265 application properties/descriptors/defaults/method/getter sources match v6. Fresh final review found no Critical, Important or Minor issues and independently confirmed 27 other preexisting static files, all 73 backend Python files, and index non-script markup unchanged. Browser verification remains pending under the existing access limitation. The owner authorized publication after verification and final review. The remote source tree must match the tested local source; owner merges the PR.
