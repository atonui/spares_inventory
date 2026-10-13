# Transfer Receipts Frontend Extraction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Preserve Native execution with one fresh final whole-branch review. Steps use checkbox tracking.

**Goal:** Give pending stock transfers and physical receipt/return confirmation one feature owner while preserving current behavior.

**Architecture:** `transferReceiptsFeature()` returns fresh pending-transfer state and the three existing receipt methods. A new v6 inventory entrypoint composes it with the current core and features; cached v5 retains its original dependency graph.

**Tech Stack:** Existing classic JavaScript, AlpineJS 3.13.0, Node VM regressions and FastAPI/pytest. No new dependencies or build step.

**Spec:** `docs/superpowers/specs/2026-10-13-frontend-organisation-design.md` (already owner-approved architecture).

**Status:** Implemented and verified; fresh final review found no issues. Prepared for publication and owner merge. Native execution retained from the approved workflow.

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
- Freeze `static/script.js` and inventory controllers through v5 byte-for-byte. V5 blob SHA: `8b03ce5ad0577f7d25fc2e2bcb52ee0d1ec508b5`.
- Existing shared helpers, reports, replenishment, counts and imports remain byte-identical. Other four HTML pages remain byte-identical; index changes only script references.
- Preserve current confirmation messages, failure wording, refresh order and loading semantics, including loading changes made by core `loadInventory()` and its existing error handling. Do not add guards or fix lifecycle behavior in this extraction.

## Ownership and Interfaces

Create `static/js/inventory/transfer-receipts.js` exposing `transferReceiptsFeature(): object`, owning exactly four properties:

| Kind | Properties |
| --- | --- |
| State | `pendingTransfers: []` |
| Methods | `loadPendingTransfers()`, `refreshTransfers()`, `confirmTransfer(transfer, action)` |

Move the default and all three method bodies unchanged from v5. Core providers accessed through composed `this`: `apiCall(endpoint, options?)`, `loadStats()`, `loadInventory(options?)`, `loadMovements()`, `loading`, `error`, `successMessage`, `selectedStore`, `storeInventory`, `inventory`. External dependency: browser `confirm(message)` and JSON.

`loadPendingTransfers()` reads `/inventory/transfers`; `refreshTransfers()` clears the shared error then loads transfers and statistics in that order. Confirmation preserves the existing `can_receive`/`can_return` and busy guards, physical receipt/return prompts, and POST `/inventory/transfers/${transfer.id}/${action}` with `{confirmed:true}`. Success refreshes transfers, inventory, selected-store inventory by ID, movements, then statistics. Failure keeps current error wording and releases loading through the existing finally block.

Keep `transferItem(item)`, `transferStock()`, `transferForm`, `showTransferModal`, equipment transfers and lifecycle `loadAllData()` in core. Their calls to `loadPendingTransfers()` resolve through the composed application, without wrappers or rebinding.

Create `static/js/pages/inventory-v6.js` from v5, removing only these four properties and adding the feature to the existing composition. Keep all 265 public properties equivalent, including descriptors, defaults and method/getter sources.

Index local script order: temporal, audit, shared csrf, shared time-context, shared features, reports, replenishment, stock-counts, stock-imports, transfer-receipts, inventory-v6. Each local reference uses `?v=20261013-frontend-6` and defer, followed by the unchanged Alpine CDN script.

## Review Focus

1. Receipt and return permissions/declined prompts prevent writes and preserve shared state.
2. Duplicate confirmation during a pending POST respects the existing shared loading guard; later core refresh loading behavior remains unchanged.
3. Write and refresh failures retain the existing pending-transfer/error/success state and request order; no accidental new retry/write.
4. Identically named stores filter refreshed balances by selected-store ID, and core dispatch/startup reach the composed transfer loader.
5. Factories allocate independent arrays; cached v5 and active v6 construct equivalent applications with the correct script order.

---

### Task 1: Extract and wire transfer receipts

**Create:** `static/js/inventory/transfer-receipts.js`, `static/js/pages/inventory-v6.js`, `regression_tests/test_transfer_receipts_feature.cjs`.

**Modify:** `static/index.html`, `regression_tests/test_frontend_entrypoints.cjs`, `regression_tests/test_transfer_receipts_ui.cjs`, `docs/frontend-organisation.md`.

**Interfaces:** Produce the four owned properties and consume the exact core providers above. Reuse the existing descriptor composer unchanged.

- [x] **Step 1: Baseline.** Run `node --test regression_tests/*.cjs` and `/workspace/scratch/22e193396fd5/timezone-venv/bin/python -m pytest -q` on merged PR105. Expected: 195 Node and 826 Python tests pass. Record v5 hash and application contract before editing production files.
- [x] **Step 2: Isolated contracts RED.** Write tests using the real composer asserting the sorted keys are exactly `confirmTransfer`, `loadPendingTransfers`, `pendingTransfers`, `refreshTransfers`; initial array is empty and independent between instances. Assert API/refresh providers receive the composed application as `this`, transfer read assigns its returned rows, and explicit refresh orders transfer read before stats. Run `node --test regression_tests/test_transfer_receipts_feature.cjs`. Expected: fail because the feature file is missing.
- [x] **Step 3: Extraction GREEN.** Move the one default and three bodies unchanged into `transferReceiptsFeature()`. Run the isolated test command. Expected: pass with no production wrapper or new provider.
- [x] **Step 4: Entrypoint contracts RED.** Expect the exact v6 index manifest/cache key and transfer factory only on index. Add cached-v5 startup using its original manifest and frozen SHA; compare all 265 descriptors/defaults/method/getter sources with the active application. Extend the frozen-controller regression guard through v5. Run `node --test regression_tests/test_frontend_entrypoints.cjs`. Expected: fail on the still-v5 index manifest/factory before wiring.
- [x] **Step 5: Wiring GREEN.** Copy v5 to v6, remove only owned properties and compose a fresh receipt feature. Update index references as specified. Run the entrypoint and feature test files. Expected: pass; cached v5 remains independent of the new feature.
- [x] **Step 6: Shipped behavior coverage.** Retain the three existing receipt regressions and add successful receive/return exact prompts and POST bodies; denied permissions and declined prompts leave state/request count unchanged; a deferred POST blocks a second confirmation; request failure retains pending rows and sets `Confirmation failed: <message>`; explicit refresh failure sets `Failed to refresh transfers: <message>`; refresh rejection after a successful write preserves success message and releases loading. Assert success ordering transfers → inventory → selected-store filtering → movements → statistics, including duplicate store names with different IDs. Cover core dispatch and `loadAllData()` invoking the real composed transfer loader, and independent application pending arrays. Run feature, entrypoint and receipt UI tests. Expected: all pass. Tests pin existing core loading/error behavior; they do not invent stronger concurrency semantics.
- [x] **Step 7: Verify and document.** Update the ownership/providers, current-controller and frozen-entrypoint sections in the guide. Run both full suites, `node --check` for both new production files, and `git diff --check`; expected all pass. Require v5/v6 application equivalence, frozen files/other features/pages byte-identical and index non-script markup identical. Report rendered browser verification as pending under the existing access limitation.
- [x] **Step 8: Review and publication.** One fresh final whole-branch reviewer checks the spec, this plan and all five Review Focus areas. Fix Critical/Important findings with RED→GREEN verification and full suites; record Minor findings. Commit and publish one PR with the remote source tree verified against the tested local tree. Owner merges; no production writes.

## Plan self-review

The boundary owns physical receipt/return confirmation, not dispatch forms or equipment transfers. All four properties have one owner, and both core callers retain flat application access. Tests cover every review-focus condition and frozen asset compatibility. Existing loading/error semantics are explicitly preserved. The existing approved architecture supplies the spec; this plan chooses the next boundary and remains subject to owner review.

## Verification result

826 Python tests and 216 JavaScript tests pass. Both new production files pass syntax checks; whitespace checks pass. All 265 application properties/descriptors/defaults/method/getter sources match v5. Seventeen historical controller/feature/helper/page files remain byte-identical; index changes only script references. Fresh final review found no Critical, Important or Minor issues across all five review-focus areas. Browser verification remains pending under the existing access limitation. The owner explicitly authorized publication after verification and final review. Owner merges the PR.
