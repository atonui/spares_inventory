# Replenishment Frontend Extraction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Preserve Native execution with one fresh final whole-branch review.

**Goal:** Give replenishment planning, minimum editing and suggested-transfer review a clear feature owner while retaining existing behaviour.

**Architecture:** `replenishmentFeature()` provides fresh state/methods to the existing descriptor composer. The active v3 inventory entrypoint composes core, reports and replenishment; older entrypoints stay frozen for their cached HTML dependency lists.

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
- Preserve `static/script.js`, `static/js/pages/inventory.js`, and `static/js/pages/inventory-v2.js` byte-for-byte. V2 blob SHA: `63f39d96fbcd2e7d2be946bc784d42f5a9c5e948`.
- New index loads only `static/js/pages/inventory-v3.js`; other four pages remain unchanged. No historical controller loads alongside the new controller.
- Index local scripts defer with `?v=20261013-frontend-3`; unchanged Alpine CDN script follows all local dependencies.
- Existing consumption report feature/composer stay unchanged; comprehensive exports, transfer dispatch/receipt implementation and shared low-stock helpers remain outside this boundary.

## Ownership and Interfaces

Create `static/js/inventory/replenishment.js` exposing `replenishmentFeature(): object`, with exactly fourteen properties:

| Kind | Properties |
| --- | --- |
| State | `showLowStockPanel`, `replenishmentPlan`, `replenishmentBusy`, `replenishmentError`, `replenishmentStoreFilter`, `minimumBusy`, `minimumForm` |
| Getter | `replenishmentRows` |
| Methods | `loadReplenishment()`, `selectMinimum()`, `saveMinimum()`, `reloadMinimum()`, `reviewReplenishmentTransfer(row, suggestion)`, `exportProcurementCSV()` |

Move defaults, getter and method bodies unchanged. The panel flag currently lives later in the core object and must move with this feature; remove both ownership locations from the active core. Preserve fresh nested minimum-form state. Do not change server allocation, shortage arithmetic, null/error handling, busy guards, stale-suggestion rules or any API payload.

The feature consumes these core providers through composed `this`: `inventory`, `loading`, `inventoryLoadFailed`, `successMessage`, `transferForm`, `apiCall(endpoint, options?, onTimeContext?)`, `loadInventory({refreshReplenishment=true}={})`, `loadStats()`, `transferItem(source)` and `downloadCSV(headers, rows, filename)`. Number and Date browser APIs remain its external dependencies.

Core intentionally calls feature methods: `loadInventory` refreshes the plan only if `showLowStockPanel && refreshReplenishment`; `openPanel('showLowStockPanel')` loads it; navigation closes the panel flag. Preserve the `refreshReplenishment:false` calls in minimum saving and transfer review so those workflows fetch the plan once. Shared `isLowStock`, `lowStockItems`, inventory/catalog arrays and editable-store getters remain core providers because other views/exports use them. Transfer dispatch stays core: its `transferForm.replenishment` marker/payload continue unchanged.

Create `static/js/pages/inventory-v3.js`: retain the v2 core minus the fourteen owned properties, then return `composeInventoryFeatures(core, consumptionReportsFeature(), replenishmentFeature())`. Do not add public application keys or change report composition/reset.

Index local order: `temporal.js`, `audit.js`, `js/shared/csrf.js`, `js/shared/time-context.js`, `js/shared/features.js`, `js/inventory/reports.js`, `js/inventory/replenishment.js`, `js/pages/inventory-v3.js`. Preserve markup outside script references.

## Review Focus

1. Filtered plan rows: the getter remains lazy and filtering never reallocates server donor quantities.
2. Minimum editing: allocated rows are excluded; expected-minimum payload and failure/refresh feedback remain intact.
3. Suggested transfers: refresh order and failure guards prevent stale dispatch forms; the server plan is fetched once without an implicit stock write.
4. Independent instances and core navigation: forms/flags are fresh, and opening/refreshing the real replenishment view invokes the composed feature.
5. Cached v2 HTML and report coexistence: both old and new controllers work with their own dependencies; reports retain their previous state/descriptors/behaviour.

---

### Task 1: Extract and wire replenishment

**Create:** `static/js/inventory/replenishment.js`, `static/js/pages/inventory-v3.js`, `regression_tests/test_replenishment_feature.cjs`.
**Modify:** `static/index.html`, `regression_tests/test_frontend_entrypoints.cjs`, `regression_tests/test_replenishment.cjs`, `docs/frontend-organisation.md`.
**Interfaces:** Consume/produce exactly the globals, fourteen owned properties and providers above; reuse the existing composer/report feature unchanged.

- [x] **Step 1: Baseline.** Run full Node/Python suites on merged PR102. Record v2 hash and current application descriptor shape; preserve all three historical controllers.
- [x] **Step 2: Write feature tests and observe RED.** Load the new feature with the real descriptor composer. Assert its exact fourteen-key set, matching defaults, lazy getter response to changed plan/filter, independent forms and provider receiver identity. With supplied core providers, select an unallocated minimum, save the exact numeric/expected-minimum payload, and verify refresh order. Initial failure is absent feature implementation.
- [x] **Step 3: Move the feature and observe GREEN.** Copy the contiguous replenishment block and separate `showLowStockPanel:false` property into its factory unchanged. Run isolated tests and verify composition never evaluates the getter or changes its descriptor.
- [x] **Step 4: Write entrypoint expectations and observe RED.** Update only index to the exact v3 dependency table/cache key. Assert only index exposes the new feature. Add legacy v2 VM coverage using its original eight-script dependency list (including Alpine as excluded remote): cached v2 remains constructible, has working report/replenishment getters and is hash-identical. Preserve earlier legacy checks and other-page manifests. Existing index must fail the new source/order expectation before wiring.
- [x] **Step 5: Compose v3 and wire index.** Remove owned block/flag from its core, add fresh feature composition and only the prescribed script-reference changes. Preserve descriptor shape, all non-moved methods, reports/reset and UI markup. Extend the controller-regression guard to forbid accidental direct loading of frozen v2 outside deliberate compatibility tests.
- [x] **Step 6: Exercise real cross-feature flows.** Extend shipped-page regressions with `openPanel('showLowStockPanel')`, real `loadInventory` automatic refresh versus `refreshReplenishment:false`, and two-instance form/flag isolation. Await actual method promises, not assumed VM microtask counts. Retain existing stale-suggestion, no-write transfer review, blocked failed refresh, minimum payload, low-stock semantics, dashboard refresh and procurement export assertions. Verify report tests remain green.
- [x] **Step 7: Verify and document.** Run all Node/Python tests, syntax checks for both new production files, staged whitespace checks and byte comparisons for frozen files. Independently compare all v3 defaults/methods/getter sources with v2, and verify only moved ownership/composition differs. Update active-file/dependency/ownership guide and historical-controller policy. Record rendered browser QA unverified if access remains blocked.
- [ ] **Step 8: Fresh final review and publish.** One fresh reviewer checks the approved spec/plan and all five Review Focus conditions. Fix Critical/Important findings using RED→GREEN and full checks. Publish one PR with a verified matching remote tree; owner merges/deploys. No production data/settings writes.

## Self-review

Ownership includes the separately declared panel flag and its cross-feature consumers. Core low-stock semantics and dispatch implementation remain unchanged. Existing getter-safe composition is reused, with no override policy or new public properties. Each review condition maps to focused or shipped-page tests. Legacy v2 retention follows the already approved compatibility approach; its cost is another historical file until a separately reviewed retirement policy.

**Execution record:** 826 Python tests and 166 JavaScript tests pass; syntax and staged-whitespace checks pass. Fresh review found no Critical, Important or actionable Minor issue. All application descriptors/defaults/method/getter sources match v2. Historical controllers and existing refresh/error semantics are preserved; rendered browser verification remains pending.
