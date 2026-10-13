# Consumption Reports Frontend Extraction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Execution method: Native implementation, then one fresh whole-branch review.

**Goal:** Give consumption reporting and work-order drill-down their own state/method owner without changing the application's behaviour.

**Architecture:** A fresh `consumptionReportsFeature()` provides report state and methods. `composeInventoryFeatures(...parts)` copies descriptors onto the same flat Alpine-facing application object and rejects duplicate ownership. A versioned active entrypoint avoids imposing new dependencies on older cached HTML.

**Tech Stack:** Existing classic JavaScript scripts, AlpineJS 3.13.0, FastAPI static hosting, Node VM tests and pytest; no new dependencies or build step.

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
- Do not introduce a generic event bus or global singleton store.
- Keep `static/script.js` unchanged. Also freeze the PR101 `static/js/pages/inventory.js` at blob SHA `5d0cae3938b31619656eb80a2fa70beaeb0a89b6`; its old HTML lacks the new dependencies.
- New inventory HTML loads `static/js/pages/inventory-v2.js`; it never loads either frozen entrypoint. Other four pages remain unchanged.
- All local inventory-page scripts defer, in the order below, with `?v=20261013-frontend-2`; the unchanged deferred Alpine CDN script comes last.

## Ownership and Interfaces

**Create `static/js/inventory/reports.js`:**

`consumptionReportsFeature(): object` owns exactly these existing properties:

| Kind | Properties |
| --- | --- |
| State | `showReportsPanel`, `consumptionReport`, `reportOptions`, `reportForm`, `reportBusy`, `reportExportBusy`, `reportError`, `reportDirty`, `reportOffset`, `reportRequest`, `reportAppliedQuery` |
| Methods | `formatReportInstant(value)`, `markReportDirty()`, `reportQuery()`, `loadConsumptionReport(offset=0)`, `openWorkOrderReport(number)`, `exportConsumptionReport()` |

Move their defaults and method bodies unchanged. The state factories must allocate fresh forms, filter-option arrays and objects. This is only consumption reporting; the comprehensive export and other CSV methods remain with their current owner for a later boundary.

`resetConsumptionReports(app: object): void` owns the existing logout reset: increment `reportRequest`, clear `reportBusy` and `consumptionReport`, replace `reportOptions` with empty parts/stores/engineers arrays, clear `reportAppliedQuery`, set `reportDirty=true`. Do not additionally reset forms, offsets, messages or export state: that would change behaviour. The core logout calls this function at exactly the current reset point. It does not become a new Alpine-facing property.

**Dependencies supplied by the core application:** `timezoneContext`, `currentUser`, `apiUrl`, `token`, `apiCall(endpoint, options?, onTimeContext?)`, `businessToday()`, `closeAllPanels()`, `logout(options?)` and `showInventoryPanel`. Preserve their existing signatures and behaviour. External report dependencies remain `InventoryTime`, URLSearchParams, Fetch, URL, Blob responses and DOM download APIs.

**Intentional cross-feature calls:** core `closeAllOtherPanels()` and `closeAllPanels()` close `showReportsPanel`; `openPanel('showReportsPanel')` starts `loadConsumptionReport()`; core logout delegates only its existing report reset. Report drill-down calls core navigation. These remain direct accesses through the flat composed `this` object.

**Create `static/js/shared/features.js`:**

`composeInventoryFeatures(...parts: object[]): object` copies each part's own property descriptors, including symbol keys, onto a fresh ordinary object. It checks for duplicate keys with own-property semantics and throws an error naming the duplicate before accepting that duplicate. Getters must not run during composition. Do not clone or share factory state, bind methods to an individual part, or permit ordered overrides. Factories, rather than composition, provide fresh nested state.

**Create `static/js/pages/inventory-v2.js`:**

`inventoryApp(): object` constructs the existing core object without the 17 report-owned properties and returns `composeInventoryFeatures(core, consumptionReportsFeature())`. Remaining state/methods/getters stay unchanged. Logout's two report-reset statements become `resetConsumptionReports(this)`; its ordering relative to session revocation/local logout remains unchanged. No extra public application properties are introduced.

**Inventory HTML local script order:** `temporal.js`, `audit.js`, `js/shared/csrf.js`, `js/shared/time-context.js`, `js/shared/features.js`, `js/inventory/reports.js`, `js/pages/inventory-v2.js`, followed by the existing Alpine CDN script. Script references are the only markup changes.

## Compatibility decision

PR101 HTML references `pages/inventory.js`. Replacing that controller with code requiring new files would fail when an old page has not learned the new script list. Therefore keep that first controller frozen, alongside the original `script.js`, and use a new active filename for the changed dependency graph. The cost is one additional historical controller retained on disk; new pages load exactly one active controller. Retiring compatibility files or choosing a release-asset generation system is separate work, not an implicit part of this extraction.

## Review Focus

1. Cold new HTML and cached PR101 HTML: both must construct a functioning report-capable app with their own dependency lists.
2. Existing getters and method receivers: composition must never evaluate a getter or bind a report method to its isolated feature object.
3. A second app/feature instance: forms/options remain independent; logout reset cannot affect another instance.
4. An in-flight report during logout or account change: stale data cannot reappear after the existing request/actor checks invalidate it.
5. Navigation and CSV: drill-down keeps active filters and export uses the applied query/report timezone revision without pagination filters.

---

### Task 1: Extract, compose and release the report boundary

**Files:**
- Create: `static/js/shared/features.js`, `static/js/inventory/reports.js`, `static/js/pages/inventory-v2.js`, `regression_tests/test_frontend_features.cjs`, `regression_tests/test_consumption_reports_feature.cjs`.
- Modify: `static/index.html`, `regression_tests/test_frontend_entrypoints.cjs`, `regression_tests/test_stock_reports_ui.cjs`, `docs/frontend-organisation.md`.
- Preserve byte-for-byte: `static/script.js`, `static/js/pages/inventory.js`.
- Existing report/timezone/security/stock tests continue to use the shipped-page loader; all other pages/controllers remain unchanged.

**Consumes/produces:** Exact production interfaces and ownership are defined above. Later feature extractions consume `composeInventoryFeatures(...parts)`; they do not change its collision or descriptor policy.

- [x] **Step 1: Baseline.** Run full Node and Python suites on merged PR101 before editing. Record the two frozen files' hashes and the complete inventory application's property-descriptor shape.
- [x] **Step 2: Write composition tests and observe RED.** Load only the new shared file in a VM. Test that a getter is not evaluated during composition, reads updated composed state later, and a method's receiver is the composed object. Assert enumerable/configurable/writable flags and symbol keys survive, and duplicate string/symbol keys throw a named error instead of overriding. The initial failure is the absent composition implementation.
- [x] **Step 3: Implement composition, then observe GREEN.** Implement only the descriptor-copy policy specified above. Run the focused composition tests.
- [x] **Step 4: Write feature tests and observe RED.** Load temporal helpers and the new report feature directly. Assert its own-key set equals the 17 named properties, defaults match current behaviour and separate factories allocate separate forms/options. Supply core dependencies on a composed object, exercise filtered query/drill-down and report formatting, and assert `resetConsumptionReports` preserves form/offset/export fields while invalidating the request and clearing exactly the existing fields. Initial failure is the absent feature module.
- [x] **Step 5: Move the feature and observe GREEN.** Copy the owned state/methods and formatter unchanged; move the two reset statements into the specified standalone reset function. Run focused feature/composition tests.
- [x] **Step 6: Write integration/compatibility tests and observe RED.** Update only the index manifest expectation to the exact new script order/cache version. Require `consumptionReportsFeature` and `composeInventoryFeatures` on index only. In a fresh legacy VM, load the PR101 temporal/audit/CSRF/context dependencies and frozen v1 controller, verify report query/work-order drill-down still work, and pin its blob hash. Preserve original script compatibility coverage and unchanged other-page manifests. The old index manifest must fail the new expectation before wiring.
- [x] **Step 7: Create the active v2 controller and wire index.** Build the core without the owned report properties, compose it with a fresh feature, delegate the reset and apply only the new script references. Preserve flat application descriptor shape and all existing getter/receiver tests. Add active-controller guard coverage so ordinary regressions cannot accidentally target either frozen controller.
- [x] **Step 8: Add lifecycle regressions.** From the shipped index entrypoint, open Reports through `openPanel`, drill down a work order with current filters, and start a pending report before `logout({localOnly:true})`. Resolve the request afterward and assert no prior report/options reappear. Preserve the existing account-change and CSV tests; extend the CSV case to assert `expected_timezone_revision` survives and limit/offset do not enter the download query. Also verify reset is independent across two apps. Run the full Node suite.
- [x] **Step 9: Document and verify.** Update the guide's active file map, dependency order, report/core contract and compatibility policy. Compare moved report methods/state against v1, unchanged aside from structural wrappers. Run full Python/Node suites, syntax checks for all three new production files, staged `git diff --check`, and frozen-file comparisons. Record browser/rendered checks as unverified if no permitted session is available.
- [ ] **Step 10: Fresh review and publication.** One fresh reviewer checks the approved spec, this plan, all five Review Focus conditions and the whole diff. Fix Critical/Important findings with RED→GREEN tests and full verification. Commit and publish one PR whose remote tree matches the tested local tree. The owner merges/deploys; no live stock or setting writes.

## Self-review

All report-owned keys, provider calls, reset semantics and helper interfaces are fixed before extraction. Cache compatibility is explicit rather than assuming query-string versions are immutable. Composition introduces no new application properties and preserves existing descriptors. The five review conditions each have a dedicated test step. Replenishment, comprehensive exports and larger frontend rearrangement remain outside this boundary.

**Execution record:** 826 Python tests and 159 Node tests pass; syntax and staged-whitespace checks pass. Fresh review found no Critical/Important issues. One deferred minor is ordinary-block formatting of the two new isolated test files. Historical controllers and existing error handling are intentionally preserved; rendered browser smoke remains pending.
