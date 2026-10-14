# Movement History Frontend Extraction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Preserve Native execution with one fresh final whole-branch review. Steps use checkbox tracking.

**Goal:** Give movement-history rows, filters, metadata and view/export operations one feature owner without changing behavior.

**Architecture:** `movementHistoryFeature()` supplies nine existing properties, composed by a new v16 inventory controller. Core retains API/date/CSV helpers, lifecycle/navigation and comprehensive inventory export. Other stock features continue calling the composed movement loader.

**Tech Stack:** Existing classic JavaScript, AlpineJS 3.13.0, Node VM regressions, FastAPI and pytest. No new dependencies or build step.

**Spec:** `docs/superpowers/specs/2026-10-13-frontend-organisation-design.md` (owner-approved architecture).

**Status:** Owner approved; implementation and verification complete. Fresh final review approved without findings. Native execution retained; automatic publication authorized.

## Global Constraints

- Retain screens, Alpine bindings, permissions, requests, authentication, CSRF recovery, timezone handling, stock workflows and exports.
- Owner merges; no deployment/production writes. Standing authorization permits automatic verified branch/PR publication without another publication question.
- No bundler, installation, runtime dependency, framework migration, HTML redesign, CSS reorganisation, new feature, endpoint, database migration or unrelated fix.
- Preserve global factories/flat application; use existing descriptor composition and duplicate-owner rejection, fresh state and composed receivers.
- Freeze static/script.js and controllers through v15. V15 blob SHA: `1aace8cb6db43d1f9baf976745e8261e78deef80`.
- Existing helpers/features and other four HTML pages remain byte-identical; index changes only script references. Backend/database/dependencies remain unchanged, including nullable activity actors.
- Copy defaults and bodies unchanged. No added loading/error handling, validation, awaits, sorting, metadata races or navigation changes.
- Browser/mobile verification remains pending under the existing credential-session limitation; do not reset or route around it.

## Ownership and Interfaces

Create `static/js/inventory/movement-history.js` exposing `movementHistoryFeature(): object`, owning exactly nine properties:

| Kind | Properties |
| --- | --- |
| State (4) | `movementTimeContext:null`, `showMovementsPanel:false`, `movements:[]`, `movementFilters:{startDate:'',endDate:'',movementType:'',partId:'',storeId:''}` |
| Methods (4) | `loadMovements()`, `clearMovementFilters()`, `toggleMovements()`, `exportMovementsCSV()` |
| Getter (1) | `recentActivity` |

Core providers through composed `this`: `apiCall(endpoint,options?,onTimeContext?)`, `formatBusinessInstant(value,context)`, `downloadCSV(headers,rows,filename)`. External dependencies: URLSearchParams and Date. Core startup calls the loader; navigation closes its panel and logout clears its metadata; comprehensive export reads movements/context. Stock entry/consumption/dispatch/receipts call the same loader. Document intentional cross-owner calls/writes; preserve all existing names and flat access.

Load builds truthy start_date/end_date/movement_type/part_id/store_id in that order, uses `/movements` with no query when blank and no added limit, calls apiCall with metadata callback and replaces rows. No loading/feedback changes or local catch; rejected API calls propagate and leave previous rows/context. Shared API retains real time-context header validation.

Clear filters allocates a fresh blank five-field object and invokes loadMovements without returning/awaiting it. Toggle flips showMovementsPanel before requesting; opening awaits loadMovements, closing performs no request. Failure propagates with panel already open; do not add rollback. Getter returns first20 rows in existing order, remains live and returns a slice rather than the owned array.

CSV retains exact existing eleven headers/row order and optional fallbacks. Both timestamps use movementTimeContext, Date/Time and Confirmed At labels use its timezone or Unknown. Missing completion timestamp remains blank. Preserve transfer/confirmation fields and raw quantities, UTC filename movement_history_YYYY-MM-DD.csv and core downloadCSV receiver. Missing/invalid metadata must not silently use activity/viewer timezone. Comprehensive export remains core and consumes the same rows/context; no export rewrite.

Create static/js/pages/inventory-v16.js from v15, removing only nine properties and composing fresh movementHistoryFeature after activityLogsFeature. Preserve all265descriptors/defaults/method/getter sources. Index local order remains through activity-logs, followed by movement-history and inventory-v16, all defer with `?v=20261014-frontend-16`; remote Alpine3.13.0 unchanged.

## Review Focus

1. Exact query truthiness/order/encoding, blank endpoint/no limit, propagated errors and untouched loading/feedback preserve prior behavior.
2. Fresh unawaited filter reset, toggle open/close/failure state, actual movement navigation/apply/clear/export button bindings and live first20 getter preserve ordering/references.
3. Metadata header validation and both CSV timestamps use movement context independently of activity/viewer context; missing/invalid context remains Unknown.
4. Core startup/navigation/logout and existing stock feature refreshes continue calling/writing owned fields through the composed receiver; comprehensive export consumes the same data.
5. Exact CSV headers/optional transfer/confirmation fallbacks/UTC filename, fresh instances, cached v15 equivalence and frozen modules/markup remain correct.

---

### Task 1: Extract and wire movement history

**Create:** static/js/inventory/movement-history.js, static/js/pages/inventory-v16.js, regression_tests/test_movement_history_feature.cjs, regression_tests/test_movement_history_ui.cjs.

**Modify:** static/index.html, regression_tests/test_frontend_entrypoints.cjs, docs/frontend-organisation.md.

**Interfaces:** Produce nine properties above; consume exact core providers. Keep stock workflows and comprehensive export unchanged.

- [x] **Step 1: Baseline.** On merged PR116 (`8c7e79d`), full Node/Python suites pass515/830. Record v15 hash/application contract before production edits. Interpreter `/workspace/scratch/22e193396fd5/timezone-venv/bin/python`.
- [x] **Step 2: Isolated RED and prior behavior.** Assert exact9keys/defaults/fresh rows/filters/getter descriptor and composed API/callback/date/CSV receivers. Missing-module RED; establish Step6 shipped cases against unchanged v15 before moving code, all pass.
- [x] **Step 3: Extraction GREEN.** Copy defaults/four bodies/getter unchanged into movementHistoryFeature; isolated tests pass without new providers/body rewrites.
- [x] **Step 4: Entrypoint RED.** Expect v16 manifest/cache/inventory-only factory. Add cached-v15 original manifest/frozen hash/no new factory and compare265descriptors/defaults/function/getter sources. Extend historical guard through v15. Expected manifest/factory failures before wiring.
- [x] **Step 5: Wiring GREEN.** Copy v15 to v16, remove only owned properties, compose feature/update index references. Isolated/entrypoint tests pass; cached v15 self-contained.
- [x] **Step 6: Shipped behavior GREEN.** Rerun established v15 tests through v16. Empty/full encoded filters and numeric0/string0 truthiness, no limit, success callback and rejection preserving prior rows/context/loading/feedback. Actual movement navigation/apply/clear/export button bindings; filter reset fresh/nonreturned pending reload; toggle open awaits, close no request, rejection leaves open. recentActivity first20 existing order, fresh slice/live changes. Real API metadata valid/invalid/missing and GET credentials; activity/viewer context distinct. Exact eleven CSV headers/rows, timestamps with business context, unconfirmed fields blank, both unknown timestamps, UTC filename. Core startup/navigation/logout and comprehensive export use composed data; full existing stock regression suites prove refresh callers unchanged. Instance isolation. New feature/UI, entrypoint, temporal and stock suites pass.
- [x] **Step 7: Verify/document.** Update ownership/provider guide, active/frozen controller and plan status consistently. Full Node/Python, syntax/diff checks pass. Exact extraction/frozen tracked/backend/other pages/non-script markup unchanged; browser verification pending.
- [x] **Step 8: Review/publication.** One fresh final whole-branch reviewer checks spec/plan and five Review Focus areas. Fix Critical/Important RED→GREEN and reverify; record Minor findings. Commit/publish branch/PR automatically; remote tree must equal tested local source. Report link; owner merges, no production writes.

## Plan self-review

Movement data/filters/metadata and its recent-history getter/export share one owner. Comprehensive inventory export stays core until its own boundary. Rejection, toggle and unawaited-reset behavior are explicit compatibility requirements. All five review-focus areas have concrete tests. Architecture approved; plan is owner-approved, Native retained and publication authorized.

## Execution evidence

Baseline: 515 JavaScript and 830 Python tests passed. Three isolated tests failed on the missing module; 14 shipped behavior cases passed on unchanged v15. Entrypoint RED had two expected manifest/factory failures. Final targeted suite: 58 passed; full suites: 533 JavaScript and 830 Python passed. Syntax, diff, exact extraction, 269 frozen tracked files and non-script markup checks passed. Fresh final reviewer independently approved without findings. Active core is 857 lines. Browser/mobile verification remains pending under the existing access limitation. Publication follows standing authorization; owner merges.
