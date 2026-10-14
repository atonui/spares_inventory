# Activity Logs Frontend Extraction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Preserve Native execution with one fresh final whole-branch review. Steps use checkbox tracking.

**Goal:** Give activity-log filters, data, metadata, dialogs and operations one feature owner without changing behavior.

**Architecture:** `activityLogsFeature()` owns activity logging state and eight existing methods, composed by a new v15 inventory controller. Core retains authentication/API/loading/feedback, date formatting, generic CSV download and navigation. Movement history and its separate timezone context remain core for a later boundary.

**Tech Stack:** Existing classic JavaScript, AlpineJS 3.13.0, Node VM regressions, FastAPI and pytest. No new dependencies or build step.

**Spec:** `docs/superpowers/specs/2026-10-13-frontend-organisation-design.md` (owner-approved architecture).

**Status:** Owner approved; implementation and verification complete. Fresh final review approved without findings. Native execution retained; automatic publication authorized.

## Global Constraints

- Retain screens, Alpine bindings, permissions, requests, authentication, CSRF recovery, timezone handling, stock workflows and exports.
- Owner merges; no deployment or production data writes. Standing authorization permits automatic verified branch/PR publication without another publication question.
- No bundler, package installation, runtime dependency, framework migration, HTML redesign, CSS reorganisation, new feature, endpoint, database migration or unrelated bug fix.
- Preserve global factories and flat Alpine-facing object. Use existing descriptor composition/duplicate-owner rejection; preserve getters, method receivers, enumerability and fresh instance state.
- Freeze `static/script.js` and inventory controllers through v14 byte-for-byte. V14 blob SHA: `975dd3005c2a56536d227a5789c4a75dc8aa1d7c`.
- Existing helpers/features and other four HTML pages remain byte-identical; index changes only script references. Backend/database/dependencies remain unchanged, including PR107 nullable actor fix.
- Copy defaults/bodies unchanged. Preserve query construction, metadata callback, loading/error/feedback, reset/fire-and-forget behavior, timers, direct diagnostic fetch and CSV fallbacks. No added guards, race fixes, validation or auth rewrites.
- Browser/mobile verification remains pending under the existing credential-session limitation; do not reset or route around it.

## Ownership and Interfaces

Create `static/js/inventory/activity-logs.js` exposing `activityLogsFeature(): object`, owning exactly sixteen properties:

| Kind | Properties |
| --- | --- |
| State (8) | `activityTimeContext:null`, `showLogsPanel:false`, `showStatsModal:false`, `showLogDetailsModal:false`, `activityLogs:[]`, `activityStats:{}`, `selectedLog:null`, `logFilters:{startDate:'',endDate:'',action:'',targetUserId:'',status:''}` |
| Methods (8) | `formatAuditDetails(details)`, `loadActivityLogs()`, `testLogging()`, `loadActivityStats()`, `clearLogFilters()`, `showLogDetails(log)`, `cleanupOldLogs()`, `exportActivityLogsCSV()` |

Consumed through composed `this`: `apiCall(endpoint,options?,onTimeContext?)`, `apiUrl`, `token`, `loading`, `error`, `successMessage`, `formatBusinessInstant(value,context)`, `downloadCSV(headers,rows,filename)`. External dependencies: formatStockAuditDetails, URLSearchParams, fetch, console, prompt, confirm, alert, setTimeout and Date. Core navigation closes showLogsPanel and core logout clears activityTimeContext through the composed application. Keep these intentional cross-owner writes unchanged. Keep movementTimeContext, movements/filters/loading/export, generic archive listing/restoration and other features with existing owners.

Load logs sets loading true and clears error; builds truthy start_date/end_date/action/target_user_id/status in that order, always limit=200; uses apiCall with the metadata callback assigning activityTimeContext and replaces activityLogs. Failure sets `Failed to load activity logs: `, empties rows and releases loading; preserve existing metadata behavior on failed requests. Do not add client-side role checks or alter nullable actor rows. Shared API retains time-context header validation.

Statistics sends only truthy start/end dates to `/logs/activity/stats`, replaces stats and opens stats modal. Failure retains prior stats/modal with existing wording; it does not set loading itself. Clear filters allocates a fresh five-field blank object and invokes loadActivityLogs without awaiting or returning it. Detail opener preserves row reference and opens modal. formatAuditDetails remains the exact formatStockAuditDetails delegation.

Cleanup prompts `Delete logs older than how many days?` with default `90`, returns on falsy response and retains exact confirmation `Delete general logs older than ${days} days? Stock audit evidence is retained. This cannot be undone.`. Retain raw days interpolation into DELETE `/logs/activity/cleanup?days=${days}`, loading behavior, `Deleted ${response.deleted_count} old log entries`, awaited logs reload and 5,000 ms success timer. Preserve lack of initial feedback clearing, swallowed loadActivityLogs failures and finally loading release. All cleanup tests use local fake requests; never invoke production cleanup.

Diagnostic testLogging retains direct fetch to `${apiUrl}/logs/test`, Bearer token and JSON header, existing alerts and catch behavior; no credential/transport modernization is bundled. Test both server status branches and network failure with fake fetch.

CSV retains Date/Time header labeled with activityTimeContext timezone or Unknown, formatBusinessInstant with that context, exact remaining headers/row fallbacks and audit-details formatter. Preserve resource_id=0 fallback to '-', nullable actor rows, UTC filename `activity_logs_YYYY-MM-DD.csv` and core downloadCSV receiver. Missing/invalid metadata must not silently use viewer timezone. Keep formatStockAuditDetails and temporal helpers unchanged.

Create `static/js/pages/inventory-v15.js` from v14, remove sixteen properties and compose fresh activityLogsFeature after equipmentFeature. Preserve all 265 descriptors/defaults/method/getter sources. Index keeps local order through equipment, then activity-logs and inventory-v15; all local references defer with `?v=20261014-frontend-15`, unchanged remote Alpine 3.13.0.

## Review Focus

1. Filter query truthiness/order/encoding/limit=200, fresh reset and its unawaited reload preserve existing behavior; actual activity-navigation/form bindings still invoke the shipped methods.
2. Statistics/details and nullable actor rows preserve data/reference/modal behavior on success/failure without changing loading or inventing identity requirements.
3. Time-context header validation and logs metadata/export pairing preserve actual business-time labeling, Unknown fallback and independent movement context; logout/navigation cross-owner writes still work.
4. Cleanup cancellation/confirmation/raw query/zero count, reload rejection versus swallowed reload error, feedback/loading and 5,000 ms timer remain unchanged; shared CSRF replay/token/permission behavior remains intact without production writes.
5. Diagnostic direct-fetch alerts, exact audit formatter/CSV fallbacks/UTC filename, fresh state/composed receivers, cached v14 equivalence and frozen modules/markup remain correct.

---

### Task 1: Extract and wire activity logs

**Create:** `static/js/inventory/activity-logs.js`, `static/js/pages/inventory-v15.js`, `regression_tests/test_activity_logs_feature.cjs`, `regression_tests/test_activity_logs_ui.cjs`.

**Modify:** `static/index.html`, `regression_tests/test_frontend_entrypoints.cjs`, `docs/frontend-organisation.md`.

**Interfaces:** Produce sixteen properties above; consume exact composed core providers and existing external helpers. Keep navigation/authentication and movement history ownership unchanged.

- [x] **Step 1: Baseline.** On merged PR115 (`00b7ed1`), run full Node/Python suites. Expected 484 Node/830 Python pass. Record v14 hash/application contract before production changes. Python interpreter `/workspace/scratch/22e193396fd5/timezone-venv/bin/python`.
- [x] **Step 2: Isolated RED and prior behavior.** Write exact16keys/defaults/fresh arrays/stats/filters and composed receiver/callback/formatter/export provider tests. Run isolated suite; expected missing-module failures. Establish Step6 shipped tests against unchanged v14 before moving code; expected pass.
- [x] **Step 3: Extraction GREEN.** Copy all defaults/eight method bodies verbatim into activityLogsFeature; isolated tests pass without new providers or body rewrites.
- [x] **Step 4: Entrypoint RED.** Expect exact v15 manifest/cache/inventory-only factory. Add cached-v14 original manifest/frozen hash/no new factory and compare265descriptors/defaults/method/getter sources. Extend historical-controller guard through v14. Entry tests fail on manifest/factory before wiring.
- [x] **Step 5: Wiring GREEN.** Copy v14 to v15, remove only owned properties, compose feature and update index references. Isolated/entrypoint tests pass; cached v14 remains self-contained.
- [x] **Step 6: Shipped behavior GREEN.** Rerun established v14 cases on shipped v15. Cover empty/full filters including encoded values and falsy target0, exact limit/order, loading/error and callback metadata; rejected load empties rows with prior context preserved. Actual activity-button and submit expressions; fresh filter reset and nonreturned pending reload; details row reference; stats date-only filters and failure preserving prior state. Through real API metadata headers test valid/invalid/missing context, nullable actor rows and CSV using activity rather than movement/viewer timezone; exact headers/rows/audit formatting/zero fallback/UTC filename. Cleanup prompt cancellation, decline, raw days and count0, successful/rejected write, rejected provider reload and swallowed actual reload, feedback/loading/timer; real JSON CSRF initial token, one explicit-rejection replay, repeated rejection, token and permission failures. Fake diagnostic fetch validates exact URL/headers/alerts for ok/error/network failure. Core navigation/logout clear owned flags/context while movement context stays independently owned. Instance isolation. Run new feature/UI, entrypoint, sitewide CSRF and existing temporal/audit suites; all pass.
- [x] **Step 7: Verify/document.** Update guide ownership/providers, active/frozen controller and plan status consistently. Full Node/Python, syntax and diff checks pass. Validate exact extraction/frozen tracked files/backend/other pages/non-script markup. Report browser/mobile verification pending.
- [x] **Step 8: Review/publication.** One fresh final whole-branch reviewer checks spec/plan and five Review Focus areas. Fix Critical/Important RED→GREEN and reverify; record Minor findings. Commit/publish branch/PR automatically, require remote tree equality with tested local source, report link. Owner merges; no production writes.

## Plan self-review

Activity logging owns its filters, response metadata, rows and dialogs together; movement history remains separate because its data/context also feed inventory exports. Shared auth/transport/date/CSV helpers remain core. Existing diagnostic/cleanup quirks are explicit compatibility requirements, exercised only by fake requests. All five review-focus areas have concrete coverage. Architecture is approved; this plan is owner-approved, with Native execution retained and publication authorized.

## Execution evidence

Baseline: 484 JavaScript and 830 Python tests passed. Four isolated tests failed on the missing module; 26 shipped behavior cases passed on unchanged v14. Entrypoint RED had two expected manifest/factory failures. Final targeted suite: 92 passed; full suites: 515 JavaScript and 830 Python passed. Syntax, diff, exact extraction, 264 frozen tracked files and non-script markup checks passed. Fresh final reviewer independently approved without findings. Active core is 931 lines. Browser/mobile verification remains pending under the existing access limitation. Publication follows standing authorization; owner merges.
