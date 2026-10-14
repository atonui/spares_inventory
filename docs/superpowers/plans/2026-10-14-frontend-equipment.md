# Equipment Frontend Extraction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Preserve Native execution with one fresh final whole-branch review. Steps use checkbox tracking.

**Goal:** Give equipment data, administration, calibration, transfer and history one coherent feature owner without changing behavior.

**Architecture:** `equipmentFeature()` owns equipment state and its existing loaders, mutations, modal openers, derived views and downloads. A new v14 inventory controller composes it with current features. Core retains authentication, shared API/feedback, timezone/date helpers, generic CSV download and navigation, which calls/writes equipment properties through the composed application.

**Tech Stack:** Existing classic JavaScript, AlpineJS 3.13.0, Node VM regressions, FastAPI and pytest. No new dependencies or build step.

**Spec:** `docs/superpowers/specs/2026-10-13-frontend-organisation-design.md` (owner-approved architecture).

**Status:** Owner approved; implementation and verification complete. Fresh final review approved; one Minor ownership-documentation finding corrected. Native execution retained; automatic publication authorized.

## Global Constraints

- Retain screens, Alpine bindings, permissions, requests, authentication, CSRF recovery, timezone handling, stock workflows and exports.
- Owner merges; no deployment/production data writes. Standing owner authorization permits automatic branch/PR publication after checks/review pass, without a publication question.
- No bundler, package installation, runtime dependency, framework migration, HTML redesign, CSS reorganisation, new feature, endpoint, database migration or unrelated bug fix.
- Preserve global factories and flat Alpine-facing object. Compose descriptors with existing duplicate-owner rejection; preserve getters, method receivers, enumerability and fresh instance state.
- Freeze `static/script.js` and historical inventory controllers through v13. V13 blob SHA: `71ab6d8de807698e12e3cc1777c16162dfbce9ba`.
- Existing helpers/features and other four HTML pages stay byte-identical; index changes only script references. No backend/database/CSS/dependency changes; preserve the activity-log null-actor fix.
- Copy defaults and bodies unchanged. Preserve payload conversions, date-only values, fallbacks, resets, refresh/error/loading/timer behavior and URL lifecycle. No new guards, normalization, race fixes or ownership event bus.
- Rendered browser/mobile verification remains pending under the existing credential-session limitation; do not reset or route around it.

## Ownership and Interfaces

Create `static/js/inventory/equipment.js` exposing `equipmentFeature(): object`, owning exactly 34 properties:

| Kind | Properties |
| --- | --- |
| Data/state (9) | `equipment:[]`, `equipmentStats:{}`, `equipmentForm`, `calibrationForm`, `transferEquipmentForm`, `editingEquipment:null`, `selectedEquipment:null`, `equipmentHistory:[]`, `calibrationReminderDays:30` |
| UI state (6) | `showEquipmentModal:false`, `showCalibrationModal:false`, `showTransferEquipmentModal:false`, `showEquipmentPanel:false`, `showEquipmentHistoryModal:false`, `showCalibrationSettingsModal:false` |
| Methods (16) | `loadEquipment()`, `loadEquipmentStats()`, `loadCalibrationSettings()`, `createEquipment()`, `editEquipment(equipment)`, `updateEquipment()`, `deleteEquipment(equipmentId,equipmentName)`, `openCalibrationModal(equipment)`, `updateCalibration()`, `openTransferEquipmentModal(equipment)`, `transferEquipmentToUser()`, `viewEquipmentHistory(equipment)`, `updateCalibrationReminderDays()`, `getCalibrationStatus(equipment)`, `exportEquipmentCSV()`, `downloadEquipmentTemplate()` |
| Getters (3) | `myEquipment`, `dueSoonEquipment`, `overdueEquipment` |

Form defaults copied exactly from v13: equipment form has ten blank fields `equipment_name`, `make`, `model`, `serial_number`, `assigned_user_id`, `calibration_cert_number`, `calibration_authority`, `calibration_date`, `next_calibration_date`, `notes`; calibration form has five blank fields `calibration_cert_number`, `calibration_authority`, `calibration_date`, `next_calibration_date`, `notes`; transfer form `{to_user_id:'',notes:''}`. Allocate all arrays/objects freshly.

Consumed through composed `this`: `apiCall(endpoint,options?)`, `loading`, `error`, `successMessage`, `currentUser`, `businessToday()`, `downloadCSV(headers,rows,filename)`. External dependencies: InventoryTime.daysBetween, confirm, setTimeout, parseInt/JSON, Date, Blob, URL and document. Equipment loaders/mutation refresh calls are intra-feature calls through the same composed receiver. Core loadAllData/refreshDashboard call the moved loaders; core navigation closes owned modal/panel flags. Document these intentional cross-owner accesses without wrappers.

Move all 15 state defaults and the contiguous 19-method/getter block from loadEquipment through downloadEquipmentTemplate unchanged. Equipment exports move with their data owner; generic CSV helper and other exports stay core. No equipment CSV upload implementation exists in this block; do not invent one.

Loaders retain GET `/equipment?show_all=true`, `/equipment/statistics`, `/settings/calibration-reminder-days`, their assignments and caught-error wording; failures retain previous values. Create/update retain POST `/equipment` and PUT `/equipment/${editingEquipment}`, unchanged raw four identity fields, truthy assignment parseInt or null and optional calibration/date/notes fields `|| null`. Edit replaces form with existing `|| ''` optional fallbacks. Save closes/resets form before equipment → statistics refresh; update clears editing ID, create leaves HTML-initialized editing ID untouched. Delete retains exact permanent-delete confirmation, DELETE endpoint and `Equipment deleted successfully!` message; it does not become archive and does not clear selection locally. Mutations retain 3,000 ms success timer and finally loading release.

Calibration opener records selected row, copies certificate/authority/next date, sets calibration date from businessToday (Unknown → blank) and blank notes. Calibration POST `/equipment/${selectedEquipment.id}/calibrate` sends the full raw calibration form; success closes modal, clears selection and resets form before equipment → statistics refresh. Transfer opener records selected row and allocates a blank transfer form. Transfer POST `/equipment/${selectedEquipment.id}/transfer` sends truthy target parseInt or null and notes or null; success closes modal, clears selection and resets before the same refreshes. Write failures retain form/selection/modal; post-write refresh rejection retains already-saved/reset state. Existing swallowed equipment-loader errors remain unchanged.

History sets selectedEquipment and loading before GET `/equipment/${equipment.id}/history`; success replaces history and opens modal. Failure retains prior history/modal state and the new selection, with `Failed to load equipment history: ` feedback. Reminder PUT `/settings/calibration-reminder-days?days=${calibrationReminderDays}` has no body; success closes settings modal, preserves value, sets exact message and schedules timer. No added refresh.

Calibration status retains none/Not set for absent date, none/Unknown for nonfinite day difference, overdue for negative days, urgent for 0–7, soon for 8–30 and ok above 30. This fixed status threshold remains distinct from dueSoonEquipment's configurable reminder threshold. Getters remain live descriptors, with strict assigned-user matching, missing/invalid date filtering and business-date semantics unchanged.

Exports retain exact header/row ordering and fallbacks, including zero days_until_calibration rendered as '-' under existing `||`. Filename remains equipment_YYYY-MM-DD.csv using UTC Date ISO, via core downloadCSV. Template retains exact existing CSV/sample dates, text/csv Blob, object URL and anchor click/filename equipment_import_template.csv; preserve current URL lifecycle.

Create `static/js/pages/inventory-v14.js` from v13, remove only owned properties and compose fresh equipmentFeature after storeTypesAdminFeature. Preserve all 265 descriptors/defaults/method/getter sources. Index keeps local order through store-types-admin, followed by equipment and inventory-v14; all local references defer with `?v=20261014-frontend-14`, remote Alpine 3.13.0 unchanged.

## Review Focus

1. Shared selectedEquipment across calibration/transfer/history, actual add/edit/cancel/submit/navigation bindings, independent forms and mutation write/refresh failures preserve existing selection/modal/reset behavior.
2. CRUD/calibration/transfer/settings payloads preserve optional nulls, integer conversion, raw date-only values, untrimmed notes, exact endpoints and refresh order; deletion retains permanent-delete semantics.
3. Business-date unavailable/invalid dates and overdue/today/7/8/30/31 boundaries retain status/getter behavior, configurable due-soon threshold and strict user matching; getters remain reactive descriptors.
4. Loaders/history preserve prior data/error/loading behavior on failure; real JSON API/CSRF preserves credentials, one explicit-rejection replay, permission failures and token-service failure behavior.
5. Equipment exports/template retain exact fallback/header/CSV/filename/browser API behavior; core startup/navigation cross-owner calls, cached v13/active v14 equivalence and frozen files remain correct.

---

### Task 1: Extract and wire equipment

**Create:** `static/js/inventory/equipment.js`, `static/js/pages/inventory-v14.js`, `regression_tests/test_equipment_feature.cjs`, `regression_tests/test_equipment_ui.cjs`.

**Modify:** `static/index.html`, `regression_tests/test_frontend_entrypoints.cjs`, `docs/frontend-organisation.md`.

**Interfaces:** Produce 34 properties above; consume exact core providers through composed receivers. Preserve core lifecycle/navigation and existing HTML expressions.

- [x] **Step 1: Baseline.** On merged PR114 (`c1ce9a0`), run full Node/Python suites. Expected 427 Node/830 Python pass. Record v13 frozen SHA/application contract before production changes. Interpreter `/workspace/scratch/22e193396fd5/timezone-venv/bin/python`.
- [x] **Step 2: Isolated RED and prior behavior.** Assert exact34keys/defaults, fresh allforms/arrays/stats and live getter descriptors. Compose real composer/core providers and exercise loader/mutation/date/export calls with their exact receivers. Run missing-module RED. Establish Step 6 shipped behavior cases against unchanged v13 before extraction; expected pass.
- [x] **Step 3: Extraction GREEN.** Copy all defaults and contiguous method/getter block unchanged into equipmentFeature; isolated tests pass without body rewrites/new providers.
- [x] **Step 4: Entrypoint RED.** Expect v14 manifest/cache/inventory-only factory. Add cached-v13 construction with original manifest/frozen SHA and no equipment factory; compare265descriptors/defaults/function/getter sources. Extend historical-controller guard through v13. Entry tests fail on manifest/factory before wiring.
- [x] **Step 5: Wiring GREEN.** Copy v13 to v14, remove owned properties, compose feature and update index references. Isolated/entrypoint tests pass; cached v13 remains self-contained.
- [x] **Step 6: Shipped behavior GREEN.** Rerun established v13 cases on shipped v14. Cover actual add/cancel/submit bindings, edit optional fallback, navigation and selectedEquipment transitions between calibration/transfer/history. CRUD blank/present optional payloads and raw fields; calibration Known/Unknown business date opener/full raw payload; transfer blank/present target/notes; reminder raw query/no body/no refresh. Verify success resets before equipment→stats refresh, exact feedback/timers and declined delete. Reject each write and relevant provider refresh; preserve form/modal/selection before write or already-reset state after write. Exercise real swallowed loaders, each loader failure retaining previous data, and history success/failure prior-state behavior. Status fixtures absent/invalid/overdue/today/7/8/30/31; configurable due-soon threshold independent of fixed status threshold, strict user-ID matching and live getters under state changes. Real API/CSRF JSON/cookies/initial token/one explicit retry/repeated rejection/permission/token failure. Exact export headers/rows/zero-day fallback/UTC filename and template CSV/Blob/URL/anchor APIs. Exercise core loadAllData/refreshDashboard/navigation against moved providers. Run new feature/UI, entrypoint, sitewide CSRF and existing temporal suites; all pass.
- [x] **Step 7: Verify/document.** Update guide ownership/providers, active/frozen controller and plan status consistently. Full Node/Python, new-file syntax and diff checks pass. Validate exact extraction, frozen tracked files/backend/other pages and non-script markup. Report browser/mobile verification pending.
- [x] **Step 8: Review/publication.** One fresh final whole-branch reviewer checks spec/plan and five Review Focus areas. Fix Critical/Important RED→GREEN and reverify; record Minor findings. Commit/publish branch and PR automatically, require remote tree equals tested local source, report link. Owner merges; no production writes.

## Plan self-review

Equipment has one shared selectedEquipment state across calibration, transfer and history, so separating these workflows now would split ownership. The 34-property feature owns related data, getters and exports while consuming narrow core providers; core remains lifecycle/navigation owner. Existing behavior quirks are explicit compatibility requirements. All five review-focus areas have concrete coverage; no new behavior is included. Architecture is approved; plan is owner-approved, Native method retained and publication authorized.

## Execution evidence

Baseline: 427 JavaScript and 830 Python tests passed. Eleven isolated tests failed on the missing module; 45 shipped behavior cases passed on unchanged v13. Entrypoint RED had two expected manifest/factory failures. Final targeted suite: 105 passed; full suites: 484 JavaScript and 830 Python passed. Syntax, diff, exact extraction, 259 frozen tracked files and non-script markup checks passed. Fresh final reviewer approved without Critical/Important findings; its Minor stale transfer-ownership sentence was corrected. Active core is 1,106 lines. Browser/mobile verification remains pending under the existing access limitation. Publication follows standing authorization; owner merges.
