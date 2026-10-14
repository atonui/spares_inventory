# Inventory Exports Frontend Extraction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Preserve Native execution with one fresh final whole-branch review. Steps use checkbox tracking.

**Goal:** Give remaining inventory exports and the shared CSV downloader one owner without changing file content or download behavior.

**Architecture:** Stateless `inventoryExportsFeature()` supplies twelve existing methods, composed by a new v17 controller. Data/derived views remain with core or existing features. Equipment/activity/movement exports remain with their feature owners and consume downloadCSV through the composed application.

**Tech Stack:** Existing classic JavaScript, AlpineJS 3.13.0, Node VM regressions, FastAPI and pytest. No new dependencies or build step.

**Spec:** `docs/superpowers/specs/2026-10-13-frontend-organisation-design.md` (owner-approved architecture).

**Status:** Owner approved; implementation and verification complete. Fresh final review approved; Minor ownership-documentation finding corrected. Native execution retained; automatic publication authorized.

## Global Constraints

- Retain screens, Alpine bindings, permissions, requests, authentication, CSRF recovery, timezone handling, stock workflows and exports.
- Owner merges; no deployment/production writes. Standing authorization permits automatic verified branch/PR publication without another publication question.
- No bundler, installation, runtime dependency, framework migration, HTML redesign, CSS reorganisation, new feature, endpoint, migration or unrelated fix.
- Preserve global factories/flat application and existing descriptor composition/duplicate-owner rejection, fresh factories and composed receivers.
- Freeze static/script.js and controllers through v16. V16 blob SHA: `fdbdd38e180a8c39b5579e99327ecf717cc43000`.
- Existing helpers/features and other four HTML pages remain byte-identical; index changes only script references. Backend/database/dependencies unchanged.
- Copy twelve bodies unchanged. Do not consolidate CSV implementations, improve escaping/formatting, alter fallbacks/order/filenames or URL lifecycle, add error handling or change data ownership.
- Browser/mobile verification remains pending under the existing credential-session limitation; do not reset or route around it.

## Ownership and Interfaces

Create `static/js/inventory/exports.js` exposing `inventoryExportsFeature(): object`, owning exactly twelve methods and no state:

`exportInventoryCSV()`, `exportAllPartsCSV()`, `exportStoresCSV()`, `exportUsersCSV()`, `exportLowStockCSV()`, `exportMyPartsCSV()`, `exportStoreInventoryCSV(storeId)`, `downloadCSV(headers,rows,filename)`, `exportComprehensiveReport()`, `exportStoreTypesCSV()`, `downloadStoreTypeTemplate()`, `exportCSV()`.

Data/getter providers via composed `this`: filteredInventory, parts, stores, inventory, users, lowStockItems, myPartsView, storeTypes, stats, currentUser, movements, movementTimeContext. Method providers: isLowStock(item), getUserName(userId), formatBusinessInstant(value,context). downloadCSV is now owned here and called through composed this by equipment/activity/movement feature exports as well as this feature. External dependencies: InventoryTime.formatInstant, Date, Blob, URL and document. Keep existing peer features byte-identical; no wrappers or duplicate downloader.

CSV tables retain exact headers/row order, view selection, field fallbacks and UTC YYYY-MM-DD filenames. Inventory export reads filteredInventory/status; catalog totals sum by part_number and unit cost uses toFixed(2); stores aggregate by strict store ID and resolve assigned user; users retain N/A territory/created date; low-stock uses existing getter/shortage; my-parts uses existing getter; per-store converts argument with Number, finds strict matching ID, returns for unknown store and sanitizes name with existing regex/lowercase. Preserve equal-name/different-ID behavior, zero quantities and empty tables. Store-type export retains active/inactive text and stores-using count by type_code.

Shared downloadCSV retains null/undefined→blank, String conversion, comma/quote/newline quoting and doubled embedded quotes, newline joins, text/csv;charset=utf-8; Blob, hidden anchor append→click→remove→revoke lifecycle. Do not add BOM, CRLF, formula handling or filtering. Feature-specific exports continue passing identical headers/rows/filenames through it.

Comprehensive report retains exact section text/order, summaries and transit fallback, raw interpolation/escaping behavior, catalog/store/inventory/low-stock rows, current-user name/email, first50 movements and movementTimeContext for generated/both movement timestamps. Missing context stays Unknown. UTC filename and its existing Blob/hidden-anchor/revoke lifecycle remain unchanged. Do not convert it into a new report format.

Store-type template retains exact CSV and sample lines, text/csv Blob, anchor filename store_types_template.csv, click then revoke without append/remove. Legacy exportCSV retains its separate five-column filteredInventory output via raw row.join(',') with work_order||Original, fixed inventory_export.csv filename, text/csv Blob and anchor click without revoke. These differences are compatibility requirements, not an invitation to rewrite.

Create static/js/pages/inventory-v17.js from v16, removing only twelve methods and composing fresh inventoryExportsFeature after movementHistoryFeature. Preserve all265descriptors/defaults/function/getter sources. Index local order remains through movement-history, then exports and inventory-v17, all defer with `?v=20261014-frontend-17`; unchanged remote Alpine3.13.0.

## Review Focus

1. Shared CSV escaping preserves commas, quotes, embedded newlines, null/undefined, zero/false, exact MIME/content and browser lifecycle; peer feature exports still use its composed receiver.
2. Each export selects the correct rows/getters, preserves aggregate/shortage/price/fallbacks, and per-store uses ID despite equal names, handles unknown ID and retains filename sanitization.
3. Comprehensive report preserves section order, first50 movements, business metadata timestamps/Unknown fallback distinct from viewer/activity context, UTC filename and raw existing text.
4. Store-type template and legacy export retain distinct exact content/header/filename and click/revoke behavior; actual HTML export bindings remain unchanged.
5. Stateless fresh factories/composed providers, cached v16/active v17 equivalence and frozen modules/markup remain correct; inventory data ownership is unchanged.

---

### Task 1: Extract and wire inventory exports

**Create:** static/js/inventory/exports.js, static/js/pages/inventory-v17.js, regression_tests/test_inventory_exports_feature.cjs, regression_tests/test_inventory_exports_ui.cjs.

**Modify:** static/index.html, regression_tests/test_frontend_entrypoints.cjs, docs/frontend-organisation.md.

**Interfaces:** Produce twelve methods above; consume exact composed data/getter/method providers. Provide downloadCSV to existing equipment/activity/movement features without editing them.

- [x] **Step 1: Baseline.** On merged PR117 (`2e49868`), full Node/Python pass533/830. Record v16 hash/application contract before production edits. Interpreter `/workspace/scratch/22e193396fd5/timezone-venv/bin/python`.
- [x] **Step 2: Isolated RED and prior behavior.** Assert exact12methodkeys/no state and fresh factory objects. Use real composer/core providers to verify getter/method receivers and ID-based rows. Missing-module RED. Establish Step6 shipped cases against unchanged v16 before moving code; expected pass.
- [x] **Step 3: Extraction GREEN.** Copy all twelve bodies unchanged into inventoryExportsFeature; isolated tests pass without new providers/body rewrites.
- [x] **Step 4: Entrypoint RED.** Expect v17 manifest/cache/inventory-only factory. Add cached-v16 original manifest/frozen hash/no new factory and compare265descriptors/defaults/function/getter sources. Extend historical guard through v16. Expected manifest/factory failures before wiring.
- [x] **Step 5: Wiring GREEN.** Copy v16 to v17, remove only owned methods, compose feature/update index references. Isolated/entrypoint tests pass; cached v16 self-contained.
- [x] **Step 6: Shipped behavior GREEN.** Rerun established v16 cases through v17. Exact header/row/UTC filename fixtures for seven data exports and store types, including empty rows, zero quantities, missing optional fields, price/aggregate/shortage values, per-store numeric/string ID/equal names/unknown ID and sanitized name. Real Blob content for downloadCSV with comma/quote/newline/null/undefined/0/false, exact MIME and anchor lifecycle. Actual HTML export expressions call unchanged method names. Comprehensive report exact representative output/section order/first50 rows, missing and valid movement metadata versus distinct viewer/activity contexts, UTC filename and lifecycle. Exact template/sample CSV/click/revoke and raw legacy CSV special-character behavior/no added revoke. Peer equipment/activity/movement exports invoke real shared downloader. Instance isolation/no state. New feature/UI, entrypoint and existing export/temporal suites pass.
- [x] **Step 7: Verify/document.** Update ownership/provider guide, active/frozen controller and plan status consistently, correcting statements that generic CSV/comprehensive exports remain core. Full Node/Python, syntax/diff checks pass. Exact extraction/frozen tracked/backend/other pages/non-script markup unchanged; browser verification pending.
- [x] **Step 8: Review/publication.** One fresh final whole-branch reviewer checks spec/plan/five Review Focus areas. Fix Critical/Important RED→GREEN and reverify; record Minor findings. Commit/publish branch/PR automatically; remote tree must equal tested local source. Report link; owner merges, no production writes.

## Plan self-review

Exports are a stateless cross-cutting owner consuming existing data/views rather than taking ownership of them. Feature-specific exports stay with their data owners and call the shared downloader. Legacy/raw and escaped CSV implementations remain distinct intentionally. All five review-focus areas have concrete tests. Architecture approved; plan is owner-approved, Native retained and publication authorized.

## Execution evidence

Baseline: 533 JavaScript and 830 Python tests passed. Two isolated tests failed on the missing module; 29 shipped behavior cases passed on unchanged v16. The initial extraction used an early object terminator; key/syntax contracts caught the missing legacy export/duplicated tail, and the corrected final-terminator extraction passed. Entrypoint RED had two expected manifest/factory failures. Final targeted suite: 158 passed; full suites: 565 JavaScript and 830 Python passed after correction. Syntax, diff, exact extraction, 274 frozen tracked files and non-script markup checks passed. Fresh final reviewer approved after correcting a Minor stale ownership sentence. Active core is 601 lines. Browser/mobile verification remains pending under the existing access limitation. Publication follows standing authorization; owner merges.
