# Frontend organisation

The app uses ordered classic JavaScript scripts and AlpineJS 3.13.0, served by FastAPI's existing `/static` mount. There is no frontend build step.

## Active code

| File | Responsibility |
| --- | --- |
| `static/temporal.js` | UTC instants, calendar dates and timezone formatting |
| `static/audit.js` | Readable stock-audit evidence |
| `static/js/shared/csrf.js` | Validated token acquisition and bounded CSRF-rejection retry |
| `static/js/shared/time-context.js` | Timezone-context validation |
| `static/js/shared/features.js` | Descriptor-preserving composition with duplicate-owner rejection |
| `static/js/inventory/application-core.js` | Shared session, request, timezone and common data lifecycle providers |
| `static/js/inventory/reports.js` | Consumption report state, methods and logout reset |
| `static/js/inventory/replenishment.js` | Replenishment planning, minimum editing and suggested-transfer review |
| `static/js/inventory/stock-counts.js` | Physical count entry/preview/confirmation and dialog focus |
| `static/js/inventory/stock-imports.js` | Stock-balance CSV parsing, preview and duplicate resolution |
| `static/js/inventory/transfer-receipts.js` | Pending stock transfers and physical receipt/return confirmation |
| `static/js/inventory/stock-dispatch.js` | Stock-dispatch form, modal opening and submission |
| `static/js/inventory/stock-entry.js` | Add/edit stock forms, quantity saves and add-stock part picker |
| `static/js/inventory/stock-consumption.js` | Consumption form, item opening and work-order stock consumption |
| `static/js/inventory/parts-admin.js` | Catalog create/edit/archive, CSV import and template download |
| `static/js/inventory/stores-admin.js` | Store create/edit/archive, CSV import and template download |
| `static/js/inventory/users-admin.js` | User create/edit/archive form state and mutations |
| `static/js/inventory/store-types-admin.js` | Store-type create/edit/delete-or-deactivate form state and mutations |
| `static/js/inventory/equipment.js` | Equipment data, CRUD, calibration, transfers, history, derived views and downloads |
| `static/js/inventory/activity-logs.js` | Activity filters, metadata, rows, statistics/details, cleanup, diagnostic and CSV export |
| `static/js/inventory/movement-history.js` | Movement rows, filters, response timezone metadata, recent activity and CSV export |
| `static/js/inventory/exports.js` | Remaining inventory exports, comprehensive report, shared CSV downloader and store-type template |
| `static/js/inventory/browsing.js` | Search/filter state, selected-store balances, permission helpers and derived views |
| `static/js/inventory/archived-records.js` | Archived parts/stores/users listing, panel state and restoration |
| `static/js/inventory/navigation.js` | Shared panel/profile-modal flags, open/close actions and live view label |
| `static/js/pages/inventory-v21.js` | `inventoryApp()`; explicit composition of fresh core and feature factories only |
| `static/js/pages/profile.js` | `profileManager()`; account, personal/organisation timezone and password settings |
| `static/js/pages/password-recovery.js` | `forgotPassword()` and `resetPassword()` |
| `static/js/pages/superadmin.js` | `superPanel()`; platform administration |

Controllers expose the existing global factories consumed by HTML `x-data` expressions. State belongs to each factory instance; do not replace it with module-level mutable forms or arrays. In the ownership sections below, core providers mean inventoryCoreFeature, not an inline object in the page entrypoint.

## Script dependencies

Each row is the exact local script order. All local scripts defer; the existing deferred Alpine CDN script follows them. Query-string cache versions are updated together when dependencies change.

| Page | Local scripts |
| --- | --- |
| Inventory | temporal → audit → csrf → time-context → features → application-core → reports → replenishment → stock-counts → stock-imports → transfer-receipts → stock-dispatch → stock-entry → stock-consumption → parts-admin → stores-admin → users-admin → store-types-admin → equipment → activity-logs → movement-history → exports → browsing → archived-records → navigation → inventory-v21 controller |
| Profile | temporal → time-context → profile controller |
| Forgot/reset password | csrf → password-recovery controller |
| Superadmin | temporal → audit → csrf → time-context → superadmin controller |

The profile controller retains its explicit security-token retry interface. Other controllers use the shared CSRF helper. Do not change those behaviours as part of file organisation.

## Frozen legacy entrypoints

`static/script.js`, the PR101 `static/js/pages/inventory.js`, PR102 `static/js/pages/inventory-v2.js`, PR103 `static/js/pages/inventory-v3.js`, PR104 `static/js/pages/inventory-v4.js`, PR105 `static/js/pages/inventory-v5.js`, PR106 `static/js/pages/inventory-v6.js`, PR108 `static/js/pages/inventory-v7.js`, PR109 `static/js/pages/inventory-v8.js`, PR110 `static/js/pages/inventory-v9.js`, PR111 `static/js/pages/inventory-v10.js`, PR112 `static/js/pages/inventory-v11.js`, PR113 `static/js/pages/inventory-v12.js`, PR114 `static/js/pages/inventory-v13.js`, PR115 `static/js/pages/inventory-v14.js`, PR116 `static/js/pages/inventory-v15.js`, PR117 `static/js/pages/inventory-v16.js`, PR118 `static/js/pages/inventory-v17.js`, PR119 `static/js/pages/inventory-v18.js`, PR120 `static/js/pages/inventory-v19.js` and PR121 `static/js/pages/inventory-v20.js` are retained byte-for-byte for older cached HTML that still references them. Current pages do not load them. Edit the active v21 controller/features, not the frozen files. Loading both the legacy file and extracted helpers in one page would redeclare globals and must not be done.

These files are temporary migration buffers. Removing them requires an explicit cache-compatibility decision; query strings do not make the old URL an immutable asset. Changes to backend contracts must also consider older open pages. Do not add a second production script loader or duplicate active controllers to work around ordering errors.

## Tests and later extraction

`regression_tests/helpers/frontend.cjs` reads actual page references and loads local scripts into Node VM contexts. It rejects executable inline controllers, asynchronous local loading, duplicate references and paths outside the static directory. Remote Alpine is not executed; these tests verify dependencies and controller behaviour, not rendered UI.

Run:

```sh
node --test regression_tests/*.cjs
python -m pytest -q
find static/js -name '*.js' -exec node --check {} \;
git diff --check
```

Existing controller regressions use shipped page entrypoints. Only dedicated legacy tests load the frozen entrypoints directly.

The inventory entrypoint explicitly composes shared application lifecycle and feature owners. New changes must map state and cross-feature calls before introducing a boundary; preserve descriptors/getters, receivers, fresh instance state and duplicate-owner rejection.

## Consumption report ownership

`consumptionReportsFeature()` owns the eleven report state fields and six methods documented in the report extraction plan. It consumes core authentication/API/timezone providers and navigationFeature actions through the flat application object. The navigation feature intentionally closes/opens `showReportsPanel`; logout invokes `resetConsumptionReports(this)` at the original reset point. Comprehensive exports belong to inventoryExportsFeature. `composeInventoryFeatures` preserves descriptors and never binds methods to their source object or evaluates getters while copying. Each feature factory allocates its own nested state.

## Replenishment ownership

`replenishmentFeature()` owns its fourteen state/getter/method properties, including `showLowStockPanel` and `minimumForm`. It consumes inventory/API/refresh/transfer/CSV providers through the composed application. Core `loadInventory` refreshes the plan when the panel is open unless `refreshReplenishment:false` is passed; minimum saving and transfer review retain that suppression to avoid duplicate plan requests. The navigation feature controls the feature panel. Shared low-stock predicates belong to inventoryBrowsingFeature; transfer dispatch and receipts belong to their respective features. Reports and the descriptor composer are unchanged.

## Physical stock count ownership

`stockCountsFeature()` owns four state fields and nine lifecycle/focus methods. Core supplies API, shared feedback and inventory/statistics refresh; inventoryBrowsingFeature supplies selected-store state. Alpine supplies `$nextTick` and `$refs.stockCountDialog` through the composed receiver. Opener DOM references stay in the instance and are neither cloned nor serialized. Existing signed preview tokens, explicit confirmation, busy guards, row validation and focus ordering are preserved. Stock dispatch is owned by its feature.

## Stock CSV import ownership

`stockImportsFeature()` owns four state fields and nine parsing/preview/resolution/template methods. Core supplies shared loading/feedback, catalog/inventory data, API calls and refresh providers; inventoryBrowsingFeature supplies selected-store state through the composed receiver. Each feature instance allocates fresh duplicate/conflict arrays. CSV validation, explicit duplicate decisions, store-ID matching, expected-quantity payloads and the single batch write retain their existing behaviour. Saving closes the preview before inventory/statistics refresh; write failures retain it. The current post-save refresh error wording is preserved, not corrected by this extraction. Browser File, Blob, URL and anchor download APIs remain external dependencies. Catalog CSV administration belongs to the parts-admin feature; store administration CSV imports belong to the stores-admin feature.

## Transfer receipt ownership

`transferReceiptsFeature()` owns the pending-transfer array and its loader, explicit refresh and physical receipt/return confirmation methods. Core provides shared loading/feedback, API access and inventory/statistics refresh; movementHistoryFeature supplies movement refresh and inventoryBrowsingFeature supplies selected-store state through the composed receiver. Browser confirmation remains the external dependency. Permissions, prompts, acknowledgment payloads, refresh ordering and error wording are preserved. Core startup and the stock-dispatch feature call the composed pending-transfer loader; equipment transfers belong to equipmentFeature. Core inventory refresh retains its existing loading and swallowed-error semantics. Each application allocates an independent pending-transfer array.

## Stock dispatch ownership

`stockDispatchFeature()` owns the transfer form, modal flag, manual opener and submission method. Core supplies shared loading/feedback, API calls and inventory/statistics refresh; the receipt feature supplies the pending-transfer loader. Replenishment invokes the composed opener, then fills the shared dispatch form. The navigation feature still closes its modal, and existing HTML remains unchanged. Each application allocates a fresh form. Integer parsing, optional replenishment payload, success/reset timing, refresh order, timer delay and failure behavior are preserved. Existing method-level duplicate-submit and core inventory-refresh semantics remain unchanged.

## Stock entry and adjustment ownership

`stockEntryFeature()` owns seven state fields and six methods for add/edit forms and the add-stock part picker. Core supplies catalog data, shared loading/feedback, API access and inventory/statistics refresh; equipmentFeature supplies equipment statistics and inventoryBrowsingFeature supplies selected-store browsing. The picker allocates a fresh initial array, then deliberately aliases the full catalog when opening or clearing search. Navigation and existing HTML continue to write form/modal state through the composed application. Addition retains its separate `addingStock` flag, Number quantity conversion, optional work-order payload and selected-store reopening; adjustment retains shared loading and parseInt conversion. Form resets, search clearing, refresh order, timer delay and existing failure semantics are preserved. Each application allocates fresh forms. Local Alpine suggestion visibility remains in markup.

## Stock consumption ownership

`stockConsumptionFeature()` owns the consumption form, modal flag, item opener and save method. Core supplies shared loading/feedback, API access, inventory/dashboard refresh; movementHistoryFeature supplies movement refresh and inventoryBrowsingFeature supplies selected-store balances. Opening replaces all form metadata; existing HTML cancellation clears the form and reopening initializes it again. Parsed quantity/ID, work-order trimming, notes handling, server message, clear/reset timing, refresh order, ID-based store filtering and the 5,000 ms timer retain existing behavior. Core dashboard refresh still runs statistics/equipment-statistics providers in parallel; core loading/error semantics remain unchanged. Each instance allocates a fresh form. Navigation and focus behavior are unchanged.

## Parts catalog administration ownership

`partsAdminFeature()` owns the part form, editing ID, modal flag and six methods for catalog create/edit/archive, CSV import and template download. Core provides shared loading/feedback, API/CSRF helpers and catalog/inventory/statistics refresh; archivedRecordsFeature provides generic archived-record browsing. Catalog data/getters/exports and stock selection remain with their current owners. Existing HTML create/cancel bindings and navigation still write feature state through the flat composed application. ParseFloat conversion, zero cost, archive confirmation, action-specific refresh/reset/timer behavior and existing failure semantics remain unchanged. CSV upload uses the existing real multipart/CSRF path, clears input after successful refresh and retains it on failure. Template bytes, filename and browser URL lifecycle are preserved; each application allocates a fresh form.

`storesAdminFeature()` owns the store form, editing ID, modal flag and six create/edit/archive/import/template methods. Core supplies API calls, loading/feedback and catalog/inventory/statistics refresh; archivedRecordsFeature supplies archive refresh and inventoryBrowsingFeature supplies browsing state through the composed receiver. Archive clears the selected store only when its ID matches the archived target, before refresh. CSV import retains server feedback and row errors, refreshes only stores, clears the input after refresh and clears both feedback fields after 5,000 ms. Multipart/CSRF remains in the shared API helper with no direct token prefetch. Store-type administration belongs to its separate feature; user lookup remains core, browsing belongs to inventoryBrowsingFeature and archive restoration belongs to archivedRecordsFeature. Forms are fresh for each application instance.

`usersAdminFeature()` owns the user form, editing ID, modal flag and four create/edit/archive methods. Core supplies shared loading/feedback, API calls and users/inventory refresh; archivedRecordsFeature supplies archive refresh through the composed receiver. Authentication/current-user state and role-aware user loading remain core. Creation sends the full raw form; update omits email, converts blank territory to null and includes only truthy passwords. The initial/create-button role is engineer; successful saves reset role to blank. Archive retains users → inventory → optional archived-record refresh and existing swallowed refresh errors. Fresh forms and original 3,000 ms feedback timers are preserved.

`storeTypesAdminFeature()` owns the store-type form, editing ID, modal flag and four create/edit/delete-or-deactivate methods. Core supplies API calls, shared loading/feedback and store-type/store refresh providers. Create includes type_code and omits is_active; update omits type_code and includes is_active. Both retain parseInt(order) or zero and raw description. The initial/add form includes is_active true; save resets omit it. Update refreshes types then stores; delete/deactivate refreshes types only and preserves server feedback. Existing swallowed loader errors, fresh forms and 3,000 ms feedback timers remain unchanged.

`equipmentFeature()` owns 34 properties: equipment data/forms/selection/reminder state, six modal/panel flags, sixteen methods and three live getters. Calibration, transfer and history share its selectedEquipment. Core supplies API calls, feedback/loading, currentUser and businessToday; inventoryExportsFeature supplies downloadCSV; core startup/dashboard calls moved loaders and navigation writes owned flags through the composed application. Equipment CRUD, calibration, transfer, history, reminder settings, derived views and downloads preserve existing behavior, including swallowed loader errors, raw dates/optional nulls, reset-before-refresh, fixed status versus configurable due-soon thresholds, zero-day export fallback and template URL lifecycle. All forms/arrays are fresh.

`activityLogsFeature()` owns sixteen properties: activity response timezone metadata, filters, rows/statistics/detail selection, three panel/modal flags and eight existing methods. Core supplies API/loading/feedback, date formatting and diagnostic API/token values; inventoryExportsFeature supplies CSV download. The navigation feature closes its panel and logout clears its metadata through the composed application. Movement history/context belong to their separate feature. Queries, stats/details, unawaited filter reset, raw cleanup query/confirmation and swallowed reload errors, direct diagnostic transport, CSV time-context labeling/audit formatting/fallbacks and timers retain prior behavior. Arrays/stats/filters are fresh; nullable actors remain supported.

`movementHistoryFeature()` owns nine properties: rows, filters, timezone metadata, panel flag, loader/reset/toggle/CSV methods and the live first20 recentActivity getter. Core supplies API/date providers; inventoryExportsFeature supplies CSV download; core startup and stock features call its loader, navigation/logout write owned flags/context, and the inventory export feature consumes its data for comprehensive reports. Queries retain truthiness/order/encoding and no limit; loading/errors and rejection propagation remain unchanged. Reset still invokes an unreturned reload, toggle changes panel before awaiting, and CSV uses movement response context independently of activity/viewer context. Rows/filters are fresh and recent activity returns a live slice without sorting.

`inventoryExportsFeature()` owns twelve stateless methods: seven inventory/catalog/store/user/low-stock/my-parts/per-store exports, store-type export/template, comprehensive report, generic downloadCSV and legacy exportCSV. Data/getters remain with existing owners and are read through the composed receiver. Equipment/activity/movement exports consume its shared downloader without changing their bodies. Exact table/aggregate/fallback/UTC filename behavior remains; generic quoting/hidden-anchor lifecycle, raw comprehensive text, template click/revoke and legacy raw CSV/no-revoke paths stay distinct intentionally.

`inventoryBrowsingFeature()` owns21properties: seven search/advanced/selected-store/filtered-row states, eight methods and six live getters. Core supplies catalog/inventory data and currentUser; navigationFeature supplies openPanel; navigation/currentViewLabel belong to navigationFeature. Stock/admin/export features consume its balances/selection/predicates through the composed app, while core loadInventory refreshes its filtered rows and selected balances. Query truthiness/case/order, advanced unused fields and reference identity, strict ownership permissions, allocation/work-order low-stock rules and view/reset navigation ordering are preserved. Arrays/advanced form are fresh. Provider references to selected-store state or low-stock predicates in other feature sections now refer to this peer feature, not core ownership.

`archivedRecordsFeature()` owns four properties: rows/panel flag plus parallel listing and restore methods. Core supplies API/feedback/loading and catalog/inventory/statistics refresh; the feature supplies its own final archived reload. Parts/store/user administration call it when the panel is open, and navigation writes its flag through the composed app. Parallel grouping/labels, guard/confirmation, server message, six-refresh ordering, partial failure and swallowed-loader behavior remain unchanged. Rows are fresh; restoration does not add timers/local row removal or alter backend policies.

`navigationFeature()` owns14properties: ten shared panel/profile-modal flags, three open/close actions and the live currentViewLabel getter. Feature-owned flags stay with their owners and are coordinated through the composed app. Exact close sets, inventory filtering order, unawaited report/replenishment calls, arbitrary panel names, unspecified modal preservation and label priority/optional-name behavior remain unchanged. Core now retains shared lifecycle/authentication/API/date/data refresh responsibilities.

## Application lifecycle ownership

`inventoryCoreFeature()` owns41properties:21shared session/request/timezone/data states and20methods. It consumes composed peer loaders, browsing filters/balances and report/time-context reset providers without taking UI/feature ownership. Cached authentication, cookie/CSRF requests, direct me fetch, logout/report reset, status-error handling, metadata validation, timezone actor guard, parallel startup, loader failure semantics and dashboard behavior are copied unchanged. Arrays/forms/stats are fresh. The v21 page factory composes core plus19feature factories exactly once per application; no inline core or dynamic loader remains.

## Implementation and acceptance status

The structural frontend refactor is implemented on this final branch, pending owner merge. Automated dependency/behavior tests and fresh review provide local evidence; deployed public script references/assets and signed-in desktop/mobile smoke acceptance remain pending until actually checked. The recorded credential-session restriction still applies. Frozen legacy retirement remains a separate cache-policy decision.
