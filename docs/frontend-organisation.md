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
| `static/js/inventory/reports.js` | Consumption report state, methods and logout reset |
| `static/js/inventory/replenishment.js` | Replenishment planning, minimum editing and suggested-transfer review |
| `static/js/inventory/stock-counts.js` | Physical count entry/preview/confirmation and dialog focus |
| `static/js/inventory/stock-imports.js` | Stock-balance CSV parsing, preview and duplicate resolution |
| `static/js/inventory/transfer-receipts.js` | Pending stock transfers and physical receipt/return confirmation |
| `static/js/inventory/stock-dispatch.js` | Stock-dispatch form, modal opening and submission |
| `static/js/inventory/stock-entry.js` | Add/edit stock forms, quantity saves and add-stock part picker |
| `static/js/pages/inventory-v8.js` | `inventoryApp()`; core workflows composed with reports, replenishment, counts, imports, receipts, dispatch and stock entry |
| `static/js/pages/profile.js` | `profileManager()`; account, personal/organisation timezone and password settings |
| `static/js/pages/password-recovery.js` | `forgotPassword()` and `resetPassword()` |
| `static/js/pages/superadmin.js` | `superPanel()`; platform administration |

Controllers expose the existing global factories consumed by HTML `x-data` expressions. State belongs to each factory instance; do not replace it with module-level mutable forms or arrays.

## Script dependencies

Each row is the exact local script order. All local scripts defer; the existing deferred Alpine CDN script follows them. Query-string cache versions are updated together when dependencies change.

| Page | Local scripts |
| --- | --- |
| Inventory | temporal → audit → csrf → time-context → features → reports → replenishment → stock-counts → stock-imports → transfer-receipts → stock-dispatch → stock-entry → inventory-v8 controller |
| Profile | temporal → time-context → profile controller |
| Forgot/reset password | csrf → password-recovery controller |
| Superadmin | temporal → audit → csrf → time-context → superadmin controller |

The profile controller retains its explicit security-token retry interface. Other controllers use the shared CSRF helper. Do not change those behaviours as part of file organisation.

## Frozen legacy entrypoints

`static/script.js`, the PR101 `static/js/pages/inventory.js`, PR102 `static/js/pages/inventory-v2.js`, PR103 `static/js/pages/inventory-v3.js`, PR104 `static/js/pages/inventory-v4.js`, PR105 `static/js/pages/inventory-v5.js`, PR106 `static/js/pages/inventory-v6.js` and PR108 `static/js/pages/inventory-v7.js` are retained byte-for-byte for older cached HTML that still references them. Current pages do not load them. Edit the active v8 controller/features, not the frozen files. Loading both the legacy file and extracted helpers in one page would redeclare globals and must not be done.

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

Consumption reports/work-order drill-down are now a separate feature. The inventory core remains large; physical counts, stock import preview/resolution, transfer receipts, dispatch and stock entry/adjustment are also separate. Consumption and administration remain in core for later boundaries. Before each move, map state ownership and cross-feature `this` calls. Later composition must preserve property descriptors/getters, method receivers and fresh instance state, and reject duplicate ownership; object spread is unsafe for getter-bearing feature objects. Each boundary receives its own reviewed plan and PR.

## Consumption report ownership

`consumptionReportsFeature()` owns the eleven report state fields and six methods documented in the report extraction plan. It consumes core authentication, API, timezone and navigation providers through the flat application object. Core navigation intentionally closes/opens `showReportsPanel`; logout invokes `resetConsumptionReports(this)` at the original reset point. Comprehensive exports remain in the core. `composeInventoryFeatures` preserves descriptors and never binds methods to their source object or evaluates getters while copying. Each feature factory allocates its own nested state.

## Replenishment ownership

`replenishmentFeature()` owns its fourteen state/getter/method properties, including `showLowStockPanel` and `minimumForm`. It consumes inventory/API/refresh/transfer/CSV providers through the composed application. Core `loadInventory` refreshes the plan when the panel is open unless `refreshReplenishment:false` is passed; minimum saving and transfer review retain that suppression to avoid duplicate plan requests. Core navigation controls the feature panel. Shared low-stock predicates and transfer dispatch/receipt execution remain core responsibilities. Reports and the descriptor composer are unchanged.

## Physical stock count ownership

`stockCountsFeature()` owns four state fields and nine lifecycle/focus methods. Core supplies API, shared feedback, inventory/statistics refresh and selected-store state. Alpine supplies `$nextTick` and `$refs.stockCountDialog` through the composed receiver. Opener DOM references stay in the instance and are neither cloned nor serialized. Existing signed preview tokens, explicit confirmation, busy guards, row validation and focus ordering are preserved. Stock dispatch is owned by its feature.

## Stock CSV import ownership

`stockImportsFeature()` owns four state fields and nine parsing/preview/resolution/template methods. Core supplies shared loading and feedback, catalog/inventory data, selected-store state, API calls and refresh providers through the composed receiver. Each feature instance allocates fresh duplicate/conflict arrays. CSV validation, explicit duplicate decisions, store-ID matching, expected-quantity payloads and the single batch write retain their existing behaviour. Saving closes the preview before inventory/statistics refresh; write failures retain it. The current post-save refresh error wording is preserved, not corrected by this extraction. Browser File, Blob, URL and anchor download APIs remain external dependencies. Catalog and store administration CSV imports remain in core for later extraction.

## Transfer receipt ownership

`transferReceiptsFeature()` owns the pending-transfer array and its loader, explicit refresh and physical receipt/return confirmation methods. Core provides shared loading/feedback, API access, inventory/movement/statistics refresh and selected-store state through the composed receiver. Browser confirmation remains the external dependency. Permissions, prompts, acknowledgment payloads, refresh ordering and error wording are preserved. Core startup and the stock-dispatch feature call the composed pending-transfer loader; equipment transfers remain in core. Core inventory refresh retains its existing loading and swallowed-error semantics. Each application allocates an independent pending-transfer array.

## Stock dispatch ownership

`stockDispatchFeature()` owns the transfer form, modal flag, manual opener and submission method. Core supplies shared loading/feedback, API calls and inventory/statistics refresh; the receipt feature supplies the pending-transfer loader. Replenishment invokes the composed opener, then fills the shared dispatch form. Core navigation still closes its modal, and existing HTML remains unchanged. Each application allocates a fresh form. Integer parsing, optional replenishment payload, success/reset timing, refresh order, timer delay and failure behavior are preserved. Existing method-level duplicate-submit and core inventory-refresh semantics remain unchanged.

## Stock entry and adjustment ownership

`stockEntryFeature()` owns seven state fields and six methods for add/edit forms and the add-stock part picker. Core supplies catalog data, shared loading/feedback, API access, inventory/statistics/equipment-statistics refresh and selected-store browsing. The picker allocates a fresh initial array, then deliberately aliases the full catalog when opening or clearing search. Navigation and existing HTML continue to write form/modal state through the composed application. Addition retains its separate `addingStock` flag, Number quantity conversion, optional work-order payload and selected-store reopening; adjustment retains shared loading and parseInt conversion. Form resets, search clearing, refresh order, timer delay and existing failure semantics are preserved. Each application allocates fresh forms. Local Alpine suggestion visibility remains in markup.
