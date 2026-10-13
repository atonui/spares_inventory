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
| `static/js/pages/inventory-v4.js` | `inventoryApp()`; core workflows composed with reports, replenishment and counts |
| `static/js/pages/profile.js` | `profileManager()`; account, personal/organisation timezone and password settings |
| `static/js/pages/password-recovery.js` | `forgotPassword()` and `resetPassword()` |
| `static/js/pages/superadmin.js` | `superPanel()`; platform administration |

Controllers expose the existing global factories consumed by HTML `x-data` expressions. State belongs to each factory instance; do not replace it with module-level mutable forms or arrays.

## Script dependencies

Each row is the exact local script order. All local scripts defer; the existing deferred Alpine CDN script follows them. Query-string cache versions are updated together when dependencies change.

| Page | Local scripts |
| --- | --- |
| Inventory | temporal → audit → csrf → time-context → features → reports → replenishment → stock-counts → inventory-v4 controller |
| Profile | temporal → time-context → profile controller |
| Forgot/reset password | csrf → password-recovery controller |
| Superadmin | temporal → audit → csrf → time-context → superadmin controller |

The profile controller retains its explicit security-token retry interface. Other controllers use the shared CSRF helper. Do not change those behaviours as part of file organisation.

## Frozen legacy entrypoints

`static/script.js`, the PR101 `static/js/pages/inventory.js`, PR102 `static/js/pages/inventory-v2.js` and PR103 `static/js/pages/inventory-v3.js` are retained byte-for-byte for older cached HTML that still references them. Current pages do not load them. Edit the active v4 controller/features, not the frozen files. Loading both the legacy file and extracted helpers in one page would redeclare globals and must not be done.

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

Consumption reports/work-order drill-down are now a separate feature. The inventory core remains large; physical counts are also separate; import preview/resolution and transfer receipts are the next boundaries. Before each move, map state ownership and cross-feature `this` calls. Later composition must preserve property descriptors/getters, method receivers and fresh instance state, and reject duplicate ownership; object spread is unsafe for getter-bearing feature objects. Each boundary receives its own reviewed plan and PR.

## Consumption report ownership

`consumptionReportsFeature()` owns the eleven report state fields and six methods documented in the report extraction plan. It consumes core authentication, API, timezone and navigation providers through the flat application object. Core navigation intentionally closes/opens `showReportsPanel`; logout invokes `resetConsumptionReports(this)` at the original reset point. Comprehensive exports remain in the core. `composeInventoryFeatures` preserves descriptors and never binds methods to their source object or evaluates getters while copying. Each feature factory allocates its own nested state.

## Replenishment ownership

`replenishmentFeature()` owns its fourteen state/getter/method properties, including `showLowStockPanel` and `minimumForm`. It consumes inventory/API/refresh/transfer/CSV providers through the composed application. Core `loadInventory` refreshes the plan when the panel is open unless `refreshReplenishment:false` is passed; minimum saving and transfer review retain that suppression to avoid duplicate plan requests. Core navigation controls the feature panel. Shared low-stock predicates and transfer dispatch/receipt execution remain core responsibilities. Reports and the descriptor composer are unchanged.

## Physical stock count ownership

`stockCountsFeature()` owns four state fields and nine lifecycle/focus methods. Core supplies API, shared feedback, inventory/statistics refresh and selected-store state. Alpine supplies `$nextTick` and `$refs.stockCountDialog` through the composed receiver. Opener DOM references stay in the instance and are neither cloned nor serialized. Existing signed preview tokens, explicit confirmation, busy guards, row validation and focus ordering are preserved. Imports and transfer execution remain core responsibilities.
