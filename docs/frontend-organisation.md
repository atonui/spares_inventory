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
| `static/js/pages/inventory-v2.js` | `inventoryApp()`; core workflows composed with consumption reports |
| `static/js/pages/profile.js` | `profileManager()`; account, personal/organisation timezone and password settings |
| `static/js/pages/password-recovery.js` | `forgotPassword()` and `resetPassword()` |
| `static/js/pages/superadmin.js` | `superPanel()`; platform administration |

Controllers expose the existing global factories consumed by HTML `x-data` expressions. State belongs to each factory instance; do not replace it with module-level mutable forms or arrays.

## Script dependencies

Each row is the exact local script order. All local scripts defer; the existing deferred Alpine CDN script follows them. Query-string cache versions are updated together when dependencies change.

| Page | Local scripts |
| --- | --- |
| Inventory | temporal → audit → csrf → time-context → features → reports → inventory-v2 controller |
| Profile | temporal → time-context → profile controller |
| Forgot/reset password | csrf → password-recovery controller |
| Superadmin | temporal → audit → csrf → time-context → superadmin controller |

The profile controller retains its explicit security-token retry interface. Other controllers use the shared CSRF helper. Do not change those behaviours as part of file organisation.

## Frozen legacy entrypoint

`static/script.js` and the PR101 `static/js/pages/inventory.js` are retained byte-for-byte for older cached HTML that still references it. Current pages do not load it. Edit the active v2 controller/features, not either frozen file. Loading both the legacy file and extracted helpers in one page would redeclare globals and must not be done.

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

Consumption reports/work-order drill-down are now a separate feature. The inventory core remains large; replenishment is the next boundary. Before each move, map state ownership and cross-feature `this` calls. Later composition must preserve property descriptors/getters, method receivers and fresh instance state, and reject duplicate ownership; object spread is unsafe for getter-bearing feature objects. Each boundary receives its own reviewed plan and PR.

## Consumption report ownership

`consumptionReportsFeature()` owns the eleven report state fields and six methods documented in the report extraction plan. It consumes core authentication, API, timezone and navigation providers through the flat application object. Core navigation intentionally closes/opens `showReportsPanel`; logout invokes `resetConsumptionReports(this)` at the original reset point. Comprehensive exports remain in the core. `composeInventoryFeatures` preserves descriptors and never binds methods to their source object or evaluates getters while copying. Each feature factory allocates its own nested state.
