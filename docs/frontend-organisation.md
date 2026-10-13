# Frontend organisation

The app uses ordered classic JavaScript scripts and AlpineJS 3.13.0, served by FastAPI's existing `/static` mount. There is no frontend build step.

## Active code

| File | Responsibility |
| --- | --- |
| `static/temporal.js` | UTC instants, calendar dates and timezone formatting |
| `static/audit.js` | Readable stock-audit evidence |
| `static/js/shared/csrf.js` | Validated token acquisition and bounded CSRF-rejection retry |
| `static/js/shared/time-context.js` | Timezone-context validation |
| `static/js/pages/inventory.js` | `inventoryApp()`; inventory workflows and application lifecycle |
| `static/js/pages/profile.js` | `profileManager()`; account, personal/organisation timezone and password settings |
| `static/js/pages/password-recovery.js` | `forgotPassword()` and `resetPassword()` |
| `static/js/pages/superadmin.js` | `superPanel()`; platform administration |

Controllers expose the existing global factories consumed by HTML `x-data` expressions. State belongs to each factory instance; do not replace it with module-level mutable forms or arrays.

## Script dependencies

Each row is the exact local script order. All local scripts defer; the existing deferred Alpine CDN script follows them. Query-string cache versions are updated together when dependencies change.

| Page | Local scripts |
| --- | --- |
| Inventory | temporal → audit → csrf → time-context → inventory controller |
| Profile | temporal → time-context → profile controller |
| Forgot/reset password | csrf → password-recovery controller |
| Superadmin | temporal → audit → csrf → time-context → superadmin controller |

The profile controller retains its explicit security-token retry interface. Other controllers use the shared CSRF helper. Do not change those behaviours as part of file organisation.

## Frozen legacy entrypoint

`static/script.js` is retained byte-for-byte for older cached HTML that still references it. Current pages do not load it. Edit active code in `static/js/`, not the frozen file. Loading both the legacy file and extracted helpers in one page would redeclare globals and must not be done.

This file is a temporary migration buffer. Removing it requires an explicit cache-compatibility decision; query strings do not make the old URL an immutable asset. Changes to backend contracts must also consider older open pages. Do not add a second production script loader or duplicate active controllers to work around ordering errors.

## Tests and later extraction

`regression_tests/helpers/frontend.cjs` reads actual page references and loads local scripts into Node VM contexts. It rejects executable inline controllers, asynchronous local loading, duplicate references and paths outside the static directory. Remote Alpine is not executed; these tests verify dependencies and controller behaviour, not rendered UI.

Run:

```sh
node --test regression_tests/*.cjs
python -m pytest -q
find static/js -name '*.js' -exec node --check {} \;
git diff --check
```

Existing controller regressions use shipped page entrypoints. Only the dedicated legacy test loads the frozen script directly.

The inventory controller is still large. The next boundary is consumption reports/work-order drill-down, followed by replenishment and other workflows. Before each move, map state ownership and cross-feature `this` calls. Later composition must preserve property descriptors/getters, method receivers and fresh instance state, and reject duplicate ownership; object spread is unsafe for getter-bearing feature objects. Each boundary receives its own reviewed plan and PR.
