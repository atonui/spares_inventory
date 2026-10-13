# Frontend organisation

Status: Approved by the owner on 13 October 2026. First entrypoint extraction implemented and reviewed; later feature boundaries remain separately planned.

## Intent and success criteria

The owner wants the existing inventory frontend organised into understandable files. The application is already used in production. This is a behaviour-preserving refactor: retain current screens, Alpine bindings, permissions, requests, authentication, CSRF recovery, timezone handling, stock workflows and exports. Work proceeds in small reviewable PRs, implemented natively with one fresh final code review per implementation PR. The owner merges; this work does not deploy or modify production data.

Success means each extracted unit has a clear responsibility and dependencies, every page loads its required code before Alpine starts, instance state remains independent, and the existing regression suites still exercise the real shipped entrypoints. Splitting files without separating responsibilities is insufficient.

## Approach

Use ordered classic JavaScript files served by the existing FastAPI static mount. This preserves the application's global Alpine factories and requires no bundler, package installation, runtime dependency, framework migration or server change. Each page loads only the shared helpers and page controller it needs. Local dependent scripts use defer in dependency order, followed by the existing deferred Alpine script. Pin all changed/new asset references with the same version within each PR.

An alternative is browser ES modules with explicit imports and Alpine.data registration. That makes dependencies more explicit but changes factory exposure and asynchronous startup behaviour. It is not the first extraction: retain the current execution model while reducing coupling, then reconsider modules if there is a concrete need.

No HTML redesign, CSS reorganisation, new feature, endpoint, database migration or unrelated bug fix is bundled into this work. Any discovered behaviour defect is documented and handled separately unless it prevents safe extraction.

## First independently shippable boundary

Create these files by moving existing implementations, preserving their names and bodies:

| File | Responsibility | Dependencies |
| --- | --- | --- |
| `static/js/shared/csrf.js` | Existing `InventoryCsrf.token` and `.request` | Browser Fetch, Headers, FormData callers; per-controller state |
| `static/js/shared/time-context.js` | Existing `validTimezoneContext(data)` | Existing `InventoryTime` from `static/temporal.js` |
| `static/js/pages/profile.js` | Existing `profileManager()` | Shared context validator, existing temporal helpers, browser APIs; preserve explicit token-retry UX |
| `static/js/pages/password-recovery.js` | Existing `forgotPassword()` and `resetPassword()` | Shared CSRF helper, browser APIs |
| `static/js/pages/superadmin.js` | Existing `superPanel()` inline controller | Shared CSRF/context helpers, existing temporal and audit helpers |
| `static/js/pages/inventory.js` | Existing `inventoryApp()` only | Shared helpers plus existing temporal/audit helpers |

`static/superadmin.html` loses its executable inline controller. All five HTML pages receive explicit script lists. Keep the existing `static/script.js` unchanged as a temporary legacy entrypoint for older cached HTML; new pages do not load it. This is an explicit migration buffer, not a second active controller or a test reference implementation. Retiring it requires a separate cache-compatibility decision. Do not introduce dynamic script injection or another loading mechanism. Keep existing global factory names so HTML expressions do not change.

## Inventory feature boundaries

After the first PR is merged, extract one feature boundary per PR, with its state and methods together:

1. Consumption reports and work-order drill-down.
2. Replenishment planning and minimum editing.
3. Physical counts, import preview/resolution and transfer receipts, subdivided where their shared state makes that safer.
4. Catalog/store/user/equipment administration, grouped by actual state ownership.
5. History, audit display, exports and navigation; reduce the remaining entrypoint to explicit composition and shared application lifecycle.

These are sequencing directions, not permission to guess field ownership. Before each extraction, map the methods' `this` reads/writes and external functions. Assign each state property to exactly one owner; document intentional cross-feature calls. Preserve the existing flat Alpine-facing object while extraction is in progress.

Feature factories return fresh state for every application instance. Compose property descriptors, rather than spreading getter-bearing objects: copying with object spread evaluates getters and can replace reactive derived values with startup snapshots. Reject duplicate property ownership instead of silently allowing a later feature to overwrite an earlier one. Composition must preserve method `this`, getter access, property enumerability and instance isolation. Do not turn cross-feature calls into a generic event bus or global singleton store.

The precise files, ownership map and interfaces for each later boundary are decided in that boundary's reviewed plan. This design does not require migrating all 3,100 lines in one PR.

## Testing and load order

Add one test-only page loader in `regression_tests/helpers/frontend.cjs`. It reads each shipped HTML page's local script references in document order and executes those files in a VM using the real filenames. It excludes remote Alpine execution; separate contracts confirm the expected factories are available before Alpine, all dependency scripts are deferred in order, local references resolve, and each page loads the required helpers. There is no production loader or testing-only runtime path.

Update existing tests to use the shipped page entrypoints instead of reading the old monolith or extracting the superadmin inline script with a regex. Preserve all existing assertions for CSRF, request payloads, report time context, receipts, imports, counts, permissions, audit, dialogs and profile states. Test the actual controller selection on each page, not only file existence. Include old-HTML load coverage for the frozen legacy entrypoint and assert that each new page loads exactly one controller for its surface.

For later composition, test that getters remain getters and change with state, separate instances do not share arrays/forms, duplicate ownership fails explicitly, and methods retain the composed receiver. Retain behaviour regressions before and after moving each boundary. Do not store a duplicate production implementation as a permanent reference fixture.

Each implementation PR runs all Python and JavaScript regression tests, JavaScript syntax checks for its changed files and `git diff --check`. It receives a fresh final review focusing on execution order, missing globals, fresh state, getters, cross-feature ownership and unchanged API behaviour. Browser/mobile checks are performed when a permitted browser session is available; automated VM tests are not presented as rendered UI verification.

## Release and rollback

Existing `uvicorn main:app` and static hosting remain unchanged. Reference every newly required file in the same PR that creates it, and update HTML cache versions together. The existing query-string versions are not immutable assets: replacing `script.js` with dependency-requiring code would break old HTML that does not load those dependencies. Freeze that legacy file during extraction, and switch new HTML to `static/js/pages/inventory.js` with explicit helper references. New pages must never load both entrypoints. Retire the legacy file only after a reviewed cache/compatibility policy, rather than guessing when every browser has refreshed. Unchanged open pages continue to use the same backend contracts.

A git revert restores the prior file layout and page references. There are no data migrations or production mutations to reverse. After the owner merges each PR, verify public asset availability and script references, then perform signed-in read-only smoke checks when browser access permits.

## Known verification limitation

Production browser observation currently cannot resume the earlier credential session. Do not reset or route around that restriction. This does not prevent local dependency/behaviour regression tests or public asset checks, but signed-in rendered smoke verification remains a separate gate and must be reported honestly.
