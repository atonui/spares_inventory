# Frontend Entrypoint Extraction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Execution method already selected: Native, followed by one fresh final code review.

**Goal:** Extract shared helpers and page controllers while preserving production behaviour and cached-page compatibility.

**Architecture:** Ordered classic scripts expose the same global Alpine factories. New HTML loads the extracted controller and its explicit dependencies before Alpine. `static/script.js` remains frozen for older HTML; no new page loads it.

**Tech Stack:** Existing FastAPI static hosting, JavaScript, AlpineJS 3.13.0, Node VM regression tests and Python pytest; no new dependencies.

**Spec:** `docs/superpowers/specs/2026-10-13-frontend-organisation-design.md`

## Global Constraints

- This is a behaviour-preserving refactor: retain current screens, Alpine bindings, permissions, requests, authentication, CSRF recovery, timezone handling, stock workflows and exports.
- The owner merges; this work does not deploy or modify production data.
- No bundler, package installation, runtime dependency, framework migration or server change.
- No HTML redesign, CSS reorganisation, new feature, endpoint, database migration or unrelated bug fix.
- Keep existing global factory names so HTML expressions do not change.
- Keep the existing `static/script.js` unchanged as a temporary legacy entrypoint for older cached HTML; new pages do not load it.
- Do not introduce dynamic script injection or another loading mechanism.
- Local dependent scripts use defer in dependency order, followed by the existing deferred Alpine script.
- Pin all changed/new JavaScript references to `?v=20261013-frontend-1` within this PR; CSS remains unchanged.
- Later inventory feature composition is outside this first extraction. It requires separately reviewed ownership maps/plans after this PR merges.

## Review Focus

1. Cold page load: the correct global factory and all its helpers exist before Alpine starts.
2. Cached old HTML: the frozen legacy entrypoint still exposes the existing factories without new dependencies.
3. Derived state and second instances: getters remain getters, receiver binding is preserved, forms/arrays are not shared.
4. Tests following real code: every existing controller regression runs the extracted page entrypoint, not the frozen legacy file or removed inline code.
5. Cross-page helpers: repeated/shared dependencies in combined VM fixtures are executed once; an accidental duplicate or wrong order in one shipped page is still rejected.

---

### Task 1: Extract and wire the first complete boundary

This is one atomic shipping boundary: controllers, shared helpers, page references and test loaders must land together. Setup and release wiring are part of this task, not independently shippable scaffolding.

**Files to create:**
- `static/js/shared/csrf.js`: existing `InventoryCsrf` implementation.
- `static/js/shared/time-context.js`: existing `validTimezoneContext(data)`.
- `static/js/pages/inventory.js`: existing `inventoryApp()` only.
- `static/js/pages/profile.js`: existing `profileManager()` only.
- `static/js/pages/password-recovery.js`: existing `forgotPassword()` and `resetPassword()`.
- `static/js/pages/superadmin.js`: existing inline `superPanel()`.
- `regression_tests/helpers/frontend.cjs`: test-only shipped-page loader.
- `regression_tests/test_frontend_entrypoints.cjs`: load-order, factory/state and legacy compatibility contracts.
- `docs/frontend-organisation.md`: current file responsibilities, load order, frozen-file policy, test command and later extraction sequence.

**Files to modify:**
- `static/index.html`, `static/profile.html`, `static/forgot_password.html`, `static/reset_password.html`, `static/superadmin.html`: script references only; remove superadmin's executable inline controller.
- `regression_tests/test_archiving_ui.cjs`, `test_inventory_usability.cjs`, `test_profile_settings_ui.cjs`, `test_replenishment.cjs`, `test_sitewide_csrf.cjs`, `test_stock_audit_ui.cjs`, `test_stock_counts_ui.cjs`, `test_stock_import_ui.cjs`, `test_stock_reports_ui.cjs`, `test_superadmin_ui.cjs`, `test_timezone_settings_ui.cjs`, `test_transfer_receipts_ui.cjs`: use the shipped-page loader instead of the old script/inline source, preserving all existing assertions.

**Interfaces:**
- Production consumes browser APIs and the unchanged existing `InventoryTime` / `formatStockAuditDetails` helpers.
- Production exposes unchanged `inventoryApp()`, `profileManager()`, `forgotPassword()`, `resetPassword()`, `superPanel()`, `validTimezoneContext(data)`, `InventoryCsrf.token(owner, base='/api')` and `.request(owner, url, options={}, base='/api')`.
- Test helper exports `pageScripts(page: string): Array<{src: string, localPath: string|null, defer: boolean}>` and `loadPageScripts(page: string, context: vm.Context): vm.Context`. Page names are the five filenames below. It resolves local script paths relative to `static/`, strips query strings and executes local files with their real filenames, in page reference order. Remote scripts are never fetched/executed. Reject executable inline scripts on the new pages, async local scripts, duplicate local paths within a page and paths escaping `static/`.
- A private WeakMap of VM contexts to executed local paths deduplicates dependencies only across intentional combined-page fixtures. Validate each page manifest before deduplicating. Do not infer browser rendering or execute Alpine in this helper.

**Exact local JavaScript order before the unchanged deferred Alpine CDN script:**

| Page | Scripts, in order |
| --- | --- |
| `index.html` | `temporal.js`, `audit.js`, `js/shared/csrf.js`, `js/shared/time-context.js`, `js/pages/inventory.js` |
| `profile.html` | `temporal.js`, `js/shared/time-context.js`, `js/pages/profile.js` |
| `forgot_password.html` | `js/shared/csrf.js`, `js/pages/password-recovery.js` |
| `reset_password.html` | `js/shared/csrf.js`, `js/pages/password-recovery.js` |
| `superadmin.html` | `temporal.js`, `audit.js`, `js/shared/csrf.js`, `js/shared/time-context.js`, `js/pages/superadmin.js` |

- [x] **Step 1: Establish baseline and preserve the frozen boundary.** Run `node --test regression_tests/*.cjs` and `python -m pytest -q` before edits. Record the current legacy blob SHA `4ac2430b70019cee3b5e53ca083b74d16c44a692` for the compatibility test. Compare `static/script.js` with main throughout execution; no change is permitted in this PR.
- [x] **Step 2: Write failing entrypoint contracts.** Assert the exact table above, all local scripts deferred with the prescribed cache key, exactly one matching controller per page, unchanged Alpine URL/version and no executable inline controller. Evaluate each shipped page in a fresh VM: expected factory callable, unrelated page factories absent (both recovery factories intentionally coexist), `validTimezoneContext` rejects missing/invalid context, CSRF acquisition is reachable on the pages that need it.
- [x] **Step 3: Add state/legacy assertions.** Confirm inventory and profile descriptor getter names/types remain identical to their legacy counterparts, and getter values respond to mutations. For inventory, profile and superadmin, mutate one instance's form/array then assert a second instance retains defaults. A legacy-only VM loading the original temporal/audit helpers and frozen `static/script.js` exposes all four legacy factories and the original CSRF helper. Assert the legacy file's Git blob hash remains the SHA above. Combined index/profile/superadmin fixtures load shared helpers without lexical redeclaration; deliberately duplicated page script references must fail manifest validation.
- [x] **Step 4: Observe RED.** Run `node --test regression_tests/test_frontend_entrypoints.cjs`. The desired page-source/order contracts must fail because the extraction is missing, not due to an invalid fixture, syntax error or absent Node/browser stub. If necessary, implement the test helper first and demonstrate the intended contract failures before moving production code.
- [x] **Step 5: Extract existing declarations unchanged.** Copy the existing function/helper declaration bodies to the six production files, preserving signatures, getters, state defaults, messages and request handling. No composition layer is needed yet. Freeze the old script rather than deleting declarations from it. Remove the superadmin inline declaration only when its external controller is wired.
- [x] **Step 6: Wire pages and migrate regression loaders.** Apply the exact script table and cache key. Preserve markup and Alpine expressions. Replace direct monolith loads and inline-script regex extraction with `loadPageScripts` for the appropriate page. Combined timezone fixtures load index plus profile; shared-CSRF fixtures select inventory/superadmin/recovery pages explicitly. Only the dedicated legacy compatibility test may load `static/script.js` directly.
- [x] **Step 7: Observe GREEN and document boundaries.** Run entrypoint contracts, then `node --test regression_tests/*.cjs`. Preserve the existing security/stock/report/dialog assertions. Write the concise maintenance guide: production ownership map, page dependency table, deprecated frozen-file warning and next reports extraction. Mark the reviewed spec approved and record this first boundary separately from later work.
- [x] **Step 8: Verify the complete change.** Run `python -m pytest -q`, `node --test regression_tests/*.cjs`, `node --check` for all six new JavaScript files and `git diff --check`. Confirm `git diff origin/main -- static/script.js` is empty. Search regression tests for old direct/inline loaders; only deliberate legacy coverage remains. Use an available permitted browser for read-only startup checks; if unavailable, explicitly record rendered QA as unverified.
- [x] **Step 9: Fresh final review.** Request one reviewer with the approved spec, this plan, base SHA and complete diff. Focus on the five conditions above, unchanged controller bodies, remote/local script order, and stale-page compatibility. Fix Critical/Important findings with failing/passing regressions; repeat affected and full checks after product changes.
- [ ] **Step 10: Commit and publish one PR.** Commit the complete extraction, test migration and docs. Publish against main, verify the remote tree matches the tested local tree, and report tests and the browser limitation. Leave merging/deployment to the owner. Later feature extraction starts only after this PR is merged and its own boundary is reviewed.

## Self-review result

The first boundary has explicit filenames, globals, load order, cache key and compatibility policy. All five review conditions map to Steps 2–3 and final review. Existing factory behaviour remains covered by the migrated suites. Later feature composition is explicitly deferred to its own plan; no getter-copy/composition helper is introduced prematurely. The plan creates no dependencies and requires no production data access.

**Execution record:** Steps 1–9 completed with 826 Python tests and 149 Node tests passing, syntax/staged-whitespace checks clean, and fresh review findings addressed. Step 10 publication is recorded in the PR metadata and execution ledger. The embedded Node harness in `test_stock_safety.py` was also migrated; extracted code received trailing-whitespace cleanup only, with the legacy file unchanged.
