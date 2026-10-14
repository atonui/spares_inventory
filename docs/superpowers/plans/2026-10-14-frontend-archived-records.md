# Archived Records Frontend Extraction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Preserve Native execution with one fresh final whole-branch review. Steps use checkbox tracking.

**Goal:** Give archived-record listing/restoration one owner without changing behavior.

**Architecture:** archivedRecordsFeature() supplies four existing properties, composed by v19. Core retains lifecycle/navigation and shared API/feedback/data refresh providers. Parts/store/user administration continue invoking its loader when the archive panel is open.

**Tech Stack:** Classic JavaScript/AlpineJS3.13.0, Node VM/FastAPI/pytest; no new dependency/build step.

**Spec:** docs/superpowers/specs/2026-10-13-frontend-organisation-design.md (owner-approved architecture).

**Status:** Owner approved; implementation/verification complete; fresh final review approved without findings; Native retained and publication authorized.

## Global Constraints

- Preserve screens/Alpine bindings/permissions/requests/auth/CSRF/timezones/stock/exports.
- Owner merges; no deployment/production writes. Standing authorization permits automatic verified branch/PR publication.
- No bundler/install/runtime dependency/framework migration/redesign/CSS/new feature/endpoint/migration/unrelated fix.
- Preserve global factories/flat application, descriptor composition/duplicate rejection, fresh state/composed receivers.
- Freeze static/script.js and controllers through v18; v18 blobSHA17480b02e74442a29448101d3ca7336b639f333d.
- Existing helpers/features/other four HTML pages byte-identical; index changes only script references. Backend/database/dependencies unchanged.
- Copy defaults/bodies unchanged. No role/validation/confirmation/refresh/error/loading/timer changes.
- Browser/mobile verification pending existing credential limitation; do not reset or route around it.

## Ownership and Interfaces

Create static/js/inventory/archived-records.js exposing archivedRecordsFeature():object with exactly archivedRecords:[],showArchivedPanel:false,loadArchivedRecords(),restoreArchivedRecord(record). Allocate rows freshly. Providers via composed this: apiCall(endpoint,options?),error,successMessage,loading,loadParts(),loadStores(),loadUsers(),loadInventory(),loadStats(); external confirm. Core navigation writes panel flag. Existing admin features read flag/call loader; keep these cross-owner accesses unchanged.

Listing clears error, starts parallel GETs /parts?include_archived=true, /stores?include_archived=true, /users?include_archived=true in that order. Flatten results by kind order, retaining row order and truthy archived_at only, mapping {kind,id,label:part_number||name,archived_at}. Same IDs across kinds remain separate. Loader does not change loading or success; failure sets Failed to load archived records: plus message and retains old rows. No added client role gate; existing HTML admin/superadmin visibility remains.

Restore returns early when loading or kind outside parts/stores/users, then exact confirmation Restore ${record.label} to active use?. Decline preserves state. Set loading true/error blank, POST /${kind}/${id}/restore with no body, copy server message, await parts→stores→users→inventory→stats→archived-record refresh. Finally release loading. Catch retains Failed to restore record: wording; no initial success clearing, timer, local row removal or selection change. Preserve partial refresh state and actual swallowed inventory/stats/archive loader errors; do not add retries outside shared CSRF.

Create static/js/pages/inventory-v19.js from v18 removing only four properties and composing fresh archivedRecordsFeature after browsing. Preserve all265descriptors/defaults/function/getter sources. Index order through browsing then archived-records and inventory-v19; all defer with ?v=20261014-frontend-19, unchanged Alpine3.13.0.

## Review Focus

1. Parallel list request order/archived truthiness/group order/label fallback/composite kind+ID identity remain unchanged, with empty results and partial failure preserving old rows.
2. Restore loading/unsupported-kind/decline guards preserve feedback/state; exact prompt/POST/server message and six refreshes retain order and composed receivers.
3. Write/refresh failures preserve old or partially refreshed state, catch wording/final loading and swallowed core loader behavior without adding timer/local mutation.
4. Actual admin/superadmin UI visibility, refresh/restore/navigation bindings and peer administration calls retain ownership; real CSRF cookies/JSON/replay/permission/token handling remains intact.
5. Fresh rows/cachedv18 equivalence/265descriptors/frozen modules and non-script markup remain correct; backend archive/history policies untouched.

---

### Task1: Extract and wire archive records

**Create:** static/js/inventory/archived-records.js,static/js/pages/inventory-v19.js,regression_tests/test_archived_records_feature.cjs,regression_tests/test_archived_records_ui.cjs.

**Modify:** static/index.html,regression_tests/test_frontend_entrypoints.cjs,docs/frontend-organisation.md.

**Interfaces:** Produce four properties above; consume exact core providers. Keep navigation/admin methods/backend unchanged.

- [x] **Step1 Baseline:** MergedPR119(dac7134), fullNode/Python597/830pass; recordv18hash/contract before edits. Interpreter /workspace/scratch/22e193396fd5/timezone-venv/bin/python.
- [x] **Step2 RED/prior behavior:** Exact4keys/defaults/freshrows and real-composer API/refresh receivers. Missing-module RED; Step6 shipped cases pass unchangedv18beforemove.
- [x] **Step3 GREEN:** Copy defaults/two bodies unchanged; isolated tests pass without new providers/body rewrites.
- [x] **Step4 Entrypoint RED:** Expectv19manifest/cache/inventory-only factory; cachedv18originalmanifest/hash/no newfactory and265descriptor/source equivalence; historicalguard throughv18. Expected manifest/factoryfail beforewiring.
- [x] **Step5 Wiring GREEN:** Copyv18→v19/remove onlyownedproperties/compose/updateindex; tests pass, cachedv18self-contained.
- [x] **Step6 Shipped GREEN:** Rerunv18-established cases throughv19. Listing deferred requests prove all3started before resolving, grouping/row order/truthy archived_at/part-name fallback/sameIDdifferentkinds/empty and rejection retaining prior data/loading/success. Restore eachkind, loading/unsupported/declined no-op, exact confirmation/request/servermessage/refreshorder/final loading/no timer, selection retained. Reject write and each refresh provider, assert partial completion/error wording; actual swallowed inventory/stats/archive errors preserve existing flow. Actual admin/superadmin markup/refresh/restore/navigation expressions and existing admin archive regressions preserve peer calls. RealapiCSRFPOSTcredentials/JSON/no body/initialtoken/one explicitretry/repeatedrejection/token/permission failures. Freshstate. Newfeature/UI, entrypoint and full existing admin/archive suites pass.
- [x] **Step7 Verify/document:** Updateowner/providers/active/frozencontroller/planstatus; fullNode/Python/syntax/diff pass; exactextraction/frozentracked/backend/otherpages/nonscriptmarkup unchanged. Browserpending.
- [x] **Step8 Review/publication:** Onefreshfinalwholebranch reviewer checks spec/plan/fivefocusareas. FixCritical/Important RED→GREEN/reverify; recordMinor. Commit/autopublishbranchPR; remotetree equals testedlocal; reportlink. Ownermerges/no production writes.

## Plan self-review

Archive rows/panel/operations share one owner; restore consumes core/peer refresh providers. Existing guard/error/partial-refresh semantics are explicit compatibility requirements. Five focus areas have concrete tests. Architecture approved; plan is owner-approved, Native retained/publicationauthorized.

## Execution evidence

Baseline597Node/830Python passed. IsolatedRED2missingmodulefail→GREEN2pass;25shipped cases passed unchangedv18; entrypointRED2expectedfail. Targeted157/full625Node pass, final830Python pass. Syntax/diff/exactextraction/284frozenfiles/nonscriptmarkup pass; fresh independent review approved without findings. Core464lines. Browser/mobile verification pending existing access limitation. Automatic publication authorized; ownermerges.
