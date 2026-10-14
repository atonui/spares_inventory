# Application Core Frontend Extraction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Preserve Native execution with one fresh final whole-branch review. Steps use checkbox tracking.

**Goal:** Give shared application lifecycle/API providers an explicit owner and finish the composition-only inventory entrypoint without changing behavior.

**Architecture:** inventoryCoreFeature() owns the remaining41core properties (21state/20methods), distinct from feature/UI owners. V21 inventoryApp only composes fresh core/feature objects. Core is the shared session/request/data lifecycle owner, not a container for restored feature workflows. Existing peers remain byte-identical.

**Tech Stack:** Classic JavaScript/AlpineJS3.13.0, Node VM/FastAPI/pytest; no dependency/build step.

**Spec:** docs/superpowers/specs/2026-10-13-frontend-organisation-design.md (owner-approved architecture).

**Status:** Owner approved; implementation/verification complete; fresh final review approved without findings; Native retained and publication authorized.

## Global Constraints

- Preserve screens/Alpine bindings/permissions/requests/auth/CSRF/timezones/stock/exports.
- Owner merges; no deployment/production writes. Standing authorization permits automatic verified branch/PR publication.
- No bundler/install/runtime dependency/framework migration/redesign/CSS/new feature/endpoint/migration/unrelated fix.
- Preserve global factories/flatapp, descriptor composition/duplicate rejection, fresh nested state/composed receivers; all265application properties/defaults/function/getter sources stay equivalent.
- Freeze static/script.js/controllers throughv20; v20blobSHAd11be851555b95abfb39ef9e957c7eca3401b497.
- Existing helpers/features/other four HTML pages byte-identical; index changes only script references. Backend/database/dependencies unchanged.
- Copy core object contents verbatim, including existing comments; do not rewrite auth/transport, remove debug logs/unused fields, normalize errors, add races/guards/reset behavior or modernize direct fetch.
- Browser/mobile verification pending existing credential limitation; do not reset or route around it. Frozen-file retirement is a separate cache-policy decision, not part of this plan.

## Ownership and Interfaces

Create static/js/inventory/application-core.js exposing inventoryCoreFeature():object with exactly41properties:

| Kind | Properties |
| --- | --- |
| State(21) | timezoneContext:null,timezoneError:'',timezoneLoading:false,isAuthenticated:false,currentUser:null,token:null,loading:false,error:'',successMessage:'',loginForm:{email:'',password:'',remember_me:false},inventoryLoadFailed:false,inventoryLoadError:'',stats:{},stores:[],parts:[],inventory:[],workOrders:[],users:[],storeTypes:[],csrfToken:'',apiUrl:'/api' |
| Methods(20) | loadTimezoneContext(),formatInstant(value),formatBusinessInstant(value,context),formatDate(value),businessToday(),checkAuth(),login(),getCurrentUser(),logout({localOnly=false}={}),getCsrfToken(),apiCall(endpoint,options={},onTimeContext=null),loadAllData(),loadStats(),loadStores(),loadStoreTypes(),loadParts(),loadInventory({refreshReplenishment=true}={}),loadUsers(),refreshDashboard(),getUserName(userId) |

External dependencies: InventoryCsrf,InventoryTime,validTimezoneContext,resetConsumptionReports,fetch,Headers/FormData via shared API,localStorage,window,console. Peer providers through composed this: movementTimeContext/activityTimeContext,filterInventory(),selectedStore/storeInventory,showLowStockPanel/loadReplenishment(),loadMovements(),loadPendingTransfers(),loadEquipment(),loadEquipmentStats(),loadCalibrationSettings(). Document these intentional lifecycle calls/writes; no peer ownership moves.

Keep timezone busy/actor guards and existing validation/errors/final loading behavior. Formatting uses existing display/business/context/date-only helpers with Unknown fallbacks. CheckAuth uses stored user, real /me direct fetch, authenticated state, token failure feedback then continues data loading; malformed stored user/auth failure clears stored/current user. Login uses real shared CSRF/cookie request with exact raw loginForm, existing failure wording and storage of user only. getCurrentUser retains direct Bearer-token header and current fetch options. Logout retains context clears, optional local-only request suppression, swallowed logout error, report reset, user/storage clear and redirect. No transport modernization.

apiCall retains JSON versus FormData header distinction/cookies/shared CSRF,401local logout/null,403detail,422detail expansion,429Retry-After,204null,other APIerrors,report-time-context validation/callback and error rethrow. Missing/invalid metadata still gives callback null. Keep existing response parsing/order and metadata behavior; no new status branches.

loadAllData retains timezone-first then parallel common/peer loaders with role-gated loadUsers, catch/final loading. loadStats preserves zero fallbacks/fresh object/swallowed failure; stores/parts load errors propagate; store-type load failure clears types; inventory retains filter/selected-store update, optional replenishment refresh suppression, inventory failure flags/error wording and finally loading release; users retain admin/superadmin gate. Dashboard keeps parallel stats/equipment-stats; getUserName retains falsy-ID Unassigned, strict match/name or Unknown.

Create static/js/pages/inventory-v21.js exposing inventoryApp() as only explicit composeInventoryFeatures(inventoryCoreFeature(), then all existing factories in current order). No inline core object, dynamic loader or setup side effects. Load application-core immediately after shared features composer and before existing inventory feature scripts; other relative order unchanged, followed by v21 and unchanged Alpine3.13.0. All index local refs defer with ?v=20261014-frontend-21. Each app constructs fresh core/features exactly once.

## Review Focus

1. Cached-user restore/login/logout and malformed/expired session/token failure preserve storage, authentication, report/time-context reset and redirects; direct /me fetch stays unchanged.
2. Real shared CSRF/API JSON/multipart/cookies, bounded replay/status errors/null responses/metadata callback retain behavior across all peer workflows.
3. Timezone loading busy/actor changes, validation/Unknown formatting and independent app state preserve current lifecycle semantics.
4. Startup/dash parallel loaders, roles, inventory selected balances/replenishment suppression and mixed caught/propagated loader errors retain composed providers/order/state.
5. Exact41core ownership/fresh state, composition-only factory/once-per-instance allocation, cachedv20/265descriptor equivalence/frozen modules/script order remain correct; final docs distinguish structural completion from pending browser acceptance.

---

### Task1: Extract application core and finish composition

**Create:** static/js/inventory/application-core.js,static/js/pages/inventory-v21.js,regression_tests/test_application_core_feature.cjs,regression_tests/test_application_core_ui.cjs.

**Modify:** static/index.html,regression_tests/test_frontend_entrypoints.cjs,docs/frontend-organisation.md.

**Interfaces:** Produce41core providers above; consume exact peers/helpers. Composition root remains global inventoryApp with265flat properties.

- [x] **Step1 Baseline:** MergedPR121(78c65b0), fullNode/Python654/830pass; recordv20hash/contract before edits. Interpreter /workspace/scratch/22e193396fd5/timezone-venv/bin/python.
- [x] **Step2 RED/prior behavior:** Exact41keys/defaults/fresharrays/forms/stats plus real-composer peer/helper receiver tests. Missing-module RED; establish Step6 cases unchangedv20beforemove, all pass.
- [x] **Step3 GREEN:** Copy whole core object contents verbatim into inventoryCoreFeature; isolated tests pass without body rewrites/new providers.
- [x] **Step4 Entrypoint RED:** Expectv21manifest/cache/core factory onlyonindex, application-core aftersharedcomposer. Cachedv20originalmanifest/hash/no newfactory/265descriptor equivalence; historicalguard throughv20. Composition-only contract asserts no inlinecore and each factory invoked once perapp. Expected manifest/factory/compositionfail beforewiring.
- [x] **Step5 Wiring GREEN:** Create explicitv21composition, updateindex/newcore ref; isolated/entrytests pass; cachedv20self-contained.
- [x] **Step6 Shipped GREEN:** Rerunv20-established lifecycle tests onv21. Stored-user absent/malformed, /me success/failure/directheaders, checkAuth token failure still loads data. Login realCSRF rawpayload/cookies/storage-user-only/success/loaders/failure state; local/remote logout with swallowed requesterror/report/context reset/storage/redirect. apiCall401/403/422/429/204/500/invalidJSON and valid/missing/invalid metadata; real JSON/multipart replay/token/permission regressions via existing sitewideCSRF/full peer suites. Timezone busy/deferred actor-change/validation/error/Unknown formatting. Data startup timezone-before-parallel-loads/role gate, each loader's success/failure behavior, selectedbalances/replenishmentsuppression, dashboard parallel and usernamefalsy/strictID. Fresh nested core state and composition allocations; actualpagecheckAuth/login expressions remain. Newcore/UI, entrypoint, temporal, timezone, CSRF/full feature suites pass.
- [x] **Step7 Verify/document:** FullNode/Python/syntax/diff/exactcorecopy/frozentracked/backend/otherpages/nonscriptmarkup pass. Guide records explicit core/peer provider ownership and final composition root; mark structural implementation complete on branch pending merge, browser/mobile/public-asset acceptance pending, frozen retirement deferred. Plan status consistent.
- [x] **Step8 Review/publication:** Onefreshfinalwholebranch reviewer checks spec/plan/fivefocusareas. FixCritical/Important RED→GREEN/reverify; recordMinor. Commit/autopublishbranchPR; remotetree equals testedlocal; reportlink. Ownermerges/no production writes.

## Final acceptance after merge

Confirm public deployed script references/asset availability once owner merges. Signed-in read-only desktop/mobile smoke checks require permitted browser access; do not present VM coverage as rendered verification or route around the recorded credential restriction. These are acceptance gates separate from the local implementation PR and must remain explicitly pending until actually checked.

## Plan self-review

Feature/UI ownership is already separated; this final owner supplies shared session/request/date/data lifecycle providers. Moving its explicit coherent core out of the page leaves inventoryApp as readable composition, rather than creating another mixed workflow monolith. All existing41properties are mapped with exact peer dependencies. Five focus areas have concrete tests and existing broad regression coverage. Architecture approved; final plan is owner-approved, Native retained/publicationauthorized.

## Execution evidence

Baseline654Node/830Python passed. IsolatedRED2missingmodulefail→GREEN2pass;37shipped cases passed unchangedv20; entrypointRED3expectedmanifest/factory/compositionfail. Targeted113/full695Node pass; final830Python pass104.62s. Syntax/diff/exactcorecopy/294frozenfiles/nonscriptmarkup pass. Fresh independent review approved without findings. V21entrypoint22lines/core+19features onceperapp. Structuralimplementationcompleteonbranchpendingownermerge; publicassets/signed-in desktopmobile acceptancepending, frozenretirementdeferred. Automatic publication authorized; ownermerges.
