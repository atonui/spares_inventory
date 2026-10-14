# Frontend Navigation Extraction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Preserve Native execution with one fresh final whole-branch review. Steps use checkbox tracking.

**Goal:** Give shared navigation flags/actions/view label one owner without changing panel or modal behavior.

**Architecture:** navigationFeature() supplies fourteen properties, composed by v20. Existing features retain their own panel/modal flags; navigation reads/writes them through the flat composed app. Shared lifecycle/API/data loading remain core.

**Tech Stack:** Classic JavaScript/AlpineJS3.13.0, Node VM/FastAPI/pytest; no new dependency/build step.

**Spec:** docs/superpowers/specs/2026-10-13-frontend-organisation-design.md (owner-approved architecture).

**Status:** Owner approved; implementation/verification complete; fresh final review approved after documentation correction; Native retained and publication authorized.

## Global Constraints

- Preserve screens/Alpine bindings/permissions/requests/auth/CSRF/timezones/stock/exports.
- Owner merges; no deployment/production writes. Standing authorization permits automatic verified branch/PR publication.
- No bundler/install/runtime dependency/framework migration/redesign/CSS/new feature/endpoint/migration/unrelated fix.
- Preserve global factories/flat app, descriptor composition/duplicate rejection, fresh factories/live getter/composed receivers.
- Freeze static/script.js and controllers through v19; v19 blobSHAc1a5ec719b2d9536c009e47044e2cebd7008ff62.
- Existing helpers/features/other four HTML pages byte-identical; index changes only script references. Backend/database/dependencies unchanged.
- Copy defaults/bodies unchanged. No extra modal closing, panel validation, role checks, awaits, focus behavior or request/error handling.
- Browser/mobile verification pending existing credential limitation; do not reset or route around it.

## Ownership and Interfaces

Create static/js/inventory/navigation.js exposing navigationFeature():object, owning fourteen properties:

| Kind | Properties |
| --- | --- |
| State(10) | showProfileModal:false; showUsersPanel:false,showStoresPanel:false,showPartsPanel:false,showAllPartsPanel:false,showAllStoresPanel:false,showMyPartsPanel:false,showStoreInventoryPanel:false,showStoreTypesPanel:false,showInventoryPanel:true |
| Methods(3) | closeAllOtherPanels(),closeAllPanels(),openPanel(panelName) |
| Getter(1) | currentViewLabel |

Consumed composed providers: selectedStore,filterInventory(),loadConsumptionReport(),loadReplenishment(); peer flags read/written include showArchivedPanel,showMovementsPanel,showLowStockPanel,showLogsPanel,showReportsPanel,showEquipmentPanel and existing stock/user/store/part/equipment/calibration/store-type modal flags. Preserve exact cross-owner assignments; do not move peer flags into this owner or rename them.

closeAllOtherPanels sets exactly existing fourteen non-inventory flags false, leaving showInventoryPanel unchanged. closeAllPanels sets the same flags false and inventory true. openPanel calls closeAllPanels, sets only the existing modal list false plus inventory false; then, for inventory, calls filterInventory before setting requested flag true. Sets this[panelName]=true; report/replenishment requests fire without awaiting/returning them. Preserve arbitrary panel names and unspecified modals remaining unchanged; no new guard or promise handling.

currentViewLabel remains a live getter with exact existing ordered priority: store inventory,inventory,all stores,all parts,my parts,replenishment,equipment,movements,users,stores,parts,store types,archived,activity,reports. Selected-store label retains existing optional-name interpolation; fallback Inventory. Do not change multiple-open-panel precedence.

Create static/js/pages/inventory-v20.js from v19 removing only fourteen properties, composing fresh navigationFeature after archivedRecordsFeature. Preserve all265descriptors/defaults/function/getter sources. Index order through archived-records, then navigation/inventory-v20; all defer with ?v=20261014-frontend-20, unchanged Alpine3.13.0.

## Review Focus

1. close helpers retain exact flag sets and inventory differences; feature-owned and unspecified modal flags keep existing behavior.
2. Inventory navigation retains filters and calls filterInventory before opening; report/replenishment requests remain unawaited, with no request on other panels.
3. View labels remain live with exact priority, selected-store naming/missing-name behavior and default fallback.
4. Actual shared HTML navigation/close bindings and feature openers/cancel/focus behavior retain composed cross-owner contracts; arbitrary panel names are unchanged.
5. Fresh factories/live descriptor, cachedv19 equivalence/265properties/frozen modules/non-script markup remain correct; shared lifecycle unchanged.

---

### Task1: Extract and wire navigation

**Create:** static/js/inventory/navigation.js,static/js/pages/inventory-v20.js,regression_tests/test_navigation_feature.cjs,regression_tests/test_navigation_ui.cjs.

**Modify:** static/index.html,regression_tests/test_frontend_entrypoints.cjs,docs/frontend-organisation.md.

**Interfaces:** Produce fourteen properties above; consume exact peer providers/flags. Keep feature owners and shared core unchanged.

- [x] **Step1 Baseline:** MergedPR120(c27edb7), fullNode/Python625/830pass; recordv19hash/contract before edits. Interpreter /workspace/scratch/22e193396fd5/timezone-venv/bin/python.
- [x] **Step2 RED/prior behavior:** Exact14keys/defaults/freshflags/livegetter and real-composer provider/order tests. Missing-module RED; Step6 shipped cases pass unchangedv19beforemove.
- [x] **Step3 GREEN:** Copy ten defaults/three methods/getter unchanged; isolated tests pass without new providers/body rewrites.
- [x] **Step4 Entrypoint RED:** Expectv20manifest/cache/inventory-only factory; cachedv19originalmanifest/hash/no newfactory/265descriptor equivalence; historicalguard throughv19. Expected manifest/factoryfail beforewiring.
- [x] **Step5 Wiring GREEN:** Copyv19→v20/remove onlyownedproperties/compose/updateindex; tests pass,cachedv19self-contained.
- [x] **Step6 Shipped GREEN:** Rerunv19-established cases throughv20. Enumerate exact non-inventory flags for both close helpers with inventory true/false. Modal fixture asserts only listed modals close, stock-count state and consumption/stats/detail flags remain as before. Opening inventory keeps search/store/advanced/selected state, calls filter before requested flag true; report/replenishment pending promises prove synchronous unreturned behavior, otherpanels no request. Arbitraryname property retained. Each view-label branch, multiple-flags priority, selected-store rename/null and default fallback; getter reacts. Execute actual HTML openPanel/closeAllPanels expressions and existing feature opening/cancellation/focus tests. Freshflags. Newfeature/UI,entrypoint/full existing feature suites pass.
- [x] **Step7 Verify/document:** Updateowner/providers/active/frozencontroller/planstatus, correcting navigation-core ownership references. FullNode/Python/syntax/diff pass; exactextraction/frozentracked/backend/otherpages/nonscriptmarkup unchanged. Browserpending.
- [x] **Step8 Review/publication:** Onefreshfinalwholebranch reviewer checks spec/plan/fivefocusareas. FixCritical/Important RED→GREEN/reverify; recordMinor. Commit/autopublishbranchPR; remotetree equals testedlocal; reportlink. Ownermerges/no production writes.

## Plan self-review

Shared navigation owns its flags/actions/label while deliberately coordinating peer-owned UI flags through existing flat interfaces. Exact reset sets and unawaited loader semantics are explicit compatibility requirements. Five focus areas have concrete tests. Architecture approved; plan is owner-approved, Native retained/publicationauthorized. Shared lifecycle/API organization is the remaining boundary after this extraction.

## Execution evidence

Baseline625Node/830Python passed. IsolatedRED2missingmodulefail→GREEN2pass;26shipped cases passed unchangedv19; entrypointRED2expectedfail. Targeted65/full654Node pass, final830Python pass150.83s. Syntax/diff/exactextraction/289frozenfiles/nonscriptmarkup pass. Fresh independent review approved with no remaining findings after provider-ownership documentation correction. Core381lines. Browser/mobile verification pending existing access limitation. Automatic publication authorized; ownermerges.
