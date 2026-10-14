# Inventory Browsing Frontend Extraction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Preserve Native execution with one fresh final whole-branch review. Steps use checkbox tracking.

**Goal:** Give inventory browsing/search/derived views and selected-store state one owner without changing behavior.

**Architecture:** inventoryBrowsingFeature() supplies21existing properties, composed by new v18 controller. Core retains inventory/catalog data loaders, authentication and lifecycle/navigation. currentViewLabel remains with navigation. Existing stock/admin/export features access composed browsing fields/providers unchanged.

**Tech Stack:** Existing classic JavaScript, AlpineJS3.13.0, Node VM regressions, FastAPI/pytest; no new dependencies/build step.

**Spec:** docs/superpowers/specs/2026-10-13-frontend-organisation-design.md (owner-approved architecture).

**Status:** Owner approved; implementation and verification complete. Fresh final review approved without findings. Native execution retained; automatic publication authorized.

## Global Constraints

- Preserve screens/Alpine bindings/permissions/requests/auth/CSRF/timezones/stock workflows/exports.
- Owner merges; no deployment/production writes. Standing authorization permits automatic verified branch/PR publication.
- No bundler/install/runtime dependency/framework migration/HTML redesign/CSS reorganisation/new feature/endpoint/migration/unrelated fix.
- Preserve global factories/flat application, existing descriptor composition/duplicate rejection, fresh state, live getters/composed receivers.
- Freeze static/script.js and controllers through v17. V17 blob SHA25836e41f5b15b2e04db4ba79397d3a19bdd322d.
- Existing helpers/features/other four HTML pages remain byte-identical; index changes only script references. Backend/database/dependencies unchanged.
- Copy defaults/bodies unchanged; no search improvements, null guards, validation, role changes, filtering fixes or new advanced-search functionality.
- Browser/mobile verification remains pending under existing credential limitation; do not reset or route around it.

## Ownership and Interfaces

Create static/js/inventory/browsing.js exposing inventoryBrowsingFeature():object with exactly21properties:

| Kind | Properties |
| --- | --- |
| State(7) | searchTerm:'',storeFilter:'',storeSearchTerm:'',selectedStore:null,storeInventory:[],filteredInventory:[],advancedSearch |
| Methods(8) | matchInventoryRows(rows,query),filterInventory(),clearInventoryFilters(),filterInventoryAdvanced(),getStoreClass(storeType,storeOwner),canEdit(storeOwner,storeType),isLowStock(item),viewStoreInventory(store) |
| Getters(6) | filteredStoreInventory,editableStores,allPartsView,allStoresView,lowStockItems,myPartsView |

advancedSearch defaults exactly {partNumber:'',description:'',category:'',storeType:'',minQuantity:'',maxQuantity:'',lowStockOnly:false}. Allocate fresh arrays/object. Consumed composed providers: inventory,parts,stores,currentUser,openPanel(panelName). Keep data/loaders/loading/errors, currentViewLabel and all UI panel/modal flags with current owners.

matchInventoryRows preserves String(query||''), trim/lowercase/whitespace splitting and all-term matching across part_number/description/store_name/work_order with String(value||''). Empty query returns a filtered array in existing order. filterInventory matches search then applies truthy storeFilter via Number and strict ID comparison. clearInventoryFilters blanks only searchTerm/storeFilter, calls openPanel('showInventoryPanel'), then filters; preserve core openPanel's own filtering call and resulting double refresh.

Advanced filtering preserves only existing part-number substring, exact category lookup through parts, low-stock predicate, truthy minimum/maximum parseInt checks and assignment to filteredInventory. Description/storeType form fields remain unused; do not activate them. No active advanced filters assigns the inventory reference as before. Preserve numeric0/string0 truthiness, case rules and raw values.

getStoreClass returns store-mine for strict owner/currentUser.id, otherwise store- plus type; keep its current authenticated-user assumption. canEdit returns false without user, true for admin/superadmin, strict owner or central type. editableStores stays live through canEdit. allPartsView/allStoresView return provider arrays directly. isLowStock requires positive threshold, quantity below threshold and no allocation/work order; derived lowStockItems/myPartsView stay live with strict current-user matching.

viewStoreInventory null returns early; otherwise keeps row reference as selectedStore, clears storeSearchTerm, filters current inventory by strict ID, then opens showStoreInventoryPanel. Do not add loads or change global filters. filteredStoreInventory applies the same matcher live. Core loadInventory and store/stock features read/write selected-store balances through composed this; store administration clears selected target after archive. Preserve these cross-owner accesses without wrappers.

Create static/js/pages/inventory-v18.js from v17, remove only21owned properties and compose fresh inventoryBrowsingFeature after inventoryExportsFeature. Preserve all265descriptors/defaults/function/getter sources. Index order remains through exports, then browsing and inventory-v18; all defer with ?v=20261014-frontend-18; Alpine3.13.0 unchanged.

## Review Focus

1. Search whitespace/case/multiple terms/null fields and strict ID filtering preserve row order and equal-name/different-ID behavior; actual search/clear/store bindings still work.
2. Advanced category/part/min/max/low-stock behavior preserves truthiness/parseInt, unused fields and unfiltered reference identity; clearing ordinary filters does not reset advanced state.
3. Permission/store classes and low-stock/my-parts predicates preserve strict actor IDs, roles, central type, allocation/work-order handling and live getters.
4. Store selection/null guard/search reset, core refresh and admin/stock cross-owner updates preserve existing browsing state; navigation/currentViewLabel remain core.
5. Fresh arrays/form/live descriptors/composed providers, cached v17/active v18 equivalence, exports and frozen modules/markup remain correct.

---

### Task1: Extract and wire browsing

**Create:** static/js/inventory/browsing.js,static/js/pages/inventory-v18.js,regression_tests/test_inventory_browsing_feature.cjs,regression_tests/test_inventory_browsing_ui.cjs.

**Modify:** static/index.html,regression_tests/test_frontend_entrypoints.cjs,docs/frontend-organisation.md.

**Interfaces:** Produce21properties above; consume exact composed providers. Keep currentViewLabel/navigation and data loaders unchanged.

- [x] **Step1 Baseline:** On mergedPR118(13c4c1c), full Node/Python pass565/830; recordv17hash/contract before product changes. Interpreter /workspace/scratch/22e193396fd5/timezone-venv/bin/python.
- [x] **Step2 RED/prior behavior:** Exact21keys/defaults/freshstate/livegetter descriptors and real-composer receiver tests. Missing-module RED. Establish Step6 shipped tests on unchangedv17, all pass before move.
- [x] **Step3 GREEN:** Copy seven defaults/eight methods/six getters unchanged; isolated tests pass without new providers/body rewrites.
- [x] **Step4 Entrypoint RED:** Expectv18manifest/cache/inventory-only factory. Cachedv17originalmanifest/hash/no newfactory and265descriptor/default/source equivalence. Extend historicalguard throughv17; expected manifest/factoryfail beforewiring.
- [x] **Step5 Wiring GREEN:** Copyv17→v18/remove onlyownedproperties/compose/updateindex; isolated/entry tests pass, cachedv17self-contained.
- [x] **Step6 Shipped GREEN:** Rerunv17-established cases onv18. Fixtures whitespace/case/multiple-termAND/missingfields/emptyquery/order; storeFilternumeric/string/invalid/equalnames strictID. Advancedpartcase/categoryexact/quantityblank/numeric0/string0/fractional/invalid/minmax/lowstock and unuseddescription/storetype, referenceidentity without filters. Actual search/clear/store expressions; ordinaryclear preserves advancedform and coreopenPanel ordering/doublefilter. Role/owner/central permission matrix; getStoreClass authenticatedcase; lowstockzero/threshold/allocation/workorder and strictmyParts IDs; getters react to data/user changes and provider arrays remain direct references. Nullstore no-op; viewstore rowreference/searchreset/IDrows/globalfilters retained. RealcoreloadInventory refreshes selectedbalances, storearchive invalidation and existing fullstock/export regressions maintain crossowner contracts. Freshstate. Newfeature/UI, entrypoint and existing browsing/stock/export suites pass.
- [x] **Step7 Verify/document:** Updateowner/providers/active/frozencontroller/planstatus consistently. FullNode/Python/syntax/diff pass; exactextraction/frozentracked/backend/otherpages/nonscriptmarkup unchanged. Browserpending.
- [x] **Step8 Review/publication:** Onefreshfinalwholebranch reviewer checks spec/plan/fivefocusareas. FixCritical/Important RED→GREEN/reverify; recordMinor. Commit/autopublishbranchPR, remote tree equals tested local source; reportlink. Ownermerges/no production writes.

## Plan self-review

Browsing owns filters/selected-store balances and derived views, not catalog loaders or navigation. currentViewLabel remains with panel ownership. Advanced unused fields and existing authenticated assumptions are preserved intentionally. Five focus areas have concrete tests. Architecture approved; plan is owner-approved, Native retained/publicationauthorized.

## Execution evidence

Baseline565JavaScript/830Python passed. Two isolated tests failed on missing module;29shipped behavior cases passed unchangedv17. EntrypointRED had2expectedmanifest/factory failures. Finaltargeted66pass; full597JavaScript/830Python pass. Syntax/diff/exactextraction/279frozenfiles/nonscriptmarkup pass. Fresh independent review approved without findings. Core490lines. Browser/mobile verification pending existing access limitation. Standing authorization permits publication; ownermerges.
