# Minimum stock and replenishment

Open **Replenishment** from the main navigation. Configure a minimum using an active store you can manage and a part from the catalog. The minimum applies to that store's **unallocated** stock. Saving a target never creates stock units or a movement; a missing balance becomes a zero-quantity row. Zero disables the target. Low-stock counts, row warnings, filters and reports now flag only unallocated stock below a positive minimum; stock at its minimum needs no replenishment. Configured minimums remain after consumption or dispatch empties the balance.

Minimum edits require the normal store permission and CSRF token. Each save checks the previously displayed minimum under the stock write lock and saves its activity audit in the same transaction. If another person changed the minimum, reload its current value before saving again.

The plan shows available stock, its minimum, incoming transfers awaiting receipt, suggested internal transfers, and remaining purchases. It excludes work-order allocations and archived parts/stores. It uses only donor stock above the donor's own minimum. Central stores are considered first, then store name and ID. Target stores are processed by name and ID; each unit of donor surplus is assigned at most once across the full plan. Filtering the screen never reallocates that shared surplus.

Incoming unallocated transfers reduce the remaining need, but are never shown as available stock before receipt. Allocated incoming parts do not cover an unallocated minimum. Suggested transfers are a planning aid, not reservations; purchase quantities assume those suggestions proceed. Refresh before ordering. When a source belongs to someone else, its owner must dispatch it through the normal workflow.

**Review transfer** refreshes the plan and opens the existing dispatch form. It does not move stock. Suggested dispatches recheck the fresh global plan inside the write lock and reject quantities above the currently assigned suggestion. Normal manual transfers keep their existing behavior. All dispatches still require physical receipt or physical return to complete their lifecycle.

**Export purchases CSV** refreshes the plan and exports only rows with remaining purchases, honoring the selected store filter. The export includes available, minimum, incoming, suggested transfer and remaining purchase quantities. A failed refresh clears actionable suggestions and prevents stale exports.

No schema migration, environment setting, automatic purchase, stock redistribution or live data correction is needed. Existing minimums default to zero, so configure useful targets before expecting shortages. Backend and JavaScript regression tests cover allocation, permissions, CSRF, empty balances, stale settings/plans, rollback, exports and receipt behavior. Browser screenshot verification was unavailable in this environment; check the deployed screen on desktop and mobile after merging.
