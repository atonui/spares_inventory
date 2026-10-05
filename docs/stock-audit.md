# Stock audit evidence

Successful additions, consumption, adjustments, balance imports, dispatches, receipts, returns, physical counts and minimum edits now write evidence inside the same SQLite write transaction as their changes. If the audit insert fails, no part of that operation commits. Failed requests remain separate best-effort activity records and never become successful-change evidence.

New evidence uses `schema_version: 1` with `balance_changes` containing before/after snapshots: inventory row ID (nullable when absent), store and part IDs/names, work-order allocation, quantity and minimum. `movement_ids` links balance changes to their movements. Transfer evidence also records the transfer ID and lifecycle before/after states; dispatch names the destination and leaves destination stock unavailable until receipt. Consumption records its service work order separately from the source stock allocation. Counts retain original reasons and submitted count evidence; minimum edits retain the existing before/after-minimum fields.

The generic endpoint decorator skips its duplicate success entry only for stock actions handled transactionally. Other application activity logging keeps its existing behavior. No historical records are rewritten and missing historic balances are not inferred.

Open **Management → Activity log** to filter the latest 200 matching events by date, action and result, view readable evidence, inspect raw records, or export displayed entries. Administrators see all activity; the API continues restricting other users to their own entries. The superadmin view also renders readable details. All evidence is displayed as plain text, including untrusted names and notes; malformed and legacy detail strings remain readable.

Both activity cleanup and superadmin log purge preserve stock-action evidence, including legacy entries. They still remove eligible general/system logs. This is retention during routine cleanup, not tamper-proof external storage: an explicitly restored older database replaces its history as well as its stock. No schema migration or environment changes are needed.

Validation covers per-operation audit failure rollback, actor/identity/before-after/movement linkage, transfer completion/replay, count and minimum evidence, retention, legacy display and authenticated log loading. Existing stock, import, archive, count, replenishment, security and receipt regressions run alongside these tests. Browser screenshots were unavailable; visually check the deployed activity view on desktop and mobile.
