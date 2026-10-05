# Transfer receipts

A dispatch removes stock from its source and places it in transit. The destination receives usable stock only after physical receipt is confirmed. This applies to new transfers; historical transfers remain completed.

## Daily use

1. Use the existing stock transfer action, select the destination and quantity, and choose **Dispatch**.
2. Both sides can see the shipment in **In-transit transfers**. Use **Refresh transfers** to check for new shipments.
3. Once all parts arrive, the destination's assigned user or an admin selects **Confirm receipt**. For an unassigned central store, authenticated staff can confirm receipt.
4. If the shipment returns, its sender, source-store owner or an admin selects **Confirm returned to source**, only after all parts are physically back. This restores the source balance.

Both confirmations apply to the entire shipment. Partial receipts and discrepancies are not supported in this version; leave such a shipment in transit while resolving the discrepancy.

Confirmation buttons require a physical receipt or return acknowledgement. Repeated or competing confirmations do not add stock again. A received shipment cannot subsequently be returned through the pending-transfer action; record a new dispatch for its onward movement.

Movement history and its CSV export show transfer status, confirmation user and time. Dispatch time and sender remain on the original movement. Work-order allocation is retained. Available inventory excludes shipments in transit; the dashboard separately shows units in transit.

## Existing installations

Startup creates an additive `stock_transfers` table and status index. It does not alter existing stock or replay historical transfers. Existing transfer movements without lifecycle records display as completed.

Old database backups remain restorable: the restore validator adds only this known missing schema to the temporary uploaded database before comparing the full schema. Full snapshot restoration still overwrites later changes, including pending transfers; pause inventory activity and choose the snapshot deliberately.

Deletion of parts, source/destination stores and involved users is blocked while they are referenced by a pending transfer. Complete its physical receipt or return first.

Stock changes and transfer state transitions run in one SQLite write transaction. Rollback leaves the transfer pending when stock cannot be added. Physical return restores the original minimum threshold when the source row is recreated or has a default zero threshold after restocking. Any nonzero threshold configured since dispatch is retained.

## Verification

Run `python -m pytest` and `node --test regression_tests/test_stock_import_ui.cjs regression_tests/test_transfer_receipts_ui.cjs` from the repository root. Tests cover stock conservation, permissions, CSRF, repeat and competing confirmations, database failures, allocated stock, deletion guards, historical transfers and older backups.
