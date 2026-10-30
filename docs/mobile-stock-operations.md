# Mobile stock operations

The versioned bearer API delegates to the same stock operations as the desktop
client. Each operation revalidates the session in the stock write transaction
and retains tenant, role, store, allocation, movement and audit checks.
Cookie-only authentication is rejected on these native routes.

| POST route | Purpose | Request schema |
| --- | --- | --- |
| `/api/v1/inventory/add` | Receive quantity into a part/store balance | `AddStockRequest` |
| `/api/v1/inventory/consume` | Issue stock against a work order | `ConsumeStockRequest` |
| `/api/v1/inventory/transfer` | Dispatch stock into a pending transfer | `TransferStockRequest` |
| `/api/v1/inventory/transfers/{transfer_id}/receive` | Confirm arrival at destination | `TransferConfirmationRequest` |
| `/api/v1/inventory/transfers/{transfer_id}/return` | Return a pending transfer | `TransferConfirmationRequest` |

Request fields and validation are published in `/api/v1/openapi.json`.
Successful responses retain the corresponding desktop operation's fields.
Failures use the existing v1 error envelope.

These operations are online only. They do not accept the count queue's operation
IDs and are not safe to retry automatically after a lost response. A client must
show an uncertain result and reconcile server state before the user tries again.
Dispatch does not make destination stock available until receipt is confirmed.

## Delivery checklist

- [x] Versioned bearer write routes reuse desktop stock rules.
- [x] Paginated native active stores and pending-transfer reads, including empty stores.
- [ ] Paginated native parts reads.
- [ ] Mobile receive and issue forms with quantity/work-order review.
- [ ] Mobile dispatch, pending transfer, receive and return screens.
- [ ] Retry-safe operation IDs before offline operational writes are enabled.
- [ ] Add/edit inventory records and permitted metadata in the mobile client.
- [ ] Paginated native movement history and mobile item history.
- [ ] PostgreSQL tenant/role and physical-device acceptance of the complete flows.

## Transfer read contract

`GET /api/v1/stores` lists the authenticated tenant's active stores, including
stores with no inventory. `GET /api/v1/inventory/transfers` lists in-transit
movements with source/destination names, part details, quantity, UTC creation
time and server-derived `can_receive` / `can_return` flags. Mutation routes
still recheck those permissions when the user confirms an action.

Both reads require bearer authentication, accept `limit` (1–100; default 50)
and an optional opaque signed `cursor`, and return `{items, page: {limit,
next_cursor}}`. Rows are ordered by ascending ID. Continue until `next_cursor`
is null. Cursors are purpose-bound; a store cursor is invalid for transfers.
Pending transfers may disappear between pages when another device completes
them; continuation does not require the previous row to remain pending.
Refresh from the first page to discover later changes. Tenant scope always
comes from the revalidated session, never from a client-supplied tenant ID.
