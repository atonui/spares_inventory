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
- [ ] Paginated native stores/parts/transfer reads, including empty stores.
- [ ] Mobile receive and issue forms with quantity/work-order review.
- [ ] Mobile dispatch, pending transfer, receive and return screens.
- [ ] Retry-safe operation IDs before offline operational writes are enabled.
- [ ] Add/edit inventory records and permitted metadata in the mobile client.
- [ ] Paginated native movement history and mobile item history.
- [ ] PostgreSQL tenant/role and physical-device acceptance of the complete flows.
