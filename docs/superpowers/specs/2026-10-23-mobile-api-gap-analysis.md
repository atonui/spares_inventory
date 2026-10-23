# Mobile API Gap Analysis

**Status:** First workflow selected: offline inventory stock adjustments
**Audience:** Mobile and backend implementation

## Current contract

The generated `/api/v1/openapi.json` contract provides native sign-in and refresh, desktop-approved device pairing, the authenticated user profile, paginated tenant inventory reads, logout, and verified email-change flows. This change adds the first mobile inventory write: setting the counted quantity of an unallocated inventory row with optimistic concurrency and retry-safe operation IDs.

The client already supports viewing inventory and scanning a code against inventory loaded on the device. Scanning does not perform server-side barcode resolution because the current part model has no barcode field or alias table.

## Workflow coverage and gaps

| Web workflow | Current mobile support | API gap for full mobile support | Priority |
| --- | --- | --- | --- |
| Inventory browse and stock counts | Browse is online/offline; add stock and edit count queue locally | This change adds `POST /api/v1/inventory/adjustments`; validate it against the SaaS PostgreSQL deployment before enabling production sync | In progress |
| Barcode and QR scanning | Exact match against cached part number; pairing QR is separate | Add tenant-scoped barcode/alias data and a lookup endpoint; define how ambiguous matches are returned | High |
| Consume stock | Not yet exposed in the mobile API | Add a bearer route matching the web consume workflow, with access checks, allocation rules, movement and audit records | High |
| Transfers | Not yet exposed in the mobile API | Add routes to list, create, receive, and return transfers, preserving the web permission and lifecycle rules | High |
| Parts and stores | Not yet exposed in the mobile API | Add paginated reads and role-protected create/edit operations; keep bulk import and archive controls out of the first mobile pass | Medium |
| Equipment | Not yet exposed in the mobile API | Add list/detail, create/edit, transfer, calibration, and history routes with the same tenant and role checks | Medium |
| Reports and activity history | Not yet exposed in the mobile API | Add tenant-scoped report/history reads and bounded pagination or date-range limits | Medium |
| Tenant user and organization administration | Not yet exposed in the mobile API | Add only tenant-admin workflows that are appropriate on a phone; do not expose platform-admin, database, billing-security, or other superadmin operations | Later |

## Contract rules for follow-on endpoints

- Derive organization scope and the authenticated principal from the bearer session. Never accept a tenant ID from the mobile client as authority.
- Enforce permissions on the server for every read and write. Hiding a button in the app is only a usability choice.
- Reuse the web business rules for stock ownership, allocated inventory, transfer lifecycle, equipment permissions, and audit records.
- Use the standard v1 error envelope and document validation, authorization, conflict, and rate-limit responses in generated OpenAPI.
- Use stable cursor pagination for unbounded collections. Bound date ranges and result sizes for reports.
- Require idempotency keys for queued/offline writes. Use expected versions or quantities where two users can edit the same state concurrently.
- Include PostgreSQL migrations and tenant-isolation tests for every new persisted field or route. Validate integration against the SaaS PostgreSQL environment, not the SQLite production service.

## Delivery sequence

1. Complete the stock-adjustment vertical slice in separate backend and mobile pull requests. Keep queued changes visible and retain stale-count conflicts for review.
2. Validate the endpoint and migrations against the SaaS/PostgreSQL environment before turning on live sync for testers.
3. Add server-side barcode aliases and tenant-scoped scan lookup.
4. Add consumption and stock transfers, then parts/stores and equipment workflows.
5. Add reports/history and appropriate tenant administration after the operational workflows are stable.

Platform-level superadmin routes remain excluded from the mobile contract. Tenant-role presentation in the client must mirror server permissions but never replace server authorization.
