# Mail Worker Database Role Isolation

**Status:** Spec approved in chat on 2026-10-17; implementation plan awaiting review.

## Goal

Prevent the SaaS web runtime from reading invitation recipient addresses and encrypted message payloads stored in the global PostgreSQL mail outbox. Preserve transactional invitation enqueueing and platform-level aggregate mail health counts. Give the mail worker a separate database identity whose access is limited to processing the outbox.

This change applies to the PostgreSQL SaaS deployment. It does not alter the legacy SQLite service, provision production roles, change production credentials, or deploy a worker.

## Current behavior

- `DATABASE_URL` is used by both the web runtime and `python -m backend.mail_worker`.
- The web runtime writes invitation rows to `mail_outbox` in the same transaction as organization and invitation creation.
- The platform dashboard queries only pending and failed counts, but its database role can read the whole outbox table, including plaintext recipients and encrypted payloads.
- The worker needs recipient and encrypted payload values to deliver queued messages. The table is global and is not protected by tenant RLS.
- `MIGRATION_DATABASE_URL` is a separate schema migration identity and must remain unavailable to both runtime services.

## Selected design

### Connection identities

- Keep `DATABASE_URL` as the web runtime connection using the restricted runtime database role.
- Add `MAIL_WORKER_DATABASE_URL`, a separate connection to the same SaaS PostgreSQL database using a dedicated mail-worker login role.
- Continue using `MIGRATION_DATABASE_URL` only for application migrations.
- Require `MAIL_WORKER_DATABASE_URL` when starting the mail worker. Missing or blank configuration must stop startup before opening a database connection or claiming mail. The worker must not fall back to `DATABASE_URL`.
- Keep current mail provider and payload encryption configuration unchanged. The worker continues to require `MAIL_PAYLOAD_ENCRYPTION_KEY`, `RESEND_API_KEY`, and `RESEND_FROM_EMAIL`.

### Web runtime permissions

The web role must not have table-level `SELECT`, `UPDATE`, or `DELETE` rights on `mail_outbox`.

Grant only the column permissions needed by `enqueue_mail`:

- `INSERT` on `organization_id`, `message_type`, `recipient_email`, `encrypted_payload`, and `idempotency_key`.
- `SELECT` on `id` and `idempotency_key`, and `UPDATE` on `idempotency_key`, to support the idempotent `ON CONFLICT` enqueue and `RETURNING id` behavior. Tests must verify PostgreSQL accepts and enforces this precise grant set.
- `USAGE` on the outbox identity sequence if required by its insert default.

Add the non-parameterized view `platform_mail_outbox_counts`, exposing exactly one row with integer columns `pending` and `failed`, counted by the corresponding `mail_outbox.status` values. The view must not expose message IDs, recipient addresses, payloads, organization IDs, error codes, or per-message status rows. Revoke `PUBLIC` privileges on the view and grant the web role `SELECT` on the view only. Update the platform dashboard to read this aggregate view.

The aggregate view is intentionally global and reveals only operational counts already shown by the platform dashboard. It is owned by the schema migration identity; web role permissions on the underlying outbox remain restricted.

### Mail worker permissions

The mail-worker role receives schema usage and only the `SELECT` and `UPDATE` privileges it needs on `mail_outbox` to claim due messages, read the recipient and encrypted payload for delivery, and mark a claim sent, retryable, or terminally failed. It receives no privileges on tenant inventory, identity, session, invitation, or platform tables, and no insert, delete, DDL, ownership, superuser, or `BYPASSRLS` privileges.

Because the worker processes a shared global queue, its database identity can read queued mail for all companies. This is necessary for its job. The boundary being added is that the web runtime and unrelated services cannot read those message contents through their database credentials.

### Database migration and operations

- Add an immutable PostgreSQL migration for the aggregate view and safe default/public privileges.
- Role creation, passwords, and login credentials remain environment provisioning responsibilities, not application migrations. The runbook will document explicit grants for the existing web runtime role and the new mail-worker role, including revoking prior broad outbox grants.
- Update `docs/environment.md` and `docs/saas-cutover-runbook.md` to distinguish all three database URLs and state which process uses each one.
- Do not edit Railway variables, create live database roles, provision services, or launch the worker as part of this code change.

## Required tests

PostgreSQL tests must use disposable roles and verify the actual privilege boundary, not just mocked collaborators:

1. The web runtime can enqueue an invitation and receive `id` from `RETURNING`, including an idempotent retry, while queries that attempt to read `recipient_email` or `encrypted_payload` fail with insufficient privilege.
2. The web runtime can read pending and failed aggregate counts but cannot query individual outbox rows or access other outbox columns beyond the narrow enqueue requirements.
3. The worker can claim and process queued messages and update delivery state, while reads from representative unrelated tenant, identity, session, invitation, and platform tables fail.
4. The worker refuses startup without `MAIL_WORKER_DATABASE_URL` and never uses `DATABASE_URL` as a fallback.
5. `platform_mail_outbox_counts` contains only `pending` and `failed` counts and returns exactly one row, including when the queue is empty.

Existing provider-independent delivery, retry, concurrency, and payload secrecy tests remain required. The PostgreSQL CI workflow must run the focused permission tests.

## Risks and limits

- A compromised mail worker can access message contents for the global queue. Restrict its host, secret access, logs, and network path accordingly.
- Column-level grants for idempotent inserts are subtle PostgreSQL behavior. The integration test is the acceptance gate; if the exact grant set cannot support the existing enqueue contract, revise the enqueue SQL and test the narrower alternative rather than granting table-wide `SELECT` to the web role.
- Existing SaaS databases need the reviewed grant-revocation and role-provisioning steps before the new worker release starts. Documentation and code changes alone do not change live credentials.
- The repository currently documents Railway as SQLite-backed. This design prepares the PostgreSQL SaaS runtime and does not imply that a production PostgreSQL environment exists or is configured.

## Out of scope

- Tenant deletion, member-account deletion, retention periods, or message purge policy.
- Encrypting recipient addresses, changing the mail provider, or redesigning the queue API around stored procedures.
- Production role provisioning, Railway variable changes, deployment, or end-to-end mail to a real recipient.
- Changing existing platform dashboard response fields or exposing additional mail metrics.
