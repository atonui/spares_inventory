# Platform support inbox implementation plan
> **For agentic workers:** Use the task sequence below. Each task is independently verifiable and should be committed when complete.

**Goal:** Receive mail sent to `support@sparestracker.com` through Resend and let platform admins read and reply from the platform dashboard.

**Architecture:** Extend the existing mail worker with a separately signed inbound webhook, encrypted PostgreSQL support records, platform-admin API routes, and a dedicated UI section. Replies use the existing encrypted outbox and worker with a separate sender setting.

**Tech Stack:** FastAPI, PostgreSQL migrations, Python mail worker, Resend API/webhooks, Alpine/vanilla JavaScript.

**Spec:** `docs/superpowers/specs/2026-11-15-platform-support-inbox-design.md`

## Global constraints

- Work only in `/workspace/scratch/706032805b3f/platform-support-inbox`; leave the older checkout untouched.
- Encrypt sender, recipient, subject, body, thread headers, and attachment metadata with `MAIL_PAYLOAD_ENCRYPTION_KEY`.
- Admin authorization and CSRF checks apply on every relevant app route. Audit metadata must exclude message content and contact details.
- Match replies only by stored Spares Tracker reply headers plus normalized original sender. Reply only to latest inbound From; no CC/BCC or automatic Reply-To.
- No purge/retention changes. Do not alter DNS or enable receiving until endpoint deployment and current MX routing are reviewed.

## Task 1: Database schema, encryption model, and grants

Files: new v26 migration under `backend/postgres_migrations/`, `registry.py`, migration tests, `docs/saas-cutover-runbook.md`.

- Add tables for conversations, messages, and inbound webhook idempotency. Enforce unique provider email/event IDs, indexes for status/activity pagination, foreign keys, and safe state constraints.
- Revoke PUBLIC and broad runtime grants; grant only required platform-web and mail-worker columns/operations. Keep encrypted content opaque to SQL.
- Add outbox message type support for `support_reply`.
- Add migration and restricted-role tests for schema, grants, and idempotency constraints.

## Task 2: Encrypted support service and inbound processing

Files: new `backend/services/platform_support_inbox.py` (or established service location), `backend/mail_webhook.py`, Resend client helpers, `regression_tests/test_mail_webhook.py`, new service tests.

- Verify a dedicated inbound webhook signing secret and bounded payload; validate event shape and exact support recipient.
- Fetch full inbound content from Resend by provider ID with bounded retries; sanitize and normalize data, encrypt sensitive fields, and persist idempotently.
- Join a conversation only when `In-Reply-To` or `References` matches a stored outbound reply and normalized From matches the original sender.
- Keep PII and raw payloads out of logs. Test valid/bad signature, unexpected recipient, duplicate events, provider retrieval failure/retry, encryption, and thread matching.

## Task 3: Platform-admin support API and audit

Files: new platform support router, `main.py`, `backend/services/platform_audit.py`, API tests.

- Add bounded list/detail endpoints, shared read/unread and open/closed mutations, reply enqueue, and authenticated attachment-download proxy.
- Apply platform-admin transaction authorization and CSRF protection to mutations/downloads. Verify denial for tenant users and non-admin platform users.
- Add allowlisted audit actions and safe identifiers only; never record body, subject, sender, or attachment names.
- Test pagination, state transitions, audit redaction, authorization, and attachment behavior.

## Task 4: Dedicated support reply delivery

Files: `backend/config.py`, `backend/services/mail_delivery.py`, outbox worker, delivery tests, environment/runbook docs.

- Add `RESEND_SUPPORT_FROM_EMAIL` without changing the transactional sender.
- Render validated plain-text replies; set only required `In-Reply-To`/`References` headers; exclude CC/BCC and caller-controlled headers.
- Persist outbound reply/thread association and update provider delivery state from existing outbound webhook events.
- Test exact sender/header behavior, idempotent enqueue, transient retries, and delivery status updates.

## Task 5: Platform dashboard inbox

Files: `static/superadmin.html`, `static/js/pages/superadmin.js`, `regression_tests/test_superadmin_ui.cjs`.

- Add platform-only `platformSupportInbox` navigation and content, preserving the existing customer-support session tab.
- Implement list/detail, read state, open/closed controls, plain-text reply, attachment downloads, and loading/error/empty/retry states.
- Render untrusted message bodies as text; do not render HTML or load remote resources. Add cache-busting version.
- Test platform navigation, safe rendering, actions, accessibility labels, and non-platform visibility.

## Task 6: Operational setup and integration verification

Files: `docs/saas-cutover-runbook.md`, environment documentation, PostgreSQL and UI integration tests.

- Document separate inbound webhook secret/endpoint, required Resend API credential, dedicated sender, least-privilege grants, activation, test, and rollback.
- Run available unit/UI tests and PostgreSQL tests if a disposable test database is available; report any unavailable checks plainly.
- Inspect authoritative nameservers and MX records before any receiving activation. If existing mail routing conflicts, stop and report the exact impact. Once endpoint is deployed and MX details are reviewable, perform the DNS/Resend activation only within the user's authorization and verify with an external test message/reply.

## Review focus

- Provider webhook authenticity, duplicate/retry behavior, encryption boundaries, and thread association.
- Authorization on every API operation and least-privilege SQL grants.
- No PII in logs or audit details; plain-text rendering and forced-download attachments.
- Transactional mail remains unchanged; support replies use only the dedicated sender and validated headers.
- Production MX changes remain gated on inspection of existing routing.
