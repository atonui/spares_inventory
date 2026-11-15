# Platform support inbox design

**Status:** Approved for implementation
**Date:** 2026-11-15

## Intent

Let users contact Spares Tracker at `support@sparestracker.com`, and let platform administrators read and answer those messages from the platform administration dashboard. Resend will handle inbound receipt and outbound delivery. Spares Tracker will own the support conversation experience and its authorization.

The support address is a human support channel, separate from invitations, password resets, and other operational mail.

## Current state

- Resend has `sparestracker.com` verified for sending; receiving is disabled.
- The separate `spares_mail_worker` service sends transactional messages from an encrypted PostgreSQL outbox.
- Its signed `/webhooks/resend` endpoint verifies provider signatures and records outbound delivery events. It has no inbound-email handling.
- Platform administration already has platform-admin-only routes, audited reads, and a dedicated console. Organization administrators do not have platform-level access.
- The authoritative DNS provider and any existing MX records must be checked before enabling Resend receiving.

## Goals

- Receive mail addressed to `support@sparestracker.com` through Resend and display it in the platform dashboard.
- Let platform administrators read and reply to a conversation from the same dashboard.
- Preserve email threading where the sender's mail client supports it.
- Show open/closed and unread/read state, newest activity, and outbound delivery state.
- Handle duplicate and retried provider webhooks idempotently.
- Keep message content, sender details, and attachments out of application logs and platform audit details.
- Keep platform access server-authorized on every request; do not rely on hiding the page in the browser.
- Queue replies durably and retry transient delivery failures using the existing mail worker pattern.

## Non-goals

- Organization-admin or tenant-user access to the platform support inbox.
- A customer-facing ticket portal, SLA management, agent assignment, canned replies, or multi-channel support.
- A newsletter or other marketing email program.
- Sending bulk mail or automatic replies to inbound messages.
- Automatically treating an email sender as authenticated to a Spares Tracker account or organization.
- Automatic message purging or retention changes in this implementation. The retention policy remains a separate decision.

## Approaches considered

### Native platform inbox using Resend inbound — selected

Enable Resend receiving for the verified domain, persist inbound conversations in PostgreSQL, show them in the platform dashboard, and queue replies through the existing mail delivery service. This matches the request and keeps access, audit, and reply behavior inside the product.

### Use the Resend dashboard as the support interface

Enable receiving and handle the work directly in Resend. This is less app work, but it does not provide the requested inbox and replies in Spares Tracker's dashboard.

### Use a separate hosted help desk

Route the address to a support product and optionally link to it from the platform dashboard. This provides mature assignment and SLA features, but adds a second product and does not meet the initial goal of handling support in the app.

The user selected the native platform inbox with Resend receiving.

## Proposed experience

Add a **Support inbox** section to the platform-admin navigation. Only platform administrators can see it or use its APIs.

The inbox list shows sender, subject, latest activity, shared read state, and open/closed state. Selecting a conversation opens its messages in chronological order. The detail view provides a plain-text reply composer, a send action, an outbound delivery state, and controls to mark read/unread and close/reopen the conversation. Read/unread state is shared across platform admins as a team inbox state; the audit event identifies which admin changed it.

Incoming attachment names, types, and sizes are shown. Attachments are fetched through an authenticated backend endpoint from Resend on demand and downloaded as attachments; they are not rendered inline or stored as binary data in the application database. Enforce a configured size ceiling and return a generic error when the provider cannot supply a file.

The first release has status filters and bounded pagination, but no free-text search. This keeps message content and contact details encrypted at rest without building a searchable plaintext index.

## Data and message flow

1. Resend receives mail for the configured support address and posts an `email.received` webhook.
2. The mail worker validates the signed webhook and verifies the recipient is the support address. It retrieves the full message from Resend by provider email ID, normalizes the relevant sender, recipient, subject, body, timestamp, and threading headers, encrypts the content and contact details with the existing mail payload key, then persists the message.
3. A unique provider email ID and a durable webhook event ID prevent duplicate conversations or messages during provider retries.
4. A follow-up message joins an existing conversation only when its `In-Reply-To` or `References` header matches a stored Spares Tracker reply and its normalized `From` address matches the conversation's original sender. Otherwise it starts a new conversation. This prevents an untrusted sender from joining another sender's thread using copied headers.
5. The platform inbox API returns paginated conversation summaries and authenticated message detail, decrypting encrypted content only inside the authorized application path. It does not expose provider API credentials, raw webhook payloads, or unrestricted Resend email identifiers.
6. A platform administrator submits a reply. The API validates and records the reply request and queues an encrypted `support_reply` item in the existing outbox, keyed idempotently to the conversation and reply. The only recipient is the latest inbound message's normalized `From` address; the first release does not send to CC/BCC or a separate `Reply-To` header.
7. The mail worker sends the reply from `support@sparestracker.com` using a dedicated support sender setting, without changing the sender used by transactional mail. It sets `In-Reply-To` and `References` using the latest message's provider `Message-ID` where available; outbound Resend events update the delivery state shown in the conversation.

Use separate inbound handling from the current outbound delivery-event branch so `email.received` is not discarded by the existing event allowlist. The deployment runbook must document the inbound endpoint URL, webhook secret, required Resend API credential access, runtime grants, support sender setting, and DNS records.

## Security, privacy, and reliability

- Authenticate every inbox, read, status, attachment, and reply route with the existing platform-admin transaction boundary and CSRF protection for browser mutations.
- Validate the current platform-admin role on every request. A revoked administrator must lose access immediately.
- Keep raw inbound data out of logs. Limit audit records to the actor, action, conversation/message identifiers, outcome, and request correlation. Never log bodies, subjects, email addresses, attachment names, credentials, or raw webhook payloads.
- Verify Resend signatures, cap webhook payload size, validate event shape and recipient, and persist events idempotently.
- Treat senders and content as untrusted. Render plain text by default, escape content, do not execute HTML, and do not auto-load remote images or links.
- Encrypt persisted sender, recipient, subject, body, threading headers, and attachment metadata with the existing dedicated mail payload encryption key. Keep only routing IDs, message/conversation state, timestamps, and provider delivery IDs queryable. The existing key must be available to the authenticated application and the mail worker; do not place it in browser code.
- Proxy attachment access through the backend after authorization; do not expose Resend credentials or provider download URLs to the browser. Force download instead of inline display.
- Use bounded pagination and status filters. Decrypt only the current page's summary fields for authorized platform admins. Do not load message bodies into the inbox list.
- Add narrow database grants: the web runtime can access support conversations only through the approved application pathways; the mail worker gets only the inbound/outbound fields required to process messages and queue state. No broad identity, organization, inventory, or migration access is added.
- Use the existing retry/idempotency behavior for outbound replies. A provider acceptance is shown as sent-to-provider; later delivery events remain distinct from inbox delivery.
- Do not add automatic purging. A message retention and deletion policy must be agreed before implementing any purge behavior.

## DNS and Resend setup

Before enabling receiving, inspect the domain's authoritative nameservers and current MX records. Confirm no existing mailbox service is using the root domain's MX route. Enable receiving in Resend, obtain its exact MX records, and add those records at the authoritative DNS provider. Preserve the already verified Resend sending and DKIM records. Configure an `email.received` endpoint on the mail worker and store its signing secret as a service secret. Configure a dedicated `RESEND_SUPPORT_FROM_EMAIL` for replies, keeping `RESEND_FROM_EMAIL` unchanged for transactional mail.

Do not change DNS or enable receiving until the implementation endpoint is deployed and the user can verify the exact MX records and routing impact. After DNS propagation, send a controlled test email from an external mailbox, verify it appears once in the inbox, and reply to that mailbox before announcing the address to customers.

## Acceptance criteria

- A message sent to `support@sparestracker.com` appears once in the platform inbox after webhook processing.
- A duplicate inbound webhook does not create a duplicate message or conversation.
- Non-platform users cannot list, read, download, change, or reply to support messages through direct API requests.
- A platform administrator can read a conversation and the access is audited without storing message content in the audit record.
- A platform administrator can reply; the reply is queued exactly once, sent from the support address, and displayed in the same conversation.
- Incoming replies attach only when their threading headers match a stored Spares Tracker reply and their normalized sender matches the original conversation sender; otherwise they start a new conversation.
- Attachment downloads require an authenticated platform-admin request and never reveal a provider secret or unexpired provider URL.
- Browser regressions, API/authorization tests, migration tests, mail-worker/webhook tests, and PostgreSQL integration tests pass.
- Runbook and environment documentation describe activation, MX records, webhook signing secret, provider API access, runtime grants, test procedure, and rollback.

## Builder decisions

- Use the existing separate mail-worker service for inbound retrieval and webhook processing.
- Use existing PostgreSQL, audit, and outbox patterns; introduce no third-party ticketing or inbox dependency.
- Initial access is platform-admin-only, the least-privilege interpretation of a product support inbox.
- The dashboard displays plain-text message content and safe attachment downloads; no automatic HTML rendering.
- Read/unread state is shared across platform admins, matching a team inbox.
- Persisted message/contact content is encrypted with the existing mail payload key; no free-text search is included initially.
- Reply only to the latest inbound sender's `From` address in the first release; do not include CC/BCC or use a separate `Reply-To` address automatically.
- Retention duration, deletion controls, and any production MX change remain explicit operational/user decisions.
