# Platform Audit and Security Logging Design

**Date:** 2026-10-31  
**Status:** Proposed design; documentation only  
**Scope:** Platform-level audit, authentication/security events, tenant activity boundaries, and operational diagnostics for the Super Admin console. This does not authorize tenant-data browsing or expand support access.

## Goals

- Give platform operators a reliable, understandable history of privileged platform actions and security-relevant events.
- Preserve the separation between global platform oversight and organization-scoped activity.
- Keep audit data useful while preventing credentials, customer content, and unnecessary personal data from leaking into logs.
- Make future retention, export, and alerting decisions deliberate and reviewable.

## Existing event streams

| Stream | Current purpose and boundary | Current gaps |
| --- | --- | --- |
| Tenant activity: `activity_logs` | Organization-scoped activity, included in the PostgreSQL tenant RLS policy list. The tenant Activity API lets users see their own entries and company admins see organization activity. Stock audit actions are written through transactional activity helpers and protected from normal cleanup. | Details and error messages are flexible text/JSON. A password-reset failure path records the account email in details. A 90-day cleanup is manually triggered, not scheduled; its default is not a complete retention policy. |
| Platform administration: `platform_audit_events` | Global, curated record of platform actions such as organization lifecycle, platform-admin changes, global settings, announcements, support sessions/data reads/denials, and logout. The API is platform-authorized, read-only, paginated, filtered, and sanitizes details against an action allowlist. | No approved retention schedule or export/archive workflow. The UI is an audit table, but relies heavily on numeric IDs/raw JSON. The source implements an application audit trail; database-level append-only grants, tamper evidence, and independent backup/export were not verified. |
| Security events | No dedicated global security-event store or platform view was found. Authentication routes attempt activity logging, but tenant activity is a poor fit for unauthenticated attempts and unknown accounts. | Login, lockout, password-reset, credential rotation, session revocation, and suspicious authentication signals need a purpose-built, privacy-limited model and reliable PostgreSQL writes. |
| Legacy system logs: `system_logs` | A global table exists. Application startup/shutdown are the only source writes identified in the inspected code. | It is not a useful operational event pipeline and has no specified retention policy or SaaS console view. |
| Runtime diagnostics | Python loggers write application, audit, and error files with size-based rotation (10 MiB per file, 10 backups) and console output. The hosting provider may also capture runtime output. | Provider-side retention/access settings were not verified. These logs are diagnostics, not a durable business audit record; there is no product UI for browsing them. |

### Data and privacy observations

- PostgreSQL `activity_logs.organization_id` is non-null and the table is tenant-scoped by RLS. Do not store unknown-account security events there or use a tenant context chosen from request input.
- `backend/app_activity.py` has a standalone `log_activity` path with SQLite-style placeholders and no organization context. Authentication routes call the injected activity logger for some public flows. Review the complete PostgreSQL call path and prove persistence before relying on those records; logger failures must not silently create false confidence.
- In `backend/routes/auth.py`, password-reset failure records for expired tokens or weak passwords include the account email in `details`. Remove that field in the security-event work; do not retain it in either the new security stream or application logs.
- Tenant activity `details` and `error_message` are not a sufficient privacy boundary by themselves. New writes should use action-specific allowlists and bounded values. Historical rows should be treated as potentially sensitive when exposed, exported, or retained.
- Platform audit detail sanitization is a strong existing pattern. Extend it by explicit action schemas and tests; do not accept arbitrary request/response bodies.
- Audit writes for consequential mutations should share the mutation transaction where possible. Authentication attempts need a separate, carefully designed write path so an unknown account can be recorded without a user or tenant row.

## Event taxonomy

1. **Platform administrative audit** — who changed a platform-controlled object, what action was taken, target organization when applicable, result, timestamp, and a bounded reason or safe before/after summary. Examples: organization suspend/reactivate, platform-admin grant/revoke, company-role change, global security setting, announcement change, and support session lifecycle/access.
2. **Tenant activity** — business actions performed inside one organization. Keep access scoped to that organization and retain existing transactional stock evidence. Platform-wide actions must not be duplicated as tenant activity merely to make them visible globally.
3. **Global security events** — authentication and account-security outcomes that can occur before tenant resolution: login success/failure, lockout, password reset request/outcome, password change, session/mobile credential issue/rotation/revoke, and relevant platform-admin authentication outcomes.
4. **Operational diagnostics** — service errors, worker health, latency, dependency failures, and deployment/runtime metadata. Keep this separate from business audit and avoid payload capture.

Every event should carry a UTC timestamp, event/action identifier, outcome, source/component, and server-generated request/correlation ID where available. Authenticated events may carry actor user ID; tenant activity may carry organization ID; platform events may carry target organization ID. Keep event schemas versionable.

## Safe-field and access rules

- Never log passwords, password hashes, reset/session/refresh/CSRF tokens, authorization headers/cookies, full request or response bodies, encrypted email payloads, or submitted invitation/reset links.
- Do not include raw email addresses in event details, including unmatched login/reset attempts. For unknown-account correlation, prefer no account identifier; if abuse detection requires correlation, use a keyed HMAC of a normalized identifier with a documented key rotation and expiry strategy. Never use a plain hash of an email.
- Capture IP address and user-agent only where there is a clear security purpose. Bound lengths and access; define retention separately from audit-event retention.
- Use action-specific allowlists for detail keys, enums for reason/result/resource, and strict maximum lengths. Treat free-text reasons as sensitive; expose only to authorized platform operators and avoid copying secrets/customer text into them.
- Keep platform audit and global security events visible only to active platform admins. Tenant activity remains visible only under existing tenant authorization and RLS. Never create a global activity endpoint for tenant admins.
- Operational logs should be accessible through the hosting/observability control plane with least-privilege access. A platform UI may link to supported provider dashboards or show approved aggregate health signals; it should not become a raw log, SQL, or tenant-payload browser.
- Treat `platform_audit_events` as application audit history until database permissions, backup/restore, and tamper-evidence properties are explicitly verified. Do not call it immutable or compliance-grade based only on the append API.

## Console placement

- **Platform Administration → Audit log:** platform administrative events only. Add human-readable actor and organization names while preserving stable identifiers in detail views; readable labels for action/result; safe detail expansion; filters by time, actor, organization, action, result; and a deliberate, permission-checked export if/when export is approved.
- **Platform Administration → Security events:** global authentication and account-security events, separated from administrative changes. Default to recent events and filters for outcome, event family, actor/account match, and time. Never expose raw submitted identifiers or credentials.
- **Organization detail → Activity:** a tenant-scoped view of that organization's activity and stock evidence, available only through the explicitly authorized support workflow when viewed by platform staff. Every support read remains audited. Organization admins continue to use the tenant Activity page.
- **Platform operations → Health:** approved aggregate service/worker/dependency signals and links to provider logs. Do not surface diagnostic payloads or imply that platform audit is a health monitor.

## Retention and evidence

No new deletion schedule is approved by this design.

| Data | Current mechanism | Design status |
| --- | --- | --- |
| Tenant activity | Manual admin cleanup defaults to 90 days; protected stock audit actions are excluded. | Keep current behavior until a product/legal retention decision. Confirm how protected stock evidence is retained and whether a separate archive is required. |
| Platform audit | No retention or archive policy identified. | Policy unset. Do not purge or export automatically before approval. |
| Security events | No dedicated stream exists. | Define event-specific retention, especially for IP and pseudonymous identifiers, before enabling writes. |
| `system_logs` and local files | Table has no identified policy; files rotate by size (10 MiB × 10 backups). | Document separately from event retention. Verify hosting provider retention and access controls. |
| Backups/archives | Outside this application-level design. | Verify restore/backup retention and access before claiming end-to-end deletion or immutability. |

Retention decisions should specify purpose, data fields, time period, purge/archive method, access, and treatment of legal holds/backups. Stock evidence, authentication events, platform admin actions, and operational diagnostics need not share one duration.

## Decisions required before later phases

1. Approve event categories and action coverage for security events.
2. Choose whether unknown-account correlation is necessary; if so, approve keyed pseudonymization and its key/rotation ownership.
3. Approve retention for platform audit, security events, IP/user-agent metadata, and operational logs; confirm stock-evidence retention separately.
4. Decide whether authorized audit export is needed, who can use it, and whether it should be append-only external storage.
5. Verify runtime PostgreSQL grants and hosting-provider log retention/access settings.
6. Decide whether platform audit UI should display emails/names, and establish redaction behavior for archived/deleted accounts.

## Source references reviewed

- `backend/postgres_migrations/v0001_core_schema.py`, `v0002_tenancy.py`, `v0003_tenant_policies.py`
- `backend/services/activity.py`, `backend/app_activity.py`
- `backend/services/platform_audit.py`, `backend/routes/platform_audit.py`
- `backend/routes/history.py`, `backend/routes/auth.py`
- `backend/logging_config.py`
- `docs/superpowers/plans/2026-10-27-superadmin-platform-admin-alignment.md`
- `docs/superpowers/specs/2026-10-17-saas-privacy-data-inventory.md`

This document is a code-based product/engineering design, not legal advice or a retention-policy approval.
