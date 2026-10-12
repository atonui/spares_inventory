# Timezone architecture and migration design

Date: 2026-10-12

Status: Proposed for user review; no runtime implementation is authorised by this document alone.

## Purpose and scope

Implement [ADR 0001](../../adr/0001-timezone-contract.md) across existing inventory,
history, reports, authentication timestamps and superadmin views. Preserve stock,
movement identities, permissions and session expiry instants. Make the policy
usable by future tenants without implementing tenant isolation, subscriptions,
PostgreSQL migration or recurring scheduling now.

## Components and interfaces

1. Backend temporal module: aware UTC clock, strict public instant parser, legacy
   storage parser/serializer, RFC 3339 output serializer, validated IANA zone,
   and inclusive-local-date to exclusive-UTC-boundary conversion.
2. Business context resolver: supplies organisation identity, business timezone
   and settings revision to routes. Today it resolves the sole organisation;
   future tenancy replaces the provider with authenticated tenant resolution.
   Routes must never read a process-global Nairobi constant directly.
3. Frontend temporal module: format an instant using a supplied IANA zone; format
   a calendar date without `Date` conversion; render explicit timezone labels.
   Reuse it in inventory/history, reports and superadmin rather than separate
   parsing implementations. Invalid values show `Unknown`, never fabricated time.
4. Report policy: resolve business context once per request; use it for filters,
   grouping, response metadata and CSV. Reuse the same boundary conversion in
   audit, consumption and movement history endpoints.

Public inputs with missing offsets fail validation. Legacy naive parsing is
limited to documented storage fields; it is not a fallback for arbitrary imports
or API requests. Preserve absent optional fields as null.

## Settings and permission model

Add a dedicated single-organisation settings table through a new numbered
migration: singleton organisation key, non-null business IANA timezone, revision,
UTC updated timestamp and updating actor. Do not mix this setting into login
security parameters. Bootstrap `Africa/Nairobi` only when missing; validate saved
values rather than silently replacing invalid settings.

Add nullable `users.display_timezone`, with null meaning organisation default.
Expose a personal profile setting and a separate administrator business-timezone
setting. Use the existing authenticated actor and administrator permission model;
do not invent unauthenticated organisation selection. Validate choices server-side
against available IANA data. Browser timezone detection only suggests a choice.

Business-zone updates require the current revision to prevent lost updates and an
audit entry containing old/new zone and actor. Explain that future report queries
and date grouping change while stored instants do not. Existing open report views
keep their resolved timezone until refresh; API responses always identify it.
No report workflow should resolve the timezone twice within one request.

When tenancy is implemented, business configuration belongs to each tenant and
the resolver is tenant-scoped. Personal timezone is an account preference unless
a later product decision deliberately makes it membership-specific. This change
adds no tenant identifiers to business rows and makes no isolation claims.

## Existing-data assessment

Before migration implementation, create a read-only inventory of every temporal
column, default, writer, reader, comparison and export, including token expiry,
session/lockout times, transfer completion, archive times and equipment dates.
The assessment must use a supplied production snapshot, not mutate the live app.
Current SQL defaults and Python writers support UTC interpretation, but do not
establish provenance for every imported/historical record.

Classify each field as instant, calendar date, duration or local schedule. Count
nulls, supported legacy formats, explicit offsets, invalid values and ambiguous
naive values. Diagnostics identify table/field/row identity without logging tokens,
passwords or unrelated personal data. Map naive fields to verified writer rules.
Unresolved provenance blocks conversion of the affected field; present it for
review rather than assuming Nairobi or UTC.

## Rollout stages

### A. Compatible policy and explicit API output

Introduce adapters and business settings while retaining established legacy UTC
database representation. Replace ad hoc comparisons and local parsing, including
history's textual comparisons, before changing persisted formats. API instants
become explicit UTC; calendar dates stay dates. Consumption `recorded_at` also
becomes UTC, and the UI/CSV format it using response metadata. Document this
format change and test known API consumers; keep existing field names and report
quantity semantics. Update static asset versioning/cache behaviour so supported
clients receive the matching formatter code.

During this stage the adapter accepts documented legacy database formats and
explicit UTC formats. No bulk timestamp rewrite occurs. Existing consumption and
audit totals must remain identical under the Nairobi default. History's local-day
boundary correction may intentionally change edge-of-day results; document and
test that difference instead of forcing the old incorrect result.

### B. Canonical SQLite storage cutover

Only after the assessment and compatible readers are complete, use another new
numbered migration to normalise verified instant columns to fixed-width UTC text.
Update all writers, defaults, comparison queries, relevant indexes and schema
validation together. Any required SQLite table rebuild preserves foreign keys,
IDs, autoincrement state, stock quantities, existing constraints and audit evidence.
Never edit a shipped migration or bypass checksums.

The migration fails transactionally on unexpected formats. Validation compares
before/after UTC instants, row counts, quantities, foreign keys and representative
report totals. Seconds-only values gain zero fractional precision without gaining
invented sub-second information. Offset-bearing values preserve their instant.
Calendar dates are excluded. Defaults emit the same canonical representation as
application writes, rather than mixing SQLite's legacy `CURRENT_TIMESTAMP` format.

Test older backups through the existing restore migration/validation path, plus
canonical backup restore. Reject incompatible future schemas. Take an independent
pre-cutover snapshot using the available application backup workflow and validate
it can be restored; do not depend on a paid Railway backup feature.

### C. Operational verification

Verify deployment readiness, migration version and read-only smoke checks. Compare
known consumption totals, history date boundaries, calibration dates and UTC
session expiry behaviour. Test two users with different display preferences and
the same business-zone report. No production timezone change is needed for this
verification; exercise alternate business zones on a disposable test database.

Rollback A requires a version compatible with the additive schema and changed API
contract. Rollback B requires compatible adapter code or deliberate recovery from
the pre-cutover snapshot; do not deploy older readers against canonical text or
manually downgrade the migration ledger. Snapshot recovery loses subsequent writes,
so pause writes and agree the recovery point before any destructive restore.

## Acceptance criteria

- All public instant fields have an explicit UTC `Z`; invalid naive public inputs
  are rejected. Legacy parsing is restricted to audited fields.
- Every date filter uses the shared business-zone boundary policy, including
  pagination and exports, and includes sub-second events on the final local day.
- Test UTC, Nairobi, New York DST transitions, a fractional-offset zone and an
  unusual midnight transition. Valid 23/25-hour local days resolve correctly;
  nonexistent/ambiguous boundaries produce explicit validation errors.
- Personal preferences change display only. Two viewers obtain identical report
  rows/totals/UTC bounds for the same business context and filters.
- Calendar dates retain their date in positive and negative offset display zones.
- Expiry, lockout and elapsed-duration comparisons use UTC instants; changing
  business/display zone cannot extend or shorten active sessions.
- Setting changes are validated, authorised, audited and protected by revision;
  invalid settings cannot silently fall back to a different zone.
- Tests preserve established Nairobi consumption/audit totals, intentional history
  edge-boundary corrections, sorting, CSV formatting and permissions.
- Migration/restore tests cover verified naive UTC, explicit offsets, nulls,
  malformed values, transaction rollback and complete preservation of stock/IDs.
- Timezone data is available in the production image and test environments;
  maintained rules are used rather than custom offsets.

## Review and next step

Review this design and the ADR before implementation planning. Once approved,
write a separate implementation plan with independently reviewable PRs for the
assessment, compatible policy/API/UI/settings, and storage cutover. Runtime code,
production settings and data remain unchanged by this documentation PR.
