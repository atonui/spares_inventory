# ADR 0001: Timezone contract for inventory and future tenants

Date: 2026-10-12

Status: Proposed; implementation awaits review of the accompanying design.

## Context

This is an operating FastAPI, AlpineJS and SQLite application. Future SaaS tenants
may operate in different timezones. Changing only the superadmin display would
leave reporting and history semantics inconsistent.

Observed implementation:

- `backend/routes/reports.py` hard-codes Nairobi for reporting boundaries and
  converts `recorded_at` to a Nairobi offset; `created_at` is also returned.
- `backend/routes/superadmin.py` hard-codes Nairobi for audit date boundaries.
- `backend/routes/history.py` compares textual timestamps to bare date strings
  and an inclusive `23:59:59` endpoint.
- SQLite defaults and several Python writers produce timezone-free UTC strings.
  This is evidence about current writers, not proof of every historical row.
- Browser formatting mixes explicit Nairobi formatting with implicit device
  timezone parsing/display.

## Decision

### Temporal types

| Meaning | Storage and API contract |
| --- | --- |
| Instant: movement, audit event, creation, session expiry | UTC internally; RFC 3339 UTC timestamp ending in `Z` at API boundaries |
| Calendar date: calibration due date | `YYYY-MM-DD`; never converted into an instant for display |
| Elapsed duration: session lifetime, lockout | Duration arithmetic on UTC instants |
| Future local schedule | Local date/time or recurrence plus an IANA timezone and explicit ambiguity policy |

UTC is not a rule to convert every date-shaped field. Field meaning determines
representation. New public instant inputs must carry an offset or `Z`; naive
inputs are rejected. A narrowly scoped legacy-storage adapter is the exception.

Use validated IANA timezone identifiers, not abbreviations or numeric offsets as
zone identities. Use aware Python `datetime` values and `ZoneInfo` for backend
operations; use `Intl.DateTimeFormat` with an explicit `timeZone` for presentation.
Timezone data must be available in deployments, including environments without a
system IANA database. No application-written offset arithmetic.

### Business and display policy

- The current organisation has a persisted business timezone, initially
  `Africa/Nairobi`, preserving existing consumption and audit report semantics.
- Tenant views will resolve business timezone from the authenticated tenant
  context. The current single-organisation provider supplies that same interface.
  This provider does not constitute tenant isolation.
- Personal display precedence is an explicitly saved user IANA timezone, then
  the organisation/tenant business timezone. Browser detection may suggest a
  preference; it must not silently change saved preferences or report boundaries.
- Reports, exports and business-date history filters use the business timezone.
  Their local timestamps and timezone labels agree, independent of personal
  display preference.
- Future platform-wide cross-tenant views use an explicit query timezone,
  defaulting to UTC, and label it. Tenant-specific views use the tenant policy.
  A platform query timezone affects presentation/boundaries, never authorisation.
- No request may nominate another tenant to obtain its settings. Business
  timezone changes require organisation/tenant administrator permission; changing
  a personal display preference does not require that permission.

### Query and reporting semantics

Inclusive local date ranges become a half-open UTC interval: start of the first
local day inclusive, start of the day after the final local date exclusive.
Calculate each boundary independently using the named zone. Never add 24 UTC
hours to obtain the next local day or use `23:59:59` as an end boundary.

If a zone's midnight is nonexistent or ambiguous, reject that requested boundary
with a clear validation error in the first implementation. Validate by UTC
round-trip and distinguish ambiguous instants; attaching `ZoneInfo` alone is not
validation. This avoids silently guessing on unusual historical transitions.

Responses include the effective reporting timezone, requested local dates and
resolved UTC bounds. JSON instant fields remain UTC even when a report is rendered
in local time. CSV headers identify the effective zone; export timestamps include
their numeric offset. Preserve pagination, identity filters and authorisation.

If reports are later persisted, store effective timezone, resolved UTC bounds,
generation timestamp and report-definition version. A timezone change does not
rewrite instants or modify an already saved report. Rerunning an unsaved report
uses current settings and may group history differently; make this visible.
Reproducing an old report also requires a saved result/data snapshot or an explicit
as-of policy: timezone metadata alone cannot freeze subsequently edited records.

### Storage and migration

SQLite remains supported. Target instant representation is fixed-width UTC text
`YYYY-MM-DDTHH:MM:SS.ffffffZ`, with a single adapter for reads and writes. Until
the migration cutover, legacy UTC storage remains supported through that adapter;
new API output is unambiguous without blindly rewriting old database strings.

Historical naive values are interpreted as UTC only where writer history and
data provenance establish that meaning. Unknown or malformed values require
review; do not silently shift, erase, or invent timestamps.

A future PostgreSQL implementation uses `timestamptz` for instants, `date` for
calendar dates and UTC database sessions. `timestamptz` preserves an instant, not
the original timezone identifier; business/display preferences remain separate.
Database migration is outside this timezone change.

## Consequences

One contract supports different display zones without changing business totals.
Tests must cover DST, midnight boundaries, legacy formats and restore behaviour.
Timezone rules can change: maintain the timezone database and retain resolved
bounds in saved reports. We cannot promise that timezone rules never change;
centralising policy makes those changes manageable.

Alternatives rejected: hard-coding Nairobi in each feature; relying on device
timezone for reporting; storing local event times; migrating databases solely to
fix timezone handling; prematurely building a tenant subsystem.

## References

- [Implementation and migration design](../superpowers/specs/2026-10-12-timezone-design.md)
- [W3C working draft: Working with Time and Timezones](https://www.w3.org/TR/timezone/)
- [PostgreSQL date/time types](https://www.postgresql.org/docs/current/datatype-datetime.html)
- [Python zoneinfo](https://docs.python.org/3/library/zoneinfo.html)
