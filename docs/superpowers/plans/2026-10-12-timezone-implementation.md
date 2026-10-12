# Timezone Contract Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans for native execution, or superpowers:subagent-driven-development if the user explicitly selects delegation. Steps use checkbox syntax for tracking. Do not begin implementation until this plan is reviewed.

**Goal:** Apply one timezone contract to existing inventory workflows and make its business-context interface usable by future tenants.

**Architecture:** Shared backend temporal adapters separate instants from dates and resolve business-day boundaries. A persisted organisation setting and optional user preference supply explicit zones to shared frontend formatting. Assess legacy data before any canonical storage rewrite; tenant isolation remains separate work.

**Tech Stack:** FastAPI, Python `datetime`/`zoneinfo`, SQLite, AlpineJS, browser `Intl.DateTimeFormat`, pytest and Node's test runner. Retain SQLite and the existing deployment entrypoint; ensure IANA data availability through the `tzdata` package where system data is absent.

**Spec:** [Timezone design](../specs/2026-10-12-timezone-design.md), [ADR 0001](../../adr/0001-timezone-contract.md).

## Global Constraints

- New public instant inputs must carry an offset or `Z`; naive inputs are rejected.
- Historical naive values are interpreted as UTC only where writer history and data provenance establish that meaning.
- The current organisation has a persisted business timezone, initially `Africa/Nairobi`, preserving existing consumption and audit report semantics.
- Personal display precedence is an explicitly saved user IANA timezone, then the organisation/tenant business timezone.
- Reports, exports and business-date history filters use the business timezone.
- Calendar dates are excluded from timestamp conversion.
- Never edit a shipped migration or bypass checksums.
- No tenant isolation, PostgreSQL migration, subscription or recurring-scheduling implementation in this work.
- Existing live records/settings are not modified during development or read-only smoke checks.

## Review Focus

- Imported naive timestamps may lack trustworthy provenance: assessment must block guessing (Task 1).
- A zone can have ambiguous/nonexistent midnight: reject an invalid boundary explicitly (Task 2).
- An older frontend/API consumer may interpret changed timestamp formats differently: preserve fields and verify the known clients before deployment (Tasks 4–5).
- A timezone setting can change while a report request is running: resolve one immutable context per request (Tasks 3–4).
- Restoring an older backup can reintroduce legacy strings or remove settings: migration and restore must preserve instants and valid defaults (Tasks 3 and 6).

## Execution and PR boundaries

Implement natively unless the user chooses delegation. Use one isolated branch per PR, based on freshly merged main. Tasks 1–6 are sequential review gates, not instructions to publish every change at once. Task 7 is the read-only production verification after each applicable deployment.

Before each commit/PR, run `node --test regression_tests/*.cjs`, `python -m pytest -q`, and `git diff --check` in the project's configured environment. First watch each new behavioural test fail for the intended reason; then implement and run the focused test, followed by both full suites. Do not quote prior test counts as new verification.

### Task 1 / PR A: Temporal manifest and read-only snapshot assessment

**Files:** Create `backend/temporal_manifest.py`, `scripts/assess_timestamps.py`, `regression_tests/test_timestamp_assessment.py`, and `docs/timezone-data-assessment.md`.

**Interfaces:** `TemporalField(table: str, column: str, kind: str, naive_policy: str | None, provenance: str)` lists every existing temporal field. Kinds are `instant`, `date`, `duration`, `schedule`; naive policy is `utc` only with documented evidence. `assess_database(path: Path) -> dict` opens SQLite read-only, reports counts and problematic row identities, and never exposes field values or secrets. CLI: `python scripts/assess_timestamps.py --database PATH`; exit 0 means every instant is classified and interpretable, 1 means unresolved data, 2 means invalid invocation.

- [ ] Write `test_assessment_never_writes_or_creates_database`, `test_manifest_covers_schema_temporal_fields`, and `test_unknown_naive_and_invalid_values_block_conversion`. Assert unchanged database hash/row counts, a missing file stays missing, both unknown naive and malformed values yield blockers, and token/password contents never appear in diagnostics.
- [ ] Run `python -m pytest regression_tests/test_timestamp_assessment.py -q`; confirm the intended failures.
- [ ] Trace all schema fields and writers/readers/defaults, including legacy migrations, auth/reset/session/lockout, transfers, archives, equipment dates, reports and exports. Implement the manifest and assessment using SQLite read-only mode. Numeric durations are classified without datetime parsing.
- [ ] Run the focused and full suites. Assess a disposable fixture containing mixed formats and a supplied production snapshot. Obtain the snapshot through the existing file workflow; do not silently substitute an old Library backup for current production evidence.
- [ ] Commit the assessment code and a sanitised report describing source snapshot date, writer evidence, per-field counts and blockers. Open PR A. Do not commit the database, raw values or credentials. Unresolved fields require an explicit correction/provenance decision before Task 6.

### Task 2 / PR B: Shared temporal primitives

**Files:** Create `backend/temporal.py`, `regression_tests/test_temporal.py`; modify `requirements.txt` to supply `tzdata` if required by the supported runtime.

**Interfaces:** `utc_now() -> datetime`; `parse_api_instant(value: str) -> datetime`; `parse_storage_instant(value: str, *, field: TemporalField) -> datetime`; `serialize_instant(value: datetime) -> str`; `serialize_legacy_utc(value: datetime) -> str`; `validate_zone(value: str) -> ZoneInfo`; `business_date_bounds(start: date, through: date, *, zone: str) -> tuple[datetime, datetime]`. All instant results are UTC-aware. Public output uses `Z`; legacy output preserves the established storage convention until Task 6. Invalid values raise `ValueError`, which routes translate to 422 for public inputs; corrupt stored data is an operational error, never a fabricated timestamp.

- [ ] Write parameterised tests for naive public-input rejection, explicit offset conversion, approved versus unapproved naive storage parsing, UTC serializer round-trip, invalid zones, null handling at caller boundaries, and sub-second preservation.
- [ ] Write `test_new_york_business_day_has_23_or_25_hours`: 2026-03-08 resolves to `[2026-03-08T05:00:00Z, 2026-03-09T04:00:00Z)`; 2026-11-01 resolves to `[2026-11-01T04:00:00Z, 2026-11-02T05:00:00Z)`. Add Nairobi, UTC, `Asia/Kathmandu`, nonexistent midnight (`Pacific/Apia`, 2011-12-30), ambiguous midnight (`America/Havana`, 2020-11-01), reversed and overflowing ranges.
- [ ] Run `python -m pytest regression_tests/test_temporal.py -q` and watch the failures.
- [ ] Implement with aware datetimes/ZoneInfo. Validate candidate local boundaries by UTC round-trip, checking distinct UTC candidates for both folds. Reject nonexistent/ambiguous boundaries; resolve next local midnight independently. No manual offset math.
- [ ] Run focused/full suites, confirm timezone data can be loaded without relying on the developer host, and commit/open PR B. This PR adds tested primitives without changing persisted timestamps.

### Task 3 / PR C: Organisation context and user display preferences

**Files:** Create `backend/services/timezone_policy.py`, `backend/routes/timezone_settings.py`, `backend/schemas/timezone_settings.py`, `backend/migrations/v0004_timezone_preferences.py`, `regression_tests/test_timezone_policy.py`, `regression_tests/test_timezone_settings.py`; modify `backend/migrations/registry.py`, `backend/migrations/validation.py`, `backend/routes/auth.py`, `backend/schemas/auth.py`, `main.py`, and migration/restore tests. Version 4 assumes no intervening migration; inspect the registry first and allocate the next unused version if necessary.

**Interfaces:** immutable `BusinessTimeContext(organisation_id: int, timezone: str, revision: int)`; `resolve_business_context(conn, *, actor_id: int) -> BusinessTimeContext`; `resolve_display_zone(user_zone: str | None, context: BusinessTimeContext) -> str`. The resolver verifies the active actor and reads singleton organisation 1; no tenant ID is accepted from a request.

Organisation table fields: `id` constrained to 1, `business_timezone`, `revision`, `updated_at`, nullable `updated_by` with user foreign key. Add nullable `users.display_timezone`. `GET /api/timezone-context` returns business/display zones and revision for the current active user. `PUT /api/organisation/timezone` accepts `{timezone, expected_revision}`, requires an existing admin/superadmin actor and CSRF, returns 409 on stale revision, and writes an audit event. Extend the existing profile update/response with nullable `display_timezone`, preserving existing email behaviour; omission leaves it unchanged and explicit null resets to organisation default.

- [ ] Write tests for Nairobi bootstrap only when missing, preservation of existing zone, invalid stored zone failure, default/preference precedence, inactive/unauthorised actors, CSRF, invalid IANA names, personal null versus omission, stale revision rejection and audited authorised changes. Test that context values remain unchanged after a subsequent database setting update.
- [ ] Add migration/restore tests for current and older backups, including preservation of user rows/session expiry instants and new settings/defaults. Run focused tests and observe intended failures.
- [ ] Implement the additive migration, authenticated context provider, settings route and profile extension. Wire the router through the existing dependency factories in `main.py`; use the existing authenticated transaction/audit mechanisms. Do not add the zone to security-config parameters.
- [ ] Run focused/full suites and migration check/restore tests. Commit/open PR C. No temporal-column rewrite occurs.

### Task 4 / PR D: Backend instant contracts and business-date queries

**Files:** Modify `backend/routes/reports.py`, `backend/routes/history.py`, `backend/routes/superadmin.py`, `backend/routes/auth.py`, temporal response schemas under `backend/schemas/`, `backend/services/session_access.py`, `backend/services/session_authentication.py`, `backend/security.py`, `backend/logging_config.py`, and affected writers identified by Task 1; extend their existing regression tests. Add `regression_tests/test_timezone_api_contract.py`. Task 1's manifest is the authoritative coverage list rather than these examples alone.

**Interfaces:** Consume Tasks 1–3. Each reporting/history request resolves one `BusinessTimeContext`. Report JSON retains existing fields, including `created_at`/`recorded_at`, with explicit UTC values. Metadata adds `timezone`, `start_date`, `end_date`, `start_utc`, `end_utc`, `timezone_revision`; all-history bounds are null. CSV formats report instants in the effective business zone with numeric offsets and a zone-labelled timestamp header.

- [ ] Write contract tests covering every public instant field in the manifest, established Nairobi consumption/audit totals, two personal zones producing identical report rows/totals/bounds, report requests unaffected by an in-flight settings change, and all-history null bounds.
- [ ] Extend history/report tests with midnight and final-day fractional-second events; assert inclusive first/exclusive next-day bounds, deterministic ordering, complete exports, unchanged actor scope/pagination, and intended corrections to history's old bare-date boundary behaviour.
- [ ] Write expiry/lockout tests showing equivalent explicit-offset and verified legacy values expire at the same UTC instant, independently of display/business zone. Verify UTC log timestamps and unchanged JWT expiry behaviour. Run focused tests and watch failures.
- [ ] Replace hard-coded zone constants, ad hoc datetime clocks/parsers and textual boundary comparisons using shared interfaces. Keep storage writes in the verified legacy format during this PR. Routes reject invalid public values; corrupt stored instants produce an operational error surfaced by the existing loading/error UI.
- [ ] Run full suites and known-client compatibility checks. Deploy PR D together with Task 5's matching client changes in the same release, so output/display/report labels remain coherent. Commit backend work separately within that PR; do not independently deploy a partially updated client contract.

### Task 5 / Same PR D: Shared frontend formatting and timezone controls

**Files:** Create `static/temporal.js`, `regression_tests/test_temporal_ui.cjs`, `regression_tests/test_timezone_settings_ui.cjs`; modify `static/script.js`, `static/audit.js`, `static/index.html`, `static/profile.html`, `static/superadmin.html`, relevant styles, and existing report/superadmin UI tests. Inventory every timestamp consumer from Task 1.

**Interfaces:** browser module `InventoryTime.formatInstant(value, zone) -> string`, `InventoryTime.formatDate(value) -> string`, `InventoryTime.parseInstant(value) -> number`, `InventoryTime.isValidZone(zone) -> boolean`. Unknown instants display `Unknown`; absent optional values retain existing empty/never text. Dates never pass through `Date`. Obtain context via `GET /api/timezone-context`; report formatting uses response metadata, not the user's preference.

- [ ] Write tests proving equivalent offset/UTC instants format identically in a selected zone, invalid/naive API values cannot be guessed, dates remain unchanged in positive/negative offset zones, and report formatting stays tied to response zone after personal preference changes.
- [ ] Write settings UI tests for saved/null preference, detected zone as a suggestion only, pending/error/retry behaviour, admin revision-conflict recovery, and retaining a report's resolved context until refresh. Add copy explaining that business-zone changes affect future report grouping, not stored event times.
- [ ] Run Node focused tests and observe failures. Implement the shared formatter, personal profile selector and administrator business-zone control outside Security Config. Zone choices use server validation; account/display default is organisation timezone.
- [ ] Replace `new Date(naiveValue)` and panel-specific formatters; label zones in timestamp columns/report filters and retain date-picker strings as dates. Version all changed static scripts/HTML references consistently to avoid stale formatter code. Preserve keyboard access, responsive spacing and visible request/error feedback.
- [ ] Run both full suites and local desktop/mobile visual checks where the environment supports actual viewport testing; report any limitation. Publish combined PR D with backend/client changes and explicit API-format release notes.

### Task 6 / PR E: Canonical storage readiness and cutover

**Files:** New next-numbered migration `backend/migrations/v0005_canonical_instants.py` (allocate the next unused version), update registry/schema validation, shared storage serializer, all defaults/writers/comparisons from Task 1's manifest, `regression_tests/test_canonical_instants.py`, migration fixtures/restore/concurrency tests, `docs/database-migrations.md`, and `docs/timezone-data-assessment.md`.

**Interfaces:** Task 1's reviewed manifest and zero-blocker snapshot assessment are required inputs. Canonical storage serializer emits `YYYY-MM-DDTHH:MM:SS.ffffffZ`; explicit offsets normalise to the same instant. Approved legacy naive values gain a UTC marker without clock shifts. Dates/durations are excluded.

- [ ] Present the readiness evidence before writing the migration: current snapshot assessment, every upgraded reader/writer, client contract checks, and pre-cutover snapshot/recovery procedure. Unresolved provenance or malformed data blocks this PR. Resolve it explicitly or keep the affected storage representation; do not weaken the manifest to make the assessment pass.
- [ ] Write tests for row-by-row instant equality, zero fractional padding, explicit-offset normalisation, unchanged stock/IDs/autoincrement/foreign keys, defaults matching application writes, deterministic ordering and preserved expiry/report totals. Test that malformed/unapproved data rolls back the complete migration and ledger entry.
- [ ] Write older/canonical backup restore tests, incompatible future-schema rejection, contention/concurrent-write behaviour and calendar-date exclusion. Run focused tests and watch failures.
- [ ] Implement the migration transaction and canonical writers/defaults together. Where a table rebuild is needed, enumerate the manifest fields and preserve the schema/constraints; never modify migrations 1–4. Continue accepting verified legacy storage formats for supported restore inputs through migration/adapter boundaries.
- [ ] Run all suites and assessment/migration/restore on disposable copies of the current snapshot. Compare baseline counts, quantities, instants and representative report totals. Document exact rollback compatibility and recovery-point loss; no automatic downgrade.
- [ ] Commit/open PR E with readiness evidence. Only deploy after a current independent application snapshot has been verified restorable and the migration review is approved. Do not rely on paid Railway backups or mutate production through ad hoc SQL.

### Task 7: Production verification and operational handoff

**Files:** Update `docs/timezone-data-assessment.md` with sanitised verification results and `docs/database-migrations.md` with the final migration/version; no separate product behaviour.

- [ ] After each relevant deployment, verify readiness and expected migration version. Use read-only navigation/filters to check known consumption totals, audit/history date boundaries, unchanged equipment dates and session expiry behaviour. Do not submit administrative changes solely to smoke-test.
- [ ] Exercise alternate business zones and two user preferences on a disposable fixture, not by changing production's organisation timezone. Verify independent display labels, identical business report totals, DST ranges and CSV/JSON metadata agreement.
- [ ] Record unresolved issues and distinguish local tests, live observations and unavailable checks. Re-run meaningful tests after fixes; do not claim mobile, restore or alternate-zone live verification without evidence.
- [ ] Record implementation completion against the accepted ADR only when its policy is implemented and verified; retain source snapshot and migration evidence outside git through the existing file workflow. Future tenant integration must preserve this resolver contract and add separately tested tenant isolation.

## Review gate

Review this plan before Task 1. Native execution is recommended because all tasks depend on the same temporal interfaces and existing migration/route patterns. Start with PR A; review each subsequent PR before deployment. Canonical storage conversion is a later gated step, not part of the first implementation PR.
