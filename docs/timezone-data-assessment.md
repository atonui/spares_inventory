# Temporal assessment: first implementation stage

Date: 2026-10-12. Scope: read-only checker and field inventory; no data conversion.

## Run the checker

```bash
python scripts/assess_timestamps.py --database /path/to/offline-snapshot.db
```

Use an offline standalone SQLite snapshot, such as an application backup. Do not
point it at the live Railway database. WAL/journal sidecars are rejected rather
than ignored. The tool opens the snapshot read-only and immutable, uses a read
transaction, creates no database/sidecar files, and checks its SHA-256 before and
after reading. Immutable mode requires an offline file: the hash check is an
additional safeguard, not a replacement for a consistent backup.

Exit 0: no malformed, unverified naive, or unclassified temporal fields detected.
Exit 1: assessment blockers exist. Exit 2: invalid invocation/unreadable snapshot.
Exit 0 is not certification of schema integrity or production migration readiness;
use the migration validation commands and provenance review as separate gates.

Reports contain field counts, a source SHA-256, missing legacy fields, unknown
temporal columns and numeric row identities for problems. They never contain
timestamp cell values, passwords, reset/session tokens, names, emails or message
contents. Each field reports at most 100 issue identities; omitted issue counts
are explicit and aggregate counts still cover every row. Keep reports containing
row identities private. This document includes only aggregate counts.

## Field inventory and code evidence

The machine-readable inventory is `backend/temporal_manifest.py`. Naive instant
policies now combine the owner's 12 October confirmation (app-generated timestamps
only), initial commit b6d0531 UTC SQLite defaults, historical authentication
75af1ae UTC expiry clocks and current writers. The unused `users.session_expires`
column remains unverified: no historical writer was found. A non-null naive value
in that column still blocks storage cutover. The old snapshot assessment below
records the policies at the time it was run; it is not a current readiness result.

| Fields | Meaning and writer evidence | Readers/comparisons requiring later changes |
| --- | --- | --- |
| activity_logs.created_at; system_logs.created_at | Instant; SQLite CURRENT_TIMESTAMP defaults, activity/log writers | History and superadmin filtering, sorting, purge boundaries, audit display |
| movements.created_at | Instant; SQLite default, inventory movement writers | Consumption reports/CSV and movement-history date bounds/display |
| inventory.updated_at | Instant; SQLite default and inventory service SQL | Inventory read serializers and frontend timestamps |
| parts.created_at; stores.created_at; work_orders.created_at | Instant; SQLite defaults in core schema | Catalogue/store/work-order response serializers and displays |
| equipment.created_at/updated_at; equipment_history.created_at | Instant; SQLite defaults and equipment route updates | Equipment responses/history formatting |
| store_types.created_at/updated_at; system_settings.updated_at | Instant; SQLite defaults/upserts | Store-type/settings/superadmin outputs |
| users.created_at/last_login | Instant; SQLite default/login update | Profile/user/session administration responses/display |
| sessions.created_at/last_activity | Instant; SQLite default and session authentication update | Session admin filtering/sorting/display |
| sessions.expires_at; users.account_locked_until/reset_token_expires | Instant; auth.py constructs naive UTC strings using a UTC-aware clock | Auth/session_access compares expiries; superadmin still compares some text to SQLite now |
| users.session_expires | Legacy instant column; archiving clears it; historical writer not established | Review old authentication paths before conversion |
| users/stores/parts.archived_at | Instant; migration 3 column, archiving CURRENT_TIMESTAMP writes | Archive responses/history display |
| stock_transfers.completed_at | Instant; transfer helper writes CURRENT_TIMESTAMP | Transfer lifecycle responses/history |
| schema_migrations.applied_at | Instant; runner writes UTC-aware ISO string | Migration metadata/operational output |
| equipment.calibration_date/next_calibration_date; equipment_history.calibration_date | Calendar dates; equipment request fields copied without zone conversion | Due/overdue checks currently use both host local today and SQLite UTC today; later business-date correction must preserve stored dates |
| system_settings.setting_value, system_announcement.set_at | Embedded instant; superadmin writes naive UTC ISO into JSON | Announcement responses; must not be missed by column-only discovery |
| system_settings durations: lockout_duration_minutes/session_duration_hours/remember_me_duration_days/calibration_reminder_days | Numeric duration; bootstrap/security/equipment settings | Expiry arithmetic and calendar reminder calculations; never timestamp conversion |

The checker discovers unknown TIMESTAMP/DATETIME/DATE columns and conventional
temporal names (`*_at`, `*_date`, `*_expires`, `last_login`, `last_activity`).
This is a drift detector, not proof that arbitrary new JSON/text keys contain no
times. New schema fields and embedded temporal payloads must update the manifest.
No schedule fields exist in the current schema; future scheduling requires a
separate local-time-plus-IANA-zone policy.

Outside the database, `backend/logging_config.py` uses Python logging's default
`asctime` conversion without a UTC converter or offset marker. File-log output
therefore depends on the host timezone; later shared temporal/logging work must
make it explicit UTC. Historical file logs need their own provenance assessment
if they are ever imported; this SQLite checker does not certify those files.

## Supplied historical snapshot results

Source: `inventory_backup_20261005_072511.db`, supplied 5 October 2026; assessed
12 October 2026. This is **not a current production snapshot** and predates later
migrations/features. Its SHA-256 remained unchanged through assessment:

`7d303e44c5a08968ac106deef29d67b74e60460dd7457b3abf308f6c048f5748`

| Field | Timezone-free values requiring provenance |
| --- | ---: |
| activity_logs.created_at | 1002 |
| inventory.updated_at | 484 |
| movements.created_at | 526 |
| parts.created_at | 313 |
| sessions.created_at | 97 |
| sessions.last_activity | 97 |
| sessions.expires_at | 97 |
| system_logs.created_at | 41 |
| stores.created_at; work_orders.created_at | 11 each |
| users.created_at | 9 |
| users.last_login | 7 |
| store_types.created_at/updated_at | 6 each |
| system_settings.updated_at | 5 |
| equipment.created_at/updated_at; equipment_history.created_at | 2 each |
| **Total timestamp values, not unique records** | **2718** |

Zero malformed temporal values or unclassified temporal columns were found.
The two calibration dates and two next-calibration dates parsed as dates;
equipment-history calibration dates were null. Existing duration settings parsed
as numeric durations. No announcement row was present. Null optional expiry
fields are reported separately, not invented or converted.

Archive timestamp fields, transfer completion and migration-ledger timestamps
were absent in this older schema. Their absence is reported without applying
migrations. This snapshot cannot establish current production coverage.

## Decisions and remaining gates

- The manifest adds optional setting-key/JSON-key selectors to cover embedded
  announcement time and duration settings. Column-only assessment was insufficient.
- Reviewed app-generated fields have UTC policies for the API adapter. Unknown
  fields and the unverified legacy session_expires column remain blockers. No
  stored timestamp conversion has run.
- Only the explicitly dated supplied snapshot was assessed. Obtain a fresh
  standalone application backup before production readiness or canonical cutover.
- Equipment due checks now use organisation-calendar today; stored calendar dates
  are never converted to instants.
- No database schema, timestamp cell, live setting, token or stock quantity changed.
  The coordinated API/UI release and storage cutover remain separate reviewed PRs.

Validation: focused tests exercise immutable/read-only behaviour, missing-file
handling, complete known schema coverage, privacy, invalid/unverified timestamps,
approved test-only provenance, embedded fields/durations, unknown schema columns,
UTC overflow, encoded paths, WAL/journal refusal and CLI exit codes. Full-suite
counts are recorded in the implementation PR after execution.

Independent review identified malformed-offset normalisation and actual text IDs
in integer-declared SQLite columns as important issues. Regression tests reproduced
both; the checker now validates offset ranges and rejects noninteger identities
with a sanitised error. Deferred test expansion: malformed/missing announcement
JSON, more than 100 diagnostic issues, and declared SQL types in the manifest
coverage test (runtime discovery already includes those types).

## Canonical cutover rehearsal — 2026-10-12

The supplied standalone `inventory_backup.db` has SHA256
`1efcbe545e6b339eb13fac5b95e32bc152829053c9b7366d6244a964aaa018da`.
It was schema version 4, with integrity `ok`, zero foreign-reference violations,
zero timestamp blockers, 3,373 verified naive UTC and five aware instants.
All nine legacy `users.session_expires` values were null; no unverified value
required interpretation. The original file remains byte-identical.

Migration 5 was rehearsed on a private disposable copy. Every prior row was
compared semantically, canonicalising only manifest instants for comparison.
All 3,378 prior instants preserve their UTC value; non-temporal fields, calendar
dates, durations, IDs and autoincrement counters are unchanged. The additional
v5 ledger entry is expected. Post-migration integrity and foreign-reference
checks pass; the read-only timestamp assessment has zero blockers.

Stock remains 314 parts, 11 stores, 487 entries and 1,220 units. Nairobi
consumption remains 10 events / 19 units / 9 parts for all history, and 2 events /
2 units / 2 parts for 2026-09-13 through 2026-10-12. Both the original v4 upload
and migrated v5 backup were restored through the actual restore service into
disposable v5 targets with deliberately altered stock. Every retained row was
compared, excluding only intentional session/reset-token revocation and the new
restore audit event. Stock, reports, counters and calibration dates matched;
the pre-restore recovery files passed integrity checks.

These are offline migration/restore results, not production cutover or mobile
verification. Production and the uploaded original were not changed. Retain a
fresh independent application export immediately before deployment and complete
the read-only post-deployment checks described in `database-migrations.md`.
