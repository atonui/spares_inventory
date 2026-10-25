"""Assess an offline, standalone SQLite snapshot without importing the web app."""
import argparse
import hashlib
import json
import re
import sqlite3
import sys
from collections import Counter
from datetime import date, datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path

if __package__ in (None, ''):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.temporal_manifest import TEMPORAL_FIELDS

INSTANT = re.compile(r'^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)?$')
CALENDAR = re.compile(r'^\d{4}-\d{2}-\d{2}$')
COUNTS = ('null', 'empty', 'aware', 'naive_verified_utc', 'naive_unverified', 'date', 'duration', 'invalid')


class AssessmentError(ValueError):
    """Invalid snapshot invocation; messages never contain database cell values."""


def _quote(identifier):
    return '"' + identifier.replace('"', '""') + '"'


def _hash(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def _classify(value, field):
    if value is None:
        return 'null'
    if field.kind == 'duration':
        try:
            number = Decimal(str(value))
            return 'duration' if number.is_finite() and number >= 0 else 'invalid'
        except InvalidOperation:
            return 'invalid'
    if not isinstance(value, str):
        return 'invalid'
    if field.kind == 'date':
        if value == '':
            return 'empty'
        try:
            if CALENDAR.fullmatch(value):
                date.fromisoformat(value)
                return 'date'
        except ValueError:
            pass
        return 'invalid'
    if not INSTANT.fullmatch(value):
        return 'invalid'
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        return 'invalid'
    if parsed.tzinfo is not None:
        try:
            parsed.astimezone(timezone.utc)
        except (ValueError, OverflowError):
            return 'invalid'
        return 'aware'
    return 'naive_verified_utc' if field.naive_policy == 'utc' else 'naive_unverified'


def assess_database(path: Path) -> dict:
    """Read only a stable snapshot; blockers mean it is not migration-ready."""
    path = Path(path).resolve()
    if not path.is_file():
        raise AssessmentError('Database must be an existing snapshot file.')
    if any(Path(str(path) + suffix).exists() for suffix in ('-wal', '-journal')):
        raise AssessmentError('Use a standalone, checkpointed offline snapshot; WAL/journal sidecars are present.')
    try:
        before = _hash(path)
        # immutable prevents SQLite from creating journal/shared-memory sidecars.
        # It is safe only for the offline standalone snapshots required above.
        conn = sqlite3.connect(path.as_uri() + '?mode=ro&immutable=1', uri=True)
        try:
            conn.execute('PRAGMA query_only=ON')
            conn.execute('BEGIN')
            tables = [r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
            if not {'users', 'parts', 'inventory', 'movements'} <= set(tables):
                raise AssessmentError('Snapshot does not contain the inventory core schema.')
            schema = {table: list(conn.execute('PRAGMA table_info(' + _quote(table) + ')')) for table in tables}
            covered = {(f.table, f.column) for f in TEMPORAL_FIELDS}
            unknown = [{'table': table, 'column': row[1]} for table, columns in schema.items() for row in columns
                       if (row[2].upper() in ('TIMESTAMP', 'DATETIME', 'DATE')
                           or row[1].endswith(('_at', '_date', '_expires'))
                           or row[1] in ('last_login', 'last_activity')) and (table, row[1]) not in covered]
            results, absent = [], []
            blockers = len(unknown)
            for field in TEMPORAL_FIELDS:
                identity = {'table': field.table, 'column': field.column, 'kind': field.kind,
                            'naive_policy': field.naive_policy, 'provenance': field.provenance}
                if field.setting_key:
                    identity['setting_key'] = field.setting_key
                if field.json_key:
                    identity['json_key'] = field.json_key
                if field.table not in schema or field.column not in {r[1] for r in schema[field.table]}:
                    absent.append(identity)
                    continue
                # Prefer a safe integer key. For tables with opaque or composite keys,
                # use a deterministic ordinal and never include the key in the report.
                table_columns = schema[field.table]
                key = next((r[1] for r in table_columns if r[5] and r[2].upper() == 'INTEGER'), None)
                parameters = ()
                where = ''
                if field.setting_key:
                    where = ' WHERE setting_key=?'
                    parameters = (field.setting_key,)
                if key:
                    query = 'SELECT ' + _quote(key) + ',' + _quote(field.column) + ' FROM ' + _quote(field.table)
                    query += where + ' ORDER BY ' + _quote(key)
                    rows = ((row[0], row[1]) for row in conn.execute(query, parameters))
                else:
                    primary_keys = [r for r in sorted(table_columns, key=lambda item: item[5]) if r[5]]
                    if not primary_keys:
                        raise AssessmentError('Temporal table lacks a stable row identity.')
                    order = ','.join(_quote(row[1]) for row in primary_keys)
                    query = 'SELECT ' + _quote(field.column) + ' FROM ' + _quote(field.table)
                    query += where + ' ORDER BY ' + order
                    rows = ((ordinal, row[0]) for ordinal, row in enumerate(conn.execute(query, parameters), 1))
                counts = Counter({name: 0 for name in COUNTS})
                issues = []
                for row_id, value in rows:
                    if key and not isinstance(row_id, int):
                        raise AssessmentError('Temporal table contains an unsupported noninteger row identity.')
                    if field.json_key:
                        try:
                            payload = json.loads(value)
                            if not isinstance(payload, dict) or (field.json_key not in payload and not getattr(field,'optional',False)):
                                raise ValueError
                            value = payload.get(field.json_key)
                        except (ValueError, TypeError):
                            value = object()  # Count malformed JSON without exposing it.
                    category = _classify(value, field)
                    counts[category] += 1
                    if category in ('invalid', 'naive_unverified'):
                        blockers += 1
                        # Bounded diagnostics; counts still include every row.
                        if len(issues) < 100:
                            issues.append({'row_id': row_id, 'reason': category})
                results.append({**identity, 'counts': dict(counts), 'issues': issues,
                                'issues_omitted': counts['invalid'] + counts['naive_unverified'] - len(issues)})
        finally:
            conn.close()
        if _hash(path) != before:
            raise AssessmentError('Snapshot changed during assessment; use an offline copy.')
        return {'sha256': before, 'blockers': blockers, 'fields': results,
                'absent_fields': absent, 'unclassified_columns': unknown,
                'note': 'Format validity is not historical provenance. No database values are changed.'}
    except (sqlite3.Error, OSError):
        raise AssessmentError('Unable to read a valid standalone SQLite snapshot.') from None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', type=Path, required=True, help='Existing offline SQLite snapshot')
    args = parser.parse_args(argv)
    try:
        report = assess_database(args.database)
    except AssessmentError as error:
        print(str(error), file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2))
    return 1 if report['blockers'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
