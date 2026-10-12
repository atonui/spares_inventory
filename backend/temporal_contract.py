"""Domain response and exact SQLite comparisons during the legacy-storage transition.

SQL date functions round fractional seconds. Normalising approved instants to
fixed-width UTC strings preserves microsecond boundaries and offset equivalence.
No storage values are modified, and arbitrary SQL results/audit details are opaque.
"""
from datetime import date, timedelta
from functools import wraps
from fastapi import HTTPException
from .temporal import business_date_bounds, business_midnight, parse_storage_instant, serialize_instant
from .temporal_manifest import TEMPORAL_FIELDS

_FIELDS = {field.column: field for field in TEMPORAL_FIELDS if field.kind == 'instant' and not field.setting_key}
_FIELDS['recorded_at'] = next(f for f in TEMPORAL_FIELDS if f.table == 'movements' and f.column == 'created_at')
_FIELDS['set_at'] = next(f for f in TEMPORAL_FIELDS if f.json_key == 'set_at')


def stored_instant(value, column='created_at'):
    return parse_storage_instant(value, field=_FIELDS[column])


def wire_instants(value):
    if isinstance(value, list):
        return [wire_instants(item) for item in value]
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if key in _FIELDS and item is not None:
                try:
                    result[key] = serialize_instant(stored_instant(item, key))
                except ValueError:
                    raise HTTPException(500, 'A stored timestamp is invalid. Contact your administrator.') from None
            else:
                result[key] = item if key in ('details', 'setting_value') else wire_instants(item)
        return result
    return value


def instant_response(handler):
    @wraps(handler)
    async def wrapped(*args, **kwargs):
        return wire_instants(await handler(*args, **kwargs))
    return wrapped


def register_instant_comparison(conn):
    def normalise(value):
        return None if value is None else serialize_instant(stored_instant(value))
    conn.create_function('utc_instant', 1, normalise, deterministic=True)


def date_metadata(context, start=None, end=None):
    try:
        for value in (start, end):
            if isinstance(value, str):
                if date.fromisoformat(value).isoformat() != value:
                    raise ValueError('Use YYYY-MM-DD calendar dates.')
        start = date.fromisoformat(start) if isinstance(start, str) else start
        end = date.fromisoformat(end) if isinstance(end, str) else end
        if start and end and end < start:
            raise ValueError('Through must be on or after From.')
        if start and end:
            lower, upper = business_date_bounds(start, end, zone=context.timezone)
        else:
            lower = business_midnight(start, zone=context.timezone) if start else None
            upper = business_midnight(end + timedelta(days=1), zone=context.timezone) if end else None
    except (ValueError, OverflowError) as error:
        raise HTTPException(422, str(error)) from None
    return dict(timezone=context.timezone, timezone_revision=context.revision,
                start_date=start.isoformat() if start else None, end_date=end.isoformat() if end else None,
                start_utc=serialize_instant(lower) if lower else None, end_utc=serialize_instant(upper) if upper else None)


def date_predicates(column, metadata):
    sql = ''; params = []
    for key, operator in [('start_utc', '>='), ('end_utc', '<')]:
        if metadata[key]:
            sql += f' AND utc_instant({column}) {operator} ?'
            params.append(metadata[key])
    return sql, params
