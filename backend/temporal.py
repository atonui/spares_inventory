"""Explicit UTC instants and named-zone business dates; no persistence changes.

Public profile: uppercase T/Z, seconds with up to six fractional digits, and
colon-delimited offsets; leap seconds are unsupported by Python datetime.
"""
import re
from datetime import date, datetime, time, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .temporal_manifest import TemporalField

_STAMP = r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?'
_OFFSET = r'(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)'
_PUBLIC = re.compile(_STAMP + _OFFSET)
_LEGACY = re.compile(_STAMP.replace('T', '[T ]') + '(?:' + _OFFSET + ')?')


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError('An aware datetime is required.')
    try:
        return value.astimezone(timezone.utc)
    except (OverflowError, ValueError):
        raise ValueError('Instant cannot be represented in UTC.') from None


def parse_api_instant(value: str) -> datetime:
    if not isinstance(value, str) or not _PUBLIC.fullmatch(value):
        raise ValueError('Use a complete RFC 3339 instant with an explicit offset or Z.')
    try:
        return _utc(datetime.fromisoformat(value.replace('Z', '+00:00')))
    except (ValueError, OverflowError):
        raise ValueError('Invalid instant.') from None


def parse_storage_instant(value: str, *, field: TemporalField) -> datetime:
    if field.kind != 'instant' or not isinstance(value, str) or not _LEGACY.fullmatch(value):
        raise ValueError('Invalid stored instant.')
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if parsed.tzinfo is None:
            if field.naive_policy != 'utc':
                raise ValueError
            parsed = parsed.replace(tzinfo=timezone.utc)
        return _utc(parsed)
    except (ValueError, OverflowError):
        raise ValueError('Stored instant is invalid or lacks verified UTC provenance.') from None


def serialize_instant(value: datetime) -> str:
    return _utc(value).isoformat(timespec='microseconds').replace('+00:00', 'Z')


def serialize_legacy_utc(value: datetime) -> str:
    # Match existing Python writers: seconds when integral, microseconds otherwise.
    return _utc(value).replace(tzinfo=None).isoformat()


def validate_zone(value: str) -> ZoneInfo:
    # Region paths (including legacy IANA aliases) or explicit UTC. Reject bare
    # abbreviations even when the host has a same-named tzfile.
    if (not isinstance(value, str) or not value or (value != 'UTC' and '/' not in value)
            or value.startswith(('posix/', 'right/'))):
        raise ValueError('Use an IANA region timezone identifier or UTC.')
    try:
        return ZoneInfo(value)
    except (ZoneInfoNotFoundError, ValueError):
        raise ValueError('Unknown or invalid IANA timezone.') from None


def _midnight(day: date, zone: ZoneInfo) -> datetime:
    local = datetime.combine(day, time.min)
    candidates = set()
    try:
        for fold in (0, 1):
            instant = local.replace(tzinfo=zone, fold=fold).astimezone(timezone.utc)
            returned = instant.astimezone(zone)
            if returned.replace(tzinfo=None) == local:
                candidates.add(instant)
    except (OverflowError, ValueError):
        raise ValueError('Local midnight cannot be represented in UTC.') from None
    if len(candidates) != 1:
        raise ValueError('Local midnight is nonexistent or ambiguous in this timezone.')
    return candidates.pop()


def business_midnight(day: date, *, zone: str) -> datetime:
    """Resolve exactly one requested local midnight, rejecting gaps and folds."""
    if type(day) is not date:
        raise ValueError('Provide a calendar date.')
    return _midnight(day, validate_zone(zone))


def business_date_bounds(start: date, through: date, *, zone: str) -> tuple[datetime, datetime]:
    if type(start) is not date or type(through) is not date or through < start:
        raise ValueError('Provide calendar dates in ascending order.')
    named_zone = validate_zone(zone)
    try:
        following = through + timedelta(days=1)
    except OverflowError:
        raise ValueError('Final calendar date is out of range.') from None
    return _midnight(start, named_zone), _midnight(following, named_zone)
