from datetime import date, datetime, timedelta, timezone
import os
import subprocess
import sys
from importlib.resources import files

import pytest

from backend import temporal as t
from backend.temporal_manifest import TemporalField


@pytest.mark.parametrize('value', [None, '', '2026-10-12', '2026-10-12T09:00:00',
                                  '2026-10-12 09:00:00Z', '2026-10-12T09:00:00+01:99',
                                  '2026-10-12T09:00:00+24:00', '2026-10-12T09:00:00+0300',
                                  '0001-01-01T00:00:00+01:00'])
def test_public_input_rejects_ambiguous_or_invalid_values(value):
    with pytest.raises(ValueError):
        t.parse_api_instant(value)


def test_explicit_offset_and_subseconds_preserve_instant():
    instant = t.parse_api_instant('2026-10-12T12:09:00.123456+03:00')
    assert instant == datetime(2026, 10, 12, 9, 9, 0, 123456, tzinfo=timezone.utc)
    assert t.serialize_instant(instant) == '2026-10-12T09:09:00.123456Z'
    assert t.parse_api_instant(t.serialize_instant(instant)) == instant
    assert t.serialize_legacy_utc(instant) == '2026-10-12T09:09:00.123456'


def test_storage_parser_requires_field_specific_provenance():
    unknown = TemporalField('events', 'at', 'instant', None, 'Unknown provenance')
    known = TemporalField('events', 'at', 'instant', 'utc', 'Verified UTC writer')
    calendar = TemporalField('equipment', 'due', 'date', None, 'Date only')
    with pytest.raises(ValueError):
        t.parse_storage_instant('2026-10-12 09:00:00', field=unknown)
    assert t.parse_storage_instant('2026-10-12 09:00:00', field=known) == datetime(2026, 10, 12, 9, tzinfo=timezone.utc)
    assert t.parse_storage_instant('2026-10-12T12:00:00+03:00', field=unknown).hour == 9
    with pytest.raises(ValueError):
        t.parse_storage_instant('2026-10-12', field=calendar)


@pytest.mark.parametrize('value', [None, datetime(2026, 1, 1), date(2026, 1, 1)])
def test_serializers_do_not_guess_naive_or_absent_instants(value):
    for serializer in (t.serialize_instant, t.serialize_legacy_utc):
        with pytest.raises(ValueError):
            serializer(value)


def test_serializer_normalises_offset_and_pads_year():
    instant = datetime(1, 1, 2, tzinfo=timezone(timedelta(hours=1)))
    assert t.serialize_instant(instant) == '0001-01-01T23:00:00.000000Z'
    assert t.serialize_legacy_utc(datetime(2026, 1, 1, tzinfo=timezone.utc)) == '2026-01-01T00:00:00'


def test_clock_is_aware_utc():
    before = datetime.now(timezone.utc)
    clock = t.utc_now()
    after = datetime.now(timezone.utc)
    assert before <= clock <= after
    assert clock.tzinfo is timezone.utc


@pytest.mark.parametrize('zone', ['IST', 'BST', '+03:00', '../UTC', '/etc/passwd', 'Africa/Unknown', '', None])
def test_invalid_or_ambiguous_zone_identifiers_are_rejected(zone):
    with pytest.raises(ValueError):
        t.validate_zone(zone)


@pytest.mark.parametrize('day,start,end', [
    (date(2026, 3, 8), '2026-03-08T05:00:00Z', '2026-03-09T04:00:00Z'),
    (date(2026, 11, 1), '2026-11-01T04:00:00Z', '2026-11-02T05:00:00Z'),
])
def test_new_york_business_day_has_23_or_25_hours(day, start, end):
    bounds = t.business_date_bounds(day, day, zone='America/New_York')
    assert bounds == (t.parse_api_instant(start), t.parse_api_instant(end))


@pytest.mark.parametrize('zone,start', [
    ('UTC', '2026-10-12T00:00:00Z'),
    ('Africa/Nairobi', '2026-10-11T21:00:00Z'),
    ('Asia/Kathmandu', '2026-10-11T18:15:00Z'),
])
def test_named_zone_boundaries(zone, start):
    first, end = t.business_date_bounds(date(2026, 10, 12), date(2026, 10, 13), zone=zone)
    assert first == t.parse_api_instant(start)
    assert end - first == timedelta(days=2)


@pytest.mark.parametrize('day,zone', [(date(2011, 12, 30), 'Pacific/Apia'),
                                     (date(2020, 11, 1), 'America/Havana')])
def test_nonexistent_or_ambiguous_midnight_is_not_guessed(day, zone):
    with pytest.raises(ValueError, match='midnight'):
        t.business_date_bounds(day, day, zone=zone)


@pytest.mark.parametrize('start,end,zone', [
    (date(2026, 10, 12), date(2026, 10, 11), 'UTC'),
    (date.max, date.max, 'UTC'),
    (date.min, date.min, 'Africa/Nairobi'),
    (None, date(2026, 1, 1), 'UTC'),
    (datetime(2026, 1, 1), date(2026, 1, 1), 'UTC'),
])
def test_invalid_or_overflowing_date_ranges_are_rejected(start, end, zone):
    with pytest.raises(ValueError):
        t.business_date_bounds(start, end, zone=zone)


def test_timezone_package_fallback_without_system_zone_database():
    # A fresh interpreter avoids ZoneInfo's cache and PYTHONTZPATH is empty.
    result = subprocess.run([sys.executable, '-c',
        "from zoneinfo import TZPATH; from backend.temporal import validate_zone; "
        "assert not TZPATH; assert validate_zone('Africa/Nairobi').key == 'Africa/Nairobi'"],
        cwd=os.path.dirname(os.path.dirname(__file__)), env={**os.environ, 'PYTHONTZPATH': ''},
        text=True, capture_output=True)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize('prefix', ['posix', 'right'])
def test_host_supplementary_zone_names_are_rejected_even_when_present(tmp_path, prefix):
    directory = tmp_path / prefix / 'Africa'
    directory.mkdir(parents=True)
    (directory / 'Nairobi').write_bytes(files('tzdata.zoneinfo').joinpath('Africa/Nairobi').read_bytes())
    result = subprocess.run([sys.executable, '-c',
        "from backend.temporal import validate_zone\n"
        f"try: validate_zone('{prefix}/Africa/Nairobi')\n"
        "except ValueError: pass\n"
        "else: raise AssertionError('Host-specific zone accepted')"],
        cwd=os.path.dirname(os.path.dirname(__file__)), env={**os.environ, 'PYTHONTZPATH': str(tmp_path)},
        text=True, capture_output=True)
    assert result.returncode == 0, result.stderr
