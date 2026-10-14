from datetime import datetime,timezone
import pytest
from fastapi import HTTPException
from backend.services.announcements import resolve_local_instant,notice_status,normalize_notice

def test_schedule_boundaries():
    n=normalize_notice({'message':'x','level':'info','revision':'A','audience':'everyone','roles':[],'dismissible':False,'starts_at':'2026-10-14T12:00:00Z','expires_at':'2026-10-14T13:00:00Z'})
    assert notice_status(n,now=datetime(2026,10,14,11,59,tzinfo=timezone.utc))=='scheduled'
    assert notice_status(n,now=datetime(2026,10,14,12,tzinfo=timezone.utc))=='active'
    assert notice_status(n,now=datetime(2026,10,14,13,tzinfo=timezone.utc))=='expired'

def test_organisation_local_conversion():
    assert resolve_local_instant('2026-10-14T15:30',zone='Africa/Nairobi')==datetime(2026,10,14,12,30,tzinfo=timezone.utc)
    assert resolve_local_instant(None,zone='Africa/Nairobi') is None

@pytest.mark.parametrize('local',['2026-03-08T02:30','2026-11-01T01:30','invalid','2026-10-14T12:00Z'])
def test_ambiguous_nonexistent_and_offset_inputs_rejected(local):
    with pytest.raises(HTTPException) as e:resolve_local_instant(local,zone='America/New_York')
    assert e.value.status_code==400
