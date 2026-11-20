from datetime import datetime,timezone
import json
import pytest
from fastapi import HTTPException
from backend.services.announcements import normalize_notice,save_notice,load_notice,remove_notice,dismiss_notice

def test_legacy_notice_defaults_are_stable():
    raw={'message':'Notice','level':'info','set_at':'2026-10-14T12:00:00.000000Z'}
    n=normalize_notice(raw)
    assert n['audience']=='everyone' and not n['dismissible']
    assert n['starts_at'] is None and n['expires_at'] is None
    assert n['revision']==normalize_notice(raw)['revision']

def test_load_notice_accepts_postgres_mapping_rows():
    payload=json.dumps({'message':'Public notice','level':'info','set_at':'2026-10-14T12:00:00.000000Z'})

    class Result:
        def fetchone(self):
            return {'setting_value': payload}

    class Connection:
        def execute(self, _sql):
            return Result()

    assert load_notice(Connection())['message']=='Public notice'

@pytest.mark.parametrize('missing',['revision','audience','roles','starts_at','expires_at','dismissible'])
def test_partial_modern_notice_fails_closed(missing):
    payload={'message':'Secret','level':'info','revision':'A','audience':'roles','roles':['superadmin'],'starts_at':None,'expires_at':None,'dismissible':False}
    del payload[missing]
    with pytest.raises(ValueError):normalize_notice(payload)
