"""Single-notice persistence and eligibility on caller-owned connections."""
import hashlib
import json
import re
import uuid
from datetime import datetime,timezone
from zoneinfo import ZoneInfo
from fastapi import HTTPException
from backend.temporal import parse_api_instant,serialize_instant,utc_now
ROLES={'engineer','manager','admin','superadmin'}

def normalize_notice(payload):
    if payload is None:return None
    controls={'revision','audience','roles','starts_at','expires_at','dismissible'}
    modern=isinstance(payload,dict) and bool(controls.intersection(payload))
    if modern and not controls.issubset(payload):raise ValueError('Incomplete saved announcement controls')
    if isinstance(payload,dict) and not modern and 'level' not in payload:payload={**payload,'level':'info'}
    if not isinstance(payload,dict) or not isinstance(payload.get('message'),str) or payload.get('level') not in {'info','warning','danger'}:
        raise ValueError('Invalid saved announcement')
    n={**payload}
    n.setdefault('revision','legacy-'+hashlib.sha256(json.dumps(payload,sort_keys=True).encode()).hexdigest())
    n.setdefault('audience','everyone');n.setdefault('roles',[])
    n.setdefault('starts_at',None);n.setdefault('expires_at',None);n.setdefault('dismissible',False)
    if not isinstance(n['revision'],str) or not n['revision'] or n['audience'] not in {'everyone','authenticated','roles'} or not isinstance(n['roles'],list) or any(r not in ROLES for r in n['roles']) or (n['audience']=='roles' and not n['roles']) or not isinstance(n['dismissible'],bool):
        raise ValueError('Invalid saved announcement controls')
    for key in ('set_at','starts_at','expires_at'):
        if n.get(key) is not None:parse_api_instant(n[key])
    return n

def load_notice(conn):
    row=conn.execute("SELECT setting_value FROM system_settings WHERE setting_key='system_announcement'").fetchone()
    return normalize_notice(json.loads(row[0])) if row else None

def check_revision(conn,expected_revision):
    old=load_notice(conn)
    if (old['revision'] if old else None)!=expected_revision:
        raise HTTPException(409,'Announcement changed. Reload before saving or removing it.')
    return old

def save_notice(conn,notice,*,actor_id,expected_revision):
    check_revision(conn,expected_revision)
    saved=normalize_notice({'audience':'everyone','roles':[],'starts_at':None,'expires_at':None,'dismissible':False,**notice,'revision':str(uuid.uuid4()),'set_at':serialize_instant(utc_now())})
    conn.execute("""INSERT INTO system_settings(setting_key,setting_value,updated_by) VALUES('system_announcement',?,?)
    ON CONFLICT(setting_key) DO UPDATE SET setting_value=excluded.setting_value,updated_by=excluded.updated_by,updated_at=strftime('%Y-%m-%dT%H:%M:%f000Z','now')""",(json.dumps(saved),actor_id))
    conn.execute('DELETE FROM announcement_dismissals')
    return saved

def remove_notice(conn,*,expected_revision):
    check_revision(conn,expected_revision)
    conn.execute("DELETE FROM system_settings WHERE setting_key='system_announcement'")
    conn.execute('DELETE FROM announcement_dismissals')

def dismiss_notice(conn,*,user_id,revision,now):
    n=load_notice(conn)
    if not n or n['revision']!=revision:raise HTTPException(409,'Announcement changed. Refresh before dismissing it.')
    conn.execute('INSERT OR IGNORE INTO announcement_dismissals(user_id,revision,dismissed_at) VALUES(?,?,?)',(user_id,revision,serialize_instant(now)))

def resolve_local_instant(value,*,zone):
    if value is None or value=='':return None
    try:
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2})?",value):raise ValueError
        local=datetime.fromisoformat(value)
        if local.tzinfo is not None:raise ValueError
        candidates=set()
        for fold in (0,1):
            instant=local.replace(tzinfo=ZoneInfo(zone),fold=fold).astimezone(timezone.utc)
            if instant.astimezone(ZoneInfo(zone)).replace(tzinfo=None)==local:candidates.add(instant)
        if len(candidates)!=1:raise ValueError
        return candidates.pop()
    except (ValueError,TypeError,OverflowError):raise HTTPException(400,'Invalid, ambiguous or nonexistent local schedule time') from None

def notice_status(notice,*,now):
    if notice['expires_at'] and now>=parse_api_instant(notice['expires_at']):return 'expired'
    if notice['starts_at'] and now<parse_api_instant(notice['starts_at']):return 'scheduled'
    return 'active'

def eligible_notice(conn,notice,*,viewer,now):
    if not notice or notice_status(notice,now=now)!='active':return None
    if notice['audience']=='authenticated' and viewer is None:return None
    if notice['audience']=='roles' and (viewer is None or viewer['role'] not in notice['roles']):return None
    if viewer and conn.execute('SELECT 1 FROM announcement_dismissals WHERE user_id=? AND revision=?',(viewer['user_id'],notice['revision'])).fetchone():return None
    return notice
