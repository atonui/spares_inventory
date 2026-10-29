"""Support authorization is exercised using a non-owner, non-bypass runtime role."""
from datetime import datetime, timedelta
from uuid import uuid4

import psycopg
import pytest
from fastapi import HTTPException
from psycopg import sql

from backend.temporal import serialize_instant, utc_now
from backend.services.session_credentials import hash_session_credential

pytest_plugins = ("regression_tests.postgres_fixtures",)


@pytest.fixture
def support_database(postgres_schema):
    from backend.postgres_migrations.runner import apply_postgres_migrations
    from regression_tests.postgres_fixtures import postgres_test_dsn
    owner, schema = postgres_schema
    apply_postgres_migrations(owner)
    actor = owner.execute("INSERT INTO users(email,name,password_hash) VALUES ('support@example.test','Support','x') RETURNING id").fetchone()['id']
    other = owner.execute("INSERT INTO users(email,name,password_hash) VALUES ('other@example.test','Other','x') RETURNING id").fetchone()['id']
    owner.execute('INSERT INTO platform_admins(user_id) VALUES (%s)', (actor,))
    token = uuid4().hex
    auth = owner.execute('INSERT INTO sessions(user_id,session_token_hash,expires_at) VALUES (%s,%s,%s) RETURNING id', (actor, hash_session_credential(token), serialize_instant(utc_now()+timedelta(hours=1)))).fetchone()['id']
    orgs = [owner.execute('INSERT INTO organizations(name,slug) VALUES (%s,%s) RETURNING id', (name,name)).fetchone()['id'] for name in ('a','b')]
    for org in orgs:
        owner.execute("INSERT INTO stores(name,type,organization_id) VALUES (%s,'main',%s)", (str(org),org))
    role = 'support_runtime_'+uuid4().hex
    owner.execute(sql.SQL('CREATE ROLE {} NOLOGIN NOSUPERUSER NOBYPASSRLS').format(sql.Identifier(role)))
    owner.execute(sql.SQL('GRANT USAGE ON SCHEMA {} TO {}').format(sql.Identifier(schema),sql.Identifier(role)))
    owner.execute(sql.SQL('GRANT SELECT ON users,sessions,organizations,organization_memberships,platform_admins,stores TO {}').format(sql.Identifier(role)))
    owner.execute(sql.SQL('GRANT UPDATE ON sessions TO {}').format(sql.Identifier(role)))
    owner.execute(sql.SQL('GRANT SELECT,INSERT ON platform_support_sessions TO {}').format(sql.Identifier(role)))
    owner.execute(sql.SQL('GRANT UPDATE (ended_at) ON platform_support_sessions TO {}').format(sql.Identifier(role)))
    owner.execute(sql.SQL('GRANT INSERT ON platform_audit_events TO {}').format(sql.Identifier(role)))
    owner.execute(sql.SQL('GRANT USAGE,SELECT ON SEQUENCE platform_audit_events_id_seq TO {}').format(sql.Identifier(role)))
    owner.commit()
    def connect():
        conn = psycopg.connect(postgres_test_dsn(), row_factory=owner.row_factory)
        conn.execute(sql.SQL('SET search_path TO {}').format(sql.Identifier(schema)))
        conn.execute(sql.SQL('SET ROLE {}').format(sql.Identifier(role)))
        conn.commit()
        return conn
    try:
        yield owner,connect,actor,other,auth,token,orgs
    finally:
        owner.rollback()
        owner.execute(sql.SQL('DROP OWNED BY {}').format(sql.Identifier(role)))
        owner.execute(sql.SQL('DROP ROLE {}').format(sql.Identifier(role)))
        owner.commit()


def start(db):
    from backend.services.platform_support import create_support_session
    owner,connect,actor,other,auth,token,orgs = db
    with connect() as conn:
        return create_support_session(conn, actor_user_id=actor,auth_session_id=auth,organization_id=orgs[0],reason='Investigate access issue',now=utc_now())


def test_create_support_session_sets_fixed_expiry_and_rejects_second_live_session(support_database):
    from backend.services.platform_support import create_support_session
    db = support_database
    session = start(db)
    assert datetime.fromisoformat(session['expires_at'].replace('Z','+00:00'))-datetime.fromisoformat(session['created_at'].replace('Z','+00:00')) == timedelta(minutes=15)
    with db[1]() as conn, pytest.raises(HTTPException) as error:
        create_support_session(conn,actor_user_id=db[2],auth_session_id=db[4],organization_id=db[6][1],reason='Investigate other issue',now=utc_now())
    assert error.value.status_code == 409


def test_concurrent_support_starts_are_serialized_by_login(support_database):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    from backend.services.platform_support import create_support_session
    db = support_database
    barrier = Barrier(2)
    def attempt():
        try:
            with db[1]() as conn:
                barrier.wait(timeout=5)
                create_support_session(conn, actor_user_id=db[2], auth_session_id=db[4],
                                       organization_id=db[6][0], reason='Concurrent access investigation',
                                       now=utc_now())
            return 201
        except HTTPException as error:
            return error.status_code
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: attempt(), range(2)))
    assert sorted(results) == [201, 409]


def test_authenticated_support_transaction_sets_only_bound_organization(support_database):
    from backend.services.platform_support import authenticated_support_transaction
    db = support_database
    session = start(db)
    with db[1]() as conn:
        assert conn.execute('SELECT * FROM stores').fetchall() == []
        conn.execute("SELECT set_config('app.organization_id',%s,true)",(str(db[6][1]),))
        assert conn.execute('SELECT * FROM stores WHERE organization_id=%s',(db[6][0],)).fetchall() == []
    with authenticated_support_transaction(db[1],session_token=db[5],support_session_id=session['id']) as (conn,principal,bound):
        assert {r['organization_id'] for r in conn.execute('SELECT * FROM stores').fetchall()} == {db[6][0]}


@pytest.mark.parametrize('state',['missing','ended','expired','wrong-actor','wrong-auth-session','inactive-auth-session','revoked-platform-admin'])
def test_authenticated_support_transaction_rejects_invalid_session_state(support_database,state):
    from backend.services.platform_support import authenticated_support_transaction
    db = support_database
    session = start(db)
    owner = db[0]
    sid = session['id']
    if state == 'missing': sid = uuid4()
    elif state == 'ended': owner.execute('UPDATE platform_support_sessions SET ended_at=now()::text WHERE id=%s',(sid,))
    elif state == 'expired': owner.execute("UPDATE platform_support_sessions SET created_at=(now()-interval '1 hour')::text,expires_at=(now()-interval '45 minutes')::text WHERE id=%s",(sid,))
    elif state == 'wrong-actor': owner.execute('UPDATE platform_support_sessions SET actor_user_id=%s WHERE id=%s',(db[3],sid))
    elif state == 'wrong-auth-session':
        other_auth=owner.execute('INSERT INTO sessions(user_id,session_token_hash,expires_at) VALUES (%s,%s,%s) RETURNING id',(db[2],uuid4().hex,serialize_instant(utc_now()+timedelta(hours=1)))).fetchone()['id']
        owner.execute('UPDATE platform_support_sessions SET auth_session_id=%s WHERE id=%s',(other_auth,sid))
    elif state == 'inactive-auth-session': owner.execute('UPDATE sessions SET is_active=FALSE WHERE id=%s',(db[4],))
    else: owner.execute('DELETE FROM platform_admins WHERE user_id=%s',(db[2],))
    owner.commit()
    with pytest.raises(HTTPException):
        with authenticated_support_transaction(db[1],session_token=db[5],support_session_id=sid):
            pytest.fail('Invalid support session yielded tenant access')
    with db[1]() as conn:
        assert conn.execute('SELECT * FROM stores').fetchall() == []
    if state == 'expired':
        assert owner.execute('SELECT ended_at FROM platform_support_sessions WHERE id=%s',(sid,)).fetchone()['ended_at'] is not None
        assert owner.execute("SELECT count(*) AS n FROM platform_audit_events WHERE action='support_session_ended'").fetchone()['n'] == 1


def test_end_support_sessions_matches_revoked_auth_sessions_only(support_database):
    from backend.services.platform_support import create_support_session, end_support_sessions
    db = support_database
    first = start(db)
    second_token = uuid4().hex
    second_auth = db[0].execute(
        'INSERT INTO sessions(user_id,session_token_hash,expires_at) VALUES (%s,%s,%s) RETURNING id',
        (db[2], hash_session_credential(second_token), serialize_instant(utc_now()+timedelta(hours=1))),
    ).fetchone()['id']
    db[0].commit()
    with db[1]() as conn:
        second = create_support_session(conn, actor_user_id=db[2], auth_session_id=second_auth,
            organization_id=db[6][1], reason='Second login support case', now=utc_now())
    with db[1]() as conn:
        assert end_support_sessions(conn, actor_user_id=db[2], end_reason='sessions_revoked',
                                    auth_session_ids=[db[4]]) == 1
    ended = db[0].execute('SELECT ended_at FROM platform_support_sessions WHERE id=%s',(first['id'],)).fetchone()['ended_at']
    preserved = db[0].execute('SELECT ended_at FROM platform_support_sessions WHERE id=%s',(second['id'],)).fetchone()['ended_at']
    assert ended is not None
    assert preserved is None
    audit = db[0].execute("SELECT details FROM platform_audit_events WHERE action='support_session_ended'").fetchone()['details']
    assert audit['support_session_id'] == str(first['id'])
    assert audit['end_reason'] == 'sessions_revoked'


def test_end_support_sessions_audit_failure_rolls_back_end(support_database):
    from backend.services.platform_support import end_support_sessions
    db = support_database
    session = start(db)
    runtime_role = None
    with db[1]() as conn:
        runtime_role = conn.execute('SELECT current_user AS role').fetchone()['role']
    db[0].execute(sql.SQL('REVOKE INSERT ON platform_audit_events FROM {}').format(sql.Identifier(runtime_role)))
    db[0].commit()
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with db[1]() as conn:
            end_support_sessions(conn, actor_user_id=db[2], end_reason='user_logout', auth_session_ids=[db[4]])
    row = db[0].execute('SELECT ended_at FROM platform_support_sessions WHERE id=%s',(session['id'],)).fetchone()
    assert row['ended_at'] is None


def test_platform_admin_revocation_end_is_attributed_to_initiator(support_database):
    from backend.services.platform_support import create_support_session, end_support_sessions
    db = support_database
    owner, actor, target = db[0], db[2], db[3]
    owner.execute('INSERT INTO platform_admins(user_id) VALUES (%s)', (target,))
    target_token = uuid4().hex
    target_auth = owner.execute(
        'INSERT INTO sessions(user_id,session_token_hash,expires_at) VALUES (%s,%s,%s) RETURNING id',
        (target, hash_session_credential(target_token), serialize_instant(utc_now()+timedelta(hours=1))),
    ).fetchone()['id']
    owner.commit()
    with db[1]() as conn:
        support = create_support_session(conn, actor_user_id=target, auth_session_id=target_auth,
            organization_id=db[6][0], reason='Target administrator support case', now=utc_now())
    with db[1]() as conn:
        assert end_support_sessions(conn, actor_user_id=actor, target_user_id=target,
                                    end_reason='platform_admin_revoked') == 1
    audit = owner.execute(
        "SELECT actor_user_id,details FROM platform_audit_events WHERE action='support_session_ended'"
    ).fetchone()
    assert audit['actor_user_id'] == actor
    assert {key:value for key,value in audit['details'].items() if key != 'request_id'} == {
        'support_session_id': str(support['id']), 'operation': 'end',
        'end_reason': 'platform_admin_revoked', 'target_user_id': target,
    }
    from uuid import UUID
    UUID(audit['details']['request_id'])


@pytest.fixture
def support_api(support_database):
    from types import SimpleNamespace
    from backend.routes.platform_support import create_platform_support_router
    db = support_database
    owner = db[0]
    runtime_role = None
    with db[1]() as conn:
        runtime_role = conn.execute('SELECT current_user AS role').fetchone()['role']
    owner.execute(sql.SQL('GRANT SELECT ON parts,inventory,work_orders,equipment,equipment_history,movements,stock_transfers TO {}').format(sql.Identifier(runtime_role)))
    owner.execute(sql.SQL('GRANT INSERT ON platform_audit_events TO {}').format(sql.Identifier(runtime_role)))
    owner.execute(sql.SQL('GRANT USAGE,SELECT ON SEQUENCE platform_audit_events_id_seq TO {}').format(sql.Identifier(runtime_role)))
    owner.commit()
    class Limiter:
        def limit(self, rule):
            assert rule == '5/minute'
            return lambda endpoint: endpoint
    router = create_platform_support_router(get_connection=db[1], current_user=lambda: None,
        csrf_dependency=lambda: True, password_verify=lambda plain, hashed: plain == 'correct-password' and hashed == 'x', limiter=Limiter())
    routes = {r.path: r.endpoint for r in router.routes if 'GET' in r.methods}
    return SimpleNamespace(db=db, router=router, routes=routes,
        request=SimpleNamespace(cookies={'session_token':db[5]},headers={}), actor=db[2])


def call_support(api, path, **kwargs):
    import asyncio
    return asyncio.run(api.routes['/api/platform/support-sessions/'+path](request=api.request,actor=api.actor,**kwargs))


def test_start_support_session_requires_current_password_and_reason(support_api):
    import asyncio
    from pydantic import ValidationError
    from backend.routes.platform_support import SupportSessionStart
    api = support_api
    endpoint = next(r.endpoint for r in api.router.routes if 'POST' in r.methods)
    for reason in ('short', 'x'*501):
        with pytest.raises(ValidationError):
            SupportSessionStart(organization_id=api.db[6][0],reason=reason,current_password='correct-password')
    with pytest.raises(HTTPException) as error:
        asyncio.run(endpoint(body=SupportSessionStart(organization_id=api.db[6][0],reason='Investigate account access',current_password='wrong'),request=api.request,actor=api.actor))
    assert error.value.status_code == 403
    assert api.db[0].execute('SELECT count(*) AS n FROM platform_support_sessions').fetchone()['n'] == 0
    assert api.db[0].execute("SELECT count(*) AS n FROM platform_audit_events WHERE action='support_access_denied'").fetchone()['n'] == 1
    result = asyncio.run(endpoint(body=SupportSessionStart(organization_id=api.db[6][0],reason='Investigate account access',current_password='correct-password'),request=api.request,actor=api.actor))
    assert result['organization']['id'] == str(api.db[6][0])
    assert result['support_session_id']
    assert 'correct-password' not in str(api.db[0].execute('SELECT * FROM platform_audit_events').fetchall())


def test_account_lookup_is_exact_and_support_organization_scoped(support_api):
    api = support_api
    owner = api.db[0]
    ids = []
    for index,org in enumerate(api.db[6]):
        uid = owner.execute('INSERT INTO users(email,name,password_hash) VALUES (%s,%s,%s) RETURNING id',(f'tenant{index}@example.test',f'Tenant {index}','hidden-hash')).fetchone()['id']
        owner.execute("INSERT INTO organization_memberships(user_id,organization_id,company_role,is_active) VALUES (%s,%s,'engineer',FALSE)",(uid,org))
        ids.append(uid)
    owner.commit()
    session = start(api.db)
    result = call_support(api,'{support_session_id}/accounts',support_session_id=session['id'],email='tenant0@example.test')
    assert [r['user_id'] for r in result['rows']] == [ids[0]]
    assert result['rows'][0]['membership_active'] is False
    assert set(result['rows'][0]) == {'user_id','name','email','archived_at','role','membership_active','failed_login_attempts','account_locked_until','last_login'}
    for email in ('tenant1@example.test','tenant0','absent@example.test'):
        assert call_support(api,'{support_session_id}/accounts',support_session_id=session['id'],email=email)['rows'] == []


def seed_support_operations(api):
    owner,_,actor,_,_,_,orgs = api.db
    for index,org in enumerate(orgs):
        store = owner.execute('SELECT id FROM stores WHERE organization_id=%s',(org,)).fetchone()['id']
        part = owner.execute("INSERT INTO parts(part_number,description,category,unit_cost,organization_id) VALUES ('PART-1','Allowed description','category',999,%s) RETURNING id",(org,)).fetchone()['id']
        work = owner.execute("INSERT INTO work_orders(work_order_number,customer_name,description,organization_id) VALUES ('WO-1','SECRET CUSTOMER','SECRET DESCRIPTION',%s) RETURNING id",(org,)).fetchone()['id']
        equipment = owner.execute("INSERT INTO equipment(equipment_name,make,model,serial_number,notes,organization_id) VALUES ('Meter','Make','Model','SERIAL-1','SECRET NOTES',%s) RETURNING id",(org,)).fetchone()['id']
        if index:
            owner.execute("UPDATE parts SET description='OTHER TENANT' WHERE id=%s",(part,))
            owner.execute("UPDATE work_orders SET status='OTHER TENANT' WHERE id=%s",(work,))
            owner.execute("UPDATE equipment SET equipment_name='OTHER TENANT' WHERE id=%s",(equipment,))
        # Cross-tenant staff references must never produce an unrelated identity.
        owner.execute('UPDATE equipment SET assigned_user_id=%s WHERE id=%s',(actor,equipment))
        for row_number in range(30):
            allocated_work = owner.execute(
                "INSERT INTO work_orders(work_order_number,organization_id) VALUES (%s,%s) RETURNING id",
                (f'SUPPORT-{index}-{row_number}', org),
            ).fetchone()['id']
            owner.execute('INSERT INTO inventory(store_id,part_id,quantity,work_order_id,organization_id) VALUES (%s,%s,3,%s,%s)',(store,part,allocated_work,org))
            owner.execute("INSERT INTO equipment_history(equipment_id,action,created_by,notes,organization_id) VALUES (%s,'calibrated',%s,'SECRET NOTES',%s)",(equipment,actor,org))
            if index:
                owner.execute("UPDATE equipment_history SET action='OTHER TENANT' WHERE equipment_id=%s",(equipment,))
            movement = owner.execute("INSERT INTO movements(part_id,quantity,movement_type,work_order_id,created_by,notes,organization_id) VALUES (%s,2,'transfer',%s,%s,'SECRET NOTES',%s) RETURNING id",(part,work,actor,org)).fetchone()['id']
            owner.execute('INSERT INTO stock_transfers(movement_id,organization_id,completion_note) VALUES (%s,%s,%s)',(movement,org,'SECRET NOTES'))
            if index:
                owner.execute('UPDATE movements SET quantity=999 WHERE id=%s',(movement,))
    owner.commit()


def test_operational_lookup_results_are_bounded_and_allowlisted(support_api):
    api = support_api
    seed_support_operations(api)
    session = start(api.db)
    for resource,query in [('inventory','PART-1'),('work-orders','WO-1'),('equipment','SERIAL-1'),('equipment-history','SERIAL-1'),('movements','PART-1')]:
        result = call_support(api,'{support_session_id}/'+resource,support_session_id=session['id'],query=query)
        assert 1 <= len(result['rows']) <= 25
        assert 'SECRET' not in str(result)
        assert 'OTHER TENANT' not in str(result)
        if resource == 'movements':
            assert {row['quantity'] for row in result['rows']} == {2}
        assert 'Support' not in str(result)  # actor has no tenant membership
        assert all('organization_id' not in row and 'unit_cost' not in row for row in result['rows'])
        assert call_support(api,'{support_session_id}/'+resource,support_session_id=session['id'],query='unmatched')['rows'] == []
        with pytest.raises(HTTPException):
            call_support(api,'{support_session_id}/'+resource,support_session_id=session['id'],query='')


def test_support_read_audit_contains_no_query_or_row_values(support_api):
    api = support_api
    session = start(api.db)
    call_support(api,'{support_session_id}/accounts',support_session_id=session['id'],email='sensitive@example.test')
    event = api.db[0].execute("SELECT * FROM platform_audit_events WHERE action='support_data_read'").fetchone()
    assert event['organization_id'] == api.db[6][0]
    assert set(event['details']) == {'support_session_id','resource','operation','request_id'}
    assert event['details']['resource'] == 'accounts'
    assert event['details']['operation'] == 'lookup'
    from uuid import UUID
    UUID(event['details']['request_id'])
    assert 'sensitive' not in str(event)


def test_support_read_rolls_back_when_audit_insert_fails(support_api):
    api = support_api
    session = start(api.db)
    owner = api.db[0]
    owner.execute("""CREATE FUNCTION reject_support_read() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='support_data_read' THEN RAISE EXCEPTION 'audit unavailable'; END IF; RETURN NEW; END $$""")
    owner.execute('CREATE TRIGGER reject_support_read BEFORE INSERT ON platform_audit_events FOR EACH ROW EXECUTE FUNCTION reject_support_read()')
    owner.commit()
    with pytest.raises(psycopg.Error,match='audit unavailable'):
        call_support(api,'{support_session_id}/accounts',support_session_id=session['id'],email='support@example.test')
    assert owner.execute("SELECT count(*) AS n FROM platform_audit_events WHERE action='support_data_read'").fetchone()['n'] == 0


def test_current_and_end_support_session_are_bound_to_login(support_api):
    import asyncio
    api = support_api
    assert call_support(api,'current') is None
    session = start(api.db)
    assert call_support(api,'current')['support_session_id'] == str(session['id'])
    endpoint = next(r.endpoint for r in api.router.routes if 'DELETE' in r.methods)
    with pytest.raises(HTTPException):
        asyncio.run(endpoint(support_session_id=uuid4(),request=api.request,actor=api.actor))
    assert asyncio.run(endpoint(support_session_id=session['id'],request=api.request,actor=api.actor)) == {'success':True}
    assert call_support(api,'current') is None
    with pytest.raises(HTTPException):
        call_support(api,'{support_session_id}/accounts',support_session_id=session['id'],email='support@example.test')
    assert api.db[0].execute("SELECT count(*) AS n FROM platform_audit_events WHERE action='support_access_denied'").fetchone()['n'] == 1


@pytest.mark.parametrize('state',['missing','expired','different-login','other-actor','anonymous'])
def test_support_data_routes_deny_invalid_bindings_without_payload(support_api,state):
    api = support_api
    session = start(api.db)
    owner = api.db[0]
    sid = session['id']
    if state == 'missing':
        sid = uuid4()
    elif state == 'expired':
        owner.execute("UPDATE platform_support_sessions SET created_at=(now()-interval '1 hour')::text,expires_at=(now()-interval '45 minutes')::text WHERE id=%s",(sid,))
    elif state in ('different-login','other-actor'):
        token = uuid4().hex
        actor = api.db[2] if state == 'different-login' else api.db[3]
        owner.execute('INSERT INTO platform_admins(user_id) VALUES (%s) ON CONFLICT DO NOTHING',(actor,))
        owner.execute('INSERT INTO sessions(user_id,session_token_hash,expires_at) VALUES (%s,%s,%s)',(actor,hash_session_credential(token),serialize_instant(utc_now()+timedelta(hours=1))))
        api.request.cookies['session_token'] = token
        api.actor = actor
    else:
        api.request.cookies.clear()
    owner.commit()
    with pytest.raises(HTTPException) as error:
        call_support(api,'{support_session_id}/accounts',support_session_id=sid,email='support@example.test')
    assert error.value.status_code in {401,403,404}
    events = owner.execute("SELECT * FROM platform_audit_events WHERE action='support_access_denied'").fetchall()
    assert len(events) == (1 if state in ('expired','different-login') else 0)
    assert 'support@example.test' not in str(events)


def test_end_support_session_cannot_use_another_login(support_api):
    import asyncio
    api = support_api
    session = start(api.db)
    token = uuid4().hex
    owner = api.db[0]
    owner.execute('INSERT INTO sessions(user_id,session_token_hash,expires_at) VALUES (%s,%s,%s)',(api.actor,hash_session_credential(token),serialize_instant(utc_now()+timedelta(hours=1))))
    owner.commit()
    api.request.cookies['session_token'] = token
    assert call_support(api,'current') is None
    endpoint = next(r.endpoint for r in api.router.routes if 'DELETE' in r.methods)
    with pytest.raises(HTTPException) as error:
        asyncio.run(endpoint(support_session_id=session['id'],request=api.request,actor=api.actor))
    assert error.value.status_code == 404
    assert owner.execute('SELECT ended_at FROM platform_support_sessions WHERE id=%s',(session['id'],)).fetchone()['ended_at'] is None


def test_suspended_organization_support_stays_read_only_and_scoped(support_api):
    from backend.services.platform_support import authenticated_support_transaction
    api = support_api
    seed_support_operations(api)
    owner, org_id = api.db[0], api.db[6][0]
    owner.execute('UPDATE organizations SET is_active=FALSE WHERE id=%s',(org_id,))
    owner.commit()
    session = start(api.db)
    result = call_support(api,'{support_session_id}/inventory',support_session_id=session['id'],query='PART-1')
    assert result['rows']
    assert 'OTHER TENANT' not in str(result)
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with authenticated_support_transaction(api.db[1],session_token=api.db[5],support_session_id=session['id']) as (conn,_,__):
            conn.execute('UPDATE stores SET name=\'not allowed\'')


def test_platform_only_support_identity_still_cannot_enter_normal_tenant_context(support_api):
    from backend.services.tenant_context import authenticated_tenant_transaction
    api = support_api
    with pytest.raises(HTTPException) as error:
        with authenticated_tenant_transaction(api.db[1],session_token=api.db[5]):
            pytest.fail('support access must not grant ordinary tenant context')
    assert error.value.status_code == 403


def test_lookup_value_and_extra_tenant_identifier_cannot_widen_support_scope(support_api):
    api = support_api
    seed_support_operations(api)
    session = start(api.db)
    # All tenant A and B records share identifiers; only the server-bound A rows may return.
    result = call_support(api,'{support_session_id}/inventory',support_session_id=session['id'],query='PART-1')
    assert result['rows']
    assert all(row['description'] == 'Allowed description' for row in result['rows'])
    # The fixed handler signature has no organization argument, so a client ID cannot become query authority.
    endpoint = api.routes['/api/platform/support-sessions/{support_session_id}/inventory']
    with pytest.raises(TypeError):
        import asyncio
        asyncio.run(endpoint(support_session_id=session['id'],query='PART-1',organization_id=api.db[6][1],
                             request=api.request,actor=api.actor))
