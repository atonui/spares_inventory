"""Platform database maintenance runs as a non-owner, non-BYPASSRLS runtime role."""
import asyncio
from datetime import timedelta
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from psycopg import sql

from backend.temporal import serialize_instant, utc_now
from regression_tests.test_platform_support import support_database  # noqa: F401  (fixture)
from stock_audit import STOCK_AUDIT_ACTIONS

pytest_plugins = ("regression_tests.postgres_fixtures",)


@pytest.fixture
def maintenance(support_database):  # noqa: F811
    from backend.routes.platform_database import create_platform_database_router
    owner, connect, actor, other, _auth, token, orgs = support_database
    with connect() as conn:
        role = conn.execute('SELECT current_user AS role').fetchone()['role']
    owner.execute(sql.SQL('GRANT SELECT, DELETE ON activity_logs, system_logs TO {}').format(sql.Identifier(role)))
    owner.commit()
    router = create_platform_database_router(get_connection=connect, current_user=lambda: actor,
                                             csrf_dependency=lambda: True)
    endpoints = {(method, route.path): route.endpoint for route in router.routes for method in route.methods}
    request = SimpleNamespace(cookies={'session_token': token}, headers={})
    return SimpleNamespace(owner=owner, connect=connect, actor=actor, other=other, token=token, orgs=orgs,
                           router=router, endpoints=endpoints, request=request)


def days_ago(days):
    return serialize_instant(utc_now() - timedelta(days=days))


def seed_logs(owner, orgs):
    protected = sorted(STOCK_AUDIT_ACTIONS)[0]
    for org in orgs:
        for action, age in (('login', 400), ('login', 5), (protected, 400)):
            owner.execute('INSERT INTO activity_logs(organization_id, action, created_at) VALUES (%s,%s,%s)',
                          (org, action, days_ago(age)))
    for age in (400, 5):
        owner.execute("INSERT INTO system_logs(level, message, created_at) VALUES ('info','event',%s)", (days_ago(age),))
    owner.commit()


def test_purge_deletes_old_unprotected_logs_in_every_organization(maintenance):
    seed_logs(maintenance.owner, maintenance.orgs)
    purge = maintenance.endpoints[('DELETE', '/api/platform/database/logs')]

    result = asyncio.run(purge(request=maintenance.request, older_than_days=365, actor=maintenance.actor, csrf_valid=True))

    assert result == {'success': True, 'older_than_days': 365, 'activity_logs_deleted': 2, 'system_logs_deleted': 1}
    remaining = maintenance.owner.execute(
        'SELECT organization_id, action FROM activity_logs ORDER BY organization_id, action'
    ).fetchall()
    protected = sorted(STOCK_AUDIT_ACTIONS)[0]
    assert sorted((row['organization_id'], row['action']) for row in remaining) == sorted(
        (org, action) for org in maintenance.orgs for action in ('login', protected)
    )
    assert maintenance.owner.execute('SELECT count(*) AS n FROM system_logs').fetchone()['n'] == 1
    [audit] = maintenance.owner.execute(
        "SELECT actor_user_id, details FROM platform_audit_events WHERE action='platform_logs_purged'"
    ).fetchall()
    assert audit['actor_user_id'] == maintenance.actor
    assert audit['details'] == {'older_than_days': 365, 'activity_logs_deleted': 2, 'system_logs_deleted': 1}


def test_purge_enforces_minimum_and_maximum_retention(maintenance):
    app = FastAPI()
    app.include_router(maintenance.router)
    client = TestClient(app)
    client.cookies.set('session_token', maintenance.token)
    for days in (0, 29, 3651):
        assert client.delete(f'/api/platform/database/logs?older_than_days={days}').status_code == 422
    assert client.delete('/api/platform/database/logs').status_code == 422


def test_table_statistics_return_metadata_only_and_are_audited(maintenance):
    seed_logs(maintenance.owner, maintenance.orgs)
    response = SimpleNamespace(headers={})
    tables = maintenance.endpoints[('GET', '/api/platform/database/tables')]

    result = asyncio.run(tables(request=maintenance.request, response=response, actor=maintenance.actor))

    assert result['database_bytes'] > 0
    names = {row['table_name'] for row in result['tables']}
    assert {'users', 'activity_logs', 'platform_audit_events'} <= names
    assert all(set(row) == {'table_name', 'estimated_rows', 'total_bytes'} for row in result['tables'])
    assert response.headers['Cache-Control'] == 'no-store'
    [audit] = maintenance.owner.execute(
        "SELECT details FROM platform_audit_events WHERE action='platform_database_stats_read'"
    ).fetchall()
    assert audit['details'] == {'result_count': len(result['tables'])}


def test_maintenance_requires_a_platform_administrator(maintenance):
    from backend.services.session_credentials import hash_session_credential
    from uuid import uuid4
    token = uuid4().hex
    maintenance.owner.execute(
        'INSERT INTO sessions(user_id,session_token_hash,expires_at) VALUES (%s,%s,%s)',
        (maintenance.other, hash_session_credential(token), serialize_instant(utc_now() + timedelta(hours=1))),
    )
    maintenance.owner.commit()
    seed_logs(maintenance.owner, maintenance.orgs)
    request = SimpleNamespace(cookies={'session_token': token}, headers={})
    purge = maintenance.endpoints[('DELETE', '/api/platform/database/logs')]
    tables = maintenance.endpoints[('GET', '/api/platform/database/tables')]

    with pytest.raises(HTTPException) as error:
        asyncio.run(purge(request=request, older_than_days=30, actor=maintenance.other, csrf_valid=True))
    assert error.value.status_code == 403
    with pytest.raises(HTTPException) as error:
        asyncio.run(tables(request=request, response=SimpleNamespace(headers={}), actor=maintenance.other))
    assert error.value.status_code == 403
    assert maintenance.owner.execute('SELECT count(*) AS n FROM activity_logs').fetchone()['n'] == 6
