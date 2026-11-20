"""Business timezone resolution on PostgreSQL: per company, from the RLS context or principal."""
from dataclasses import FrozenInstanceError

import pytest
from fastapi import HTTPException

from backend.services.principals import AuthenticatedPrincipal
from backend.services.timezone_policy import resolve_business_context, resolve_display_zone
from regression_tests.postgres_app import ORG_A, ORG_B


@pytest.fixture
def conn(stock_database):
    c = stock_database.connect()
    c.execute("SELECT set_config('app.organization_id', %s, false)", (str(ORG_A),))
    c.commit()
    try:
        yield c
    finally:
        c.close()


def set_zone(stock_database, organization_id, zone, revision):
    stock_database.db.execute(
        'UPDATE organization_settings SET business_timezone=%s, revision=%s WHERE organization_id=%s',
        (zone, revision, organization_id))
    stock_database.db.commit()


def test_default_context_and_preference_precedence(conn):
    context = resolve_business_context(conn, actor_id=1)
    assert (context.organisation_id, context.timezone, context.revision) == (ORG_A, 'Africa/Nairobi', 1)
    assert resolve_display_zone(None, context) == 'Africa/Nairobi'
    assert resolve_display_zone('Europe/London', context) == 'Europe/London'
    with pytest.raises(ValueError):
        resolve_display_zone('IST', context)
    with pytest.raises(FrozenInstanceError):
        context.timezone = 'UTC'


def test_each_company_resolves_its_own_zone(conn, stock_database):
    set_zone(stock_database, ORG_B, 'Asia/Kathmandu', 4)
    assert resolve_business_context(conn, actor_id=1).timezone == 'Africa/Nairobi'
    other_owner = AuthenticatedPrincipal(5, ORG_B, 'owner', False)
    # Row-level security: company A's context cannot read company B's settings.
    with pytest.raises(ValueError):
        resolve_business_context(conn, actor_id=other_owner)
    conn.rollback()
    conn.execute("SELECT set_config('app.organization_id', %s, false)", (str(ORG_B),))
    context = resolve_business_context(conn, actor_id=other_owner)
    assert (context.organisation_id, context.timezone, context.revision) == (ORG_B, 'Asia/Kathmandu', 4)


def test_resolved_context_is_a_snapshot(conn, stock_database):
    context = resolve_business_context(conn, actor_id=1)
    set_zone(stock_database, ORG_A, 'America/New_York', 2)
    assert context.timezone == 'Africa/Nairobi'
    conn.commit()
    assert resolve_business_context(conn, actor_id=1).timezone == 'America/New_York'


def test_invalid_saved_zone_fails_instead_of_defaulting(conn, stock_database):
    set_zone(stock_database, ORG_A, 'IST', 1)
    with pytest.raises(ValueError):
        resolve_business_context(conn, actor_id=1)


def test_missing_actor_or_company_context_cannot_resolve(conn, stock_database):
    with pytest.raises(HTTPException) as missing:
        resolve_business_context(conn, actor_id=999)
    assert missing.value.status_code == 403
    conn.execute("SELECT set_config('app.organization_id', '', false)")
    with pytest.raises(HTTPException) as no_company:
        resolve_business_context(conn, actor_id=1)
    assert no_company.value.detail == 'Active company context required'
