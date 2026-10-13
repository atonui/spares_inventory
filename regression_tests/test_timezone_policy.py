import sqlite3
from dataclasses import FrozenInstanceError

import pytest
from fastapi import HTTPException

from backend.migrations.runner import apply_migrations
from backend.migrations.validation import MigrationError
from backend.services.timezone_policy import resolve_business_context, resolve_display_zone


@pytest.fixture
def conn(tmp_path):
    with sqlite3.connect(tmp_path / 'policy.db') as c:
        c.row_factory = sqlite3.Row
        apply_migrations(c)
        c.execute("INSERT INTO users(id,email,name,password_hash) VALUES(1,'test@example.com','Test','hash')")
        c.commit()
        yield c


def test_bootstrap_context_and_preference_precedence(conn):
    context = resolve_business_context(conn, actor_id=1)
    assert (context.organisation_id, context.timezone, context.revision) == (1, 'Africa/Nairobi', 1)
    assert resolve_display_zone(None, context) == 'Africa/Nairobi'
    assert resolve_display_zone('Europe/London', context) == 'Europe/London'
    with pytest.raises(ValueError): resolve_display_zone('IST', context)
    with pytest.raises(FrozenInstanceError): context.timezone = 'UTC'


def test_existing_zone_preserved_and_resolved_context_is_snapshot(conn):
    context = resolve_business_context(conn, actor_id=1)
    conn.execute("UPDATE organisation_settings SET business_timezone='America/New_York',revision=2")
    conn.commit()
    apply_migrations(conn)
    assert context.timezone == 'Africa/Nairobi'
    assert resolve_business_context(conn, actor_id=1).timezone == 'America/New_York'


def test_invalid_saved_zone_fails_instead_of_defaulting(conn):
    conn.execute("UPDATE organisation_settings SET business_timezone='IST'")
    conn.commit()
    with pytest.raises(MigrationError): apply_migrations(conn)
    with pytest.raises(ValueError): resolve_business_context(conn, actor_id=1)


def test_inactive_or_missing_actor_cannot_resolve_context(conn):
    with pytest.raises(HTTPException): resolve_business_context(conn, actor_id=9)
    conn.execute("UPDATE users SET archived_at=CURRENT_TIMESTAMP WHERE id=1")
    with pytest.raises(HTTPException): resolve_business_context(conn, actor_id=1)


def test_optional_preferences_and_existing_expiry_are_preserved(conn):
    conn.execute("UPDATE users SET display_timezone='Asia/Kathmandu',session_expires='2099-01-01T00:00:00.000000Z' WHERE id=1")
    conn.commit()
    apply_migrations(conn)
    assert tuple(conn.execute('SELECT display_timezone,session_expires FROM users WHERE id=1').fetchone()) == ('Asia/Kathmandu', '2099-01-01T00:00:00.000000Z')


def test_versioned_v3_upgrade_preserves_existing_expiry(tmp_path, monkeypatch):
    from backend.migrations import registry
    path=tmp_path/'version3.db'
    with sqlite3.connect(path) as c:
        with monkeypatch.context() as patch:
            patch.setattr(registry,'MIGRATIONS',registry.MIGRATIONS[:3])
            apply_migrations(c)
        c.execute("INSERT INTO users(id,email,name,password_hash,session_expires) VALUES(1,'test@example.com','Test','hash','2099-01-01T00:00:00.000000Z')")
        c.commit()
        assert apply_migrations(c).applied==(1,2,3,4,5)
        assert c.execute('SELECT session_expires,display_timezone FROM users').fetchone()==('2099-01-01T00:00:00.000000Z',None)
        assert c.execute('SELECT business_timezone FROM organisation_settings').fetchone()[0]=='Africa/Nairobi'


def test_recorded_v4_missing_singleton_fails_without_reseeding(conn):
    conn.execute('DELETE FROM organisation_settings')
    conn.commit()
    with pytest.raises(MigrationError): apply_migrations(conn)
    assert conn.execute('SELECT COUNT(*) FROM organisation_settings').fetchone()[0]==0
