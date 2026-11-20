"""Support-session account actions: unlock, sign out and password-reset email.

Runs as a non-owner, non-BYPASSRLS runtime role, like the other support tests.
"""
import asyncio
from datetime import timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException
from psycopg import sql

from backend.services.session_credentials import hash_session_credential
from backend.temporal import serialize_instant, utc_now
from regression_tests.test_platform_support import start, support_database  # noqa: F401  (fixture)

pytest_plugins = ("regression_tests.postgres_fixtures",)


@pytest.fixture
def actions(support_database):  # noqa: F811
    from backend.routes.platform_support import create_platform_support_router
    db = support_database
    owner, connect, actor, _other, _auth, token, orgs = db
    with connect() as conn:
        role = conn.execute('SELECT current_user AS role').fetchone()['role']
    owner.execute(sql.SQL('GRANT SELECT, UPDATE ON users, mobile_device_sessions TO {}').format(sql.Identifier(role)))
    owner.commit()

    members = {}
    for name, org in (('a', orgs[0]), ('b', orgs[1])):
        uid = owner.execute(
            """INSERT INTO users(email,name,password_hash,failed_login_attempts,account_locked_until)
               VALUES (%s,%s,'x',5,%s) RETURNING id""",
            (f'member-{name}@example.test', f'Member {name}', serialize_instant(utc_now() + timedelta(minutes=15))),
        ).fetchone()['id']
        owner.execute("INSERT INTO organization_memberships(user_id,organization_id,company_role) VALUES (%s,%s,'engineer')",
                      (uid, org))
        members[name] = uid
    owner.commit()

    queued, events = [], []

    def queue_reset_email(conn, email, reset_token, expires_at):
        queued.append({'email': email, 'token': reset_token, 'expires_at': expires_at})

    class Limiter:
        def limit(self, rule):
            return lambda endpoint: endpoint

    router = create_platform_support_router(
        get_connection=connect, current_user=lambda: None, csrf_dependency=lambda: True,
        password_verify=lambda plain, hashed: False, limiter=Limiter(),
        queue_reset_email=queue_reset_email, security_event=lambda **event: events.append(event),
    )
    endpoints = {(method, route.path): route.endpoint for route in router.routes for method in route.methods}
    session = start(db)
    request = SimpleNamespace(cookies={'session_token': token}, headers={})

    def call(method, path, **kwargs):
        endpoint = endpoints[(method, '/api/platform/support-sessions/{support_session_id}' + path)]
        return asyncio.run(endpoint(support_session_id=session['id'], request=request, actor=actor, **kwargs))

    return SimpleNamespace(db=db, owner=owner, members=members, orgs=orgs, call=call,
                           queued=queued, events=events, session=session, actor=actor)


def audit_rows(owner, action):
    return owner.execute(
        'SELECT actor_user_id, organization_id, result, details FROM platform_audit_events WHERE action=%s ORDER BY id',
        (action,),
    ).fetchall()


def user_row(owner, user_id):
    return owner.execute(
        'SELECT failed_login_attempts, account_locked_until, reset_token, reset_token_expires FROM users WHERE id=%s',
        (user_id,),
    ).fetchone()


def add_session(owner, user_id, *, is_mobile=False, active=True):
    return owner.execute(
        """INSERT INTO sessions(user_id,session_token_hash,expires_at,is_active,is_mobile)
           VALUES (%s,%s,%s,%s,%s) RETURNING id""",
        (user_id, hash_session_credential(uuid4().hex), serialize_instant(utc_now() + timedelta(hours=1)), active, is_mobile),
    ).fetchone()['id']


def test_unlock_clears_lockout_and_audits_with_support_context(actions):
    member = actions.members['a']
    result = actions.call('POST', '/accounts/{user_id}/unlock', user_id=member, csrf_valid=True)

    assert result == {'success': True, 'user_id': member, 'was_locked': True}
    row = user_row(actions.owner, member)
    assert row['failed_login_attempts'] == 0 and row['account_locked_until'] is None
    [audit] = audit_rows(actions.owner, 'support_account_action')
    assert audit['actor_user_id'] == actions.actor
    assert audit['organization_id'] == actions.orgs[0]
    assert audit['details']['operation'] == 'unlock'
    assert audit['details']['target_user_id'] == member
    assert audit['details']['support_session_id'] == str(actions.session['id'])


def test_account_actions_cannot_reach_another_organization(actions):
    other_tenant_member = actions.members['b']
    for path in ('/accounts/{user_id}/unlock', '/accounts/{user_id}/sign-out', '/accounts/{user_id}/password-reset'):
        with pytest.raises(HTTPException) as error:
            actions.call('POST', path, user_id=other_tenant_member, csrf_valid=True)
        assert error.value.status_code == 409

    row = user_row(actions.owner, other_tenant_member)
    assert row['failed_login_attempts'] == 5 and row['account_locked_until'] is not None
    assert row['reset_token'] is None
    assert actions.queued == []
    assert audit_rows(actions.owner, 'support_account_action') == []
    denials = audit_rows(actions.owner, 'support_access_denied')
    assert [d['details']['operation'] for d in denials] == ['unlock', 'sign_out', 'password_reset']
    assert {d['organization_id'] for d in denials} == {actions.orgs[0]}


def test_locked_accounts_lists_only_this_organization_and_is_audited(actions):
    unlocked = actions.owner.execute(
        "INSERT INTO users(email,name,password_hash) VALUES ('fine@example.test','Fine','x') RETURNING id"
    ).fetchone()['id']
    actions.owner.execute("INSERT INTO organization_memberships(user_id,organization_id,company_role) VALUES (%s,%s,'engineer')",
                          (unlocked, actions.orgs[0]))
    actions.owner.commit()

    result = actions.call('GET', '/locked-accounts')

    assert [row['user_id'] for row in result['rows']] == [actions.members['a']]
    assert 'password_hash' not in result['rows'][0] and 'reset_token' not in result['rows'][0]
    [audit] = audit_rows(actions.owner, 'support_data_read')
    assert audit['details']['resource'] == 'locked-accounts'


def test_bulk_unlock_is_all_or_nothing_across_organizations(actions):
    from backend.routes.platform_support import SupportAccountUnlock
    with pytest.raises(HTTPException) as error:
        actions.call('POST', '/locked-accounts/unlock', csrf_valid=True,
                     body=SupportAccountUnlock(user_ids=[actions.members['a'], actions.members['b']]))
    assert error.value.status_code == 409
    assert user_row(actions.owner, actions.members['a'])['account_locked_until'] is not None

    result = actions.call('POST', '/locked-accounts/unlock', csrf_valid=True,
                          body=SupportAccountUnlock(user_ids=[actions.members['a']]))
    assert result == {'success': True, 'unlocked_count': 1}


def test_sign_out_revokes_only_the_target_members_sessions(actions):
    member = actions.members['a']
    browser = add_session(actions.owner, member)
    phone = add_session(actions.owner, member, is_mobile=True)
    add_session(actions.owner, member, active=False)
    bystander = add_session(actions.owner, actions.members['b'])
    actions.owner.commit()

    result = actions.call('POST', '/accounts/{user_id}/sign-out', user_id=member, csrf_valid=True)

    assert result == {'success': True, 'user_id': member, 'sessions_revoked': 2}
    active = {row['id'] for row in actions.owner.execute('SELECT id FROM sessions WHERE is_active=TRUE').fetchall()}
    assert browser not in active and phone not in active and bystander in active
    [audit] = audit_rows(actions.owner, 'support_account_action')
    assert audit['details']['operation'] == 'sign_out' and audit['details']['session_count'] == 2
    assert actions.events == [{
        'event': 'session_revoked', 'outcome': 'success', 'actor_user_id': actions.actor,
        'details': {'reason': 'platform_support_revoked', 'session_count': 2, 'target_user_id': member},
    }]


def test_password_reset_queues_mail_without_returning_the_token(actions):
    member = actions.members['a']
    result = actions.call('POST', '/accounts/{user_id}/password-reset', user_id=member, csrf_valid=True)

    assert result == {'success': True, 'user_id': member}
    [mail] = actions.queued
    assert mail['email'] == 'member-a@example.test'
    row = user_row(actions.owner, member)
    assert row['reset_token'] == mail['token'] and row['reset_token_expires']
    audits = actions.owner.execute('SELECT details::text AS details FROM platform_audit_events').fetchall()
    assert all(mail['token'] not in audit['details'] for audit in audits)
    [audit] = audit_rows(actions.owner, 'support_account_action')
    assert audit['details']['operation'] == 'password_reset'


def test_password_reset_rolls_back_when_mail_cannot_be_queued(actions):
    member = actions.members['a']
    owner, connect, actor, *_ = actions.db

    def broken_queue(*_args):
        raise ValueError('MAIL_PAYLOAD_ENCRYPTION_KEY is required')

    from backend.routes.platform_support import create_platform_support_router

    class Limiter:
        def limit(self, rule):
            return lambda endpoint: endpoint

    router = create_platform_support_router(get_connection=connect, current_user=lambda: None,
                                            csrf_dependency=lambda: True, password_verify=lambda *_: False,
                                            limiter=Limiter(), queue_reset_email=broken_queue)
    endpoint = next(r.endpoint for r in router.routes if r.path.endswith('/password-reset'))
    with pytest.raises(HTTPException) as error:
        asyncio.run(endpoint(support_session_id=actions.session['id'], user_id=member,
                             request=SimpleNamespace(cookies={'session_token': actions.db[5]}, headers={}),
                             actor=actor, csrf_valid=True))
    assert error.value.status_code == 503
    assert user_row(owner, member)['reset_token'] is None
    assert audit_rows(owner, 'support_account_action') == []


def test_suspended_organization_allows_sign_out_but_not_access_granting_actions(actions):
    member = actions.members['a']
    add_session(actions.owner, member)
    actions.owner.execute('UPDATE organizations SET is_active=FALSE WHERE id=%s', (actions.orgs[0],))
    actions.owner.commit()

    for path in ('/accounts/{user_id}/unlock', '/accounts/{user_id}/password-reset'):
        with pytest.raises(HTTPException) as error:
            actions.call('POST', path, user_id=member, csrf_valid=True)
        assert error.value.status_code == 409
    assert user_row(actions.owner, member)['account_locked_until'] is not None
    assert actions.queued == []

    result = actions.call('POST', '/accounts/{user_id}/sign-out', user_id=member, csrf_valid=True)
    assert result['sessions_revoked'] == 1


def test_password_reset_refuses_archived_accounts(actions):
    member = actions.members['a']
    actions.owner.execute('UPDATE users SET archived_at=%s WHERE id=%s', (serialize_instant(utc_now()), member))
    actions.owner.commit()
    with pytest.raises(HTTPException) as error:
        actions.call('POST', '/accounts/{user_id}/password-reset', user_id=member, csrf_valid=True)
    assert error.value.status_code == 409
    assert actions.queued == []


def test_account_lookup_reports_active_session_count(actions):
    member = actions.members['a']
    add_session(actions.owner, member)
    add_session(actions.owner, member, active=False)
    actions.owner.commit()
    result = actions.call('GET', '/accounts', email='MEMBER-A@example.test')
    assert [row['active_session_count'] for row in result['rows']] == [1]
