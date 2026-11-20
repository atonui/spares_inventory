"""Who sees a platform announcement, end to end over HTTP on PostgreSQL.

The platform admin publishes through /api/platform/announcement with a real
session and CSRF token; each viewer reads the public banner endpoint.
"""
import pytest

from regression_tests.postgres_app import database_state

PUBLIC = '/api/superadmin/announcement'


def publish(api, **fields):
    client = api.as_actor('platform')
    current = client.get('/api/platform/announcement/manage').json()['announcement']
    body = {'message': 'Restricted notice', 'level': 'info', 'timezone_revision': 0,
            'expected_revision': current['revision'] if current else None, **fields}
    response = client.post('/api/platform/announcement', json=body)
    assert response.status_code == 200, response.text
    return response


def read_as(api, viewer):
    client = api.client
    client.cookies.clear()
    client.headers.pop('X-CSRF-Token', None)
    if viewer == 'unknown':
        client.cookies.set('session_token', 'not-a-session')
    elif viewer is not None:
        api.as_actor(viewer)
    response = client.get(PUBLIC)
    assert response.status_code == 200, response.text
    assert response.headers['cache-control'] == 'no-store'
    return response


@pytest.mark.parametrize('audience,roles', [('everyone', []), ('authenticated', []), ('roles', ['manager']),
                                           ('roles', ['admin', 'engineer'])])
@pytest.mark.parametrize('viewer,role', [(None, None), ('unknown', None), ('owner', 'owner'), ('admin', 'admin'),
                                         ('manager', 'manager'), ('engineer', 'engineer'), ('other', 'owner')])
def test_audience_matrix(tenant_api, audience, roles, viewer, role):
    publish(tenant_api, audience=audience, roles=roles)
    response = read_as(tenant_api, viewer)
    expected = (audience == 'everyone' or (audience == 'authenticated' and role is not None)
                or (audience == 'roles' and role in roles))
    assert (response.json()['announcement'] is not None) == expected
    if not expected:
        assert 'Restricted notice' not in response.text
    # PostgreSQL uses browser-side dismissal; no per-account state is kept.
    assert response.json()['dismissal_mode'] == 'browser'


@pytest.mark.xfail(strict=True, reason=(
    'Gap: company owners cannot be targeted. Announcement roles are engineer, manager, admin '
    'and the legacy superadmin; "owner" is rejected, so owners never see role-targeted notices.'))
def test_owners_can_be_targeted(tenant_api):
    publish(tenant_api, audience='roles', roles=['owner'])
    assert read_as(tenant_api, 'owner').json()['announcement'] is not None


@pytest.mark.parametrize('fields', [{'audience': 'roles', 'roles': []}, {'audience': 'unknown'},
                                    {'audience': 'roles', 'roles': ['unknown']},
                                    {'starts_local': '2027-01-01T12:00', 'expires_local': '2027-01-01T11:00'},
                                    {'expires_local': '2020-01-01T12:00'}])
def test_invalid_controls_change_nothing(tenant_api, fields):
    client = tenant_api.as_actor('platform')
    before = database_state(tenant_api.db)
    response = client.post('/api/platform/announcement',
                           json={'message': 'x', 'level': 'info', 'timezone_revision': 0, **fields})
    assert response.status_code in (400, 422), response.text
    assert database_state(tenant_api.db) == before


@pytest.mark.parametrize('viewer', ['owner', 'admin', 'engineer'])
def test_company_members_cannot_manage_platform_announcements(tenant_api, viewer):
    client = tenant_api.as_actor(viewer)
    before = database_state(tenant_api.db)
    assert client.get('/api/platform/announcement/manage').status_code == 403
    assert client.post('/api/platform/announcement',
                       json={'message': 'x', 'level': 'info', 'timezone_revision': 0}).status_code == 403
    assert database_state(tenant_api.db) == before
