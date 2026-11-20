"""Cookie/session lifetime verification against disposable databases and real auth."""
from datetime import datetime,timedelta,timezone
from http.cookies import SimpleCookie
import pytest
from fastapi.testclient import TestClient
import main
from regression_tests.test_auth_router import auth_api

def csrf(client):
    """A CSRF token bound to the client's current session (or none), as the browser gets it."""
    return {'X-CSRF-Token':client.get('/api/csrf-token').json()['csrf_token']}


def login(client,remember):
    return client.post('/api/auth/login',json={'email':'admin@example.test','password':'test-password','remember_me':remember},
                       headers=csrf(client))


@pytest.mark.parametrize('remember,seconds',[(False,3*3600),(True,7*86400)])
def test_configured_cookie_lifetime_and_session_expiry(auth_api,monkeypatch,remember,seconds):
    _,db,_=auth_api
    now=datetime.now(timezone.utc)
    import backend.routes.auth as auth
    import backend.services.principals as access  # session expiry is checked here on Postgres
    monkeypatch.setattr(auth,'utc_now',lambda:now)
    monkeypatch.setattr(access,'utc_now',lambda:now)
    for key,value in (('session_duration_hours','3'),('remember_me_duration_days','7')):
        db.execute("""INSERT INTO system_settings(setting_key,setting_value) VALUES(?,?)
                      ON CONFLICT (setting_key) DO UPDATE SET setting_value=EXCLUDED.setting_value""",(key,value))
    with TestClient(main.app,base_url='https://www.sparestracker.com') as client:
        r=login(client,remember)
        assert r.status_code==200
        cookie=SimpleCookie(r.headers['set-cookie'])['session_token']
        assert int(cookie['max-age'])==seconds and cookie['httponly'] and cookie['secure']
        assert cookie['path']=='/' and cookie['samesite']=='lax'
        with db as conn:
            from backend.services.session_credentials import hash_session_credential
            expires=datetime.fromisoformat(conn.execute('SELECT expires_at FROM sessions WHERE session_token_hash=?',(hash_session_credential(cookie.value),)).fetchone()[0])
        assert expires==now+timedelta(seconds=seconds)
        # A new client represents reopening with the persisted cookie, no user cache.
        with TestClient(main.app,base_url='https://www.sparestracker.com',cookies=client.cookies) as reopened:
            monkeypatch.setattr(access,'utc_now',lambda:expires-timedelta(microseconds=1))
            assert reopened.get('/api/me').status_code==200
            monkeypatch.setattr(access,'utc_now',lambda:expires)
            assert reopened.get('/api/me').status_code==401

@pytest.mark.parametrize('action',['logout','revoke','deactivated','password_change'])
def test_remembered_cookie_cannot_bypass_session_invalidation(auth_api,action):
    _,db,current=auth_api;current['anonymous']=True
    with TestClient(main.app,base_url='https://www.sparestracker.com') as client:
        assert login(client,True).status_code==200
        token=client.cookies.get('session_token')
        if action=='logout':
            r=client.post('/api/auth/logout',headers=csrf(client));assert r.status_code==200
            assert SimpleCookie(r.headers['set-cookie'])['session_token']['max-age']=='0'
        elif action=='password_change':
            assert client.post('/api/profile/change-password',json={'current_password':'test-password','new_password':'new-test-password'},headers=csrf(client)).status_code==200
        else:
            with db as conn:
                if action=='revoke':
                    from backend.services.session_credentials import hash_session_credential
                    conn.execute('UPDATE sessions SET is_active=FALSE WHERE session_token_hash=?',(hash_session_credential(token),))
                else:conn.execute("UPDATE organization_memberships SET is_active=FALSE WHERE user_id=1")
        client.cookies.set('session_token',token,domain='inventory.test',path='/')
        # A deactivated member keeps a valid session but has no company access (403).
        assert client.get('/api/me').status_code==(403 if action=='deactivated' else 401)
