"""Cookie/session lifetime verification against disposable databases and real auth."""
from datetime import datetime,timedelta,timezone
from http.cookies import SimpleCookie
import sqlite3
import pytest
from fastapi.testclient import TestClient
import main
from regression_tests.test_auth_router import auth_api
from regression_tests.test_stock_safety import api

@pytest.mark.parametrize('remember,seconds',[(False,3*3600),(True,7*86400)])
def test_configured_cookie_lifetime_and_session_expiry(auth_api,monkeypatch,remember,seconds):
    _,db,_=auth_api
    main.app.dependency_overrides.pop(main.get_current_user)
    now=datetime.now(timezone.utc)
    import backend.routes.auth as auth
    import backend.services.session_access as access
    monkeypatch.setattr(auth,'utc_now',lambda:now)
    monkeypatch.setattr(access,'utc_now',lambda:now)
    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE system_settings SET setting_value='3' WHERE setting_key='session_duration_hours'")
        conn.execute("UPDATE system_settings SET setting_value='7' WHERE setting_key='remember_me_duration_days'")
    with TestClient(main.app,base_url='https://inventory.test') as client:
        r=client.post('/api/auth/login',json={'email':'user1@example.com','password':'test-password','remember_me':remember})
        assert r.status_code==200
        cookie=SimpleCookie(r.headers['set-cookie'])['session_token']
        assert int(cookie['max-age'])==seconds and cookie['httponly'] and cookie['secure']
        assert cookie['path']=='/' and cookie['samesite']=='lax'
        with sqlite3.connect(db) as conn:
            expires=datetime.fromisoformat(conn.execute('SELECT expires_at FROM sessions WHERE session_token=?',(cookie.value,)).fetchone()[0])
        assert expires==now+timedelta(seconds=seconds)
        # A new client represents reopening with the persisted cookie, no user cache.
        with TestClient(main.app,base_url='https://inventory.test',cookies=client.cookies) as reopened:
            monkeypatch.setattr(access,'utc_now',lambda:expires-timedelta(microseconds=1))
            assert reopened.get('/api/me').status_code==200
            monkeypatch.setattr(access,'utc_now',lambda:expires)
            assert reopened.get('/api/me').status_code==401

@pytest.mark.parametrize('action',['logout','revoke','archive','password_change'])
def test_remembered_cookie_cannot_bypass_session_invalidation(auth_api,action):
    _,db,_=auth_api;main.app.dependency_overrides.pop(main.get_current_user)
    with TestClient(main.app,base_url='https://inventory.test') as client:
        assert client.post('/api/auth/login',json={'email':'user1@example.com','password':'test-password','remember_me':True}).status_code==200
        token=client.cookies.get('session_token')
        if action=='logout':
            r=client.post('/api/auth/logout');assert r.status_code==200
            assert SimpleCookie(r.headers['set-cookie'])['session_token']['max-age']=='0'
        elif action=='password_change':
            assert client.post('/api/profile/change-password',json={'current_password':'test-password','new_password':'new-test-password'}).status_code==200
        else:
            with sqlite3.connect(db) as conn:
                if action=='revoke':conn.execute('UPDATE sessions SET is_active=0 WHERE session_token=?',(token,))
                else:conn.execute("UPDATE users SET archived_at='2026-10-14T00:00:00.000000Z' WHERE id=1")
        client.cookies.set('session_token',token,domain='inventory.test',path='/')
        assert client.get('/api/me').status_code==401
