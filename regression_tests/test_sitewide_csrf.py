"""Coverage for every unsafe application route and authentication boundaries."""
from fastapi.routing import APIRoute
import main
from regression_tests.test_auth_router import auth_api
from regression_tests.test_stock_safety import api

TOKEN_AUTHENTICATED_MUTATIONS = {
    ('/api/auth/native/refresh', frozenset({'POST'})),
    ('/api/v1/auth/native/refresh', frozenset({'POST'})),
    # One-time pairing credentials and native bearer sessions authorize these writes.
    ('/api/v1/auth/mobile-pairing/claim', frozenset({'POST'})),
    ('/api/v1/auth/mobile-pairing/complete', frozenset({'POST'})),
    ('/api/v1/inventory/adjustments', frozenset({'POST'})),
}

def dependencies(dependant):
    return {d.call for d in dependant.dependencies} | {call for d in dependant.dependencies for call in dependencies(d)}

def test_every_mutation_route_requires_csrf():
    missing=[(route.path, sorted(route.methods)) for route in main.app.routes
             if isinstance(route,APIRoute) and route.methods & {'POST','PUT','PATCH','DELETE'}
             and (route.path, frozenset(route.methods)) not in TOKEN_AUTHENTICATED_MUTATIONS
             and not ({main.verify_csrf, main.verify_authenticated_csrf} & dependencies(route.dependant))]
    assert missing == []

def test_login_and_logout_reject_missing_and_invalid_tokens(auth_api):
    client,db,actor=auth_api
    # The application marks cookies Secure; exercise browser cookie rotation over HTTPS.
    client.base_url = "https://testserver"
    main.app.dependency_overrides.pop(main.verify_csrf)
    main.app.dependency_overrides.pop(main.verify_authenticated_csrf)
    for path,body in [('/api/auth/login',{'email':'user1@example.com','password':'test-password'}),('/api/auth/logout',{})]:
        assert client.post(path,json=body).json()['detail']=='CSRF token missing'
        assert client.post(path,json=body,headers={'X-CSRF-Token':'bad'}).json()['detail']=='Invalid CSRF token'
    token=client.get('/api/csrf-token').json()['csrf_token']
    assert client.post('/api/auth/login',json={'email':'user1@example.com','password':'test-password'},headers={'X-CSRF-Token':token}).status_code==200
    assert client.post('/api/auth/logout',headers={'X-CSRF-Token':token}).status_code==403
    bound_token=client.get('/api/csrf-token').json()['csrf_token']
    assert client.post('/api/auth/logout',headers={'X-CSRF-Token':bound_token}).status_code==200

def test_csrf_token_response_cannot_be_cached(auth_api):
    client,_,_=auth_api
    assert client.get('/api/csrf-token').headers.get('cache-control')=='no-store'


def test_validated_bearer_may_omit_csrf_but_cookie_and_invalid_tokens_may_not(monkeypatch):
    from fastapi import APIRouter, Cookie, Depends, FastAPI, Request
    from fastapi.testclient import TestClient

    from backend.services.session_credentials import get_request_credential

    async def authenticated_user(request: Request, session_token: str = Cookie(None)):
        credential = get_request_credential(request)
        if credential.value != 'known-valid-session':
            from fastapi import HTTPException
            raise HTTPException(status_code=401, detail='Invalid or expired session')
        return 1

    app = FastAPI()
    app.dependency_overrides[main.get_current_user] = authenticated_user
    router = APIRouter()

    @router.post('/write')
    async def write(user_id=Depends(main.get_current_user), csrf=Depends(main.verify_authenticated_csrf)):
        return {'user_id': user_id}

    app.include_router(router)
    cookie_client = TestClient(app)
    cookie_client.cookies.set('session_token', 'known-valid-session')
    bearer_client = TestClient(app)
    mixed_client = TestClient(app)
    mixed_client.cookies.set('session_token', 'known-valid-session')

    assert cookie_client.post('/write').status_code == 403
    assert bearer_client.post('/write', headers={'Authorization': 'Bearer known-valid-session'}).status_code == 200
    assert bearer_client.post('/write', headers={'Authorization': 'Bearer invalid'}).status_code == 401
    assert mixed_client.post(
        '/write', headers={'Authorization': 'Bearer known-valid-session'},
    ).status_code == 401


def test_unsafe_routes_keep_csrf_and_only_protected_writes_get_authenticated_variant():
    missing = [
        (route.path, sorted(route.methods))
        for route in main.app.routes
        if isinstance(route, APIRoute)
        and route.methods & {'POST', 'PUT', 'PATCH', 'DELETE'}
        and (route.path, frozenset(route.methods)) not in TOKEN_AUTHENTICATED_MUTATIONS
        and not ({main.verify_csrf, main.verify_authenticated_csrf} & dependencies(route.dependant))
    ]
    assert missing == []
    for path in ('/api/auth/login', '/api/auth/native/login', '/api/forgot-password', '/api/reset-password', '/api/invitations/accept'):
        route = next(r for r in main.app.routes if isinstance(r, APIRoute) and r.path == path)
        assert main.verify_csrf in dependencies(route.dependant)
