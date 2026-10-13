"""Coverage for every unsafe application route and authentication boundaries."""
from fastapi.routing import APIRoute
import main
from regression_tests.test_auth_router import auth_api
from regression_tests.test_stock_safety import api

def dependencies(dependant):
    return {d.call for d in dependant.dependencies} | {call for d in dependant.dependencies for call in dependencies(d)}

def test_every_mutation_route_requires_csrf():
    missing=[(route.path, sorted(route.methods)) for route in main.app.routes
             if isinstance(route,APIRoute) and route.methods & {'POST','PUT','PATCH','DELETE'}
             and main.verify_csrf not in dependencies(route.dependant)]
    assert missing == []

def test_login_and_logout_reject_missing_and_invalid_tokens(auth_api):
    client,db,actor=auth_api
    main.app.dependency_overrides.pop(main.verify_csrf)
    for path,body in [('/api/auth/login',{'email':'user1@example.com','password':'test-password'}),('/api/auth/logout',{})]:
        assert client.post(path,json=body).json()['detail']=='CSRF token missing'
        assert client.post(path,json=body,headers={'X-CSRF-Token':'bad'}).json()['detail']=='Invalid CSRF token'
    token=client.get('/api/csrf-token').json()['csrf_token']
    assert client.post('/api/auth/login',json={'email':'user1@example.com','password':'test-password'},headers={'X-CSRF-Token':token}).status_code==200
    assert client.post('/api/auth/logout',headers={'X-CSRF-Token':token}).status_code==200

def test_csrf_token_response_cannot_be_cached(auth_api):
    client,_,_=auth_api
    assert client.get('/api/csrf-token').headers.get('cache-control')=='no-store'
