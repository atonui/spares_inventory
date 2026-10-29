"""Native operations reject cookies and reuse stock lifecycle services."""
from contextlib import contextmanager
from unittest.mock import Mock

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from backend.routes.inventory_writes import create_inventory_write_router


@pytest.fixture
def native_operations():
    completion = Mock(return_value={'success': True})
    writes = Mock()

    @contextmanager
    def writer(*args, **kwargs):
        writes(*args, **kwargs)
        raise HTTPException(409, 'shared writer reached')
        yield

    def log(**kwargs):
        return lambda fn: fn

    app = FastAPI()
    app.include_router(create_inventory_write_router(
        current_user=lambda: 7, csrf_dependency=lambda: (_ for _ in ()).throw(AssertionError('cookie CSRF dependency invoked')),
        endpoint_log=log, authenticated_writer=writer, stock_access_guard=Mock(),
        active_record_guard=Mock(), balance_reader=Mock(), inventory_adder=Mock(),
        stock_audit=Mock(), stock_change_reader=Mock(), planned_dispatch_guard=Mock(),
        transfer_completion=completion,
    ))
    return TestClient(app), writes, completion


CASES = [
    ('consume', {'inventory_id': 1, 'quantity': 2, 'work_order_number': 'WO-1'}),
    ('add', {'part_id': 1, 'store_id': 2, 'quantity': 2}),
    ('transfer', {'inventory_id': 1, 'to_store_id': 2, 'quantity': 2}),
    ('transfers/1/receive', {'confirmed': True}),
    ('transfers/1/return', {'confirmed': True}),
]


@pytest.mark.parametrize('path,payload', CASES)
def test_native_operations_reject_cookie_only_sessions(native_operations, path, payload):
    client, writes, completion = native_operations
    client.cookies.set('session_token', 'cookie-session')
    assert client.post('/api/v1/inventory/' + path, json=payload).status_code == 401
    writes.assert_not_called()
    completion.assert_not_called()


@pytest.mark.parametrize('path,payload', CASES[:3])
def test_native_operations_revalidate_bearer_in_shared_writer(native_operations, path, payload):
    client, writes, _ = native_operations
    response = client.post('/api/v1/inventory/' + path, json=payload,
                           headers={'Authorization': 'Bearer native-session'})
    assert response.status_code == 409
    assert response.json()['detail'] == 'shared writer reached'
    assert writes.call_args.args == (7, 'native-session')


@pytest.mark.parametrize('action,state', [('receive', 'received'), ('return', 'returned')])
def test_native_transfer_actions_use_shared_completion(native_operations, action, state):
    client, _, completion = native_operations
    response = client.post(f'/api/v1/inventory/transfers/12/{action}',
                           json={'confirmed': True, 'notes': 'Checked'},
                           headers={'Authorization': 'Bearer native-session'})
    assert response.status_code == 200
    assert completion.call_args.args[0] == 12
    assert completion.call_args.args[2:4] == (7, state)
    assert completion.call_args.kwargs['session_token'] == 'native-session'
