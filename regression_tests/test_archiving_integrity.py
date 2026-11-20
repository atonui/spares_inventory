import psycopg
import pytest
import main
from regression_tests.test_stock_safety import api


def seed(api):
    with api[1] as c:
        c.execute("INSERT INTO stores(id,name,type) VALUES(970,'Archive Store','central')")
        c.execute("INSERT INTO parts(id,part_number,description,category,unit_cost) VALUES(970,'ARCHIVE','Archive Part','test',0)")
        c.execute("INSERT INTO movements(to_store_id,part_id,quantity,movement_type,created_by) VALUES(970,970,1,'add',3)")


@pytest.mark.parametrize('kind',['parts','stores'])
def test_archive_preserves_history_and_can_be_restored(api,kind):
    seed(api);identifier=970
    assert api[0].delete(f'/api/{kind}/{identifier}').status_code==200
    with api[1] as c:
        assert c.execute(f'SELECT archived_at FROM {kind} WHERE id=?',(identifier,)).fetchone()[0]
    assert not any(x['id']==identifier for x in api[0].get('/api/'+kind).json())
    assert any(x['id']==identifier for x in api[0].get('/api/'+kind+'?include_archived=true').json())
    history=api[0].get('/api/movements').json()
    assert next(x for x in history if x['part_number']=='ARCHIVE')['created_by_name']=='Engineer'
    assert api[0].post(f'/api/{kind}/{identifier}/restore').status_code==200
    assert any(x['id']==identifier for x in api[0].get('/api/'+kind).json())


@pytest.mark.parametrize('kind',['parts','stores'])
def test_stock_blocks_archive(api,kind):
    seed(api)
    with api[1] as c:c.execute('INSERT INTO inventory(store_id,part_id,quantity) VALUES(970,970,2)')
    assert api[0].delete(f'/api/{kind}/970').status_code==400


def test_archived_parts_and_stores_reject_stock_add_and_import(api):
    seed(api)
    assert api[0].delete('/api/parts/970').status_code==200
    assert api[0].post('/api/inventory/add',json={'part_id':970,'store_id':970,'quantity':1}).status_code==400
    assert api[0].post('/api/inventory/import-balances',json={'store_id':970,'rows':[{'part_number':'ARCHIVE','quantity':1,'expected_quantity':None}]}).status_code==400
    assert api[0].post('/api/parts/970/restore').status_code==200
    assert api[0].delete('/api/stores/970').status_code==200
    assert api[0].post('/api/inventory/add',json={'part_id':970,'store_id':970,'quantity':1}).status_code==400


def test_assigned_store_blocks_user_archive(api):
    seed(api)
    with api[1] as c:c.execute('UPDATE stores SET assigned_user_id=3 WHERE id=970')
    assert api[0].delete('/api/users/3').status_code==400


def test_archived_user_cannot_be_assigned_a_store(api):
    seed(api)
    assert api[0].delete('/api/users/3').status_code==200
    assert api[0].put('/api/stores/970',json={'assigned_user_id':3}).status_code==400


def test_archive_permissions_and_csrf(api):
    seed(api);api[2]['id']=3
    assert api[0].delete('/api/parts/970').status_code==403
    assert api[0].get('/api/parts?include_archived=true').status_code==403
    assert api[0].post('/api/parts/970/restore').status_code==403
    api[2]['id']=1
    api[2]['csrf'] = False  # send an invalid CSRF token
    assert api[0].post('/api/parts/970/restore').status_code==403


def test_foreign_keys_reject_stock_for_missing_records(api):
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        api[1].execute('INSERT INTO inventory(store_id,part_id,quantity) VALUES(99999,99999,1)')


def test_duplicate_unallocated_stock_is_rejected_by_database(api):
    seed(api)
    api[1].execute('INSERT INTO inventory(store_id,part_id,quantity) VALUES(970,970,1)')
    with pytest.raises(psycopg.errors.UniqueViolation):
        api[1].execute('INSERT INTO inventory(store_id,part_id,quantity) VALUES(970,970,2)')




@pytest.mark.parametrize('method,path', [('delete', '/api/users/3'), ('post', '/api/users/3/remove')])
def test_member_with_assigned_equipment_cannot_leave_until_reassigned(api, method, path):
    client, db, _ = api
    db.execute("INSERT INTO equipment(id,equipment_name,make,model,serial_number,assigned_user_id) VALUES(970,'Meter','M','M1','S-970',3)")
    response = getattr(client, method)(path)
    assert response.status_code == 400
    assert response.json() == {'detail': 'Reassign stores and equipment before deactivating this member'}
    assert db.execute('SELECT is_active FROM organization_memberships WHERE user_id=3').fetchone()[0] is True
    db.execute('UPDATE equipment SET assigned_user_id=NULL WHERE id=970')
    assert getattr(client, method)(path).status_code == 200


def test_member_with_in_transit_transfer_cannot_be_removed(api):
    from regression_tests.test_transfer_receipts import seed as seed_transfer, dispatch
    seed_transfer(api); dispatch(api, 10); api[2]['id'] = 1
    response = api[0].post('/api/users/3/remove')
    assert response.status_code == 400
    assert api[1].execute('SELECT count(*) FROM organization_memberships WHERE user_id=3').fetchone()[0] == 1


def test_store_cannot_be_assigned_to_another_companys_user(api):
    seed(api)
    for response in (api[0].put('/api/stores/970', json={'assigned_user_id': 5}),
                     api[0].post('/api/stores', json={'name': 'Taken', 'type': 'central', 'assigned_user_id': 5})):
        assert response.status_code == 400
        assert response.json() == {'detail': 'users record does not exist'}
    assert api[1].execute('SELECT assigned_user_id FROM stores WHERE id=970').fetchone()[0] is None
