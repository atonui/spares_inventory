import asyncio
import shutil
import sqlite3
from datetime import datetime, timedelta

import pytest
import main
from regression_tests.test_stock_safety import api


def seed(api):
    with sqlite3.connect(api[1]) as c:
        c.execute("INSERT INTO stores(id,name,type) VALUES(970,'Archive Store','central')")
        c.execute("INSERT INTO parts(id,part_number,description,category,unit_cost) VALUES(970,'ARCHIVE','Archive Part','test',0)")
        c.execute("INSERT INTO movements(to_store_id,part_id,quantity,movement_type,created_by) VALUES(970,970,1,'add',3)")


@pytest.mark.parametrize('kind',['parts','stores','users'])
def test_archive_preserves_history_and_can_be_restored(api,kind):
    seed(api);identifier=3 if kind=='users' else 970
    assert api[0].delete(f'/api/{kind}/{identifier}').status_code==200
    with sqlite3.connect(api[1]) as c:
        assert c.execute(f'SELECT archived_at FROM {kind} WHERE id=?',(identifier,)).fetchone()[0]
    assert not any(x['id']==identifier for x in api[0].get('/api/'+kind).json())
    assert any(x['id']==identifier for x in api[0].get('/api/'+kind+'?include_archived=true').json())
    history=api[0].get('/api/movements').json()
    assert next(x for x in history if x['part_number']=='ARCHIVE')['created_by_name']=='User 3'
    assert api[0].post(f'/api/{kind}/{identifier}/restore').status_code==200
    assert any(x['id']==identifier for x in api[0].get('/api/'+kind).json())


@pytest.mark.parametrize('kind',['parts','stores'])
def test_stock_blocks_archive(api,kind):
    seed(api)
    with sqlite3.connect(api[1]) as c:c.execute('INSERT INTO inventory(store_id,part_id,quantity) VALUES(970,970,2)')
    assert api[0].delete(f'/api/{kind}/970').status_code==400


def test_archived_parts_and_stores_reject_stock_add_and_import(api):
    seed(api)
    assert api[0].delete('/api/parts/970').status_code==200
    assert api[0].post('/api/inventory/add',json={'part_id':970,'store_id':970,'quantity':1}).status_code==400
    assert api[0].post('/api/inventory/import-balances',json={'store_id':970,'rows':[{'part_number':'ARCHIVE','quantity':1,'expected_quantity':None}]}).status_code==400
    assert api[0].post('/api/parts/970/restore').status_code==200
    assert api[0].delete('/api/stores/970').status_code==200
    assert api[0].post('/api/inventory/add',json={'part_id':970,'store_id':970,'quantity':1}).status_code==400


def test_user_archive_revokes_sessions_and_blocks_login(api):
    seed(api)
    with sqlite3.connect(api[1]) as c:
        c.execute('INSERT INTO sessions(user_id,session_token,expires_at,is_active) VALUES(3,?,?,1)',('archived-token',(datetime.utcnow()+timedelta(days=1)).isoformat()))
    assert api[0].delete('/api/users/3').status_code==200
    assert api[0].post('/api/auth/login',json={'email':'user3@example.com','password':'test-password'}).status_code==401
    with pytest.raises(main.HTTPException) as exc:asyncio.run(main.get_current_user('archived-token'))
    assert exc.value.status_code==401
    assert api[0].post('/api/users/3/restore').status_code==200
    with pytest.raises(main.HTTPException):asyncio.run(main.get_current_user('archived-token'))


def test_login_started_before_archive_cannot_create_a_new_active_session(api,monkeypatch):
    seed(api)
    verify=main.verify_password
    def archive_during_verification(password,password_hash):
        main.archive_record('users',3,1)
        return verify(password,password_hash)
    monkeypatch.setattr(main,'verify_password',archive_during_verification)
    response=api[0].post('/api/auth/login',json={'email':'user3@example.com','password':'test-password'})
    assert response.status_code==401
    with sqlite3.connect(api[1]) as c:
        assert c.execute('SELECT COUNT(*) FROM sessions WHERE user_id=3 AND is_active=1').fetchone()[0]==0


def test_reset_started_before_archive_and_restore_cannot_use_revoked_token(api,monkeypatch):
    seed(api)
    with sqlite3.connect(api[1]) as c:
        previous=c.execute('SELECT password_hash FROM users WHERE id=3').fetchone()[0]
        c.execute('UPDATE users SET reset_token=?,reset_token_expires=? WHERE id=3',('racing-reset',(datetime.utcnow()+timedelta(hours=1)).isoformat()))
    hash_password=main.hash_password
    def archive_during_hash(password):
        main.archive_record('users',3,1)
        main.archive_record('users',3,1,restore=True)
        return hash_password(password)
    monkeypatch.setattr(main,'hash_password',archive_during_hash)
    main.app.state.limiter.reset()
    response=api[0].post('/api/reset-password',json={'token':'racing-reset','new_password':'new-password'})
    assert response.status_code==400
    with sqlite3.connect(api[1]) as c:
        assert c.execute('SELECT password_hash FROM users WHERE id=3').fetchone()[0]==previous


def test_assigned_store_blocks_user_archive(api):
    seed(api)
    with sqlite3.connect(api[1]) as c:c.execute('UPDATE stores SET assigned_user_id=3 WHERE id=970')
    assert api[0].delete('/api/users/3').status_code==400


def test_archived_user_cannot_receive_or_verify_reset_credentials(api,monkeypatch):
    seed(api)
    assert api[0].delete('/api/users/3').status_code==200
    # A stale/external token must also be rejected, independent of archive clearing.
    with sqlite3.connect(api[1]) as c:
        c.execute('UPDATE users SET reset_token=?,reset_token_expires=? WHERE id=3',('stale-token',(datetime.utcnow()+timedelta(hours=1)).isoformat()))
    assert api[0].get('/api/verify-reset-token/stale-token').status_code==400
    main.app.state.limiter.reset()
    monkeypatch.setattr(main,'send_reset_email',lambda *args:None)
    assert api[0].post('/api/forgot-password',json={'email':'user3@example.com'}).status_code==200
    with sqlite3.connect(api[1]) as c:
        assert c.execute('SELECT reset_token FROM users WHERE id=3').fetchone()[0]=='stale-token'


def test_archived_user_cannot_be_assigned_a_store(api):
    seed(api)
    assert api[0].delete('/api/users/3').status_code==200
    assert api[0].put('/api/stores/970',json={'assigned_user_id':3}).status_code==400


def test_unknown_orphans_stop_migration_without_changing_stock(api):
    seed(api)
    with sqlite3.connect(api[1]) as c:c.execute('UPDATE movements SET created_by=99999 WHERE part_id=970')
    with pytest.raises(ValueError,match='foreign'):main.init_db()
    with sqlite3.connect(api[1]) as c:
        assert c.execute('SELECT created_by FROM movements WHERE part_id=970').fetchone()[0]==99999


def test_duplicate_keys_stop_migration_without_merging_stock(api):
    seed(api)
    with sqlite3.connect(api[1]) as c:
        c.execute('DROP INDEX idx_inventory_unallocated_unique')
        c.execute('INSERT INTO inventory(store_id,part_id,quantity) VALUES(970,970,1),(970,970,2)')
    with pytest.raises(ValueError,match='duplicate'):main.init_db()
    with sqlite3.connect(api[1]) as c:
        assert c.execute('SELECT quantity FROM inventory WHERE part_id=970 ORDER BY id').fetchall()==[(1,),(2,)]


def test_archive_permissions_and_csrf(api):
    seed(api);api[2]['id']=3
    assert api[0].delete('/api/parts/970').status_code==403
    assert api[0].get('/api/parts?include_archived=true').status_code==403
    assert api[0].post('/api/parts/970/restore').status_code==403
    api[2]['id']=1
    main.app.dependency_overrides.pop(main.verify_csrf)
    assert api[0].post('/api/parts/970/restore').status_code==403


def test_foreign_keys_enabled_for_application_connections(api):
    with main.get_db_connection() as c:
        assert c.execute('PRAGMA foreign_keys').fetchone()[0]==1
        with pytest.raises(sqlite3.IntegrityError):c.execute('INSERT INTO inventory(store_id,part_id,quantity) VALUES(99999,99999,1)')


def test_duplicate_unallocated_stock_is_rejected_by_database(api):
    seed(api)
    with main.get_db_connection() as c:
        c.execute('INSERT INTO inventory(store_id,part_id,quantity) VALUES(970,970,1)')
        with pytest.raises(sqlite3.IntegrityError):c.execute('INSERT INTO inventory(store_id,part_id,quantity) VALUES(970,970,2)')


@pytest.mark.parametrize("text_work_order",["0970","9.7e2"])
def test_allocated_stock_uses_work_order_identity_despite_text_storage(api,text_work_order):
    seed(api)
    with main.get_db_connection() as c:
        c.execute("INSERT INTO work_orders(id,work_order_number) VALUES(970,'ARCHIVE-WO')")
        c.execute('INSERT INTO inventory(store_id,part_id,quantity,work_order_id) VALUES(970,970,1,970)')
        with pytest.raises(sqlite3.IntegrityError):
            c.execute("INSERT INTO inventory(store_id,part_id,quantity,work_order_id) VALUES(970,970,2,?)",(text_work_order,))


@pytest.mark.parametrize("text_work_order",["0970","9.7e2"])
def test_receipt_reuses_noncanonical_text_work_order_identity(api,text_work_order):
    seed(api)
    with sqlite3.connect(api[1]) as c:
        c.execute("INSERT INTO work_orders(id,work_order_number) VALUES(970,'TEXT-WO')")
        c.execute("INSERT INTO inventory(store_id,part_id,quantity,work_order_id) VALUES(970,970,1,?)",(text_work_order,))
    with main.get_db_connection() as c:
        main.add_inventory_quantity(c,970,970,3,970)
    with sqlite3.connect(api[1]) as c:
        assert c.execute('SELECT quantity FROM inventory WHERE part_id=970').fetchall()==[(4,)]


def test_legacy_anonymous_audit_log_keeps_text_and_migration_is_repeatable(api):
    with sqlite3.connect(api[1]) as c:c.execute("INSERT INTO activity_logs(user_id,username,action,details) VALUES(0,'anonymous','failed_login','keep me')")
    main.init_db();main.init_db()
    with sqlite3.connect(api[1]) as c:
        assert c.execute("SELECT user_id,username,details FROM activity_logs WHERE details='keep me'").fetchone()==(None,'anonymous','keep me')
        assert c.execute('PRAGMA foreign_key_check').fetchall()==[]


def test_restore_rejects_orphan_reference_without_live_changes(api,tmp_path):
    from database_restore import restore_database
    seed(api);upload=tmp_path/'orphan.db';shutil.copyfile(api[1],upload)
    with sqlite3.connect(upload) as c:c.execute('UPDATE movements SET part_id=99999 WHERE part_id=970')
    before=api[1].read_bytes()
    with pytest.raises(ValueError,match='reference|foreign'):restore_database(upload,api[1],2)
    assert api[1].read_bytes()==before


def test_restore_cannot_archive_the_requesting_superadmin(api,tmp_path):
    from database_restore import restore_database
    upload=tmp_path/'archived-admin.db';shutil.copyfile(api[1],upload)
    with sqlite3.connect(upload) as c:c.execute("UPDATE users SET archived_at=CURRENT_TIMESTAMP WHERE id=2")
    before=api[1].read_bytes()
    with pytest.raises(ValueError,match='superadmin'):restore_database(upload,api[1],2)
    assert api[1].read_bytes()==before
