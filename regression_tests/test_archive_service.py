from contextlib import closing

import pytest
from fastapi import HTTPException

from backend.database import connect_database
from regression_tests.session_fixtures import session_database


def archive(path, table, identifier, restore=False):
    from backend.services.archiving import archive_record
    from backend.services.authorization import require_archive_admin, require_user_management
    from backend.services.stock_access import require_active_record
    from backend.services.transfer_helpers import require_no_pending_transfer
    from backend.services.authenticated_transactions import authenticated_write_transaction

    return archive_record(table, identifier, 2, restore, session_token='root-token',
        authenticated_write_transaction=lambda uid, token, **kwargs: authenticated_write_transaction(
            lambda: connect_database(path), user_id=uid, session_token=token, **kwargs),
        require_archive_admin=require_archive_admin, require_user_management=require_user_management,
        require_no_pending_transfer=require_no_pending_transfer, require_active_record=require_active_record)


def test_user_archive_and_restore_revoke_sessions_and_preserve_audit(tmp_path):
    path = session_database(tmp_path / 'archive.db')
    assert archive(path, 'users', 3)['success'] is True
    with closing(connect_database(path)) as conn:
        assert conn.execute('SELECT archived_at FROM users WHERE id=3').fetchone()[0]
        assert conn.execute('SELECT is_active FROM sessions WHERE user_id=3').fetchone()[0] == 0
    assert archive(path, 'users', 3, True)['success'] is True
    with closing(connect_database(path)) as conn:
        assert conn.execute('SELECT archived_at FROM users WHERE id=3').fetchone()[0] is None
        assert conn.execute('SELECT is_active FROM sessions WHERE user_id=3').fetchone()[0] == 0
        assert [row[0] for row in conn.execute('SELECT action FROM activity_logs ORDER BY id')] == ['archive', 'restore']


def test_stock_blocks_archive_without_mutation(tmp_path):
    path = session_database(tmp_path / 'archive.db')
    with pytest.raises(HTTPException) as error:
        archive(path, 'parts', 1)
    assert error.value.status_code == 400
    with closing(connect_database(path)) as conn:
        assert conn.execute('SELECT archived_at FROM parts WHERE id=1').fetchone()[0] is None
        assert conn.execute('SELECT COUNT(*) FROM activity_logs').fetchone()[0] == 0
