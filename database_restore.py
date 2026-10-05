"""Validated SQLite restoration; caller authenticates and limits the upload."""
import os
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path


def restore_database(upload, live, actor_id, *, defaults=None):
    live = Path(live).resolve(strict=True)
    source = sqlite3.connect(upload)
    target = sqlite3.connect(live, timeout=10)
    try:
        deadline = time.monotonic() + 10
        source.set_progress_handler(lambda: int(time.monotonic() > deadline), 10000)
        source.execute('PRAGMA trusted_schema=OFF')
        if source.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise ValueError('Uploaded database failed its integrity check')
        if source.execute("SELECT 1 FROM sqlite_master WHERE type IN ('trigger','view') OR upper(sql) LIKE '%VIRTUAL TABLE%'").fetchone():
            raise ValueError('Uploaded database contains unsupported schema objects')
        from backend.database import bootstrap_defaults, DEFAULT_SETTINGS
        from backend.migrations import apply_migrations, check_database
        live_status=check_database(target)
        if live_status.pending:
            raise ValueError('Live database must be initialized to the current migration version before restore')
        apply_migrations(source,bootstrap=lambda c:bootstrap_defaults(c,DEFAULT_SETTINGS if defaults is None else defaults))
        if source.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise ValueError('Upgraded upload failed its integrity check')
        if source.execute('PRAGMA foreign_key_check').fetchone():
            raise ValueError('Uploaded database contains invalid foreign references')
        # Match the running application schema before copying any data.
        from backend.migrations.validation import schema_signature
        if schema_signature(source) != schema_signature(target):
            raise ValueError('Uploaded database schema differs from the live database')
        active_clause=' AND archived_at IS NULL' if any(row[1]=='archived_at' for row in target.execute('PRAGMA table_info(users)')) else ''
        actor = target.execute('SELECT email FROM users WHERE id=? AND role=?'+active_clause,(actor_id,'superadmin')).fetchone()
        restored_actor = source.execute('SELECT email FROM users WHERE id=? AND role=?'+active_clause,(actor_id,'superadmin')).fetchone()
        if not actor or restored_actor != actor:
            raise ValueError('The backup must retain your superadmin account')
        source.execute('UPDATE sessions SET is_active=0')
        source.execute('UPDATE users SET session_token=NULL, reset_token=NULL, reset_token_expires=NULL')
        source.execute("INSERT INTO activity_logs(user_id,username,action,resource_type,details) VALUES(?,?,'database_restore','database',?)",(actor_id,actor[0],'Superadmin restored an uploaded database; all sessions revoked'))
        source.commit()
        source.set_progress_handler(None, 0)
        directory = live.parent / 'restore_backups'
        directory.mkdir(mode=0o700,exist_ok=True)
        backup = directory / ('before_restore_'+datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S_%f')+'.db')
        fd=os.open(backup,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        os.close(fd)
        deadline=time.monotonic()+30
        def progress(status,remaining,total):
            if time.monotonic()>deadline:
                raise TimeoutError('Database is busy; restore was stopped')
        with sqlite3.connect(backup) as saved:
            target.backup(saved,pages=128,progress=progress,sleep=0.05)
            if saved.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                raise ValueError('Pre-restore backup failed validation')
        deadline=time.monotonic()+30
        # SQLite backup writes atomically and preserves the destination file.
        source.backup(target,pages=128,progress=progress,sleep=0.05)
        return backup.name
    finally:
        source.close()
        target.close()
