"""Validated SQLite restoration; caller authenticates and limits the upload."""
import os
import sqlite3
import time
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path


def restore_database(upload, live, actor_id, *, defaults=None, validate_actor=None):
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
        apply_migrations(source,bootstrap=lambda c:bootstrap_defaults(c,DEFAULT_SETTINGS if defaults is None else defaults))
        if source.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise ValueError('Upgraded upload failed its integrity check')
        if source.execute('PRAGMA foreign_key_check').fetchone():
            raise ValueError('Uploaded database contains invalid foreign references')
        # Reserve the live writer before validating/snapshotting its state.
        # Other processes use the same SQLite lock; no process-local mutex is needed.
        target.execute('PRAGMA foreign_keys=ON')
        target.execute('BEGIN IMMEDIATE')
        # HTTP callers must revalidate their exact live session under this lock.
        # Omission is reserved for explicit trusted offline callers.
        if validate_actor is not None:
            validate_actor(target)
        live_status=check_database(target)
        if live_status.pending:
            raise ValueError('Live database must be initialized to the current migration version before restore')
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
        # A separate reader can snapshot the committed state while target holds
        # the reserved write lock. Backing up target itself would wait on its transaction.
        from backend.database import connect_database
        with closing(connect_database(live,readonly=True)) as reader, closing(sqlite3.connect(backup)) as saved:
            reader.backup(saved,pages=128,progress=progress,sleep=0.05)
            if saved.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                raise ValueError('Pre-restore backup failed validation')
        deadline=time.monotonic()+30
        # The backup API cannot write into an active destination transaction.
        # Keep the validated live schema and replace its records under the same lock.
        target.set_progress_handler(lambda: int(time.monotonic()>deadline),10000)
        target.execute('PRAGMA defer_foreign_keys=ON')
        tables=[row[0] for row in source.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
        for table in tables:
            target.execute(f'DELETE FROM "{table}"')
        for table in tables:
            names=[row[1] for row in source.execute(f'PRAGMA table_xinfo("{table}")')]
            fields=','.join('"'+name+'"' for name in names)
            placeholders=','.join('?' for _ in names)
            target.executemany(f'INSERT INTO "{table}" ({fields}) VALUES ({placeholders})',
                               source.execute(f'SELECT {fields} FROM "{table}"'))
        # Preserve counters even when their highest allocated row was deleted.
        target.execute('DELETE FROM sqlite_sequence')
        target.executemany('INSERT INTO sqlite_sequence(name,seq) VALUES(?,?)',
                           source.execute('SELECT name,seq FROM sqlite_sequence'))
        check_database(target)
        if target.execute('PRAGMA integrity_check').fetchone()[0]!='ok':
            raise ValueError('Restored database failed its integrity check')
        target.commit()
        return backup.name
    except Exception as error:
        target.rollback()
        if isinstance(error,sqlite3.OperationalError):
            code=getattr(error,'sqlite_errorcode',0)&0xff
            if code in (sqlite3.SQLITE_BUSY,sqlite3.SQLITE_LOCKED):
                raise TimeoutError('Database is busy; retry the restore when other writes finish') from error
            if code==sqlite3.SQLITE_INTERRUPT:
                raise TimeoutError('Restore exceeded its time limit; no live changes were committed') from error
        raise
    finally:
        source.close()
        target.close()
