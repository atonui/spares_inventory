"""Inspect or upgrade a database without importing the web application."""
import argparse
import sqlite3
import sys
from contextlib import closing
from pathlib import Path
from ..database import connect_database,initialize_database,DEFAULT_SETTINGS
from . import check_database,MigrationError

def main(argv=None):
    parser=argparse.ArgumentParser(description='Inspect and apply explicit inventory database migrations')
    commands=parser.add_subparsers(dest='command',required=True)
    for name in ('status','check','upgrade'):
        command=commands.add_parser(name)
        command.add_argument('--database',required=True,type=Path)
        if name=='upgrade':command.add_argument('--create',action='store_true',help='Allow creation of a new database')
    args=parser.parse_args(argv)
    path=args.database.resolve()
    try:
        if not path.exists() and not (args.command=='upgrade' and args.create):
            raise MigrationError('Database does not exist; upgrade requires --create for a new file')
        if args.command=='upgrade':status=initialize_database(path,defaults=DEFAULT_SETTINGS)
        else:
            with closing(connect_database(path,readonly=True)) as conn:status=check_database(conn)
        print(f'Database: {path}')
        print(f'Current version: {status.current_version}; target version: {status.target_version}')
        print('Pending: '+(', '.join(map(str,status.pending)) or 'none'))
        if status.legacy:print('Legacy database: unversioned, recognized for upgrade')
        return 1 if args.command=='check' and status.pending else 0
    except (MigrationError,sqlite3.Error,OSError) as error:
        print(f'Database {path}: {error}',file=sys.stderr)
        return 1

if __name__=='__main__':raise SystemExit(main())
