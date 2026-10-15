"""Guarded, read-only-source imports from the legacy SQLite installation."""

__all__ = ["ImportReport", "import_sqlite_snapshot"]


def __getattr__(name):
    if name in __all__:
        from . import sqlite_to_postgres
        return getattr(sqlite_to_postgres, name)
    raise AttributeError(name)
