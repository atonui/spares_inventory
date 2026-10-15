"""Small dialect helpers for SQL shared by SQLite and Psycopg connections."""

import psycopg


def is_postgres(conn) -> bool:
    return isinstance(conn, psycopg.Connection)


def _postgres_placeholders(statement: str) -> str:
    """Translate SQLite qmark parameters without changing quoted question marks."""
    output = []
    quote = None
    index = 0
    while index < len(statement):
        char = statement[index]
        if quote:
            output.append(char)
            if char == quote:
                if index + 1 < len(statement) and statement[index + 1] == quote:
                    output.append(statement[index + 1])
                    index += 1
                else:
                    quote = None
        elif char in ("'", '"'):
            quote = char
            output.append(char)
        elif char == "?":
            output.append("%s")
        else:
            output.append(char)
        index += 1
    return "".join(output)


def execute_cursor(conn, cursor, statement: str, params=()):
    if is_postgres(conn):
        statement = _postgres_placeholders(statement)
    cursor.execute(statement, params)
    return cursor


def execute(conn, statement: str, params=()):
    if is_postgres(conn):
        statement = _postgres_placeholders(statement)
    return conn.execute(statement, params)
