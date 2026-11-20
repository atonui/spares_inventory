"""Authenticate a session and record its activity in one transaction."""


def authenticate_session(session_token, get_connection):
    from backend.postgres_database import postgres_transaction
    from backend.services.principals import resolve_principal
    from backend.services.session_credentials import hash_session_credential
    from backend.temporal import serialize_instant, utc_now

    connection = get_connection()
    try:
        with postgres_transaction(connection):
            principal = resolve_principal(connection, session_token)
            connection.execute(
                "UPDATE sessions SET last_activity = %s WHERE session_token_hash = %s",
                (serialize_instant(utc_now()), hash_session_credential(session_token)),
            )
            return principal
    finally:
        connection.close()
