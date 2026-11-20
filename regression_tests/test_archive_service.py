from contextlib import closing

import pytest
from fastapi import HTTPException


def test_postgres_user_archive_passes_principal_to_membership_guard(monkeypatch):
    from contextlib import contextmanager
    from uuid import uuid4

    from backend.services import archiving
    from backend.services.principals import AuthenticatedPrincipal

    principal = AuthenticatedPrincipal(12, uuid4(), "admin", False)
    seen = []

    @contextmanager
    def authenticated_writer(_user, _token, **_kwargs):
        yield object()

    def membership_guard(actor, **_kwargs):
        seen.append(actor)
        raise RuntimeError("stop after verifying authorization input")

    with pytest.raises(RuntimeError, match="stop after verifying"):
        archiving.archive_record(
            "users", 34, principal, session_token="session",
            authenticated_write_transaction=authenticated_writer,
            require_archive_admin=lambda *_args: None,
            require_user_management=membership_guard,
            require_no_pending_transfer=lambda *_args: None,
            require_active_record=lambda *_args: None,
        )

    assert seen == [principal]
