import hashlib

import pytest
from fastapi import HTTPException


def test_session_credential_hash_is_stable_and_does_not_reveal_raw_value():
    from backend.services.session_credentials import hash_session_credential

    raw = "random-session-secret"

    first = hash_session_credential(raw)
    second = hash_session_credential(raw)

    assert first == second == hashlib.sha256(raw.encode("utf-8")).hexdigest()
    assert raw not in first


@pytest.mark.parametrize(
    ("cookie", "authorization", "expected", "transport"),
    [
        ("cookie-secret", None, "cookie-secret", "cookie"),
        (None, "Bearer bearer-secret", "bearer-secret", "bearer"),
        (None, "bEaReR bearer-secret", "bearer-secret", "bearer"),
    ],
)
def test_resolve_request_credential_accepts_exactly_one_supported_credential(
    cookie, authorization, expected, transport
):
    from backend.services.session_credentials import resolve_request_credential

    parsed = resolve_request_credential(cookie, authorization)

    assert parsed.value == expected
    assert parsed.transport == transport


@pytest.mark.parametrize(
    ("cookie", "authorization"),
    [
        (None, None),
        (None, "Basic abc"),
        (None, "Bearer"),
        (None, "Bearer one two"),
        ("cookie-secret", "Bearer bearer-secret"),
    ],
)
def test_resolve_request_credential_rejects_missing_malformed_or_mixed_credentials(
    cookie, authorization
):
    from backend.services.session_credentials import resolve_request_credential

    with pytest.raises(HTTPException) as error:
        resolve_request_credential(cookie, authorization)

    assert error.value.status_code == 401


def test_resolve_request_credential_can_disable_bearer_for_legacy_runtime():
    from backend.services.session_credentials import resolve_request_credential

    with pytest.raises(HTTPException) as error:
        resolve_request_credential(None, "Bearer bearer-secret", allow_bearer=False)

    assert error.value.status_code == 401


def test_optional_request_credential_allows_anonymous_but_rejects_bad_authorization():
    from fastapi import HTTPException
    from starlette.requests import Request

    from backend.services.session_credentials import get_optional_request_credential

    anonymous = Request({"type": "http", "headers": []})
    assert get_optional_request_credential(anonymous) is None

    malformed = Request({"type": "http", "headers": [(b"authorization", b"Basic abc")]})
    with pytest.raises(HTTPException) as error:
        get_optional_request_credential(malformed)
    assert error.value.status_code == 401


def test_request_credential_supports_request_shims_without_headers():
    from types import SimpleNamespace

    from backend.services.session_credentials import get_request_credential

    credential = get_request_credential(SimpleNamespace(cookies={"session_token": "cookie-secret"}))
    assert (credential.value, credential.transport) == ("cookie-secret", "cookie")


def test_authenticated_route_modules_do_not_read_session_cookie_directly():
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    offenders = []
    for path in (root / "backend/routes").glob("*.py"):
        source = path.read_text()
        if "request.cookies.get(\"session_token\")" in source or "request.cookies.get('session_token')" in source:
            offenders.append(path.name)

    assert offenders == []
