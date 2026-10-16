import pytest

from backend.services.native_refresh import decrypt_retry_response, encrypt_retry_response


KEY = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="


def test_refresh_retry_cache_encrypts_response_and_binds_it_to_token_hash():
    response = {"access_token": "opaque-access", "refresh_token": "opaque-refresh"}
    ciphertext = encrypt_retry_response(KEY, response, "a" * 64)

    assert "opaque-access" not in ciphertext
    assert decrypt_retry_response(KEY, ciphertext, "a" * 64) == response
    with pytest.raises(Exception):
        decrypt_retry_response(KEY, ciphertext, "b" * 64)


@pytest.mark.parametrize("key", [None, "", "not-base64!!!", "YWJj"])
def test_refresh_retry_cache_rejects_missing_or_invalid_encryption_keys(key):
    with pytest.raises(ValueError):
        encrypt_retry_response(key, {"secret": "value"}, "token-hash")
