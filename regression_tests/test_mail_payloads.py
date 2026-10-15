import pytest


def test_mail_payload_round_trips_and_rejects_tampering():
    from cryptography.fernet import Fernet, InvalidToken

    from backend.services.mail_payloads import (
        decrypt_mail_payload,
        encrypt_mail_payload,
    )

    payload = {"invitation_url": "https://example.test/invite?token=secret"}
    key = Fernet.generate_key().decode("ascii")
    ciphertext = encrypt_mail_payload(payload, key)

    assert decrypt_mail_payload(ciphertext, key) == payload
    with pytest.raises(InvalidToken):
        decrypt_mail_payload(ciphertext, Fernet.generate_key().decode("ascii"))
    altered = ciphertext[:-2] + ("AA" if ciphertext[-2:] != "AA" else "BB")
    with pytest.raises(InvalidToken):
        decrypt_mail_payload(altered, key)
