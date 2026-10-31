import pytest
from pydantic import ValidationError

from backend.schemas.mobile_pairing import MobilePairingClaim


def test_mobile_pairing_claim_accepts_qr_or_normalized_manual_code():
    qr = MobilePairingClaim(qr_data="sparesflow://pair?token=abc", device_name="Phone")
    code = MobilePairingClaim(pairing_code="abcde-23456", device_name="Phone")

    assert qr.qr_data == "sparesflow://pair?token=abc"
    assert code.pairing_code == "ABCDE23456"


@pytest.mark.parametrize(
    "payload",
    [
        {"device_name": "Phone"},
        {"qr_data": "sparesflow://pair?token=abc", "pairing_code": "ABCDE23456", "device_name": "Phone"},
        {"pairing_code": "ABCDE-01234", "device_name": "Phone"},
        {"pairing_code": "ABCDE-2345", "device_name": "Phone"},
    ],
)
def test_mobile_pairing_claim_rejects_missing_ambiguous_or_malformed_credentials(payload):
    with pytest.raises(ValidationError):
        MobilePairingClaim(**payload)
