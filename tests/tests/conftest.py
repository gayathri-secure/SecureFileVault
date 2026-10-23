import pytest


@pytest.fixture(autouse=True)
def set_test_otp_secret(monkeypatch):
    monkeypatch.setenv(
        "OTP_SECRET",
        "test-only-secret-for-securefilevault",
    )
