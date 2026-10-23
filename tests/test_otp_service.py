
import time

from app.otp_service import (
    OTP_EXPIRY_SECONDS,
    MAX_OTP_ATTEMPTS,
    generate_otp,
    create_otp_record,
    verify_otp,
)


SECRET = "test-secret-for-otp-tests"


def test_generate_otp_is_six_digits():
    otp = generate_otp()

    assert len(otp) == 6
    assert otp.isdigit()


def test_correct_otp_is_accepted():
    otp = "123456"
    record = create_otp_record(otp, SECRET)

    success, message = verify_otp(record, otp, SECRET)

    assert success is True
    assert message == "Email OTP verified successfully."
    assert record["verified"] is True


def test_incorrect_otp_is_rejected():
    record = create_otp_record("123456", SECRET)

    success, message = verify_otp(record, "654321", SECRET)

    assert success is False
    assert message == "Incorrect OTP."
    assert record["verified"] is False


def test_expired_otp_is_rejected():
    record = create_otp_record("123456", SECRET)
    record["expires_at"] = time.time() - 1

    success, message = verify_otp(record, "123456", SECRET)

    assert success is False
    assert message == "OTP expired. Please request a new one."


def test_otp_cannot_be_reused_after_success():
    record = create_otp_record("123456", SECRET)

    first_success, _ = verify_otp(record, "123456", SECRET)
    second_success, message = verify_otp(record, "123456", SECRET)

    assert first_success is True
    assert second_success is False
    assert message == "This OTP has already been used."


def test_attempt_limit_is_enforced():
    record = create_otp_record("123456", SECRET)

    for _ in range(MAX_OTP_ATTEMPTS):
        success, _ = verify_otp(record, "000000", SECRET)
        assert success is False

    success, message = verify_otp(record, "123456", SECRET)

    assert success is False
    assert message == "Too many attempts. Please request a new OTP."


def test_invalid_otp_format_is_rejected():
    record = create_otp_record("123456", SECRET)

    success, message = verify_otp(record, "12AB", SECRET)

    assert success is False
    assert message == "Enter the six-digit OTP."


def test_otp_with_wrong_secret_is_rejected():
    record = create_otp_record("123456", SECRET)

    success, message = verify_otp(record, "123456", "different-secret")

    assert success is False
    assert message == "Incorrect OTP."


def test_otp_expiry_is_five_minutes():
    record = create_otp_record("123456", SECRET)

    remaining = record["expires_at"] - time.time()

    assert 0 < remaining <= OTP_EXPIRY_SECONDS
