
import pytest

from app.owner_record import (
    OwnerRecordError,
    create_owner_record,
    normalize_email,
    verify_owner_record,
)


TEST_SECRET = "test-secret-for-owner-record-tests"


def test_create_and_verify_owner_record():
    record = create_owner_record(
        "Owner@Example.com",
        TEST_SECRET,
    )

    assert record["owner_email"] == "owner@example.com"
    assert verify_owner_record(record, TEST_SECRET) == "owner@example.com"


def test_email_normalization():
    assert normalize_email("  Owner@Example.com  ") == "owner@example.com"


def test_modified_email_is_rejected():
    record = create_owner_record("owner@example.com", TEST_SECRET)
    record["owner_email"] = "attacker@example.com"

    with pytest.raises(OwnerRecordError):
        verify_owner_record(record, TEST_SECRET)


def test_modified_signature_is_rejected():
    record = create_owner_record("owner@example.com", TEST_SECRET)
    record["signature"] = "invalid-signature"

    with pytest.raises(OwnerRecordError):
        verify_owner_record(record, TEST_SECRET)


def test_wrong_secret_is_rejected():
    record = create_owner_record("owner@example.com", TEST_SECRET)

    with pytest.raises(OwnerRecordError):
        verify_owner_record(record, "different-secret")


def test_missing_record_is_rejected():
    with pytest.raises(OwnerRecordError):
        verify_owner_record(None, TEST_SECRET)


def test_missing_secret_is_rejected():
    with pytest.raises(OwnerRecordError):
        create_owner_record("owner@example.com", "")


def test_unsupported_version_is_rejected():
    record = create_owner_record("owner@example.com", TEST_SECRET)
    record["version"] = 2

    with pytest.raises(OwnerRecordError):
        verify_owner_record(record, TEST_SECRET)
