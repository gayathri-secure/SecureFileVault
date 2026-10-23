
import hashlib
import hmac
import json


OWNER_RECORD_VERSION = 1


class OwnerRecordError(Exception):
    """Raised when an owner record is invalid or cannot be verified."""


def normalize_email(email):
    """Normalize an email address for consistent comparison."""
    if not isinstance(email, str):
        raise OwnerRecordError("A valid owner email address is required.")

    normalized = email.strip().casefold()

    if not normalized or "@" not in normalized:
        raise OwnerRecordError("A valid owner email address is required.")

    return normalized


def _derive_record_key(secret):
    """Derive a dedicated HMAC key from the application secret."""
    if not isinstance(secret, str) or not secret:
        raise OwnerRecordError("The owner-record secret is missing.")

    return hmac.new(
        secret.encode("utf-8"),
        b"SecureFileVault:owner-record:v1",
        hashlib.sha256,
    ).digest()


def _record_signature(version, owner_email, secret):
    """Calculate an HMAC over the version and normalized email."""
    payload = json.dumps(
        {
            "version": version,
            "owner_email": owner_email,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    return hmac.new(
        _derive_record_key(secret),
        payload,
        hashlib.sha256,
    ).hexdigest()


def create_owner_record(email, secret):
    """Create a versioned, integrity-protected owner record."""
    normalized_email = normalize_email(email)

    return {
        "version": OWNER_RECORD_VERSION,
        "owner_email": normalized_email,
        "signature": _record_signature(
            OWNER_RECORD_VERSION,
            normalized_email,
            secret,
        ),
    }


def verify_owner_record(record, secret):
    """Verify record integrity and return its normalized owner email."""
    if not isinstance(record, dict):
        raise OwnerRecordError("The owner record is missing or invalid.")

    version = record.get("version")
    owner_email = record.get("owner_email")
    signature = record.get("signature")

    if version != OWNER_RECORD_VERSION or isinstance(version, bool):
        raise OwnerRecordError("Unsupported owner-record version.")

    if not isinstance(owner_email, str) or not isinstance(signature, str):
        raise OwnerRecordError("The owner record is incomplete.")

    normalized_email = normalize_email(owner_email)

    # Reject non-normalized records instead of silently accepting edits.
    if normalized_email != owner_email:
        raise OwnerRecordError("The owner record has been modified.")

    expected_signature = _record_signature(
        version,
        normalized_email,
        secret,
    )

    if not hmac.compare_digest(signature, expected_signature):
        raise OwnerRecordError(
            "The owner record is invalid or has been modified."
        )

    return normalized_email
