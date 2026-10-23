
"""Email OTP generation and verification helpers for SecureFileVault."""

import hashlib
import hmac
import secrets
import time


OTP_LENGTH = 6
OTP_EXPIRY_SECONDS = 300
MAX_OTP_ATTEMPTS = 5


def generate_otp():
    """Generate a cryptographically secure six-digit OTP."""
    return f"{secrets.randbelow(1_000_000):06d}"


def hash_otp(otp, secret):
    """Hash an OTP using a server-side secret."""
    return hmac.new(
        secret.encode("utf-8"),
        otp.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def create_otp_record(otp, secret):
    """Create the data needed to verify an OTP later."""
    return {
        "otp_hash": hash_otp(otp, secret),
        "expires_at": time.time() + OTP_EXPIRY_SECONDS,
        "attempts": 0,
        "verified": False,
    }


def verify_otp(record, submitted_otp, secret):
    """Check OTP expiry, attempt limit, and value."""
    if not isinstance(record, dict):
        return False, "Please request a new OTP."

    if record.get("verified"):
        return False, "This OTP has already been used."

    if time.time() >= record.get("expires_at", 0):
        return False, "OTP expired. Please request a new one."

    if record.get("attempts", 0) >= MAX_OTP_ATTEMPTS:
        return False, "Too many attempts. Please request a new OTP."

    record["attempts"] += 1

    if not isinstance(submitted_otp, str) or not (
        len(submitted_otp) == OTP_LENGTH and submitted_otp.isdigit()
    ):
        return False, "Enter the six-digit OTP."

    expected_hash = record.get("otp_hash", "")
    actual_hash = hash_otp(submitted_otp, secret)

    if not hmac.compare_digest(actual_hash, expected_hash):
        return False, "Incorrect OTP."

    record["verified"] = True
    return True, "Email OTP verified successfully."
