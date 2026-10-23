
import pytest

from app.encryption.aes_gcm import (
    encrypt_bytes,
    decrypt_bytes,
    EncryptionError,
)


def test_encrypt_then_decrypt():
    original = b"SecureFileVault test content."
    package = encrypt_bytes(original, "TestPassword-123!")

    decrypted = decrypt_bytes(package, "TestPassword-123!")

    assert decrypted == original


def test_wrong_password_is_rejected():
    package = encrypt_bytes(b"secret content", "CorrectPassword-123!")

    with pytest.raises(EncryptionError):
        decrypt_bytes(package, "WrongPassword-456!")


def test_modified_ciphertext_is_rejected():
    package = encrypt_bytes(b"important content", "TestPassword-123!")

    package["ciphertext"] = (
        package["ciphertext"][:-4] + "AAAA"
    )

    with pytest.raises(EncryptionError):
        decrypt_bytes(package, "TestPassword-123!")


def test_original_data_is_not_modified():
    original = b"Original file data must remain unchanged."
    before = original[:]

    package = encrypt_bytes(original, "TestPassword-123!")
    decrypt_bytes(package, "TestPassword-123!")

    assert original == before
