
import pytest
import hashlib

from app.encryption.file_encryptor import (
    encrypt_file,
    decrypt_file,
    FileEncryptionError,
)


def test_file_encrypt_decrypt_round_trip(tmp_path):
    source = tmp_path / "notes.txt"
    encrypted = tmp_path / "notes.sfv"
    decrypted = tmp_path / "notes_restored.txt"

    original = b"SecureFileVault file encryption test.\n" * 100
    source.write_bytes(original)

    encrypt_file(source, encrypted, "TestPassword-123!")
    decrypt_file(encrypted, decrypted, "TestPassword-123!")

    assert decrypted.read_bytes() == original
    assert source.read_bytes() == original


def test_empty_file_round_trip(tmp_path):
    source = tmp_path / "empty.txt"
    encrypted = tmp_path / "empty.sfv"
    decrypted = tmp_path / "empty_restored.txt"

    source.write_bytes(b"")

    encrypt_file(source, encrypted, "TestPassword-123!")
    decrypt_file(encrypted, decrypted, "TestPassword-123!")

    assert decrypted.read_bytes() == b""


def test_wrong_password_does_not_publish_plaintext(tmp_path):
    source = tmp_path / "secret.txt"
    encrypted = tmp_path / "secret.sfv"
    decrypted = tmp_path / "restored.txt"

    source.write_bytes(b"Confidential test data.")
    encrypt_file(source, encrypted, "CorrectPassword-123!")

    with pytest.raises(FileEncryptionError):
        decrypt_file(encrypted, decrypted, "WrongPassword-456!")

    assert not decrypted.exists()


def test_existing_output_is_not_overwritten(tmp_path):
    source = tmp_path / "source.txt"
    encrypted = tmp_path / "source.sfv"

    source.write_bytes(b"Original")
    encrypted.write_bytes(b"Do not overwrite")

    with pytest.raises(FileEncryptionError):
        encrypt_file(source, encrypted, "TestPassword-123!")

    assert encrypted.read_bytes() == b"Do not overwrite"


def test_tampered_encrypted_file_is_rejected(tmp_path):
    source = tmp_path / "secret.txt"
    encrypted = tmp_path / "secret.sfv"
    decrypted = tmp_path / "restored.txt"

    source.write_bytes(b"Detect changes to encrypted content.")
    encrypt_file(source, encrypted, "TestPassword-123!")

    data = bytearray(encrypted.read_bytes())
    data[-1] ^= 1
    encrypted.write_bytes(data)

    with pytest.raises(FileEncryptionError):
        decrypt_file(encrypted, decrypted, "TestPassword-123!")

    assert not decrypted.exists()


def test_truncated_encrypted_file_is_rejected(tmp_path):
    source = tmp_path / "source.txt"
    encrypted = tmp_path / "source.sfv"
    decrypted = tmp_path / "restored.txt"

    source.write_bytes(b"Test truncation detection.")
    encrypt_file(source, encrypted, "TestPassword-123!")

    encrypted.write_bytes(encrypted.read_bytes()[:-5])

    with pytest.raises(FileEncryptionError):
        decrypt_file(encrypted, decrypted, "TestPassword-123!")

    assert not decrypted.exists()


def test_encryption_result_contains_original_sha256(tmp_path):
    source = tmp_path / "notes.txt"
    encrypted = tmp_path / "notes.sfv"
    original = b"Integrity verification test data."
    source.write_bytes(original)

    result = encrypt_file(
        source,
        encrypted,
        "TestPassword-123!",
    )

    expected_hash = hashlib.sha256(original).hexdigest()

    # This test will guide the implementation of hash reporting.
    assert result.get("original_sha256") == expected_hash


def test_restored_file_sha256_matches_original(tmp_path):
    source = tmp_path / "notes.txt"
    encrypted = tmp_path / "notes.sfv"
    restored = tmp_path / "restored.txt"

    original = b"Restored content must match exactly."
    source.write_bytes(original)

    encrypt_file(source, encrypted, "TestPassword-123!")
    decrypt_file(encrypted, restored, "TestPassword-123!")

    original_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    restored_hash = hashlib.sha256(restored.read_bytes()).hexdigest()

    assert restored_hash == original_hash
