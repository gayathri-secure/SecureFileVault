
import pytest

from app.encryption.folder_encryptor import encrypt_folder
from app.decryption.folder_decryptor import (
    decrypt_folder,
    FolderDecryptionError,
)

@pytest.fixture(autouse=True)
def set_test_otp_secret(monkeypatch):
    monkeypatch.setenv(
        "OTP_SECRET",
        "test-only-secret-for-securefilevault",
    )


def test_folder_decryption_restores_nested_files(tmp_path):
    source = tmp_path / "documents"
    source.mkdir()

    (source / "notes.txt").write_bytes(b"Original notes")

    nested = source / "reports"
    nested.mkdir()
    (nested / "report.pdf").write_bytes(b"Sample PDF content")

    encrypted_parent = tmp_path / "encrypted"
    encrypted_parent.mkdir()
    output_parent = tmp_path / "restored"
    output_parent.mkdir()

    encrypted = encrypt_folder(
        source,
        encrypted_parent,
        "TestPassword-123!",
        "owner@example.com",
    )

    result = decrypt_folder(
        encrypted["output_folder"],
        output_parent,
        "TestPassword-123!",
    )

    restored = __import__("pathlib").Path(result["output_folder"])

    assert result["decrypted_file_count"] == 2
    assert (restored / "notes.txt").read_bytes() == b"Original notes"
    assert (
        restored / "reports" / "report.pdf"
    ).read_bytes() == b"Sample PDF content"

    assert (source / "notes.txt").read_bytes() == b"Original notes"


def test_wrong_password_removes_incomplete_output(tmp_path):
    source = tmp_path / "documents"
    source.mkdir()
    (source / "secret.txt").write_bytes(b"Private content")

    encrypted_parent = tmp_path / "encrypted"
    encrypted_parent.mkdir()
    output_parent = tmp_path / "restored"
    output_parent.mkdir()

    encrypted = encrypt_folder(
        source,
        encrypted_parent,
        "CorrectPassword-123!",
        "owner@example.com",
    )

    with pytest.raises(FolderDecryptionError):
        decrypt_folder(
            encrypted["output_folder"],
            output_parent,
            "WrongPassword-456!",
        )

    assert list(output_parent.iterdir()) == []


def test_existing_encrypted_files_are_preserved(tmp_path):
    source = tmp_path / "documents"
    source.mkdir()
    (source / "notes.txt").write_bytes(b"Keep originals")

    encrypted_parent = tmp_path / "encrypted"
    encrypted_parent.mkdir()
    output_parent = tmp_path / "restored"
    output_parent.mkdir()

    encrypted = encrypt_folder(
        source,
        encrypted_parent,
        "TestPassword-123!",
        "owner@example.com",
    )

    encrypted_file = (
        __import__("pathlib").Path(encrypted["output_folder"])
        / "notes.txt.sfv"
    )
    before = encrypted_file.read_bytes()

    decrypt_folder(
        encrypted["output_folder"],
        output_parent,
        "TestPassword-123!",
    )

    assert encrypted_file.read_bytes() == before


def test_rejects_output_inside_encrypted_source(tmp_path):
    source = tmp_path / "documents"
    source.mkdir()
    (source / "notes.txt").write_bytes(b"test")

    encrypted_parent = tmp_path / "encrypted"
    encrypted_parent.mkdir()
    encrypted = encrypt_folder(
        source,
        encrypted_parent,
        "TestPassword-123!",
        "owner@example.com",
    )

    encrypted_folder = __import__("pathlib").Path(
        encrypted["output_folder"]
    )
    inside = encrypted_folder / "inside"
    inside.mkdir()

    with pytest.raises(FolderDecryptionError):
        decrypt_folder(
            encrypted_folder,
            inside,
            "TestPassword-123!",
        )
