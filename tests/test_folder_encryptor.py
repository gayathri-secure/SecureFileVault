from pathlib import Path
import pytest

from app.encryption.file_encryptor import FileEncryptionError
from app.encryption.folder_encryptor import (
    encrypt_folder,
    FolderEncryptionError,
)
import app.encryption.folder_encryptor as folder_module


@pytest.fixture(autouse=True)
def set_test_otp_secret(monkeypatch):
    monkeypatch.setenv(
        "OTP_SECRET",
        "test-only-secret-for-securefilevault",
    )


def test_encrypts_nested_folder_and_preserves_originals(tmp_path):
    source = tmp_path / "documents"
    source.mkdir()

    first = source / "notes.txt"
    first.write_bytes(b"My notes")

    nested = source / "reports"
    nested.mkdir()

    second = nested / "report.pdf"
    second.write_bytes(b"Sample PDF content")

    output_parent = tmp_path / "output"
    output_parent.mkdir()

    result = encrypt_folder(
        source,
        output_parent,
        "TestPassword-123!",
        "owner@example.com",
    )

    encrypted_root = result["output_folder"]

    assert result["success"] is True
    assert result["encrypted_file_count"] == 2
    assert (source / "notes.txt").read_bytes() == b"My notes"
    assert (source / "reports" / "report.pdf").read_bytes() == (
        b"Sample PDF content"
    )
    assert (source / "notes.txt").exists()
    assert (source / "reports" / "report.pdf").exists()

    assert (tmp_path / "output" / Path(result["operation_folder"]).name
            / "owner_record.json").exists()

    assert (Path(encrypted_root) / "notes.txt.sfv").exists()
    assert (Path(encrypted_root) / "reports" / "report.pdf.sfv").exists()


def test_preserves_empty_subdirectories(tmp_path):
    source = tmp_path / "documents"
    source.mkdir()
    (source / "empty_folder").mkdir()

    output_parent = tmp_path / "output"
    output_parent.mkdir()

    result = encrypt_folder(
        source,
        output_parent,
        "TestPassword-123!",
        "owner@example.com",
    )

    encrypted_root = Path(result["output_folder"])
    assert (encrypted_root / "empty_folder").is_dir()


def test_creates_unique_output_folder(tmp_path):
    source = tmp_path / "documents"
    source.mkdir()
    (source / "notes.txt").write_text("hello", encoding="utf-8")

    output_parent = tmp_path / "output"
    output_parent.mkdir()

    first = encrypt_folder(
        source,
        output_parent,
        "TestPassword-123!",
        "owner@example.com",
    )

    second = encrypt_folder(
        source,
        output_parent,
        "TestPassword-123!",
        "owner@example.com",
    )

    assert first["operation_folder"] != second["operation_folder"]
    assert Path(first["operation_folder"]).is_dir()
    assert Path(second["operation_folder"]).is_dir()


def test_rejects_output_location_inside_source(tmp_path):
    source = tmp_path / "documents"
    source.mkdir()

    inside = source / "inside"
    inside.mkdir()

    with pytest.raises(FolderEncryptionError):
        encrypt_folder(
            source,
            inside,
            "TestPassword-123!",
            "owner@example.com",
        )


def test_removes_incomplete_output_when_encryption_fails(
    tmp_path,
    monkeypatch,
):
    source = tmp_path / "documents"
    source.mkdir()
    (source / "notes.txt").write_text("hello", encoding="utf-8")

    output_parent = tmp_path / "output"
    output_parent.mkdir()

    def fail_encryption(*args, **kwargs):
        raise FileEncryptionError("Simulated encryption failure.")

    monkeypatch.setattr(
        folder_module,
        "encrypt_file",
        fail_encryption,
    )

    with pytest.raises(FolderEncryptionError):
        encrypt_folder(
            source,
            output_parent,
            "TestPassword-123!",
            "owner@example.com",
        )

    # A failed operation must not leave a partial output folder.
    assert list(output_parent.iterdir()) == []
