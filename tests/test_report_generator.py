
import hashlib

import pytest
from openpyxl import load_workbook

from app.integrity.report_generator import (
    generate_encryption_report,
    ReportGenerationError,
)


def sample_record():
    original_hash = hashlib.sha256(b"original file").hexdigest()
    encrypted_hash = hashlib.sha256(b"encrypted file").hexdigest()

    return {
        "original_path": "documents/notes.txt",
        "encrypted_path": "documents/notes.txt.sfv",
        "original_size_bytes": len(b"original file"),
        "encrypted_size_bytes": len(b"encrypted file"),
        "original_sha256": original_hash,
        "encrypted_sha256": encrypted_hash,
    }


def test_creates_excel_report(tmp_path):
    report = tmp_path / "encryption_report.xlsx"

    result = generate_encryption_report(
        report,
        [sample_record()],
    )

    assert report.is_file()
    assert result["record_count"] == 1

    workbook = load_workbook(report, read_only=True)
    worksheet = workbook["Encryption Report"]

    assert worksheet["A5"].value == "Original File"
    assert worksheet["C6"].value == sample_record()["original_sha256"]
    assert worksheet["D6"].value == sample_record()["encrypted_sha256"]
    assert worksheet["G6"].value == "AES-256-GCM"
    assert worksheet["H6"].value == "Encrypted"

    workbook.close()


def test_report_supports_empty_file_list(tmp_path):
    report = tmp_path / "empty_report.xlsx"

    result = generate_encryption_report(report, [])

    assert report.is_file()
    assert result["record_count"] == 0


def test_existing_report_is_not_overwritten(tmp_path):
    report = tmp_path / "existing.xlsx"
    report.write_bytes(b"Keep this report")

    with pytest.raises(ReportGenerationError):
        generate_encryption_report(report, [sample_record()])

    assert report.read_bytes() == b"Keep this report"


def test_rejects_invalid_hash(tmp_path):
    record = sample_record()
    record["original_sha256"] = "not-a-valid-hash"

    with pytest.raises(ReportGenerationError):
        generate_encryption_report(
            tmp_path / "invalid.xlsx",
            [record],
        )


def test_rejects_non_xlsx_filename(tmp_path):
    with pytest.raises(ReportGenerationError):
        generate_encryption_report(
            tmp_path / "report.txt",
            [sample_record()],
        )
