
import pytest

from app.file_manager.scanner import (
    scan_folder,
    FileScanError,
)


def test_scans_files_recursively(tmp_path):
    source = tmp_path / "sample"
    source.mkdir()

    (source / "first.txt").write_text("hello", encoding="utf-8")

    nested = source / "documents"
    nested.mkdir()
    (nested / "second.txt").write_text("world!", encoding="utf-8")

    result = scan_folder(source)

    assert result["file_count"] == 2
    assert result["total_size_bytes"] == 11
    assert len(result["files"]) == 2
    assert result["skipped"] == []


def test_empty_folder_has_zero_files(tmp_path):
    source = tmp_path / "empty"
    source.mkdir()

    result = scan_folder(source)

    assert result["file_count"] == 0
    assert result["total_size_bytes"] == 0
    assert result["files"] == []


def test_missing_source_folder_is_rejected(tmp_path):
    with pytest.raises(FileNotFoundError):
        scan_folder(tmp_path / "missing")


def test_file_is_not_accepted_as_source(tmp_path):
    source_file = tmp_path / "example.txt"
    source_file.write_text("hello", encoding="utf-8")

    with pytest.raises(FileScanError):
        scan_folder(source_file)
