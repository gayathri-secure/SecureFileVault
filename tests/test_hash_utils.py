
import hashlib
from pathlib import Path

import pytest

from app.integrity.hash_utils import (
    calculate_sha256,
    HashCalculationError,
    calculate_folder_hashes,
)


def test_calculates_correct_sha256(tmp_path):
    file_path = tmp_path / "sample.txt"
    content = b"Hello SecureFileVault!"
    file_path.write_bytes(content)

    expected = hashlib.sha256(content).hexdigest()

    assert calculate_sha256(file_path) == expected


def test_empty_file_hash(tmp_path):
    file_path = tmp_path / "empty.txt"
    file_path.write_bytes(b"")

    expected = hashlib.sha256(b"").hexdigest()

    assert calculate_sha256(file_path) == expected


def test_rejects_missing_file(tmp_path):
    with pytest.raises(HashCalculationError):
        calculate_sha256(tmp_path / "missing.txt")


def test_hashing_does_not_modify_file(tmp_path):
    file_path = tmp_path / "important.txt"
    original_content = b"Original content must remain unchanged."
    file_path.write_bytes(original_content)

    calculate_sha256(file_path)

    assert file_path.read_bytes() == original_content


def test_calculates_hashes_for_folder_files(tmp_path):
    source = tmp_path / "documents"
    source.mkdir()

    first = source / "first.txt"
    first.write_bytes(b"first file")

    nested = source / "nested"
    nested.mkdir()

    second = nested / "second.txt"
    second.write_bytes(b"second file")

    result = calculate_folder_hashes(source)

    assert result["file_count"] == 2
    assert len(result["files"]) == 2
    assert result["skipped"] == []

    hashes = {
        item["path"]: item["sha256"]
        for item in result["files"]
    }

    assert hashes["first.txt"] == hashlib.sha256(
        b"first file"
    ).hexdigest()

    nested_path = str(Path("nested") / "second.txt")

    assert hashes[nested_path] == hashlib.sha256(
        b"second file"
    ).hexdigest()


def test_folder_hashing_does_not_modify_originals(tmp_path):
    source = tmp_path / "documents"
    source.mkdir()

    original = source / "important.txt"
    original.write_bytes(b"Keep this original file unchanged.")

    before = original.read_bytes()

    calculate_folder_hashes(source)

    assert original.read_bytes() == before
