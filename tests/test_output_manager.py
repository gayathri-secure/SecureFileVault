
from pathlib import Path

import pytest

from app.file_manager.output_manager import (
    create_unique_output_folder,
    OutputFolderError,
)


def test_creates_unique_output_folder(tmp_path):
    source = tmp_path / "test"
    source.mkdir()

    output_parent = tmp_path / "Desktop"
    output_parent.mkdir()

    result = create_unique_output_folder(source, output_parent)

    assert result == output_parent / "test_encrypted"
    assert result.is_dir()
    assert list(result.iterdir()) == []


def test_does_not_overwrite_existing_output(tmp_path):
    source = tmp_path / "test"
    source.mkdir()

    output_parent = tmp_path / "Desktop"
    output_parent.mkdir()

    existing = output_parent / "test_encrypted"
    existing.mkdir()

    important_file = existing / "keep.txt"
    important_file.write_text("Do not overwrite", encoding="utf-8")

    result = create_unique_output_folder(source, output_parent)

    assert result == output_parent / "test_encrypted_1"
    assert important_file.read_text(encoding="utf-8") == "Do not overwrite"


def test_rejects_output_location_inside_source(tmp_path):
    source = tmp_path / "test"
    source.mkdir()

    output_parent = source / "inside"
    output_parent.mkdir()

    with pytest.raises(OutputFolderError):
        create_unique_output_folder(source, output_parent)


def test_rejects_source_that_does_not_exist(tmp_path):
    source = tmp_path / "missing"
    output_parent = tmp_path / "Desktop"
    output_parent.mkdir()

    with pytest.raises(FileNotFoundError):
        create_unique_output_folder(source, output_parent)
