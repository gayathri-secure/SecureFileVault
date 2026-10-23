
import hashlib
import os
from pathlib import Path


class HashCalculationError(Exception):
    """Raised when a file hash cannot be calculated."""


def calculate_sha256(file_path):
    """Calculate a file's SHA-256 hash without modifying it."""

    path = Path(file_path)

    try:
        if path.is_symlink():
            raise HashCalculationError(
                "Symbolic links are not supported."
            )

        if not path.is_file():
            raise HashCalculationError(
                "The specified path is not a regular file."
            )

        sha256 = hashlib.sha256()

        with path.open("rb") as file:
            while True:
                chunk = file.read(1024 * 1024)

                if not chunk:
                    break

                sha256.update(chunk)

        return sha256.hexdigest()

    except HashCalculationError:
        raise

    except OSError as exc:
        raise HashCalculationError(
            f"Could not calculate SHA-256: {exc}"
        ) from exc


def calculate_folder_hashes(source_folder):
    """
    Calculate SHA-256 hashes for regular files in a folder.

    Symbolic links are skipped. Original files are never modified.
    """

    source = Path(source_folder).resolve(strict=True)

    if not source.is_dir():
        raise HashCalculationError(
            "The source path is not a directory."
        )

    results = []
    skipped = []

    def handle_walk_error(error):
        skipped.append({
            "path": str(error.filename or source),
            "reason": "Could not access folder."
        })

    for current_root, dir_names, file_names in os.walk(
        source,
        topdown=True,
        followlinks=False,
        onerror=handle_walk_error,
    ):
        current_path = Path(current_root)

        safe_dirs = []

        for dir_name in dir_names:
            directory = current_path / dir_name

            if directory.is_symlink():
                skipped.append({
                    "path": str(directory.relative_to(source)),
                    "reason": "Symbolic-link directory skipped."
                })
            else:
                safe_dirs.append(dir_name)

        dir_names[:] = safe_dirs

        for file_name in file_names:
            file_path = current_path / file_name
            relative_path = str(file_path.relative_to(source))

            try:
                if file_path.is_symlink():
                    skipped.append({
                        "path": relative_path,
                        "reason": "Symbolic link skipped."
                    })
                    continue

                if not file_path.is_file():
                    continue

                file_hash = calculate_sha256(file_path)

                results.append({
                    "path": relative_path,
                    "sha256": file_hash
                })

            except (OSError, HashCalculationError) as exc:
                skipped.append({
                    "path": relative_path,
                    "reason": str(exc)
                })

    return {
        "source": str(source),
        "file_count": len(results),
        "files": results,
        "skipped": skipped
    }
