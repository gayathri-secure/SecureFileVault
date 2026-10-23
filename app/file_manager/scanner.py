
from pathlib import Path


class FileScanError(Exception):
    """Raised when the source folder cannot be scanned safely."""


def scan_folder(source_folder):
    """
    Scan a source folder recursively without modifying any files.

    Returns:
        A dictionary containing file details, file count and total size.
    """

    source = Path(source_folder).resolve(strict=True)

    if not source.is_dir():
        raise FileScanError("The source path is not a directory.")

    files = []
    total_size = 0
    skipped = []

    def walk_error(error):
        raise FileScanError(
            f"Could not access a folder: {error}"
        ) from error

    import os

    for current_root, dir_names, file_names in os.walk(
        source,
        topdown=True,
        followlinks=False,
        onerror=walk_error,
    ):
        current_path = Path(current_root)

        # Do not follow symbolic-link directories.
        safe_dirs = []

        for dir_name in dir_names:
            directory = current_path / dir_name

            if directory.is_symlink():
                skipped.append({
                    "path": str(directory.relative_to(source)),
                    "reason": "Symbolic-link directory skipped",
                })
            else:
                safe_dirs.append(dir_name)

        dir_names[:] = safe_dirs

        for file_name in file_names:
            file_path = current_path / file_name

            try:
                if file_path.is_symlink():
                    skipped.append({
                        "path": str(file_path.relative_to(source)),
                        "reason": "Symbolic link skipped",
                    })
                    continue

                if not file_path.is_file():
                    continue

                size = file_path.stat().st_size

                files.append({
                    "path": str(file_path.relative_to(source)),
                    "size_bytes": size,
                })

                total_size += size

            except OSError as exc:
                skipped.append({
                    "path": str(file_path.relative_to(source)),
                    "reason": f"Could not inspect file: {exc}",
                })

    return {
        "source": str(source),
        "file_count": len(files),
        "total_size_bytes": total_size,
        "files": files,
        "skipped": skipped,
    }
