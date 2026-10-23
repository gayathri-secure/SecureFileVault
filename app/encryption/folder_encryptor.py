
import os
import shutil
from pathlib import Path

from app.encryption.file_encryptor import (
    encrypt_file,
    FileEncryptionError,
)
from app.file_manager.scanner import scan_folder, FileScanError
from app.file_manager.output_manager import (
    create_unique_output_folder,
    OutputFolderError,
)
import json

from app.owner_record import create_owner_record

class FolderEncryptionError(Exception):
    """Raised when folder encryption cannot complete safely."""


def encrypt_folder(
        source_folder,
        output_parent,
        password,
        owner_email=None,
        ):
    """Encrypt a folder into a unique operation folder."""

    if not isinstance(password, str) or not password:
        raise FolderEncryptionError("A non-empty password is required.")

    if not isinstance(owner_email, str) or not owner_email.strip():
        raise FolderEncryptionError(
            "A valid owner email is required."
        )

    try:
        source = Path(source_folder).resolve(strict=True)
        parent = Path(output_parent).resolve(strict=True)

        if not source.is_dir():
            raise FolderEncryptionError(
                "The source path must be a folder."
            )

        if not parent.is_dir():
            raise FolderEncryptionError(
                "The output location must be an existing folder."
            )

        if source == parent:
            raise FolderEncryptionError(
                "Choose a separate output parent folder."
            )

        scan = scan_folder(source)

        if scan["skipped"]:
            examples = "; ".join(
                f'{item["path"]}: {item["reason"]}'
                for item in scan["skipped"][:3]
            )
            raise FolderEncryptionError(
                "The source contains items that could not be scanned "
                f"safely. Resolve them and try again. Details: {examples}"
            )

        # Outer folder, e.g. documents_encrypted.
        operation_folder = create_unique_output_folder(source, parent)

        try:
            # Actual encrypted files are stored here.
            encrypted_folder = operation_folder / "encrypted_files"
            encrypted_folder.mkdir()

            owner_record = create_owner_record(
                owner_email,
                os.getenv("OTP_SECRET"),
            )

            owner_record_path = operation_folder / "owner_record.json"

            with owner_record_path.open("x", encoding="utf-8") as record_file:
                json.dump(
                    owner_record,
                    record_file,
                    indent=2,
                )

            # Preserve nested and empty directories.
            for current_root, dir_names, _ in os.walk(
                source,
                topdown=True,
                followlinks=False,
            ):
                current_path = Path(current_root)

                for directory_name in dir_names:
                    directory = current_path / directory_name

                    if directory.is_symlink():
                        raise FolderEncryptionError(
                            "A symbolic-link directory appeared during "
                            "processing. Folder encryption was cancelled."
                        )

                    relative_dir = directory.relative_to(source)
                    (encrypted_folder / relative_dir).mkdir(
                        parents=True,
                        exist_ok=True,
                    )

            encrypted_count = 0
            total_original_bytes = 0
            encrypted_files = []

            for item in scan["files"]:
                relative_path = Path(item["path"])

                if (
                    relative_path.is_absolute()
                    or ".." in relative_path.parts
                ):
                    raise FolderEncryptionError(
                        "Unsafe relative file path detected."
                    )

                input_file = source / relative_path
                output_file = encrypted_folder / relative_path.with_name(
                    relative_path.name + ".sfv"
                )

                if input_file.is_symlink() or not input_file.is_file():
                    raise FolderEncryptionError(
                        f"Source file changed during processing: {relative_path}"
                    )

                output_file.parent.mkdir(parents=True, exist_ok=True)

                result = encrypt_file(
                    input_file,
                    output_file,
                    password,
                )

                encrypted_count += 1
                total_original_bytes += result["original_size_bytes"]

                encrypted_files.append({
                    "original_path": str(relative_path),
                    "encrypted_path": str(
                        output_file.relative_to(encrypted_folder)
                    ),
                    "original_size_bytes": result["original_size_bytes"],
                    "encrypted_size_bytes": result["encrypted_size_bytes"],
                })

            return {
                "success": True,
                "source": str(source),

                # Backward-compatible: this points directly to .sfv files.
                "output_folder": str(encrypted_folder),

                # New key: outer folder for reports and organization.
                "operation_folder": str(operation_folder),

                "algorithm": "AES-256-GCM",
                "encrypted_file_count": encrypted_count,
                "total_original_bytes": total_original_bytes,
                "files": encrypted_files,
            }

        except Exception:
            # Clean up only the folder created by this operation.
            shutil.rmtree(operation_folder, ignore_errors=True)
            raise

    except (FileScanError, OutputFolderError, FileEncryptionError) as exc:
        raise FolderEncryptionError(str(exc)) from exc
    except FolderEncryptionError:
        raise
    except OSError as exc:
        raise FolderEncryptionError(
            f"Folder encryption failed: {exc}"
        ) from exc
