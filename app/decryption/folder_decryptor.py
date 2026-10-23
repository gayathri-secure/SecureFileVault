
import os
import shutil
from pathlib import Path

from app.encryption.file_encryptor import (
    decrypt_file,
    FileEncryptionError,
)


class FolderDecryptionError(Exception):
    """Raised when folder decryption cannot complete safely."""


def decrypt_folder(encrypted_folder, output_parent, password):
    """Decrypt into a unique operation folder without overwriting files."""

    if not isinstance(password, str) or not password:
        raise FolderDecryptionError("A non-empty password is required.")

    operation_folder = None

    try:
        source = Path(encrypted_folder).resolve(strict=True)
        parent = Path(output_parent).resolve(strict=True)

        if not source.is_dir():
            raise FolderDecryptionError(
                "The encrypted source must be a folder."
            )

        if not parent.is_dir():
            raise FolderDecryptionError(
                "The output location must be an existing folder."
            )

        if source == parent:
            raise FolderDecryptionError(
                "Choose a separate output parent folder."
            )

        try:
            parent.relative_to(source)
        except ValueError:
            pass
        else:
            raise FolderDecryptionError(
                "The output location cannot be inside "
                "the encrypted folder."
            )

        encrypted_files = []
        empty_directories = []

        def handle_walk_error(error):
            raise FolderDecryptionError(
                f"Could not access encrypted folder: {error}"
            )

        for current_root, dir_names, file_names in os.walk(
            source,
            topdown=True,
            followlinks=False,
            onerror=handle_walk_error,
        ):
            current = Path(current_root)

            for name in dir_names:
                directory = current / name

                if directory.is_symlink():
                    raise FolderDecryptionError(
                        "Symbolic-link directories are not supported."
                    )

                if not any(directory.iterdir()):
                    empty_directories.append(
                        directory.relative_to(source)
                    )

            for name in file_names:
                file_path = current / name

                if file_path.is_symlink() or not file_path.is_file():
                    raise FolderDecryptionError(
                        "Symbolic links and non-regular files "
                        "are not supported."
                    )

                if not file_path.name.endswith(".sfv"):
                    raise FolderDecryptionError(
                        f"Unexpected file in encrypted folder: "
                        f"{file_path.name}"
                    )

                encrypted_files.append(file_path.relative_to(source))

        # Choose a meaningful name for the outer operation folder.
        if (
            source.name == "encrypted_files"
            and source.parent.name.endswith("_encrypted")
        ):
            base_name = (
                source.parent.name.removesuffix("_encrypted")
                + "_decryption_output"
            )
        else:
            base_name = (
                source.name.removesuffix("_encrypted")
                + "_decryption_output"
            )

        # Create a unique operation folder; never reuse an existing one.
        for number in range(10000):
            folder_name = (
                base_name
                if number == 0
                else f"{base_name}_{number}"
            )
            candidate = parent / folder_name

            try:
                candidate.mkdir()
                operation_folder = candidate
                break
            except FileExistsError:
                continue

        if operation_folder is None:
            raise FolderDecryptionError(
                "Could not create a unique output folder."
            )

        try:
            restored_folder = operation_folder / "restored_files"
            restored_folder.mkdir()

            for relative_dir in empty_directories:
                (restored_folder / relative_dir).mkdir(
                    parents=True,
                    exist_ok=True,
                )

            decrypted_files = []
            verified_count = 0
            unavailable_count = 0

            for relative_encrypted in encrypted_files:
                encrypted_path = source / relative_encrypted

                # Remove only the final .sfv extension.
                relative_output = Path(str(relative_encrypted)[:-4])

                if (
                    relative_output.is_absolute()
                    or ".." in relative_output.parts
                ):
                    raise FolderDecryptionError(
                        "Unsafe relative path detected."
                    )

                destination = restored_folder / relative_output
                destination.parent.mkdir(
                    parents=True,
                    exist_ok=True,
                )

                result = decrypt_file(
                    encrypted_path,
                    destination,
                    password,
                )

                integrity_verified = result.get(
                    "integrity_verified", False
                )

                if integrity_verified:
                    integrity_status = "VERIFIED"
                    verified_count += 1
                else:
                    integrity_status = "NOT AVAILABLE (SFV1)"
                    unavailable_count += 1

                decrypted_files.append({
                    "encrypted_path": str(relative_encrypted),
                    "restored_path": str(relative_output),
                    "size_bytes": result["decrypted_size_bytes"],
                    "original_sha256": result.get("original_sha256"),
                    "restored_sha256": result.get("restored_sha256"),
                    "integrity_verified": integrity_verified,
                    "integrity_status": integrity_status,
                    "format_version": result.get("format_version"),
                })

            return {
                "success": True,
                "encrypted_source": str(source),
                # Backward-compatible path: restored files are inside here.
                "output_folder": str(restored_folder),
                # Outer folder: report will be saved here.
                "operation_folder": str(operation_folder),
                "decrypted_file_count": len(decrypted_files),
                "integrity_verified_count": verified_count,
                "integrity_unavailable_count": unavailable_count,
                "files": decrypted_files,
            }

        except Exception:
            shutil.rmtree(operation_folder, ignore_errors=True)
            raise

    except FolderDecryptionError:
        raise

    except (OSError, FileEncryptionError, ValueError) as exc:
        raise FolderDecryptionError(
            f"Folder decryption failed: {exc}"
        ) from exc
