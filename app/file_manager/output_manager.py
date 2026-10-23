
from pathlib import Path


class OutputFolderError(Exception):
    """Raised when an output folder cannot be safely created."""


def create_unique_output_folder(source_folder, output_parent):
    """
    Create a unique, empty output folder inside the selected parent.

    Existing output folders are never reused or overwritten.
    """

    # Preserve FileNotFoundError for paths that do not exist.
    source = Path(source_folder).resolve(strict=True)
    parent = Path(output_parent).resolve(strict=True)

    if not source.is_dir():
        raise OutputFolderError("The source path is not a directory.")

    if not parent.is_dir():
        raise OutputFolderError("The output location is not a directory.")

    # Prevent the output parent from being inside the source folder.
    try:
        parent.relative_to(source)
    except ValueError:
        pass
    else:
        raise OutputFolderError(
            "The output location cannot be inside the source folder."
        )

    base_name = f"{source.name}_encrypted"

    for number in range(10000):
        if number == 0:
            candidate = parent / base_name
        else:
            candidate = parent / f"{base_name}_{number}"

        # Prevent the generated output folder from containing the source.
        resolved_candidate = candidate.resolve(strict=False)

        try:
            source.relative_to(resolved_candidate)
        except ValueError:
            pass
        else:
            raise OutputFolderError(
                "The generated output folder cannot contain the source folder."
            )

        try:
            candidate.mkdir()
            return candidate
        except FileExistsError:
            continue
        except OSError as exc:
            raise OutputFolderError(
                f"Could not create the output folder: {exc}"
            ) from exc

    raise OutputFolderError(
        "Could not find an available unique output folder name."
    )
