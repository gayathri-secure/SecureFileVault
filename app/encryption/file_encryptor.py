
import hashlib
import hmac
import os
import struct
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


MAGIC_V1 = b"SFV1"
MAGIC_V2 = b"SFV2"

SALT_SIZE = 16
NONCE_PREFIX_SIZE = 8
TAG_SIZE = 16
KEY_SIZE = 32

CHUNK_SIZE = 1024 * 1024
MAX_CHUNK_SIZE = 4 * 1024 * 1024

HEADER_SIZE_V1 = 4 + SALT_SIZE + NONCE_PREFIX_SIZE + 4
HEADER_SIZE_V2 = HEADER_SIZE_V1 + 32


class FileEncryptionError(Exception):
    """Raised when file encryption or decryption fails."""


def _derive_key(password, salt):
    if not isinstance(password, str) or not password:
        raise FileEncryptionError("A non-empty password is required.")

    if len(salt) != SALT_SIZE:
        raise FileEncryptionError("Invalid encryption salt.")

    kdf = Scrypt(
        salt=salt,
        length=KEY_SIZE,
        n=2**14,
        r=8,
        p=1,
    )
    return kdf.derive(password.encode("utf-8"))


def _make_nonce(prefix, counter):
    if len(prefix) != NONCE_PREFIX_SIZE:
        raise FileEncryptionError("Invalid nonce prefix.")

    if not 0 <= counter <= 0xFFFFFFFF:
        raise FileEncryptionError("File contains too many chunks.")

    return prefix + struct.pack(">I", counter)


def _chunk_aad(header, counter):
    return header + struct.pack(">I", counter)


def encrypt_file(source_path, output_path, password):
    """Encrypt using AES-256-GCM with authenticated SHA-256 metadata."""

    source = Path(source_path)
    output = Path(output_path)
    output_created = False

    if not isinstance(password, str) or not password:
        raise FileEncryptionError("A non-empty password is required.")

    if source.is_symlink() or output.is_symlink():
        raise FileEncryptionError("Symbolic links are not supported.")

    try:
        source = source.resolve(strict=True)
        output_parent = output.parent.resolve(strict=True)
        output = output_parent / output.name

        if not source.is_file():
            raise FileEncryptionError(
                "The source must be a regular file."
            )

        if source == output:
            raise FileEncryptionError(
                "Input and output files must be different."
            )

        if output.exists():
            raise FileEncryptionError(
                "Output already exists. Choose a new output filename."
            )

        # First pass: calculate original SHA-256.
        original_hasher = hashlib.sha256()

        with source.open("rb") as input_file:
            while True:
                chunk = input_file.read(CHUNK_SIZE)
                if not chunk:
                    break
                original_hasher.update(chunk)

        digest = original_hasher.digest()
        salt = os.urandom(SALT_SIZE)
        nonce_prefix = os.urandom(NONCE_PREFIX_SIZE)

        key = _derive_key(password, salt)
        aesgcm = AESGCM(key)

        # SFV2 header includes the original SHA-256 digest.
        header = (
            MAGIC_V2
            + salt
            + nonce_prefix
            + struct.pack(">I", CHUNK_SIZE)
            + digest
        )

        with source.open("rb") as input_file:
            # Exclusive creation prevents overwriting existing files.
            with output.open("xb") as output_file:
                output_created = True
                output_file.write(header)

                counter = 0
                second_hasher = hashlib.sha256()

                while True:
                    chunk = input_file.read(CHUNK_SIZE)
                    if not chunk:
                        break

                    second_hasher.update(chunk)

                    nonce = _make_nonce(nonce_prefix, counter)
                    aad = _chunk_aad(header, counter)

                    encrypted_chunk = aesgcm.encrypt(
                        nonce, chunk, aad
                    )

                    output_file.write(
                        struct.pack(">I", len(encrypted_chunk))
                    )
                    output_file.write(encrypted_chunk)
                    counter += 1

                # Detect a source file that changed during encryption.
                if not hmac.compare_digest(
                    second_hasher.digest(), digest
                ):
                    raise FileEncryptionError(
                        "The source file changed during encryption. "
                        "The encrypted output was not completed."
                    )

                # Authenticated end marker detects truncation.
                final_nonce = _make_nonce(nonce_prefix, counter)
                final_aad = _chunk_aad(header, counter)

                final_marker = aesgcm.encrypt(
                    final_nonce, b"", final_aad
                )

                output_file.write(
                    struct.pack(">I", len(final_marker))
                )
                output_file.write(final_marker)
                output_file.flush()
                os.fsync(output_file.fileno())

        return {
            "source": str(source),
            "output": str(output),
            "original_size_bytes": source.stat().st_size,
            "encrypted_size_bytes": output.stat().st_size,
            "original_sha256": digest.hex(),
            "algorithm": "AES-256-GCM",
            "format_version": 2,
        }

    except FileEncryptionError:
        if output_created:
            try:
                output.unlink(missing_ok=True)
            except OSError:
                pass
        raise

    except (OSError, ValueError, OverflowError) as exc:
        if output_created:
            try:
                output.unlink(missing_ok=True)
            except OSError:
                pass

        raise FileEncryptionError(
            f"File encryption failed: {exc}"
        ) from exc


def decrypt_file(encrypted_path, output_path, password):
    """Decrypt, authenticate, and verify SHA-256 for SFV2 files."""

    encrypted = Path(encrypted_path)
    output = Path(output_path)
    temporary = None

    if not isinstance(password, str) or not password:
        raise FileEncryptionError("A non-empty password is required.")

    if encrypted.is_symlink() or output.is_symlink():
        raise FileEncryptionError("Symbolic links are not supported.")

    try:
        encrypted = encrypted.resolve(strict=True)
        output_parent = output.parent.resolve(strict=True)
        output = output_parent / output.name

        if not encrypted.is_file():
            raise FileEncryptionError(
                "The encrypted source must be a regular file."
            )

        if encrypted == output:
            raise FileEncryptionError(
                "Input and output files must be different."
            )

        if output.exists():
            raise FileEncryptionError(
                "Output already exists. Choose a new output filename."
            )

        with encrypted.open("rb") as input_file:
            magic = input_file.read(4)

            if magic == MAGIC_V1:
                version = 1
                header_size = HEADER_SIZE_V1
                expected_digest = None

            elif magic == MAGIC_V2:
                version = 2
                header_size = HEADER_SIZE_V2
                expected_digest = None

            else:
                raise FileEncryptionError(
                    "Invalid or unsupported encrypted file."
                )

            remaining_header = input_file.read(header_size - 4)

            if len(remaining_header) != header_size - 4:
                raise FileEncryptionError(
                    "Encrypted file header is incomplete."
                )

            header = magic + remaining_header
            offset = 4

            salt = header[offset:offset + SALT_SIZE]
            offset += SALT_SIZE

            nonce_prefix = header[
                offset:offset + NONCE_PREFIX_SIZE
            ]
            offset += NONCE_PREFIX_SIZE

            chunk_size = struct.unpack(
                ">I", header[offset:offset + 4]
            )[0]
            offset += 4

            if not 1 <= chunk_size <= MAX_CHUNK_SIZE:
                raise FileEncryptionError(
                    "Invalid encrypted file chunk size."
                )

            if version == 2:
                expected_digest = header[offset:offset + 32]

            key = _derive_key(password, salt)
            aesgcm = AESGCM(key)

            # Temporary file is published only after verification.
            for _ in range(1000):
                candidate = output.with_name(
                    f".{output.name}.sfvtmp-{os.urandom(8).hex()}"
                )

                try:
                    temporary = candidate
                    output_file = temporary.open("xb")
                    break

                except FileExistsError:
                    continue

            else:
                raise FileEncryptionError(
                    "Could not create a temporary output file."
                )

            restored_hasher = hashlib.sha256()

            with output_file:
                counter = 0

                while True:
                    length_bytes = input_file.read(4)

                    if len(length_bytes) != 4:
                        raise FileEncryptionError(
                            "Encrypted file is incomplete or corrupted."
                        )

                    encrypted_length = struct.unpack(
                        ">I", length_bytes
                    )[0]

                    if encrypted_length < TAG_SIZE:
                        raise FileEncryptionError(
                            "Invalid encrypted chunk length."
                        )

                    if encrypted_length > chunk_size + TAG_SIZE:
                        raise FileEncryptionError(
                            "Encrypted chunk exceeds the allowed size."
                        )

                    encrypted_chunk = input_file.read(encrypted_length)

                    if len(encrypted_chunk) != encrypted_length:
                        raise FileEncryptionError(
                            "Encrypted file is truncated."
                        )

                    nonce = _make_nonce(nonce_prefix, counter)
                    aad = _chunk_aad(header, counter)

                    try:
                        plaintext = aesgcm.decrypt(
                            nonce, encrypted_chunk, aad
                        )

                    except InvalidTag as exc:
                        raise FileEncryptionError(
                            "Authentication failed: wrong password "
                            "or encrypted data was modified."
                        ) from exc

                    if plaintext == b"":
                        if input_file.read(1):
                            raise FileEncryptionError(
                                "Unexpected data after the end marker."
                            )
                        break

                    if len(plaintext) > chunk_size:
                        raise FileEncryptionError(
                            "Decrypted chunk exceeds the allowed size."
                        )

                    output_file.write(plaintext)
                    restored_hasher.update(plaintext)
                    counter += 1

                output_file.flush()
                os.fsync(output_file.fileno())

            restored_digest = restored_hasher.digest()

            if version == 2 and not hmac.compare_digest(
                restored_digest, expected_digest
            ):
                raise FileEncryptionError(
                    "Integrity verification failed: restored SHA-256 "
                    "does not match the authenticated original hash."
                )

        # Publish without overwriting an existing destination.
        os.link(temporary, output)
        temporary.unlink()
        temporary = None

        return {
            "encrypted_source": str(encrypted),
            "output": str(output),
            "decrypted_size_bytes": output.stat().st_size,
            "original_sha256": (
                expected_digest.hex() if version == 2 else None
            ),
            "restored_sha256": restored_digest.hex(),
            "integrity_verified": version == 2,
            "format_version": version,
            "algorithm": "AES-256-GCM",
        }

    except FileEncryptionError:
        raise

    except (OSError, ValueError, OverflowError, struct.error) as exc:
        raise FileEncryptionError(
            f"File decryption failed: {exc}"
        ) from exc

    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
