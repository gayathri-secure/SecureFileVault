
import os
import base64
import hashlib
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32


class EncryptionError(Exception):
    """Raised when encryption or decryption fails."""


def derive_key(password, salt):
    """Derive a 256-bit encryption key from a password and salt."""

    if not isinstance(password, str) or not password:
        raise EncryptionError("A non-empty password is required.")

    if len(salt) != SALT_SIZE:
        raise EncryptionError("Invalid salt length.")

    kdf = Scrypt(
        salt=salt,
        length=KEY_SIZE,
        n=2**14,
        r=8,
        p=1,
    )

    return kdf.derive(password.encode("utf-8"))


def encrypt_bytes(data, password):
    """
    Encrypt bytes with AES-256-GCM.

    Returns a self-contained encrypted package with salt, nonce,
    and ciphertext. This is for the initial module tests.
    """

    if not isinstance(data, bytes):
        raise EncryptionError("Data must be bytes.")

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(password, salt)

    ciphertext = AESGCM(key).encrypt(nonce, data, None)

    return {
        "version": 1,
        "algorithm": "AES-256-GCM",
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }


def decrypt_bytes(package, password):
    """Decrypt and authenticate a package created by encrypt_bytes."""

    try:
        if package.get("version") != 1:
            raise EncryptionError("Unsupported encrypted package version.")

        if package.get("algorithm") != "AES-256-GCM":
            raise EncryptionError("Unsupported encryption algorithm.")

        salt = base64.b64decode(package["salt"], validate=True)
        nonce = base64.b64decode(package["nonce"], validate=True)
        ciphertext = base64.b64decode(
            package["ciphertext"],
            validate=True,
        )

        if len(salt) != SALT_SIZE or len(nonce) != NONCE_SIZE:
            raise EncryptionError("Invalid encryption metadata.")

        key = derive_key(password, salt)

        return AESGCM(key).decrypt(nonce, ciphertext, None)

    except EncryptionError:
        raise

    except (KeyError, TypeError, ValueError) as exc:
        raise EncryptionError("Invalid encrypted package.") from exc

    except InvalidTag as exc:
        raise EncryptionError(
            "Decryption failed: password is incorrect or data was modified."
        ) from exc
