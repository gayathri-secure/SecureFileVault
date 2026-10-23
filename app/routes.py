
from pathlib import Path
import tkinter as tk
import os
from tkinter import filedialog

from flask import Blueprint, render_template, request, jsonify

from app.encryption.folder_encryptor import (
    encrypt_folder,
    FolderEncryptionError,
)
from app.decryption.folder_decryptor import (
    decrypt_folder,
    FolderDecryptionError,
)
from app.integrity.hash_utils import (
    calculate_sha256,
    calculate_folder_hashes,
    HashCalculationError,
)
from app.integrity.report_generator import (
    generate_encryption_report,
    generate_decryption_report,
    ReportGenerationError,
)
from app.file_manager.scanner import (
    scan_folder,
    FileScanError,
)

import json
from app.owner_record import verify_owner_record, OwnerRecordError

import re
import secrets
import threading
import time

from flask import session

from app.otp_service import (
    generate_otp,
    create_otp_record,
    verify_otp,
)
from app.email_service import send_otp_email, EmailDeliveryError

main_bp = Blueprint("main", __name__)

# Temporary server-side OTP storage for local development.
# OTP records are not stored in the browser cookie.
_OTP_STORE = {}
_OTP_LOCK = threading.Lock()

OTP_RESEND_COOLDOWN = 60
OTP_MAX_REQUESTS_PER_HOUR = 5


def _get_otp_session_id():
    """Get or create a random identifier for the current browser session."""
    if "otp_session_id" not in session:
        session["otp_session_id"] = secrets.token_urlsafe(32)

    return session["otp_session_id"]


@main_bp.route("/")
def home():
    return render_template("index.html")


@main_bp.route("/encrypt")
def encrypt_page():
    return render_template("encrypt.html")


@main_bp.route("/decrypt")
def decrypt_page():
    return render_template("decrypt.html")


@main_bp.route("/api/select-folder", methods=["POST"])
def select_folder():
    data = request.get_json(silent=True) or {}
    folder_type = data.get("type")

    if folder_type not in {"source", "output"}:
        return jsonify({
            "success": False,
            "message": "Invalid folder selection type.",
        }), 400

    root = None

    try:
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)

        dialog_title = (
            "Choose Source Folder"
            if folder_type == "source"
            else "Choose Output Location (Parent Folder)"
        )

        selected_folder = filedialog.askdirectory(
            parent=root,
            title=dialog_title,
            mustexist=True,
        )

        if not selected_folder:
            return jsonify({
                "success": False,
                "cancelled": True,
                "message": "Folder selection cancelled.",
            })

        return jsonify({
            "success": True,
            "path": selected_folder,
        })

    except tk.TclError:
        return jsonify({
            "success": False,
            "message": "Could not open the folder picker.",
        }), 500

    finally:
        if root is not None:
            try:
                root.destroy()
            except tk.TclError:
                pass


@main_bp.route("/api/scan-folder", methods=["POST"])
def scan_source_folder():
    data = request.get_json(silent=True) or {}
    source_folder = data.get("source")

    if not isinstance(source_folder, str) or not source_folder.strip():
        return jsonify({
            "success": False,
            "message": "Please select a source folder.",
        }), 400

    try:
        result = scan_folder(source_folder)

        return jsonify({
            "success": True,
            "scan": result,
        })

    except FileScanError as exc:
        return jsonify({
            "success": False,
            "message": str(exc),
        }), 400

    except (OSError, ValueError) as exc:
        return jsonify({
            "success": False,
            "message": f"Could not scan the source folder: {exc}",
        }), 400


@main_bp.route("/api/hash-folder", methods=["POST"])
def hash_source_folder():
    data = request.get_json(silent=True) or {}
    source_folder = data.get("source")

    if not isinstance(source_folder, str) or not source_folder.strip():
        return jsonify({
            "success": False,
            "message": "Please select a source folder.",
        }), 400

    try:
        result = calculate_folder_hashes(source_folder)

        return jsonify({
            "success": True,
            "hashes": result,
        })

    except (HashCalculationError, OSError, ValueError) as exc:
        return jsonify({
            "success": False,
            "message": f"Could not calculate file hashes: {exc}",
        }), 400


@main_bp.route("/api/encrypt-folder", methods=["POST"])
def encrypt_source_folder():
    data = request.get_json(silent=True) or {}

    source = data.get("source")
    output_parent = data.get("output_parent")
    password = data.get("password")
    algorithm = data.get("algorithm")
    generate_report = data.get("generate_report", False)
    owner_email = data.get("owner_email")

    if not isinstance(source, str) or not source.strip():
        return jsonify({
            "success": False,
            "message": "Please select a source folder.",
        }), 400

    if not isinstance(output_parent, str) or not output_parent.strip():
        return jsonify({
            "success": False,
            "message": "Please select an output location.",
        }), 400

    if not isinstance(password, str) or len(password) < 12:
        return jsonify({
            "success": False,
            "message": "Password must contain at least 12 characters.",
        }), 400

    if algorithm != "AES-256-GCM":
        return jsonify({
            "success": False,
            "message": "Only AES-256-GCM is currently supported.",
        }), 400

    if not isinstance(generate_report, bool):
        return jsonify({
            "success": False,
            "message": "Invalid report option.",
        }), 400

        owner_email = data.get("owner_email")

    if not isinstance(owner_email, str) or not re.fullmatch(
        r"[^@\s]+@[^@\s]+\.[^@\s]+",
        owner_email.strip(),
    ):
        return jsonify({
            "success": False,
            "message": "Please enter a valid owner email address.",
        }), 400

    owner_email = owner_email.strip().casefold()
    session_id = session.get("otp_session_id")

    if not session_id:
        return jsonify({
            "success": False,
            "message": "Verify the owner email OTP before encryption.",
        }), 403

    with _OTP_LOCK:
        otp_record = _OTP_STORE.get(session_id)

        if not otp_record or not otp_record.get("verified"):
            return jsonify({
                "success": False,
                "message": "Please verify the owner email OTP before encryption.",
            }), 403

        if time.time() >= otp_record.get("expires_at", 0):
            _OTP_STORE.pop(session_id, None)
            return jsonify({
                "success": False,
                "message": "OTP authorization expired. Please verify again.",
            }), 403

        if owner_email != otp_record.get("email"):
            return jsonify({
                "success": False,
                "message": "Owner email does not match the verified email.",
            }), 403

        # Consume the verified authorization for this encryption attempt.
        _OTP_STORE.pop(session_id, None)

    try:
        original_hashes = {}

        if generate_report:
            scan = scan_folder(source)

            if scan["skipped"]:
                return jsonify({
                    "success": False,
                    "message": (
                        "Some source items could not be scanned safely. "
                        "Resolve them before encryption."
                    ),
                }), 400

            source_root = Path(source).resolve(strict=True)

            for item in scan["files"]:
                original_path = source_root / item["path"]
                original_hashes[item["path"]] = calculate_sha256(
                    original_path
                )

        result = encrypt_folder(
            source_folder=source,
            output_parent=output_parent,
            password=password,
            owner_email=owner_email,
            )

    except (
        FolderEncryptionError,
        HashCalculationError,
        OSError,
        ValueError,
    ) as exc:
        return jsonify({
            "success": False,
            "message": f"Could not complete encryption: {exc}",
        }), 400

    report_info = None
    report_error = None

    if generate_report:
        try:
            # output_folder contains the .sfv files.
            encrypted_root = Path(result["output_folder"])
            operation_folder = Path(result["operation_folder"])
            records = []

            for item in result["files"]:
                relative_original = item["original_path"]
                relative_encrypted = item["encrypted_path"]
                encrypted_path = encrypted_root / relative_encrypted

                records.append({
                    "original_path": relative_original,
                    "encrypted_path": relative_encrypted,
                    "original_sha256": original_hashes[
                        relative_original
                    ],
                    "encrypted_sha256": calculate_sha256(
                        encrypted_path
                    ),
                    "original_size_bytes": item[
                        "original_size_bytes"
                    ],
                    "encrypted_size_bytes": item[
                        "encrypted_size_bytes"
                    ],
                })

            # Store the report beside encrypted_files.
            report_path = operation_folder / "encryption_report.xlsx"

            report_info = generate_encryption_report(
                report_path,
                records,
                algorithm="AES-256-GCM",
            )

        except (
            ReportGenerationError,
            HashCalculationError,
            OSError,
            ValueError,
            KeyError,
        ) as exc:
            # Encryption succeeded, even if report generation failed.
            report_error = str(exc)

    return jsonify({
        "success": True,
        "result": result,
        "report": report_info,
        "report_error": report_error,
    })


@main_bp.route("/api/request-otp", methods=["POST"])
def request_otp():
    data = request.get_json(silent=True) or {}
    email = data.get("email")

    if not isinstance(email, str):
        return jsonify({
            "success": False,
            "message": "Please enter a valid email address.",
        }), 400

    email = email.strip()

    if (
        len(email) > 254
        or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email)
    ):
        return jsonify({
            "success": False,
            "message": "Please enter a valid email address.",
        }), 400

    # For decryption, verify the vault owner before sending any OTP.
    purpose = data.get("purpose", "encrypt")

    if purpose == "decrypt":
        encrypted_folder = data.get("encrypted_folder")

        if (
            not isinstance(encrypted_folder, str)
            or not encrypted_folder.strip()
        ):
            return jsonify({
                "success": False,
                "message": "Please select the encrypted vault first.",
            }), 400

        try:
            encrypted_path = Path(encrypted_folder).resolve(strict=True)

            if (
                not encrypted_path.is_dir()
                or encrypted_path.name != "encrypted_files"
            ):
                return jsonify({
                    "success": False,
                    "message": "Please select the vault's encrypted_files folder.",
                }), 400

            owner_record_path = (
                encrypted_path.parent / "owner_record.json"
            )

            with owner_record_path.open("r", encoding="utf-8") as record_file:
                owner_record = json.load(record_file)

            registered_owner_email = verify_owner_record(
                owner_record,
                os.getenv("OTP_SECRET"),
            )

        except (OSError, json.JSONDecodeError, OwnerRecordError):
            return jsonify({
                "success": False,
                "message": "The vault owner record is missing or invalid.",
            }), 403

        if email.casefold() != registered_owner_email:
            return jsonify({
                "success": False,
                "message": (
                    "This email is not the registered owner of this vault. "
                    "No OTP was sent."
                ),
            }), 403

    elif purpose != "encrypt":
        return jsonify({
            "success": False,
            "message": "Invalid OTP request purpose.",
        }), 400

    session_id = _get_otp_session_id()
    now = time.time()

    with _OTP_LOCK:
        previous = _OTP_STORE.get(session_id, {})
        request_times = [
            timestamp
            for timestamp in previous.get("request_times", [])
            if now - timestamp < 3600
        ]

        if request_times and now - request_times[-1] < OTP_RESEND_COOLDOWN:
            return jsonify({
                "success": False,
                "message": "Please wait 60 seconds before requesting another OTP.",
            }), 429

        if len(request_times) >= OTP_MAX_REQUESTS_PER_HOUR:
            return jsonify({
                "success": False,
                "message": "OTP request limit reached. Try again later.",
            }), 429

        # Preserve request limits even when a new OTP is requested.
        request_times.append(now)

    otp = generate_otp()

    try:
        send_otp_email(email, otp)
    except EmailDeliveryError:
        return jsonify({
            "success": False,
            "message": "Could not send the OTP email. Check the email configuration and try again.",
        }), 502

    record = create_otp_record(otp, os.getenv("OTP_SECRET"))
    record["email"] = email.casefold()
    record["request_times"] = request_times

    with _OTP_LOCK:
        _OTP_STORE[session_id] = record

    return jsonify({
        "success": True,
        "message": "OTP sent. Check your email.",
    })


@main_bp.route("/api/verify-otp", methods=["POST"])
def verify_email_otp():
    data = request.get_json(silent=True) or {}
    submitted_otp = data.get("otp")
    session_id = session.get("otp_session_id")

    if not session_id:
        return jsonify({
            "success": False,
            "message": "Request an OTP first.",
        }), 400

    with _OTP_LOCK:
        record = _OTP_STORE.get(session_id)

        if not record:
            return jsonify({
                "success": False,
                "message": "No active OTP. Please request a new one.",
            }), 400

        success, message = verify_otp(
            record,
            submitted_otp,
            os.getenv("OTP_SECRET"),
        )

        if not success:
            if (
                record.get("attempts", 0) >= 5
                or time.time() >= record.get("expires_at", 0)
            ):
                _OTP_STORE.pop(session_id, None)

            return jsonify({
                "success": False,
                "message": message,
            }), 400

    return jsonify({
        "success": True,
        "message": "Email verified. You can now attempt decryption.",
    })


@main_bp.route("/api/decrypt-folder", methods=["POST"])
def decrypt_source_folder():
    data = request.get_json(silent=True) or {}

    encrypted_folder = data.get("encrypted_folder")
    output_parent = data.get("output_parent")
    password = data.get("password")

    if (
        not isinstance(encrypted_folder, str)
        or not encrypted_folder.strip()
    ):
        return jsonify({
            "success": False,
            "message": "Please select the encrypted folder.",
        }), 400

    if (
        not isinstance(output_parent, str)
        or not output_parent.strip()
    ):
        return jsonify({
            "success": False,
            "message": "Please select an output location.",
        }), 400

    if not isinstance(password, str) or not password:
        return jsonify({
            "success": False,
            "message": "Please enter the encryption password.",
        }), 400


    # Require a verified, unexpired OTP for this browser session.
    session_id = session.get("otp_session_id")

    if not session_id:
        return jsonify({
            "success": False,
            "message": "Email verification is required before decryption.",
        }), 403

    with _OTP_LOCK:
        otp_record = _OTP_STORE.get(session_id)

        if not otp_record or not otp_record.get("verified"):
            return jsonify({
                "success": False,
                "message": "Please verify your email OTP before decrypting.",
            }), 403

        if time.time() >= otp_record.get("expires_at", 0):
            _OTP_STORE.pop(session_id, None)
            return jsonify({
                "success": False,
                "message": "OTP authorization expired. Please verify your email again.",
            }), 403


        requested_email = data.get("email")

        if (
            not isinstance(requested_email, str)
            or requested_email.strip().casefold() != otp_record.get("email")
        ):
            return jsonify({
                "success": False,
                "message": "The email address does not match the verified email.",
            }), 403

        # Verify the registered owner of this encrypted vault.
        try:
            encrypted_path = Path(encrypted_folder).resolve(strict=True)

            if (
                not encrypted_path.is_dir()
                or encrypted_path.name != "encrypted_files"
            ):
                return jsonify({
                    "success": False,
                    "message": (
                        "Please select the encrypted_files folder "
                        "inside a SecureFileVault operation folder."
                    ),
                }), 400

            owner_record_path = (
                encrypted_path.parent / "owner_record.json"
            )

            with owner_record_path.open("r", encoding="utf-8") as record_file:
                owner_record = json.load(record_file)

            registered_owner_email = verify_owner_record(
                owner_record,
                os.getenv("OTP_SECRET"),
            )

        except (OSError, json.JSONDecodeError, OwnerRecordError):
            return jsonify({
                "success": False,
                "message": (
                    "The owner record is missing, invalid, or could not "
                    "be verified. Decryption was not started."
                ),
            }), 403

        if registered_owner_email != otp_record.get("email"):
            return jsonify({
                "success": False,
                "message": (
                    "The verified email does not match this vault's "
                    "registered owner."
                ),
            }), 403

        # Consume the authorization so it cannot be reused.
        _OTP_STORE.pop(session_id, None)

    # First decrypt and verify the files.
    try:
        result = decrypt_folder(
            encrypted_folder=encrypted_folder,
            output_parent=output_parent,
            password=password,
        )

    except FolderDecryptionError as exc:
        return jsonify({
            "success": False,
            "message": str(exc),
        }), 400

    report_info = None
    report_error = None

    try:
        # Save the report beside restored_files.
        operation_folder = Path(result["operation_folder"])
        report_path = operation_folder / "decryption_report.xlsx"

        report_info = generate_decryption_report(
            report_path,
            result["files"],
            algorithm="AES-256-GCM",
        )

    except (
        ReportGenerationError,
        OSError,
        ValueError,
        KeyError,
    ) as exc:
        # Decryption succeeded, even if report generation failed.
        report_error = str(exc)

    return jsonify({
        "success": True,
        "result": result,
        "report": report_info,
        "report_error": report_error,
    })
