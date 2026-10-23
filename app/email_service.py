
"""Send SecureFileVault OTP emails using Gmail SMTP."""

import os
import smtplib
from email.message import EmailMessage


class EmailDeliveryError(Exception):
    """Raised when an OTP email cannot be delivered."""


def send_otp_email(recipient_email, otp):
    """Send an OTP to the email address supplied by the user."""

    sender_email = os.getenv("GMAIL_ADDRESS")
    app_password = os.getenv("GMAIL_APP_PASSWORD")

    if not sender_email or not app_password:
        raise EmailDeliveryError(
            "Email sender configuration is missing. Check your .env file."
        )

    if not isinstance(recipient_email, str) or not recipient_email.strip():
        raise EmailDeliveryError("Please enter a valid recipient email address.")

    message = EmailMessage()
    message["Subject"] = "Your SecureFileVault Verification Code"
    message["From"] = sender_email
    message["To"] = recipient_email.strip()
    message.set_content(
        f"""Hello,

Your SecureFileVault verification code is: {otp}

This code expires in 5 minutes. Do not share it with anyone.

If you did not request this code, you can ignore this email.

SecureFileVault
"""
    )

    try:
        with smtplib.SMTP_SSL(
            "smtp.gmail.com", 465, timeout=30
        ) as smtp:
            smtp.login(sender_email, app_password)
            smtp.send_message(message)

    except (smtplib.SMTPException, OSError) as exc:
        print(f"OTP email error ({type(exc).__name__}): {exc}")
        raise EmailDeliveryError(
            "Could not send the verification email. Check the email "
            "configuration and internet connection."
        ) from exc
