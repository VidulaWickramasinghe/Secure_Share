"""Minimal email delivery boundary for verification and recovery messages."""

from __future__ import annotations

import os
import smtplib
import ssl
from email.message import EmailMessage
from pathlib import Path
from urllib.parse import quote
from uuid import uuid4

from flask import current_app

from app.models.user import User


class EmailDeliveryError(RuntimeError):
    """An email could not be handed to the configured local transport."""


def _message(recipient: str, subject: str, text: str) -> EmailMessage:
    message = EmailMessage()
    message["From"] = current_app.config["MAIL_FROM_ADDRESS"]
    message["To"] = recipient
    message["Subject"] = subject
    message.set_content(text)
    return message


def _deliver_to_memory(message: EmailMessage) -> None:
    """Testing transport kept entirely inside the current app instance."""

    outbox = current_app.extensions.setdefault("secure_share_mail_outbox", [])
    outbox.append(message)


def _deliver_to_file(message: EmailMessage) -> None:
    """Write a development-only RFC 5322 message with private permissions."""

    try:
        configured = Path(current_app.config["MAIL_FILE_OUTBOX"])
        if not configured.is_absolute():
            configured = Path(current_app.instance_path) / configured
        directory = configured.resolve()
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if os.name == "posix":
            directory.chmod(0o700)

        destination = directory / f"{uuid4().hex}.eml"
        descriptor = os.open(
            destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
        )
        with os.fdopen(descriptor, "wb") as destination_file:
            destination_file.write(message.as_bytes())
    except OSError as exc:
        raise EmailDeliveryError(
            "The development email could not be written."
        ) from exc


def _deliver_to_smtp(message: EmailMessage) -> None:
    host = current_app.config["SMTP_HOST"]
    port = int(current_app.config["SMTP_PORT"])
    timeout = float(current_app.config["SMTP_TIMEOUT_SECONDS"])
    username = current_app.config.get("SMTP_USERNAME")
    password = current_app.config.get("SMTP_PASSWORD")
    use_ssl = bool(current_app.config["SMTP_USE_SSL"])
    use_starttls = bool(current_app.config["SMTP_USE_STARTTLS"])
    context = ssl.create_default_context()

    try:
        connection = (
            smtplib.SMTP_SSL(host, port, timeout=timeout, context=context)
            if use_ssl
            else smtplib.SMTP(host, port, timeout=timeout)
        )
        with connection:
            if use_starttls and not use_ssl:
                connection.starttls(context=context)
            if username:
                connection.login(username, password or "")
            connection.send_message(message)
    except (OSError, smtplib.SMTPException) as exc:
        raise EmailDeliveryError("The email provider rejected the message.") from exc


def deliver_email(recipient: str, subject: str, text: str) -> bool:
    """Deliver without logging message content or secret-bearing links."""

    message = _message(recipient, subject, text)
    backend = current_app.config["MAIL_BACKEND"]
    if backend == "memory":
        _deliver_to_memory(message)
    elif backend == "file":
        _deliver_to_file(message)
    elif backend == "smtp":
        _deliver_to_smtp(message)
    elif backend == "disabled":
        return False
    else:
        raise RuntimeError(f"Unsupported MAIL_BACKEND: {backend}")
    return True


def _fragment_link(path: str, token: str) -> str:
    base_url = current_app.config["PUBLIC_BASE_URL"].rstrip("/")
    return f"{base_url}{path}#token={quote(token, safe='')}"


def send_verification_email(user: User, raw_token: str) -> bool:
    link = _fragment_link("/verify-email", raw_token)
    return deliver_email(
        user.email,
        "Verify your Secure Share email",
        (
            f"Hello {user.username},\n\n"
            "Verify your email address to receive files shared with you:\n"
            f"{link}\n\n"
            "This single-use link expires automatically. If you did not create "
            "this account, you can ignore this message."
        ),
    )


def send_password_reset_email(user: User, raw_token: str) -> bool:
    link = _fragment_link("/reset-password", raw_token)
    return deliver_email(
        user.email,
        "Reset your Secure Share password",
        (
            f"Hello {user.username},\n\n"
            "Use this single-use link to choose a new password:\n"
            f"{link}\n\n"
            "If you did not request a reset, ignore this message. Your current "
            "password has not been changed."
        ),
    )


def send_password_changed_email(user: User) -> bool:
    return deliver_email(
        user.email,
        "Your Secure Share password was changed",
        (
            f"Hello {user.username},\n\n"
            "Your Secure Share password was changed. Other existing sessions "
            "were revoked as a precaution. If this was not you, contact the "
            "service operator immediately."
        ),
    )


__all__ = [
    "EmailDeliveryError",
    "deliver_email",
    "send_password_changed_email",
    "send_password_reset_email",
    "send_verification_email",
]
