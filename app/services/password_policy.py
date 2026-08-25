"""Password-establishment policy and offline compromised-value checks.

This policy applies only when a password is created or replaced. Authentication
continues to verify existing hashes exactly as they were established so a
policy change never silently locks out an existing account.
"""

from __future__ import annotations

import hashlib
import re
from functools import lru_cache
from pathlib import Path

from flask import current_app

MINIMUM_PASSWORD_LENGTH = 15
MAXIMUM_PASSWORD_LENGTH = 1024
MINIMUM_PRODUCTION_BLOCKLIST_DIGESTS = 10_000

_DIGEST_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")
_BUNDLED_BLOCKLIST_PATH = (
    Path(__file__).resolve().parent.parent
    / "data"
    / "compromised_passwords.sha256"
)


class PasswordPolicyError(ValueError):
    """A prospective password does not satisfy the public policy."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class PasswordPolicyConfigurationError(RuntimeError):
    """The operator-provided blocklist cannot be used safely."""


def _read_digest_file(path: Path) -> frozenset[str]:
    """Read a strict newline-delimited SHA-256 digest file.

    Blank lines and comments are allowed. Invalid data is rejected instead of
    being silently ignored because an operator may otherwise believe a custom
    compromised-password corpus is active when it is not.
    """

    try:
        lines = path.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError) as exc:
        raise PasswordPolicyConfigurationError(
            f"Password blocklist is not readable: {path}"
        ) from exc

    digests: set[str] = set()
    for line_number, raw_line in enumerate(lines, start=1):
        value = raw_line.strip()
        if not value or value.startswith("#"):
            continue
        if not _DIGEST_PATTERN.fullmatch(value):
            raise PasswordPolicyConfigurationError(
                "Password blocklist entries must be SHA-256 hex digests "
                f"({path}, line {line_number})."
            )
        digests.add(value.lower())
    return frozenset(digests)


_BUNDLED_DIGESTS = _read_digest_file(_BUNDLED_BLOCKLIST_PATH)


@lru_cache(maxsize=16)
def _read_configured_digest_file(path_value: str) -> frozenset[str]:
    return _read_digest_file(Path(path_value))


def _configured_digests() -> frozenset[str]:
    configured_path = current_app.config.get("PASSWORD_BLOCKLIST_PATH")
    if configured_path is None or not str(configured_path).strip():
        return frozenset()

    path = Path(str(configured_path)).expanduser()
    if not path.is_absolute():
        path = Path(current_app.root_path).parent / path
    return _read_configured_digest_file(str(path.resolve()))


def validate_password_policy_configuration(application) -> None:
    """Require a substantial external compromised corpus in production."""

    if str(application.config.get("APP_ENV", "")).lower() != "production":
        return
    configured_path = application.config.get("PASSWORD_BLOCKLIST_PATH")
    if configured_path is None or not str(configured_path).strip():
        raise PasswordPolicyConfigurationError(
            "Production requires PASSWORD_BLOCKLIST_PATH."
        )
    path = Path(str(configured_path)).expanduser()
    if not path.is_absolute():
        path = Path(application.root_path).parent / path
    digests = _read_configured_digest_file(str(path.resolve()))
    if len(digests) < MINIMUM_PRODUCTION_BLOCKLIST_DIGESTS:
        raise PasswordPolicyConfigurationError(
            "The production password blocklist must contain at least "
            f"{MINIMUM_PRODUCTION_BLOCKLIST_DIGESTS:,} unique SHA-256 digests."
        )


def _is_blocklisted(password: str) -> bool:
    digest = hashlib.sha256(password.encode("utf-8")).hexdigest()
    return digest in _BUNDLED_DIGESTS or digest in _configured_digests()


def validate_new_password(
    password: object,
    *,
    field: str = "password",
) -> str:
    """Validate a password that is about to be established.

    Spaces and Unicode are accepted and preserved. The complete value is
    checked without substring rules, case folding, trimming, or normalization.
    """

    if not isinstance(password, str):
        raise PasswordPolicyError(f"{field} is required.")
    if len(password) < MINIMUM_PASSWORD_LENGTH:
        raise PasswordPolicyError(
            f"{field} must be at least {MINIMUM_PASSWORD_LENGTH} characters."
        )
    if len(password) > MAXIMUM_PASSWORD_LENGTH:
        raise PasswordPolicyError(f"{field} is too long.")
    if _is_blocklisted(password):
        raise PasswordPolicyError(
            f"{field} is too common or is known to be compromised. "
            "Choose a different password."
        )
    return password


__all__ = [
    "MAXIMUM_PASSWORD_LENGTH",
    "MINIMUM_PASSWORD_LENGTH",
    "MINIMUM_PRODUCTION_BLOCKLIST_DIGESTS",
    "PasswordPolicyConfigurationError",
    "PasswordPolicyError",
    "validate_password_policy_configuration",
    "validate_new_password",
]
