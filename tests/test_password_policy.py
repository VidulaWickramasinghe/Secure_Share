"""Negative and compatibility tests for newly established passwords."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from app.extensions import db
from app.models import User
from app.services.password_policy import (
    PasswordPolicyConfigurationError,
    validate_password_policy_configuration,
)


def test_shipped_production_corpus_is_valid_and_contains_real_common_passwords(app):
    path = Path(app.root_path) / "data" / "production-password-blocklist.sha256"
    app.config.update(APP_ENV="production", PASSWORD_BLOCKLIST_PATH=str(path))
    validate_password_policy_configuration(app)
    digests = set(path.read_text(encoding="ascii").splitlines())
    assert hashlib.sha256(b"123456").hexdigest() in digests
    assert hashlib.sha256(b"password").hexdigest() in digests


def _registration(client, password: str, *, username: str = "alice"):
    return client.post(
        "/api/auth/register",
        json={
            "username": username,
            "email": f"{username}@example.com",
            "password": password,
        },
    )


def test_new_password_requires_fifteen_characters(client):
    fourteen_characters = "abcdefghijklmn"
    fifteen_characters = "abcdefghijklmno"

    rejected = _registration(client, fourteen_characters)
    accepted = _registration(client, fifteen_characters, username="bob")

    assert len(fourteen_characters) == 14
    assert rejected.status_code == 400
    assert rejected.get_json() == {
        "error": "password must be at least 15 characters."
    }
    assert len(fifteen_characters) == 15
    assert accepted.status_code == 201


def test_long_password_with_unicode_and_spaces_is_preserved(client):
    password = "  moonlit caf\u00e9 \U0001f6e1\ufe0f passphrase  "

    registered = _registration(client, password)
    exact_login = client.post(
        "/api/auth/login",
        json={"identifier": "alice", "password": password},
    )
    trimmed_login = client.post(
        "/api/auth/login",
        json={"identifier": "alice", "password": password.strip()},
    )

    assert len(password) >= 15
    assert registered.status_code == 201
    assert exact_login.status_code == 200
    assert trimmed_login.status_code == 401


def test_bundled_compromised_password_is_rejected_as_a_whole_value(
    app, client
):
    compromised = "correcthorsebatterystaple"

    rejected = _registration(client, compromised)
    extended_value = _registration(
        client,
        f"{compromised} with a unique suffix",
        username="bob",
    )

    assert rejected.status_code == 400
    assert "compromised" in rejected.get_json()["error"].lower()
    assert compromised.encode() not in rejected.data
    assert extended_value.status_code == 201
    with app.app_context():
        assert User.query.filter_by(username="alice").one_or_none() is None


def test_configured_digest_file_extends_the_bundled_blocklist(
    app, client, tmp_path
):
    configured_password = "custom corpus passphrase 37"  # pragma: allowlist secret
    digest = hashlib.sha256(configured_password.encode("utf-8")).hexdigest()
    digest_file = tmp_path / "additional-passwords.sha256"
    digest_file.write_text(
        f"# deployment-specific whole-password digests\n{digest.upper()}\n",
        encoding="ascii",
    )
    app.config["PASSWORD_BLOCKLIST_PATH"] = str(digest_file)

    response = _registration(client, configured_password)

    assert response.status_code == 400
    assert "compromised" in response.get_json()["error"].lower()


def test_production_rejects_an_undersized_compromised_password_corpus(
    app, tmp_path
):
    digest_file = tmp_path / "undersized-passwords.sha256"
    digest_file.write_text("0" * 64 + "\n", encoding="ascii")
    app.config.update(
        APP_ENV="production",
        PASSWORD_BLOCKLIST_PATH=str(digest_file),
    )

    with pytest.raises(PasswordPolicyConfigurationError, match="10,000"):
        validate_password_policy_configuration(app)


def test_password_change_uses_the_same_policy(
    client, register_user, login_user, bearer_headers
):
    register_user("alice")
    token = login_user("alice")
    headers = bearer_headers(token)

    too_short = client.patch(
        "/api/auth/password",
        headers=headers,
        json={
            "current_password": "CorrectHorseBatteryStaple!42",  # pragma: allowlist secret
            "new_password": "abcdefghijklmn",
        },
    )
    compromised = client.patch(
        "/api/auth/password",
        headers=headers,
        json={
            "current_password": "CorrectHorseBatteryStaple!42",  # pragma: allowlist secret
            "new_password": "correcthorsebatterystaple",  # pragma: allowlist secret
        },
    )

    assert too_short.status_code == 400
    assert "at least 15" in too_short.get_json()["error"]
    assert compromised.status_code == 400
    assert "compromised" in compromised.get_json()["error"].lower()
    assert client.post(
        "/api/auth/login",
        json={
            "identifier": "alice",
            "password": "CorrectHorseBatteryStaple!42",  # pragma: allowlist secret
        },
    ).status_code == 200


def test_existing_short_hashed_credential_still_authenticates(app, client):
    legacy_password = "legacy8!"  # pragma: allowlist secret
    with app.app_context():
        user = User(
            username="legacy",
            email="legacy@example.com",
            password_hash="",
        )
        # set_password deliberately remains a hashing primitive. Establishment
        # flows enforce policy before calling it, while pre-policy hashes remain
        # verifiable for compatibility.
        user.set_password(legacy_password)
        db.session.add(user)
        db.session.commit()

    response = client.post(
        "/api/auth/login",
        json={"identifier": "legacy", "password": legacy_password},
    )

    assert len(legacy_password) < 15
    assert response.status_code == 200
    assert response.get_json()["token"]
