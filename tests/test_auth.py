"""Authentication, account-management, and credential-security tests."""

from __future__ import annotations

from datetime import timedelta

from werkzeug.security import check_password_hash

from app.extensions import db
from app.models import AuthSession, User
from app.models.user import utc_now
from app.utils.security import hash_session_token


def test_registration_returns_safe_account_data(client):
    response = client.post(
        "/api/auth/register",
        json={
            "username": "alice",
            "email": "alice@example.com",
            "password": "CorrectHorseBatteryStaple!42",
        },
    )

    assert response.status_code == 201
    user = response.get_json()["user"]
    assert user["username"] == "alice"
    assert user["email"] == "alice@example.com"
    assert isinstance(user["id"], int)
    assert user["created_at"]
    assert "password" not in user
    assert "password_hash" not in user


def test_registration_hashes_password(app, client):
    plain_text = "CorrectHorseBatteryStaple!42"
    response = client.post(
        "/api/auth/register",
        json={
            "username": "alice",
            "email": "alice@example.com",
            "password": plain_text,
        },
    )
    assert response.status_code == 201

    with app.app_context():
        user = User.query.filter_by(username="alice").one()
        assert user.password_hash != plain_text
        assert plain_text not in user.password_hash
        assert check_password_hash(user.password_hash, plain_text)


def test_duplicate_username_and_email_are_rejected(client, register_user):
    register_user("alice", "alice@example.com")

    duplicate_username = client.post(
        "/api/auth/register",
        json={
            "username": "Alice",
            "email": "different@example.com",
            "password": "AnotherSecurePassword!42",
        },
    )
    duplicate_email = client.post(
        "/api/auth/register",
        json={
            "username": "different",
            "email": "ALICE@EXAMPLE.COM",
            "password": "AnotherSecurePassword!42",
        },
    )

    assert duplicate_username.status_code == 409
    assert duplicate_email.status_code == 409
    assert "error" in duplicate_username.get_json()
    assert "error" in duplicate_email.get_json()


def test_registration_validates_required_fields_and_json(client):
    missing = client.post(
        "/api/auth/register",
        json={"username": "alice", "email": "alice@example.com"},
    )
    malformed_content_type = client.post(
        "/api/auth/register",
        data="not-json",
        content_type="text/plain",
    )

    assert missing.status_code == 400
    assert malformed_content_type.status_code == 400
    assert "error" in missing.get_json()
    assert "error" in malformed_content_type.get_json()


def test_login_with_valid_credentials_returns_bearer_token(
    app, client, register_user
):
    register_user("alice", "alice@example.com")

    response = client.post(
        "/api/auth/login",
        json={
            "identifier": "alice",
            "password": "CorrectHorseBatteryStaple!42",
        },
    )

    assert response.status_code == 200
    body = response.get_json()
    assert isinstance(body["token"], str) and len(body["token"]) >= 32
    assert body["token_type"] == "Bearer"
    assert body["expires_at"]
    assert body["user"]["username"] == "alice"
    assert "password" not in body["user"]
    assert "password_hash" not in body["user"]
    with app.app_context():
        session = AuthSession.query.one()
        assert session.token_hash != body["token"]
        assert session.token_hash == hash_session_token(body["token"])


def test_login_accepts_email_as_identifier(client, register_user):
    register_user("alice", "alice@example.com")

    response = client.post(
        "/api/auth/login",
        json={
            "identifier": "alice@example.com",
            "password": "CorrectHorseBatteryStaple!42",
        },
    )

    assert response.status_code == 200
    assert response.get_json()["token"]


def test_login_rejects_invalid_credentials_without_account_leakage(
    client, register_user
):
    register_user("alice", "alice@example.com")

    wrong_password = client.post(
        "/api/auth/login",
        json={"identifier": "alice", "password": "definitely-wrong"},
    )
    unknown_user = client.post(
        "/api/auth/login",
        json={"identifier": "unknown", "password": "definitely-wrong"},
    )

    assert wrong_password.status_code == 401
    assert unknown_user.status_code == 401
    assert wrong_password.get_json()["error"] == unknown_user.get_json()["error"]


def test_oversized_password_inputs_are_rejected_before_hashing(
    client, register_user, login_user, bearer_headers
):
    register_user("alice", "alice@example.com")
    oversized = "x" * 1_025

    login = client.post(
        "/api/auth/login",
        json={"identifier": "alice", "password": oversized},
    )
    token = login_user("alice")
    change = client.patch(
        "/api/auth/password",
        headers=bearer_headers(token),
        json={
            "current_password": oversized,
            "new_password": "A-Different-Strong-Password!99",
        },
    )

    assert login.status_code == 401
    assert change.status_code == 400


def test_protected_account_endpoint_requires_authentication(client):
    response = client.get("/api/auth/me")

    assert response.status_code == 401
    assert "error" in response.get_json()


def test_me_returns_authenticated_user(
    client, register_user, login_user, bearer_headers
):
    expected = register_user("alice", "alice@example.com")
    token = login_user("alice")

    response = client.get("/api/auth/me", headers=bearer_headers(token))

    assert response.status_code == 200
    assert response.get_json()["user"]["id"] == expected["id"]
    assert "password_hash" not in response.get_json()["user"]


def test_logout_revokes_current_token(
    client, register_user, login_user, bearer_headers
):
    register_user("alice")
    token = login_user("alice")

    logout = client.post(
        "/api/auth/logout", headers=bearer_headers(token)
    )
    after_logout = client.get(
        "/api/auth/me", headers=bearer_headers(token)
    )

    assert logout.status_code == 200
    assert after_logout.status_code == 401


def test_expired_session_token_is_rejected(
    app, client, register_user, login_user, bearer_headers
):
    register_user("alice")
    token = login_user("alice")
    with app.app_context():
        session = AuthSession.query.one()
        session.expires_at = utc_now() - timedelta(seconds=1)
        db.session.commit()

    response = client.get("/api/auth/me", headers=bearer_headers(token))

    assert response.status_code == 401


def test_change_password_requires_current_password_and_revokes_old_sessions(
    client, register_user, login_user, bearer_headers
):
    register_user("alice")
    token_one = login_user("alice")
    token_two = login_user("alice")

    wrong_current = client.patch(
        "/api/auth/password",
        headers=bearer_headers(token_one),
        json={
            "current_password": "wrong-password",
            "new_password": "A-Different-Strong-Password!99",
        },
    )
    changed = client.patch(
        "/api/auth/password",
        headers=bearer_headers(token_one),
        json={
            "current_password": "CorrectHorseBatteryStaple!42",
            "new_password": "A-Different-Strong-Password!99",
        },
    )

    assert wrong_current.status_code == 400
    assert changed.status_code == 200
    assert client.get("/api/auth/me", headers=bearer_headers(token_one)).status_code == 200
    assert client.get("/api/auth/me", headers=bearer_headers(token_two)).status_code == 401
    assert client.post(
        "/api/auth/login",
        json={
            "identifier": "alice",
            "password": "CorrectHorseBatteryStaple!42",
        },
    ).status_code == 401
    assert client.post(
        "/api/auth/login",
        json={
            "identifier": "alice",
            "password": "A-Different-Strong-Password!99",
        },
    ).status_code == 200


def test_malformed_and_unknown_bearer_tokens_are_rejected(client):
    malformed = client.get(
        "/api/auth/me", headers={"Authorization": "not-a-bearer-token"}
    )
    unknown = client.get(
        "/api/auth/me", headers={"Authorization": "Bearer unknown-token"}
    )

    assert malformed.status_code == 401
    assert unknown.status_code == 401
