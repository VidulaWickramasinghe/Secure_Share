"""Authentication, account-management, and credential-security tests."""

from __future__ import annotations

from datetime import timedelta

import pytest
from werkzeug.security import check_password_hash

from app import create_app
from app.extensions import db
from app.models import AuthSession, User
from app.models.user import utc_now
from app.utils.security import hash_csrf_token, hash_session_token


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
    assert response.headers.getlist("Set-Cookie") == []
    with app.app_context():
        session = AuthSession.query.one()
        assert session.token_hash != body["token"]
        assert session.token_hash == hash_session_token(body["token"])
        assert session.csrf_token_hash is None


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


def test_browser_login_requires_same_origin_and_does_not_create_session(
    app, client, register_user
):
    register_user("alice", "alice@example.com")
    payload = {
        "identifier": "alice",
        "password": "CorrectHorseBatteryStaple!42",
    }

    missing_origin = client.post("/api/auth/browser-login", json=payload)
    cross_origin = client.post(
        "/api/auth/browser-login",
        headers={"Origin": "https://attacker.example"},
        json=payload,
    )

    assert missing_origin.status_code == 403
    assert cross_origin.status_code == 403
    with app.app_context():
        assert AuthSession.query.count() == 0


def test_browser_login_uses_configured_public_origin_behind_proxy(
    client, register_user
):
    register_user("alice", "alice@example.com")

    response = client.post(
        "/api/auth/browser-login",
        base_url="http://internal-service.local",
        headers={"Origin": "http://localhost"},
        json={
            "identifier": "alice",
            "password": "CorrectHorseBatteryStaple!42",
        },
    )

    assert response.status_code == 200
    assert "token" not in response.get_json()


def test_browser_login_sets_separate_session_and_csrf_cookies(
    app, client, register_user
):
    register_user("alice", "alice@example.com")

    response = client.post(
        "/api/auth/browser-login",
        headers={"Origin": "http://localhost"},
        json={
            "identifier": "alice",
            "password": "CorrectHorseBatteryStaple!42",
        },
    )

    assert response.status_code == 200
    body = response.get_json()
    assert body["user"]["username"] == "alice"
    assert body["expires_at"]
    assert "token" not in body
    assert "token_type" not in body

    session_cookie = client.get_cookie("secure_share_session")
    csrf_cookie = client.get_cookie("secure_share_csrf")
    assert session_cookie is not None
    assert csrf_cookie is not None
    assert session_cookie.http_only is True
    assert csrf_cookie.http_only is False
    assert session_cookie.same_site == "Lax"
    assert csrf_cookie.same_site == "Lax"
    assert session_cookie.path == "/"
    assert csrf_cookie.path == "/"
    assert session_cookie.value not in response.get_data(as_text=True)
    assert csrf_cookie.value not in response.get_data(as_text=True)

    with app.app_context():
        auth_session = AuthSession.query.one()
        assert auth_session.token_hash == hash_session_token(session_cookie.value)
        assert auth_session.token_hash != session_cookie.value
        assert auth_session.csrf_token_hash == hash_csrf_token(csrf_cookie.value)
        assert auth_session.csrf_token_hash != csrf_cookie.value


def test_production_browser_cookie_has_secure_flag(
    app, client, register_user
):
    register_user("alice", "alice@example.com")
    app.config["BROWSER_COOKIE_SECURE"] = True

    response = client.post(
        "/api/auth/browser-login",
        headers={"Origin": "http://localhost"},
        json={
            "identifier": "alice",
            "password": "CorrectHorseBatteryStaple!42",
        },
    )

    cookie_headers = response.headers.getlist("Set-Cookie")
    assert response.status_code == 200
    assert len(cookie_headers) == 2
    assert all("; Secure" in header for header in cookie_headers)
    assert any(
        header.startswith("secure_share_session=") and "; HttpOnly" in header
        for header in cookie_headers
    )


def test_production_configuration_rejects_insecure_browser_cookies(tmp_path):
    with pytest.raises(RuntimeError, match="BROWSER_COOKIE_SECURE"):
        create_app(
            {
                "TESTING": True,
                "APP_ENV": "production",
                "SECRET_KEY": "production-test-secret",
                "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'prod.db'}",
                "UPLOAD_FOLDER": str(tmp_path / "uploads"),
                "BROWSER_COOKIE_SECURE": False,
            }
        )


def test_cookie_session_authenticates_safe_request(client, register_user, browser_login_user):
    expected = register_user("alice", "alice@example.com")
    browser_login_user("alice")

    response = client.get("/api/auth/me")

    assert response.status_code == 200
    assert response.get_json()["user"]["id"] == expected["id"]


@pytest.mark.parametrize(
    ("method", "path"),
    (
        ("POST", "/api/auth/logout"),
        ("POST", "/api/auth/email-verification/request"),
        ("PUT", "/api/auth/password"),
        ("PATCH", "/api/auth/password"),
        ("DELETE", "/api/files/00000000-0000-0000-0000-000000000000"),
    ),
)
def test_cookie_authenticated_unsafe_methods_require_csrf(
    app, client, register_user, browser_login_user, method, path
):
    register_user("alice")
    browser_login_user("alice")

    response = client.open(path, method=method, json={})

    assert response.status_code == 403
    assert response.get_json()["code"] == "csrf_failed"
    with app.app_context():
        assert AuthSession.query.count() == 1


def test_cookie_csrf_must_match_cookie_and_stored_digest(
    app, client, register_user, browser_login_user
):
    register_user("alice")
    browser = browser_login_user("alice")

    missing = client.post("/api/auth/logout")
    wrong_header = client.post(
        "/api/auth/logout", headers={"X-CSRF-Token": "wrong-token"}
    )
    client.set_cookie("secure_share_csrf", "tampered-cookie")
    matching_tampered_values = client.post(
        "/api/auth/logout",
        headers={"X-CSRF-Token": "tampered-cookie"},
    )

    assert missing.status_code == 403
    assert wrong_header.status_code == 403
    assert matching_tampered_values.status_code == 403
    with app.app_context():
        session = AuthSession.query.one()
        assert session.csrf_token_hash == hash_csrf_token(browser["csrf_token"])


def test_cookie_logout_revokes_session_and_clears_both_cookies(
    app, client, register_user, browser_login_user
):
    register_user("alice")
    browser = browser_login_user("alice")

    response = client.post(
        "/api/auth/logout",
        headers={"X-CSRF-Token": browser["csrf_token"]},
    )

    assert response.status_code == 200
    assert client.get_cookie("secure_share_session") is None
    assert client.get_cookie("secure_share_csrf") is None
    deletion_headers = response.headers.getlist("Set-Cookie")
    assert len(deletion_headers) == 2
    assert all("Max-Age=0" in header and "Path=/" in header for header in deletion_headers)
    with app.app_context():
        assert AuthSession.query.count() == 0


def test_cookie_password_change_keeps_current_session_and_revokes_others(
    client, register_user, login_user, browser_login_user, bearer_headers
):
    register_user("alice")
    other_token = login_user("alice")
    browser = browser_login_user("alice")

    changed = client.patch(
        "/api/auth/password",
        headers={"X-CSRF-Token": browser["csrf_token"]},
        json={
            "current_password": "CorrectHorseBatteryStaple!42",
            "new_password": "A-Different-Strong-Password!99",
        },
    )

    assert changed.status_code == 200
    assert client.get("/api/auth/me").status_code == 200
    assert client.get(
        "/api/auth/me", headers=bearer_headers(other_token)
    ).status_code == 401
    assert client.post(
        "/api/auth/login",
        json={
            "identifier": "alice",
            "password": "A-Different-Strong-Password!99",
        },
    ).status_code == 200


def test_expired_cookie_session_is_rejected_and_cleared(
    app, client, register_user, browser_login_user
):
    register_user("alice")
    browser_login_user("alice")
    with app.app_context():
        session = AuthSession.query.one()
        session.expires_at = utc_now() - timedelta(seconds=1)
        db.session.commit()

    response = client.get("/api/auth/me")

    assert response.status_code == 401
    assert client.get_cookie("secure_share_session") is None
    assert client.get_cookie("secure_share_csrf") is None
    assert len(response.headers.getlist("Set-Cookie")) == 2


def test_revoked_cookie_session_is_rejected_and_cleared(
    app, client, register_user, browser_login_user
):
    register_user("alice")
    browser_login_user("alice")
    with app.app_context():
        db.session.delete(AuthSession.query.one())
        db.session.commit()

    response = client.get("/api/auth/me")

    assert response.status_code == 401
    assert client.get_cookie("secure_share_session") is None
    assert client.get_cookie("secure_share_csrf") is None


def test_csrf_refresh_rotates_cookie_and_database_digest(
    app, client, register_user, browser_login_user
):
    register_user("alice")
    browser = browser_login_user("alice")

    response = client.get(
        "/api/auth/csrf",
        headers={
            "X-Secure-Share-CSRF-Restore": "1",
            "Sec-Fetch-Site": "same-origin",
        },
    )
    refreshed_cookie = client.get_cookie("secure_share_csrf")

    assert response.status_code == 200
    assert refreshed_cookie is not None
    assert refreshed_cookie.value != browser["csrf_token"]
    assert refreshed_cookie.value not in response.get_data(as_text=True)
    with app.app_context():
        session = AuthSession.query.one()
        assert session.csrf_token_hash == hash_csrf_token(refreshed_cookie.value)

    stale = client.post(
        "/api/auth/logout",
        headers={"X-CSRF-Token": browser["csrf_token"]},
    )
    assert stale.status_code == 403
    assert client.post(
        "/api/auth/logout",
        headers={"X-CSRF-Token": refreshed_cookie.value},
    ).status_code == 200


def test_csrf_refresh_rejects_cross_site_navigation_without_rotation(
    app, client, register_user, browser_login_user
):
    register_user("alice")
    browser = browser_login_user("alice")

    missing_signal = client.get("/api/auth/csrf")
    cross_site = client.get(
        "/api/auth/csrf",
        headers={
            "X-Secure-Share-CSRF-Restore": "1",
            "Sec-Fetch-Site": "cross-site",
        },
    )

    assert missing_signal.status_code == cross_site.status_code == 403
    assert client.get_cookie("secure_share_csrf").value == browser["csrf_token"]
    with app.app_context():
        session = AuthSession.query.one()
        assert session.csrf_token_hash == hash_csrf_token(browser["csrf_token"])


def test_bearer_session_cannot_be_replayed_as_browser_cookie(
    client, register_user, login_user
):
    register_user("alice")
    bearer_token = login_user("alice")
    client.set_cookie("secure_share_session", bearer_token)

    response = client.get("/api/auth/me")

    assert response.status_code == 401
    assert client.get_cookie("secure_share_session") is None


def test_browser_session_cannot_bypass_csrf_as_bearer_and_header_never_falls_back(
    client, register_user, browser_login_user
):
    register_user("alice")
    browser_login_user("alice")
    browser_token = client.get_cookie("secure_share_session").value

    wrong_transport = client.get(
        "/api/auth/me", headers={"Authorization": f"Bearer {browser_token}"}
    )
    malformed = client.get(
        "/api/auth/me", headers={"Authorization": "malformed"}
    )

    assert wrong_transport.status_code == 401
    assert malformed.status_code == 401
    assert client.get_cookie("secure_share_session") is not None
    assert client.get("/api/auth/me").status_code == 200


def test_explicit_valid_bearer_takes_precedence_over_different_cookie_user(
    client, register_user, login_user, browser_login_user, bearer_headers
):
    register_user("alice", "alice@example.com")
    register_user("bob", "bob@example.com")
    browser_login_user("alice")
    bob_token = login_user("bob")

    bearer_response = client.get(
        "/api/auth/me", headers=bearer_headers(bob_token)
    )
    cookie_response = client.get("/api/auth/me")

    assert bearer_response.status_code == 200
    assert bearer_response.get_json()["user"]["username"] == "bob"
    assert cookie_response.status_code == 200
    assert cookie_response.get_json()["user"]["username"] == "alice"


def test_bearer_logout_does_not_clear_or_revoke_unrelated_browser_session(
    client, register_user, login_user, browser_login_user, bearer_headers
):
    register_user("alice", "alice@example.com")
    register_user("bob", "bob@example.com")
    browser_login_user("alice")
    bob_token = login_user("bob")
    alice_cookie = client.get_cookie("secure_share_session").value

    logout = client.post(
        "/api/auth/logout", headers=bearer_headers(bob_token)
    )

    assert logout.status_code == 200
    assert client.get_cookie("secure_share_session").value == alice_cookie
    assert client.get("/api/auth/me").get_json()["user"]["username"] == "alice"
    assert client.get(
        "/api/auth/me", headers=bearer_headers(bob_token)
    ).status_code == 401


def test_bearer_csrf_refresh_is_rejected_without_affecting_session(
    client, register_user, login_user, bearer_headers
):
    register_user("alice")
    token = login_user("alice")

    response = client.get("/api/auth/csrf", headers=bearer_headers(token))

    assert response.status_code == 400
    assert client.get("/api/auth/me", headers=bearer_headers(token)).status_code == 200


def _production_config(tmp_path):
    blocklist = tmp_path / "production-password-blocklist.sha256"
    blocklist.write_text(
        "\n".join(f"{value:064x}" for value in range(10_000)) + "\n",
        encoding="ascii",
    )
    return {
        "TESTING": True,
        "APP_ENV": "production",
        "SECRET_KEY": "s" * 48,
        "ACCOUNT_TOKEN_PEPPER": "p" * 48,
        "RATE_LIMIT_KEY_SECRET": "r" * 48,
        "BROWSER_COOKIE_SECURE": True,
        "PUBLIC_BASE_URL": "https://secure-share.example",
        "MAIL_BACKEND": "smtp",
        "SECURITY_EMAIL_INLINE_DELIVERY": False,
        "MAIL_FROM_ADDRESS": "no-reply@secure-share.example",
        "SMTP_HOST": "smtp.secure-share.example",
        "PASSWORD_BLOCKLIST_PATH": str(blocklist),
        "RATELIMIT_STORAGE_URI": "redis://127.0.0.1:6379/15",
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'production.db'}",
        "UPLOAD_FOLDER": str(tmp_path / "uploads"),
    }


@pytest.mark.parametrize(
    ("override", "expected_error"),
    (
        (
            {"ACCOUNT_TOKEN_PEPPER": "s" * 48},
            "ACCOUNT_TOKEN_PEPPER",
        ),
        (
            {"PUBLIC_BASE_URL": "http://secure-share.example"},
            "HTTPS origin",
        ),
        (
            {"PUBLIC_BASE_URL": "https://secure-share.example/not-an-origin"},
            "HTTPS origin",
        ),
        ({"MAIL_BACKEND": "file"}, "SMTP mail backend"),
        (
            {"SECURITY_EMAIL_INLINE_DELIVERY": True},
            "SECURITY_EMAIL_INLINE_DELIVERY",
        ),
        (
            {"SMTP_USE_SSL": False, "SMTP_USE_STARTTLS": False},
            "encrypted TLS mode",
        ),
        (
            {
                "SMTP_TIMEOUT_SECONDS": 60,
                "SECURITY_EMAIL_LEASE_SECONDS": 300,
            },
            "SECURITY_EMAIL_LEASE_SECONDS",
        ),
        (
            {"PASSWORD_RESET_MINIMUM_RESPONSE_SECONDS": 0},
            "PASSWORD_RESET_MINIMUM_RESPONSE_SECONDS",
        ),
        (
            {"PASSWORD_BLOCKLIST_PATH": None},
            "PASSWORD_BLOCKLIST_PATH",
        ),
        ({"RATE_LIMIT_KEY_SECRET": "p" * 48}, "RATE_LIMIT_KEY_SECRET"),
    ),
)
def test_production_rejects_unsafe_security_configuration(
    tmp_path, override, expected_error
):
    config = _production_config(tmp_path)
    config.update(override)

    with pytest.raises(RuntimeError, match=expected_error):
        create_app(config)


def test_production_restricts_hosts_and_sends_hsts(tmp_path):
    application = create_app(_production_config(tmp_path))
    client = application.test_client()

    accepted = client.get("/", base_url="https://secure-share.example")
    rejected = client.get("/", base_url="https://attacker.example")

    assert accepted.status_code == 200
    assert accepted.headers["Strict-Transport-Security"] == (
        "max-age=31536000; includeSubDomains"
    )
    assert rejected.status_code == 400


def test_configured_vercel_app_starts_without_writing_to_the_bundle(
    tmp_path, monkeypatch
):
    import secrets
    from pathlib import Path

    config = _production_config(tmp_path)
    config.update(
        SQLALCHEMY_DATABASE_URI="postgresql+psycopg://localhost/unused_startup_test",
        FILE_STORAGE_BACKEND="vercel_blob",
        BLOB_READ_WRITE_TOKEN=secrets.token_urlsafe(32),
        CRON_SECRET=secrets.token_urlsafe(48),
        MAX_CONTENT_LENGTH=4 * 1024 * 1024,
        MAX_FILE_SIZE=4 * 1024 * 1024 - 64 * 1024,
    )
    monkeypatch.setenv("VERCEL", "1")

    def reject_write(*args, **kwargs):
        raise AssertionError("A configured Vercel app must not write to its bundle")

    monkeypatch.setattr(Path, "mkdir", reject_write)
    monkeypatch.setattr(Path, "chmod", reject_write)
    application = create_app(config)
    client = application.test_client()
    base = "https://secure-share.example"
    assert client.get("/", base_url=base).status_code == 200
    assert client.get("/static/css/style.css", base_url=base).status_code == 200
    assert client.get("/api/files", base_url=base).status_code == 401
    assert client.post("/api/internal/email-worker", base_url=base).status_code == 401
