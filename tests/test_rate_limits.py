"""Negative tests for privacy-preserving, finite server-side rate limits."""

from __future__ import annotations

import io
import time

import limits.storage.memory as memory_storage
import pytest

from app import create_app
from app.extensions import limiter


PASSWORD = "CorrectHorseBatteryStaple!42"  # pragma: allowlist secret


def _registration_payload(username: str) -> dict[str, str]:
    return {
        "username": username,
        "email": f"{username}@example.com",
        "password": PASSWORD,
    }


def _failed_login(
    client,
    identifier: str,
    *,
    remote_address: str = "127.0.0.1",
):
    return client.post(
        "/api/auth/login",
        json={
            "identifier": identifier,
            "password": "incorrect-password",  # pragma: allowlist secret
        },
        environ_overrides={"REMOTE_ADDR": remote_address},
    )


def _upload(client, headers: dict[str, str], filename: str):
    return client.post(
        "/api/files",
        headers=headers,
        data={"file": (io.BytesIO(b"rate-limit test"), filename)},
        content_type="multipart/form-data",
    )


def test_rate_limit_response_is_json_with_retry_after(app, client):
    app.config["REGISTRATION_IP_RATE_LIMIT"] = "1 per minute"

    assert client.post(
        "/api/auth/register", json=_registration_payload("alice")
    ).status_code == 201
    rejected = client.post(
        "/api/auth/register", json=_registration_payload("bob")
    )

    assert rejected.status_code == 429
    assert rejected.is_json
    assert rejected.get_json() == {
        "error": "Too many requests. Please try again later.",
        "code": "rate_limit_exceeded",
    }
    assert rejected.headers["Retry-After"].isdigit()
    assert int(rejected.headers["Retry-After"]) > 0
    assert rejected.headers["X-RateLimit-Limit"] == "1"
    assert rejected.headers["X-RateLimit-Remaining"] == "0"


def test_rate_limit_storage_errors_cannot_fail_open(app):
    assert app.config["RATELIMIT_ENABLED"] is True
    assert app.config["RATELIMIT_SWALLOW_ERRORS"] is False
    assert app.config["RATELIMIT_IN_MEMORY_FALLBACK_ENABLED"] is False
    assert app.config["RATELIMIT_IN_MEMORY_FALLBACK"] == []


def test_socket_peer_buckets_ignore_spoofed_forwarded_for(app, client):
    app.config["REGISTRATION_IP_RATE_LIMIT"] = "1 per minute"

    first = client.post(
        "/api/auth/register",
        json=_registration_payload("alice"),
        headers={"X-Forwarded-For": "198.51.100.10"},
        environ_overrides={"REMOTE_ADDR": "203.0.113.5"},
    )
    spoofed = client.post(
        "/api/auth/register",
        json=_registration_payload("bob"),
        headers={"X-Forwarded-For": "198.51.100.99"},
        environ_overrides={"REMOTE_ADDR": "203.0.113.5"},
    )
    isolated_peer = client.post(
        "/api/auth/register",
        json=_registration_payload("charlie"),
        headers={"X-Forwarded-For": "198.51.100.10"},
        environ_overrides={"REMOTE_ADDR": "203.0.113.6"},
    )

    assert first.status_code == 201
    assert spoofed.status_code == 429
    assert isolated_peer.status_code == 201


def test_known_and_unknown_credentials_receive_identical_limits(
    app, client, register_user
):
    register_user("alice")
    app.config["LOGIN_IP_RATE_LIMIT"] = "100 per minute"
    app.config["LOGIN_FAILURE_IP_RATE_LIMIT"] = "100 per minute"
    app.config["LOGIN_FAILURE_CREDENTIAL_RATE_LIMIT"] = "1 per minute"

    known_first = _failed_login(
        client, "alice", remote_address="203.0.113.10"
    )
    unknown_first = _failed_login(
        client, "nobody", remote_address="203.0.113.11"
    )
    known_second = _failed_login(
        client, "alice", remote_address="203.0.113.10"
    )
    unknown_second = _failed_login(
        client, "nobody", remote_address="203.0.113.11"
    )

    assert known_first.status_code == unknown_first.status_code == 401
    assert known_first.get_json() == unknown_first.get_json()
    assert known_second.status_code == unknown_second.status_code == 429
    assert known_second.get_json() == unknown_second.get_json()


def test_login_credential_buckets_are_isolated(app, client):
    app.config["LOGIN_IP_RATE_LIMIT"] = "100 per minute"
    app.config["LOGIN_FAILURE_IP_RATE_LIMIT"] = "100 per minute"
    app.config["LOGIN_FAILURE_CREDENTIAL_RATE_LIMIT"] = "1 per minute"

    assert _failed_login(client, "first-target").status_code == 401
    assert _failed_login(client, "first-target").status_code == 429
    assert _failed_login(client, "second-target").status_code == 401


def test_login_target_limit_cannot_be_evaded_by_rotating_source_address(
    app, client, register_user
):
    register_user("alice")
    app.config["LOGIN_IP_RATE_LIMIT"] = "100 per minute"
    app.config["LOGIN_FAILURE_IP_RATE_LIMIT"] = "100 per minute"
    app.config["LOGIN_FAILURE_CREDENTIAL_RATE_LIMIT"] = "1 per minute"

    first = _failed_login(client, "alice", remote_address="203.0.113.31")
    rotated_source = _failed_login(
        client, "alice", remote_address="203.0.113.32"
    )

    assert first.status_code == 401
    assert rotated_source.status_code == 429


def test_api_and_browser_login_share_failed_credential_limit(
    app, client, register_user
):
    register_user("alice")
    app.config["LOGIN_IP_RATE_LIMIT"] = "100 per minute"
    app.config["LOGIN_FAILURE_IP_RATE_LIMIT"] = "100 per minute"
    app.config["LOGIN_FAILURE_CREDENTIAL_RATE_LIMIT"] = "1 per minute"

    api_failure = _failed_login(client, "alice")
    browser_failure = client.post(
        "/api/auth/browser-login",
        headers={"Origin": "http://localhost"},
        json={
            "identifier": "alice",
            "password": "incorrect-password",  # pragma: allowlist secret
        },
    )

    assert api_failure.status_code == 401
    assert browser_failure.status_code == 429


def test_email_verification_request_limit_runs_after_authentication(
    app, client, register_user, login_user, bearer_headers
):
    register_user("alice")
    token = login_user("alice")
    app.config["ACCOUNT_ACTION_IP_RATE_LIMIT"] = "100 per minute"
    app.config["EMAIL_VERIFICATION_REQUEST_RATE_LIMIT"] = "1 per minute"

    first = client.post(
        "/api/auth/email-verification/request", headers=bearer_headers(token)
    )
    rejected = client.post(
        "/api/auth/email-verification/request", headers=bearer_headers(token)
    )

    assert first.status_code == 202
    assert rejected.status_code == 429


def test_verification_request_user_limit_survives_source_rotation(
    app, client, register_user, login_user, bearer_headers
):
    register_user("alice")
    token = login_user("alice")
    app.config["ACCOUNT_ACTION_IP_RATE_LIMIT"] = "100 per minute"
    app.config["EMAIL_VERIFICATION_REQUEST_RATE_LIMIT"] = "1 per minute"

    first = client.post(
        "/api/auth/email-verification/request",
        headers=bearer_headers(token),
        environ_overrides={"REMOTE_ADDR": "203.0.113.41"},
    )
    rotated_source = client.post(
        "/api/auth/email-verification/request",
        headers=bearer_headers(token),
        environ_overrides={"REMOTE_ADDR": "203.0.113.42"},
    )

    assert first.status_code == 202
    assert rotated_source.status_code == 429


def test_password_reset_request_limits_known_and_unknown_equally(
    app, client, register_user
):
    register_user("alice", "alice@example.com")
    app.config["ACCOUNT_ACTION_IP_RATE_LIMIT"] = "100 per minute"
    app.config["PASSWORD_RESET_REQUEST_RATE_LIMIT"] = (  # pragma: allowlist secret
        "1 per minute"
    )

    known_first = client.post(
        "/api/auth/password-reset/request",
        json={"email": "ALICE@example.com"},
        environ_overrides={"REMOTE_ADDR": "203.0.113.20"},
    )
    unknown_first = client.post(
        "/api/auth/password-reset/request",
        json={"email": "unknown@example.com"},
        environ_overrides={"REMOTE_ADDR": "203.0.113.21"},
    )
    known_second = client.post(
        "/api/auth/password-reset/request",
        json={"email": "alice@EXAMPLE.com"},
        environ_overrides={"REMOTE_ADDR": "203.0.113.20"},
    )
    unknown_second = client.post(
        "/api/auth/password-reset/request",
        json={"email": "UNKNOWN@example.com"},
        environ_overrides={"REMOTE_ADDR": "203.0.113.21"},
    )

    assert known_first.status_code == unknown_first.status_code == 202
    assert known_first.get_json() == unknown_first.get_json()
    assert known_second.status_code == unknown_second.status_code == 429
    assert known_second.get_json() == unknown_second.get_json()


def test_reset_target_limit_cannot_be_evaded_by_rotating_source_address(
    app, client, register_user
):
    register_user("alice", "alice@example.com")
    app.config["ACCOUNT_ACTION_IP_RATE_LIMIT"] = "100 per minute"
    app.config["PASSWORD_RESET_REQUEST_RATE_LIMIT"] = (  # pragma: allowlist secret
        "1 per minute"
    )

    first = client.post(
        "/api/auth/password-reset/request",
        json={"email": "alice@example.com"},
        environ_overrides={"REMOTE_ADDR": "203.0.113.51"},
    )
    rotated_source = client.post(
        "/api/auth/password-reset/request",
        json={"email": "ALICE@EXAMPLE.COM"},
        environ_overrides={"REMOTE_ADDR": "203.0.113.52"},
    )

    assert first.status_code == 202
    assert rotated_source.status_code == 429


@pytest.mark.parametrize(
    ("endpoint", "config_name"),
    [
        (
            "/api/auth/email-verification/confirm",
            "EMAIL_VERIFICATION_CONFIRM_RATE_LIMIT",
        ),
        (
            "/api/auth/password-reset/confirm",
            "PASSWORD_RESET_CONFIRM_RATE_LIMIT",
        ),
    ],
)
def test_action_token_attempt_buckets_are_hmac_protected_and_isolated(
    app, client, endpoint, config_name
):
    app.config["ACCOUNT_ACTION_IP_RATE_LIMIT"] = "100 per minute"
    app.config[config_name] = "1 per minute"
    first_token = "raw-sensitive-action-token-one"
    second_token = "raw-sensitive-action-token-two"

    def payload(token: str) -> dict[str, str]:
        body = {"token": token}
        if endpoint.endswith("password-reset/confirm"):
            body["new_password"] = (  # pragma: allowlist secret
                "A-Different-Strong-Password!99"
            )
        return body

    assert client.post(
        endpoint,
        json=payload(first_token),
        environ_overrides={"REMOTE_ADDR": "203.0.113.61"},
    ).status_code == 400
    assert client.post(
        endpoint,
        json=payload(first_token),
        environ_overrides={"REMOTE_ADDR": "203.0.113.62"},
    ).status_code == 429
    assert client.post(endpoint, json=payload(second_token)).status_code == 400

    stored_keys = " ".join(str(key) for key in limiter.storage.storage)
    assert first_token not in stored_keys
    assert second_token not in stored_keys


def test_successful_logins_do_not_consume_failed_only_limit(
    app, client, register_user
):
    register_user("alice")
    app.config["LOGIN_IP_RATE_LIMIT"] = "100 per minute"
    app.config["LOGIN_FAILURE_IP_RATE_LIMIT"] = "1 per minute"
    app.config["LOGIN_FAILURE_CREDENTIAL_RATE_LIMIT"] = "1 per minute"
    payload = {"identifier": "alice", "password": PASSWORD}

    assert client.post("/api/auth/login", json=payload).status_code == 200
    assert client.post("/api/auth/login", json=payload).status_code == 200
    assert _failed_login(client, "alice").status_code == 401
    assert _failed_login(client, "alice").status_code == 429


def test_failed_login_limit_expires_without_account_lockout(
    app, client, register_user, monkeypatch
):
    register_user("alice")
    app.config["LOGIN_IP_RATE_LIMIT"] = "100 per minute"
    app.config["LOGIN_FAILURE_IP_RATE_LIMIT"] = "1 per minute"
    app.config["LOGIN_FAILURE_CREDENTIAL_RATE_LIMIT"] = "1 per minute"

    clock = [time.time()]
    monkeypatch.setattr(memory_storage.time, "time", lambda: clock[0])

    assert _failed_login(client, "alice").status_code == 401
    assert _failed_login(client, "alice").status_code == 429

    clock[0] += 61
    recovered = client.post(
        "/api/auth/login",
        json={"identifier": "alice", "password": PASSWORD},
    )
    assert recovered.status_code == 200


def test_upload_session_buckets_are_isolated(
    app, client, register_user, login_user
):
    register_user("alice")
    token_one = login_user("alice")
    token_two = login_user("alice")
    app.config["UPLOAD_USER_RATE_LIMIT"] = "100 per minute"
    app.config["UPLOAD_SESSION_RATE_LIMIT"] = "1 per minute"

    assert _upload(
        client,
        {"Authorization": f"Bearer {token_one}"},
        "one.txt",
    ).status_code == 201
    assert _upload(
        client,
        {"Authorization": f"Bearer {token_one}"},
        "two.txt",
    ).status_code == 429
    assert _upload(
        client,
        {"Authorization": f"Bearer {token_two}"},
        "three.txt",
    ).status_code == 201


def test_upload_peer_limit_runs_before_authentication(app, client):
    app.config["UPLOAD_IP_RATE_LIMIT"] = "1 per minute"

    first = _upload(client, {}, "unauthenticated-one.txt")
    rejected = _upload(client, {}, "unauthenticated-two.txt")

    assert first.status_code == 401
    assert rejected.status_code == 429


def test_bearer_and_cookie_uploads_share_the_user_bucket(
    app, client, register_user, login_user, browser_login_user
):
    register_user("alice")
    bearer_token = login_user("alice")
    browser = browser_login_user("alice")
    app.config["UPLOAD_USER_RATE_LIMIT"] = "2 per minute"
    app.config["UPLOAD_SESSION_RATE_LIMIT"] = "100 per minute"

    bearer_headers = {"Authorization": f"Bearer {bearer_token}"}
    cookie_headers = {"X-CSRF-Token": browser["csrf_token"]}
    assert _upload(client, bearer_headers, "bearer.txt").status_code == 201
    assert _upload(client, cookie_headers, "cookie.txt").status_code == 201
    # An explicit bearer credential takes precedence even while cookie
    # credentials are present, and both transports resolve to the same user.
    assert _upload(client, bearer_headers, "limited.txt").status_code == 429


def test_download_resource_bucket_isolated_across_files_and_transports(
    app,
    client,
    register_user,
    login_user,
    browser_login_user,
    upload_file,
):
    register_user("alice")
    bearer_token = login_user("alice")
    browser_login_user("alice")
    first_file = upload_file(bearer_token, filename="first.txt").get_json()["file"]
    second_file = upload_file(bearer_token, filename="second.txt").get_json()["file"]
    app.config["DOWNLOAD_USER_RATE_LIMIT"] = "100 per minute"
    app.config["DOWNLOAD_SESSION_RATE_LIMIT"] = "100 per minute"
    app.config["DOWNLOAD_RESOURCE_RATE_LIMIT"] = "1 per minute"

    bearer_headers = {"Authorization": f"Bearer {bearer_token}"}
    assert client.get(
        f"/api/files/{first_file['id']}/download", headers=bearer_headers
    ).status_code == 200
    assert client.get(f"/api/files/{first_file['id']}/download").status_code == 429
    assert client.get(f"/api/files/{second_file['id']}/download").status_code == 200


def test_download_peer_limit_runs_before_session_lookup(app, client):
    app.config["DOWNLOAD_IP_RATE_LIMIT"] = "1 per minute"
    endpoint = "/api/files/not-a-private-file/download"

    first = client.get(endpoint)
    rejected = client.get(
        endpoint,
        headers={"Authorization": "Bearer random-unknown-session"},
    )

    assert first.status_code == 401
    assert rejected.status_code == 429


@pytest.mark.parametrize("storage_uri", ["memory://", "mongodb://localhost/rates"])
def test_production_requires_shared_redis_storage(tmp_path, storage_uri):
    blocklist = tmp_path / "production-password-blocklist.sha256"
    blocklist.write_text(
        "\n".join(f"{value:064x}" for value in range(10_000)) + "\n",
        encoding="ascii",
    )
    with pytest.raises(RuntimeError, match="Production requires shared Redis"):
        create_app(
            {
                "TESTING": True,
                "APP_ENV": "production",
                "BROWSER_COOKIE_SECURE": True,
                "SECRET_KEY": "s" * 48,
                "ACCOUNT_TOKEN_PEPPER": "p" * 48,
                "PUBLIC_BASE_URL": "https://secure-share.example",
                "MAIL_BACKEND": "smtp",
                "SMTP_HOST": "smtp.example",
                "SECURITY_EMAIL_INLINE_DELIVERY": False,
                "PASSWORD_BLOCKLIST_PATH": str(blocklist),
                "RATE_LIMIT_KEY_SECRET": "x" * 48,
                "RATELIMIT_STORAGE_URI": storage_uri,
                "UPLOAD_FOLDER": str(tmp_path / "uploads"),
            }
        )


def test_shared_storage_requires_dedicated_hmac_secret(tmp_path):
    with pytest.raises(RuntimeError, match="RATE_LIMIT_KEY_SECRET is required"):
        create_app(
            {
                "TESTING": True,
                "APP_ENV": "development",
                "RATE_LIMIT_KEY_SECRET": None,
                "RATELIMIT_STORAGE_URI": "redis://localhost:6379/15",
                "UPLOAD_FOLDER": str(tmp_path / "uploads"),
            }
        )


def test_rate_limit_hmac_secret_cannot_reuse_application_secret(tmp_path):
    reused_secret = (  # pragma: allowlist secret
        "same-secret-must-not-cross-security-domains" * 2
    )
    with pytest.raises(RuntimeError, match="must be dedicated"):
        create_app(
            {
                "TESTING": True,
                "APP_ENV": "test",
                "SECRET_KEY": reused_secret,
                "RATE_LIMIT_KEY_SECRET": reused_secret,
                "RATELIMIT_STORAGE_URI": "memory://",
                "UPLOAD_FOLDER": str(tmp_path / "uploads"),
            }
        )
