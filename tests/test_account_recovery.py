"""Email-verification and password-recovery security lifecycle tests."""

from __future__ import annotations

import re
from datetime import timedelta
from urllib.parse import parse_qs, urlsplit

from sqlalchemy import select

from app.extensions import db
from app.models.account_action_token import (
    AccountActionToken,
    EMAIL_VERIFICATION,
    PASSWORD_RESET,
)
from app.models.auth_session import AuthSession
from app.models.permission import FilePermission
from app.models.security_email_job import SecurityEmailJob
from app.models.user import User, utc_now
from app.services.account_token_service import (
    hash_account_token,
    issue_password_reset_token,
)
from app.services.email_outbox_service import process_security_email_job


CURRENT_CREDENTIAL = (  # pragma: allowlist secret
    "CorrectHorseBatteryStaple!42"
)
RESET_CREDENTIAL = "Reset-Passphrase-For-2026!"  # pragma: allowlist secret
CHANGED_CREDENTIAL = "Changed-Passphrase-For-2026!"  # pragma: allowlist secret


def _register_unverified(client, username: str, email: str):
    return client.post(
        "/api/auth/register",
        json={
            "username": username,
            "email": email,
            "password": CURRENT_CREDENTIAL,
        },
    )


def _outbox(app) -> list:
    return app.extensions.setdefault("secure_share_mail_outbox", [])


def _clear_outbox(app) -> None:
    _outbox(app).clear()


def _token_from_message(message, expected_path: str) -> str:
    """Read an action token only from the URL fragment in a memory email."""

    body = message.get_content()
    for candidate in re.findall(r"https?://[^\s]+", body):
        parsed = urlsplit(candidate)
        if parsed.path != expected_path:
            continue
        assert parsed.query == ""
        values = parse_qs(parsed.fragment, strict_parsing=True)
        assert set(values) == {"token"}
        assert len(values["token"]) == 1
        return values["token"][0]
    raise AssertionError(f"No {expected_path} fragment link found in memory email")


def _latest_outbox_token(app, subject: str, expected_path: str) -> str:
    messages = [message for message in _outbox(app) if message["Subject"] == subject]
    assert messages
    return _token_from_message(messages[-1], expected_path)


def _verification_token(app) -> str:
    return _latest_outbox_token(
        app,
        "Verify your Secure Share email",
        "/verify-email",
    )


def _reset_token(app) -> str:
    return _latest_outbox_token(
        app,
        "Reset your Secure Share password",
        "/reset-password",
    )


def _record_for_raw_token(raw_token: str, purpose: str) -> AccountActionToken:
    digest = hash_account_token(raw_token, purpose)
    return db.session.execute(
        select(AccountActionToken).where(AccountActionToken.token_hash == digest)
    ).scalar_one()


def _request_reset(client, email: str):
    return client.post("/api/auth/password-reset/request", json={"email": email})


def _confirm_reset(client, token: str, new_password: str):
    return client.post(
        "/api/auth/password-reset/confirm",
        json={"token": token, "new_password": new_password},
    )


def test_registration_starts_unverified_and_never_returns_or_stores_raw_token(
    app, client
):
    response = _register_unverified(client, "new-user", "new-user@example.com")

    assert response.status_code == 201
    body = response.get_json()
    assert body["user"]["email_verified"] is False
    assert "token" not in body
    raw_token = _verification_token(app)
    assert raw_token not in response.get_data(as_text=True)

    with app.app_context():
        user = db.session.get(User, body["user"]["id"])
        assert user is not None
        assert user.email_verified_at is None
        records = db.session.execute(
            select(AccountActionToken).where(
                AccountActionToken.user_id == user.id,
                AccountActionToken.purpose == EMAIL_VERIFICATION,
            )
        ).scalars().all()
        assert len(records) == 1
        record = records[0]
        assert record.token_hash == hash_account_token(
            raw_token, EMAIL_VERIFICATION
        )
        assert len(record.token_hash) == 64
        for persisted_value in (
            record.id,
            record.purpose,
            record.token_hash,
            record.target_email,
        ):
            assert raw_token not in persisted_value


def test_email_verification_rejects_expired_token_without_consuming_it(app, client):
    registration = _register_unverified(
        client, "expired-verification", "expired-verification@example.com"
    )
    user_id = registration.get_json()["user"]["id"]
    raw_token = _verification_token(app)

    with app.app_context():
        record = _record_for_raw_token(raw_token, EMAIL_VERIFICATION)
        record.expires_at = utc_now() - timedelta(seconds=1)
        db.session.commit()

    response = client.post(
        "/api/auth/email-verification/confirm", json={"token": raw_token}
    )

    assert response.status_code == 400
    with app.app_context():
        user = db.session.get(User, user_id)
        record = _record_for_raw_token(raw_token, EMAIL_VERIFICATION)
        assert user is not None and user.email_verified_at is None
        assert record.consumed_at is None


def test_token_expiring_while_waiting_for_account_lock_is_rejected(
    app, client, monkeypatch
):
    registration = _register_unverified(
        client, "lock-expiry", "lock-expiry@example.com"
    )
    raw_token = _verification_token(app)
    before_expiry = utc_now()
    after_expiry = before_expiry + timedelta(seconds=2)

    with app.app_context():
        record = _record_for_raw_token(raw_token, EMAIL_VERIFICATION)
        record.expires_at = before_expiry + timedelta(seconds=1)
        db.session.commit()

    clock = iter((before_expiry, after_expiry))
    monkeypatch.setattr(
        "app.services.account_token_service.utc_now",
        lambda: next(clock),
    )
    response = client.post(
        "/api/auth/email-verification/confirm", json={"token": raw_token}
    )

    assert response.status_code == 400
    with app.app_context():
        user = db.session.get(User, registration.get_json()["user"]["id"])
        record = _record_for_raw_token(raw_token, EMAIL_VERIFICATION)
        assert user is not None and user.email_verified_at is None
        assert record.consumed_at is None


def test_email_verification_token_is_single_use(app, client):
    registration = _register_unverified(
        client, "single-verification", "single-verification@example.com"
    )
    user_id = registration.get_json()["user"]["id"]
    raw_token = _verification_token(app)

    first = client.post(
        "/api/auth/email-verification/confirm", json={"token": raw_token}
    )
    reused = client.post(
        "/api/auth/email-verification/confirm", json={"token": raw_token}
    )

    assert first.status_code == 200
    assert first.get_json() == {"message": "Email verified successfully."}
    assert reused.status_code == 400
    with app.app_context():
        user = db.session.get(User, user_id)
        record = _record_for_raw_token(raw_token, EMAIL_VERIFICATION)
        assert user is not None and user.email_verified_at is not None
        assert record.consumed_at is not None


def test_email_verification_supports_unicode_email_local_part(app, client):
    registration = _register_unverified(
        client, "unicode-email", "café@example.com"
    )
    assert registration.status_code == 201

    response = client.post(
        "/api/auth/email-verification/confirm",
        json={"token": _verification_token(app)},
    )

    assert response.status_code == 200


def test_verification_resend_invalidates_previous_challenge(app, client, login_user):
    registration = _register_unverified(
        client, "resend-verification", "resend-verification@example.com"
    )
    user_id = registration.get_json()["user"]["id"]
    first_token = _verification_token(app)
    bearer = login_user("resend-verification")

    resend = client.post(
        "/api/auth/email-verification/request",
        headers={"Authorization": f"Bearer {bearer}"},
    )
    second_token = _verification_token(app)

    assert resend.status_code == 202
    assert first_token != second_token
    with app.app_context():
        first_record = _record_for_raw_token(first_token, EMAIL_VERIFICATION)
        second_record = _record_for_raw_token(second_token, EMAIL_VERIFICATION)
        assert first_record.invalidated_at is not None
        assert first_record.consumed_at is None
        assert second_record.invalidated_at is None
        assert second_record.consumed_at is None

    old_confirmation = client.post(
        "/api/auth/email-verification/confirm", json={"token": first_token}
    )
    new_confirmation = client.post(
        "/api/auth/email-verification/confirm", json={"token": second_token}
    )

    assert old_confirmation.status_code == 400
    assert new_confirmation.status_code == 200
    with app.app_context():
        user = db.session.get(User, user_id)
        assert user is not None and user.email_verified_at is not None


def test_verified_account_resend_is_generic_and_issues_no_new_token(
    app, client, login_user
):
    registration = _register_unverified(
        client, "already-verified", "already-verified@example.com"
    )
    user_id = registration.get_json()["user"]["id"]
    assert client.post(
        "/api/auth/email-verification/confirm",
        json={"token": _verification_token(app)},
    ).status_code == 200
    bearer = login_user("already-verified", CURRENT_CREDENTIAL)
    _clear_outbox(app)

    response = client.post(
        "/api/auth/email-verification/request",
        headers={"Authorization": f"Bearer {bearer}"},
    )

    assert response.status_code == 202
    assert _outbox(app) == []
    with app.app_context():
        records = db.session.execute(
            select(AccountActionToken).where(
                AccountActionToken.user_id == user_id,
                AccountActionToken.purpose == EMAIL_VERIFICATION,
            )
        ).scalars().all()
        assert len(records) == 1


def test_unverified_recipient_cannot_receive_file_access(
    app, client, register_user, login_user, upload_file
):
    owner = register_user("verified-owner", "verified-owner@example.com")
    recipient = register_user(
        "unverified-recipient",
        "unverified-recipient@example.com",
        verified=False,
    )
    owner_token = login_user("verified-owner")
    upload = upload_file(owner_token, filename="verification-required.txt")
    file_id = upload.get_json()["file"]["id"]

    response = client.post(
        f"/api/files/{file_id}/permissions",
        headers={"Authorization": f"Bearer {owner_token}"},
        json={"user_id": recipient["id"]},
    )

    assert response.status_code == 404
    assert response.get_json()["error"] == "Recipient not found or unavailable."
    with app.app_context():
        permission = db.session.execute(
            select(FilePermission).where(
                FilePermission.file_id == file_id,
                FilePermission.user_id == recipient["id"],
            )
        ).scalar_one_or_none()
        assert permission is None
        owner_record = db.session.get(User, owner["id"])
        recipient_record = db.session.get(User, recipient["id"])
        assert owner_record is not None and owner_record.email_verified_at is not None
        assert (
            recipient_record is not None
            and recipient_record.email_verified_at is None
        )


def test_existing_share_survives_later_unverified_state(
    app, client, register_user, login_user, upload_file
):
    owner = register_user("grandfather-owner", "grandfather-owner@example.com")
    recipient = register_user(
        "grandfather-recipient", "grandfather-recipient@example.com"
    )
    owner_token = login_user(owner["username"])
    recipient_token = login_user(recipient["username"])
    upload = upload_file(owner_token, filename="existing-share.txt")
    file_id = upload.get_json()["file"]["id"]
    granted = client.post(
        f"/api/files/{file_id}/permissions",
        headers={"Authorization": f"Bearer {owner_token}"},
        json={"user_id": recipient["id"]},
    )
    assert granted.status_code == 201

    with app.app_context():
        recipient_record = db.session.get(User, recipient["id"])
        assert recipient_record is not None
        recipient_record.email_verified_at = None
        db.session.commit()

    listing = client.get(
        "/api/files",
        headers={"Authorization": f"Bearer {recipient_token}"},
    )
    download = client.get(
        f"/api/files/{file_id}/download",
        headers={"Authorization": f"Bearer {recipient_token}"},
    )

    assert listing.status_code == 200
    assert [item["id"] for item in listing.get_json()["files"]] == [file_id]
    assert download.status_code == 200


def test_unverified_account_cannot_change_sensitive_password_setting(
    client, login_user
):
    registration = _register_unverified(
        client, "unverified-change", "unverified-change@example.com"
    )
    assert registration.status_code == 201
    bearer = login_user("unverified-change", CURRENT_CREDENTIAL)

    response = client.patch(
        "/api/auth/password",
        headers={"Authorization": f"Bearer {bearer}"},
        json={
            "current_password": CURRENT_CREDENTIAL,
            "new_password": CHANGED_CREDENTIAL,
        },
    )

    assert response.status_code == 403
    assert "verify your email" in response.get_json()["error"].lower()


def test_password_reset_request_is_identical_for_known_and_unknown_email(
    app, client, register_user
):
    register_user("reset-known", "reset-known@example.com")
    _clear_outbox(app)

    known = _request_reset(client, "reset-known@example.com")
    raw_token = _reset_token(app)
    delivered_count = len(_outbox(app))
    unknown = _request_reset(client, "does-not-exist@example.com")

    assert known.status_code == unknown.status_code == 202
    assert known.get_json() == unknown.get_json()
    assert raw_token not in known.get_data(as_text=True)
    assert len(_outbox(app)) == delivered_count


def test_password_reset_expiry_and_reuse_are_rejected(app, client, register_user):
    user = register_user("reset-lifecycle", "reset-lifecycle@example.com")
    _clear_outbox(app)
    assert _request_reset(client, user["email"]).status_code == 202
    expired_token = _reset_token(app)

    with app.app_context():
        expired_record = _record_for_raw_token(expired_token, PASSWORD_RESET)
        expired_record.expires_at = utc_now() - timedelta(seconds=1)
        db.session.commit()

    expired = _confirm_reset(client, expired_token, RESET_CREDENTIAL)
    assert expired.status_code == 400

    assert _request_reset(client, user["email"]).status_code == 202
    usable_token = _reset_token(app)
    success = _confirm_reset(client, usable_token, RESET_CREDENTIAL)
    reused = _confirm_reset(client, usable_token, CHANGED_CREDENTIAL)

    assert success.status_code == 200
    assert reused.status_code == 400
    with app.app_context():
        expired_record = _record_for_raw_token(expired_token, PASSWORD_RESET)
        consumed_record = _record_for_raw_token(usable_token, PASSWORD_RESET)
        assert expired_record.consumed_at is None
        assert expired_record.invalidated_at is not None
        assert consumed_record.consumed_at is not None


def test_weak_reset_password_does_not_consume_token(app, client, register_user):
    user = register_user("reset-weak", "reset-weak@example.com")
    _clear_outbox(app)
    assert _request_reset(client, user["email"]).status_code == 202
    raw_token = _reset_token(app)

    weak = _confirm_reset(client, raw_token, "too-short")

    assert weak.status_code == 400
    with app.app_context():
        record = _record_for_raw_token(raw_token, PASSWORD_RESET)
        assert record.consumed_at is None
        assert record.invalidated_at is None

    retry = _confirm_reset(client, raw_token, RESET_CREDENTIAL)
    assert retry.status_code == 200


def test_successful_reset_also_verifies_the_token_bound_email(app, client):
    registration = _register_unverified(
        client, "reset-verifies", "reset-verifies@example.com"
    )
    user_id = registration.get_json()["user"]["id"]
    _clear_outbox(app)
    assert _request_reset(client, "reset-verifies@example.com").status_code == 202

    response = _confirm_reset(client, _reset_token(app), RESET_CREDENTIAL)

    assert response.status_code == 200
    with app.app_context():
        user = db.session.get(User, user_id)
        assert user is not None and user.email_verified_at is not None


def test_successful_reset_changes_password_and_revokes_every_session(
    app, client, register_user, login_user
):
    user = register_user("reset-sessions", "reset-sessions@example.com")
    first_session = login_user("reset-sessions", CURRENT_CREDENTIAL)
    second_session = login_user("reset-sessions", CURRENT_CREDENTIAL)
    _clear_outbox(app)
    assert _request_reset(client, user["email"]).status_code == 202
    raw_token = _reset_token(app)

    response = _confirm_reset(client, raw_token, RESET_CREDENTIAL)

    assert response.status_code == 200
    with app.app_context():
        sessions = db.session.execute(
            select(AuthSession).where(AuthSession.user_id == user["id"])
        ).scalars().all()
        account = db.session.get(User, user["id"])
        assert sessions == []
        assert account is not None
        assert account.check_password(RESET_CREDENTIAL)
        assert not account.check_password(CURRENT_CREDENTIAL)

    for old_token in (first_session, second_session):
        assert client.get(
            "/api/auth/me",
            headers={"Authorization": f"Bearer {old_token}"},
        ).status_code == 401
    assert client.post(
        "/api/auth/login",
        json={"identifier": user["email"], "password": CURRENT_CREDENTIAL},
    ).status_code == 401
    assert client.post(
        "/api/auth/login",
        json={"identifier": user["email"], "password": RESET_CREDENTIAL},
    ).status_code == 200


def test_authenticated_password_change_invalidates_pending_reset(
    app, client, register_user, login_user
):
    user = register_user("change-invalidates", "change-invalidates@example.com")
    bearer = login_user("change-invalidates", CURRENT_CREDENTIAL)
    _clear_outbox(app)
    assert _request_reset(client, user["email"]).status_code == 202
    pending_token = _reset_token(app)

    changed = client.patch(
        "/api/auth/password",
        headers={"Authorization": f"Bearer {bearer}"},
        json={
            "current_password": CURRENT_CREDENTIAL,
            "new_password": CHANGED_CREDENTIAL,
        },
    )

    assert changed.status_code == 200
    with app.app_context():
        record = _record_for_raw_token(pending_token, PASSWORD_RESET)
        assert record.consumed_at is None
        assert record.invalidated_at is not None

    rejected = _confirm_reset(client, pending_token, RESET_CREDENTIAL)
    assert rejected.status_code == 400
    assert client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {bearer}"},
    ).status_code == 200


def test_authenticated_password_change_cancels_queued_reset_delivery(
    app, client, register_user, login_user
):
    user = register_user("queued-change", "queued-change@example.com")
    bearer = login_user("queued-change", CURRENT_CREDENTIAL)
    _clear_outbox(app)
    app.config["SECURITY_EMAIL_INLINE_DELIVERY"] = False
    assert _request_reset(client, user["email"]).status_code == 202

    with app.app_context():
        reset_job = db.session.execute(
            select(SecurityEmailJob).where(
                SecurityEmailJob.user_id == user["id"],
                SecurityEmailJob.kind == PASSWORD_RESET,
                SecurityEmailJob.cancelled_at.is_(None),
            )
        ).scalar_one()
        reset_job_id = reset_job.id

    changed = client.patch(
        "/api/auth/password",
        headers={"Authorization": f"Bearer {bearer}"},
        json={
            "current_password": CURRENT_CREDENTIAL,
            "new_password": CHANGED_CREDENTIAL,
        },
    )

    assert changed.status_code == 200
    with app.app_context():
        reset_job = db.session.get(SecurityEmailJob, reset_job_id)
        assert reset_job is not None and reset_job.cancelled_at is not None
        assert process_security_email_job(reset_job_id) is None
        active_reset = db.session.execute(
            select(AccountActionToken).where(
                AccountActionToken.user_id == user["id"],
                AccountActionToken.purpose == PASSWORD_RESET,
                AccountActionToken.consumed_at.is_(None),
                AccountActionToken.invalidated_at.is_(None),
            )
        ).scalar_one_or_none()
        assert active_reset is None

    worker = app.test_cli_runner().invoke(args=["email-worker", "--once"])
    assert worker.exit_code == 0, worker.output
    assert [message["Subject"] for message in _outbox(app)] == [
        "Your Secure Share password was changed"
    ]


def test_reset_confirmation_cancels_other_queued_reset_delivery(app, client):
    registration = _register_unverified(
        client, "queued-confirm", "queued-confirm@example.com"
    )
    user_id = registration.get_json()["user"]["id"]
    _clear_outbox(app)
    app.config["SECURITY_EMAIL_INLINE_DELIVERY"] = False

    with app.app_context():
        user = db.session.get(User, user_id)
        assert user is not None
        raw_token = issue_password_reset_token(user)
        queued = SecurityEmailJob(user_id=user_id, kind=PASSWORD_RESET)
        db.session.add(queued)
        db.session.commit()
        queued_id = queued.id

    response = _confirm_reset(client, raw_token, RESET_CREDENTIAL)

    assert response.status_code == 200
    with app.app_context():
        queued = db.session.get(SecurityEmailJob, queued_id)
        assert queued is not None and queued.cancelled_at is not None
        assert process_security_email_job(queued_id) is None
