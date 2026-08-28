"""Secret-free security-email outbox and worker lifecycle tests."""

from __future__ import annotations

import re
import secrets
from datetime import timedelta
from urllib.parse import parse_qs, urlsplit

from sqlalchemy import select

from app.extensions import db
from app.models.account_action_token import (
    AccountActionToken,
    EMAIL_VERIFICATION,
    PASSWORD_RESET,
)
from app.models.security_email_job import PASSWORD_CHANGED, SecurityEmailJob
from app.models.user import User, utc_now
from app.services.account_token_service import (
    hash_account_token,
    issue_password_reset_token,
)
from app.services.email_outbox_service import (
    claim_security_email_job,
    enqueue_security_email,
    process_pending_security_email,
    process_security_email_job,
)
from app.services.email_service import EmailDeliveryError


def _create_user(*, verified: bool = False) -> User:
    user = User(
        username=f"outbox-user-{len(db.session.identity_map)}",
        email=f"outbox-{utc_now().timestamp()}@example.test",
        password_hash="",  # nosec B106 - immediately replaced with a hash
        email_verified_at=utc_now() if verified else None,
    )
    user.set_password("Outbox-Test-Passphrase-2026!")
    db.session.add(user)
    db.session.commit()
    return user


def _token_from_message(message, expected_path: str) -> str:
    for candidate in re.findall(r"https?://[^\s]+", message.get_content()):
        parsed = urlsplit(candidate)
        if parsed.path == expected_path:
            values = parse_qs(parsed.fragment, strict_parsing=True)
            assert set(values) == {"token"}
            return values["token"][0]
    raise AssertionError(f"No {expected_path} token link found")


def test_job_schema_cannot_persist_message_content_or_secrets(app):
    with app.app_context():
        assert set(SecurityEmailJob.__table__.columns.keys()) == {
            "id",
            "user_id",
            "kind",
            "created_at",
            "available_at",
            "lease_expires_at",
            "completed_at",
            "cancelled_at",
            "attempts",
        }
        forbidden_fragments = {
            "token",
            "secret",
            "body",
            "message",
            "subject",
            "recipient",
            "email",
            "password",
        }
        assert not any(
            fragment in column.name
            for column in SecurityEmailJob.__table__.columns
            for fragment in forbidden_fragments
        )


def test_http_worker_requires_its_own_secret_and_processes_bounded_batches(app, client):
    app.config.update(
        CRON_SECRET=secrets.token_urlsafe(48),
        SECURITY_EMAIL_INLINE_DELIVERY=False,
        SECURITY_EMAIL_HTTP_BATCH_SIZE=1,
    )
    with app.app_context():
        user = _create_user(verified=True)
        enqueue_security_email(user, PASSWORD_RESET)
        enqueue_security_email(user, PASSWORD_CHANGED)
        db.session.commit()
    path = "/api/internal/email-worker"
    for headers in (
        {},
        {"Authorization": "Bearer wrong"},
        {"Authorization": f"Bearer {app.config['SECRET_KEY']}"},
    ):
        response = client.post(path, headers=headers)
        assert response.status_code == 401
    with app.app_context():
        assert all(job.attempts == 0 for job in SecurityEmailJob.query.all())
    headers = {"Authorization": f"Bearer {app.config['CRON_SECRET']}"}
    first = client.post(path + "?limit=1000", headers=headers, json={"limit": 1000})
    assert first.status_code == 200
    assert first.get_json() == {"processed": 1, "outcomes": {"completed": 1}}
    assert first.headers["Cache-Control"] == "no-store"
    assert app.config["CRON_SECRET"] not in first.get_data(as_text=True)
    second = client.get(path, headers=headers)
    assert second.get_json() == {"processed": 1, "outcomes": {"completed": 1}}
    assert client.get(path, headers=headers).get_json() == {
        "processed": 0,
        "outcomes": {},
    }


def test_http_worker_stays_disabled_without_a_secret(app, client):
    app.config["CRON_SECRET"] = None
    assert client.post("/api/internal/email-worker").status_code == 503


def test_enqueue_cancels_prior_job_and_invalidates_active_challenge(app):
    with app.app_context():
        user = _create_user(verified=True)
        first = enqueue_security_email(user, PASSWORD_RESET)
        first_id = first.id
        raw_token = issue_password_reset_token(user)
        token_digest = hash_account_token(raw_token, PASSWORD_RESET)

        second = enqueue_security_email(user, PASSWORD_RESET)
        second_id = second.id

        first_record = db.session.get(SecurityEmailJob, first_id)
        second_record = db.session.get(SecurityEmailJob, second_id)
        challenge = db.session.execute(
            select(AccountActionToken).where(
                AccountActionToken.token_hash == token_digest
            )
        ).scalar_one()
        assert first_record is not None and first_record.cancelled_at is not None
        assert second_record is not None and second_record.cancelled_at is None
        assert challenge.invalidated_at is not None
        assert challenge.consumed_at is None


def test_worker_delivers_verification_and_persists_only_digest(app):
    with app.app_context():
        user = _create_user(verified=False)
        user_id = user.id
        job = enqueue_security_email(user, EMAIL_VERIFICATION)
        job_id = job.id

        result = process_security_email_job(job_id)

        assert result is not None
        assert result.job_id == job_id
        assert result.outcome == "completed"
        messages = app.extensions["secure_share_mail_outbox"]
        assert len(messages) == 1
        raw_token = _token_from_message(messages[0], "/verify-email")
        challenge = db.session.execute(
            select(AccountActionToken).where(
                AccountActionToken.user_id == user_id,
                AccountActionToken.purpose == EMAIL_VERIFICATION,
            )
        ).scalar_one()
        persisted_job = db.session.get(SecurityEmailJob, job_id)
        assert challenge.token_hash == hash_account_token(raw_token, EMAIL_VERIFICATION)
        assert raw_token not in challenge.token_hash
        assert persisted_job is not None
        assert persisted_job.completed_at is not None
        assert persisted_job.lease_expires_at is None
        assert persisted_job.attempts == 1
        assert all(
            raw_token not in str(getattr(persisted_job, column.name))
            for column in SecurityEmailJob.__table__.columns
        )


def test_delivery_failure_invalidates_link_and_schedules_bounded_retry(
    app, monkeypatch
):
    def reject_delivery(_user, _raw_token):
        raise EmailDeliveryError("simulated provider failure")

    monkeypatch.setattr(
        "app.services.email_outbox_service.send_password_reset_email",
        reject_delivery,
    )
    app.config.update(
        SECURITY_EMAIL_RETRY_BASE_SECONDS=2,
        SECURITY_EMAIL_RETRY_MAX_SECONDS=3,
        SECURITY_EMAIL_MAX_ATTEMPTS=4,
    )

    with app.app_context():
        user = _create_user(verified=True)
        job = enqueue_security_email(user, PASSWORD_RESET)
        job_id = job.id

        result = process_security_email_job(job_id)

        assert result is not None and result.outcome == "retry_scheduled"
        persisted_job = db.session.get(SecurityEmailJob, job_id)
        challenges = (
            db.session.execute(
                select(AccountActionToken).where(
                    AccountActionToken.user_id == user.id,
                    AccountActionToken.purpose == PASSWORD_RESET,
                )
            )
            .scalars()
            .all()
        )
        assert persisted_job is not None
        assert persisted_job.completed_at is None
        assert persisted_job.cancelled_at is None
        assert persisted_job.lease_expires_at is None
        assert persisted_job.available_at > persisted_job.created_at
        assert persisted_job.attempts == 1
        assert len(challenges) == 1
        assert challenges[0].invalidated_at is not None
        assert len(challenges[0].token_hash) == 64
        assert app.extensions.get("secure_share_mail_outbox", []) == []


def test_delivery_retry_delay_is_capped_and_attempts_are_exhaustible(app, monkeypatch):
    def reject_delivery(_user, _raw_token):
        raise EmailDeliveryError("simulated provider failure")

    monkeypatch.setattr(
        "app.services.email_outbox_service.send_password_reset_email",
        reject_delivery,
    )
    app.config.update(
        SECURITY_EMAIL_RETRY_BASE_SECONDS=60,
        SECURITY_EMAIL_RETRY_MAX_SECONDS=2,
        SECURITY_EMAIL_MAX_ATTEMPTS=3,
    )

    with app.app_context():
        user = _create_user(verified=True)
        job = enqueue_security_email(user, PASSWORD_RESET)
        job_id = job.id

        first = process_security_email_job(job_id)
        persisted_job = db.session.get(SecurityEmailJob, job_id)

        assert first is not None and first.outcome == "retry_scheduled"
        assert persisted_job is not None
        scheduled_at = persisted_job.available_at
        comparison_now = utc_now()
        if scheduled_at.tzinfo is None:
            comparison_now = comparison_now.replace(tzinfo=None)
        assert (
            timedelta(seconds=0) < scheduled_at - comparison_now <= timedelta(seconds=2)
        )

        # Simulate the next claim having already failed as well. The third
        # attempt is accepted for processing, then permanently exhausts the
        # job rather than allowing unbounded retries.
        persisted_job.attempts = 2
        persisted_job.available_at = utc_now() - timedelta(seconds=1)
        db.session.commit()

        exhausted = process_security_email_job(job_id)
        persisted_job = db.session.get(SecurityEmailJob, job_id)
        assert exhausted is not None and exhausted.outcome == "cancelled"
        assert persisted_job is not None
        assert persisted_job.attempts == 3
        assert persisted_job.cancelled_at is not None
        assert persisted_job.lease_expires_at is None


def test_atomic_claim_excludes_competitors_and_recovers_expired_lease(app):
    app.config["SECURITY_EMAIL_LEASE_SECONDS"] = 60
    with app.app_context():
        user = _create_user(verified=True)
        job = enqueue_security_email(user, PASSWORD_CHANGED)
        job_id = job.id

        first_claim = claim_security_email_job(job_id)
        competing_claim = claim_security_email_job(job_id)

        assert first_claim is not None and first_claim.attempts == 1
        assert competing_claim is None

        persisted_job = db.session.get(SecurityEmailJob, job_id)
        assert persisted_job is not None
        persisted_job.lease_expires_at = utc_now() - timedelta(seconds=1)
        db.session.commit()

        recovered_claim = claim_security_email_job(job_id)
        assert recovered_claim is not None
        assert recovered_claim.attempts == 2
        assert recovered_claim.lease_expires_at != first_claim.lease_expires_at


def test_replacement_cancels_an_actively_leased_recovery_job(app):
    with app.app_context():
        user = _create_user(verified=True)
        first = enqueue_security_email(user, PASSWORD_RESET)
        assert first is not None
        first_id = first.id
        assert claim_security_email_job(first_id) is not None

        replacement = enqueue_security_email(user, PASSWORD_RESET)

        assert replacement is not None
        stale = db.session.get(SecurityEmailJob, first_id)
        assert stale is not None
        assert stale.cancelled_at is not None
        assert stale.lease_expires_at is None
        assert process_security_email_job(first_id) is None


def test_password_change_alerts_are_not_coalesced(app):
    with app.app_context():
        user = _create_user(verified=True)

        first = enqueue_security_email(user, PASSWORD_CHANGED)
        second = enqueue_security_email(user, PASSWORD_CHANGED)

        assert first is not None and second is not None
        assert db.session.get(SecurityEmailJob, first.id).cancelled_at is None
        assert db.session.get(SecurityEmailJob, second.id).cancelled_at is None


def test_batch_processor_honors_limit_and_returns_secret_free_summaries(app):
    with app.app_context():
        users = [_create_user(verified=True) for _ in range(2)]
        jobs = [enqueue_security_email(user, PASSWORD_CHANGED) for user in users]

        first_batch = process_pending_security_email(limit=1)
        second_batch = process_pending_security_email(limit=2)

        assert [result.outcome for result in first_batch] == ["completed"]
        assert [result.outcome for result in second_batch] == ["completed"]
        assert {result.job_id for result in first_batch + second_batch} == {
            job.id for job in jobs
        }
        assert len(app.extensions["secure_share_mail_outbox"]) == 2


def test_reset_request_queues_delivery_until_worker_runs(app, client, register_user):
    user = register_user("queued-reset", "queued-reset@example.com")
    app.extensions["secure_share_mail_outbox"].clear()
    app.config["SECURITY_EMAIL_INLINE_DELIVERY"] = False

    response = client.post(
        "/api/auth/password-reset/request",
        json={"email": user["email"]},
    )

    assert response.status_code == 202
    assert app.extensions["secure_share_mail_outbox"] == []
    with app.app_context():
        job = db.session.execute(
            select(SecurityEmailJob).where(
                SecurityEmailJob.user_id == user["id"],
                SecurityEmailJob.kind == PASSWORD_RESET,
                SecurityEmailJob.completed_at.is_(None),
                SecurityEmailJob.cancelled_at.is_(None),
            )
        ).scalar_one()
        assert job.attempts == 0
        assert (
            db.session.execute(
                select(AccountActionToken).where(
                    AccountActionToken.user_id == user["id"],
                    AccountActionToken.purpose == PASSWORD_RESET,
                    AccountActionToken.invalidated_at.is_(None),
                )
            ).scalar_one_or_none()
            is None
        )

    worker = app.test_cli_runner().invoke(args=["email-worker", "--once"])

    assert worker.exit_code == 0, worker.output
    assert "completed=1" in worker.output
    assert len(app.extensions["secure_share_mail_outbox"]) == 1
    raw_token = _token_from_message(
        app.extensions["secure_share_mail_outbox"][0], "/reset-password"
    )
    assert raw_token not in worker.output
    with app.app_context():
        persisted_job = db.session.get(SecurityEmailJob, job.id)
        assert persisted_job is not None and persisted_job.completed_at is not None
        challenge = db.session.execute(
            select(AccountActionToken).where(
                AccountActionToken.user_id == user["id"],
                AccountActionToken.purpose == PASSWORD_RESET,
                AccountActionToken.invalidated_at.is_(None),
            )
        ).scalar_one()
        assert challenge.token_hash == hash_account_token(raw_token, PASSWORD_RESET)
