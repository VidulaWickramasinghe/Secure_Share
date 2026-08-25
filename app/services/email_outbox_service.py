"""Durable, secret-free outbox processing for account security email."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal

from flask import current_app
from sqlalchemy import or_, select, update

from app.extensions import db
from app.models.account_action_token import (
    AccountActionToken,
    EMAIL_VERIFICATION,
    PASSWORD_RESET,
)
from app.models.security_email_job import (
    PASSWORD_CHANGED,
    SECURITY_EMAIL_KINDS,
    SecurityEmailJob,
)
from app.models.user import User, utc_now
from app.services.email_service import (
    EmailDeliveryError,
    send_password_changed_email,
    send_password_reset_email,
    send_verification_email,
)


ProcessOutcome = Literal[
    "completed",
    "retry_scheduled",
    "cancelled",
    "lost_lease",
]


@dataclass(frozen=True)
class SecurityEmailClaim:
    """The non-secret state needed to process one leased job."""

    job_id: str
    user_id: int
    kind: str
    attempts: int
    lease_expires_at: datetime


@dataclass(frozen=True)
class SecurityEmailProcessResult:
    """A CLI-friendly summary which never includes email content or secrets."""

    job_id: str
    outcome: ProcessOutcome


def _positive_config_int(name: str, default: int) -> int:
    value = current_app.config.get(name, default)
    if isinstance(value, bool):
        raise RuntimeError(f"{name} must be a positive integer.")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise RuntimeError(f"{name} must be a positive integer.") from exc
    if parsed <= 0:
        raise RuntimeError(f"{name} must be a positive integer.")
    return parsed


def _validate_kind(kind: str) -> str:
    if kind not in SECURITY_EMAIL_KINDS:
        raise ValueError("Unsupported security email kind.")
    return kind


def _invalidate_active_action_tokens(
    user_id: int,
    purpose: str,
    now: datetime,
) -> None:
    if purpose not in {EMAIL_VERIFICATION, PASSWORD_RESET}:
        return
    db.session.execute(
        update(AccountActionToken)
        .where(
            AccountActionToken.user_id == user_id,
            AccountActionToken.purpose == purpose,
            AccountActionToken.consumed_at.is_(None),
            AccountActionToken.invalidated_at.is_(None),
        )
        .values(invalidated_at=now)
    )


def cancel_security_email_jobs(
    user: User,
    kind: str,
    *,
    commit: bool = True,
) -> int:
    """Cancel every incomplete job of one kind and invalidate its challenge."""

    kind = _validate_kind(kind)
    if user.id is None:
        db.session.flush()
    locked_user = db.session.execute(
        select(User)
        .where(User.id == user.id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one()
    now = utc_now()
    result = db.session.execute(
        update(SecurityEmailJob)
        .where(
            SecurityEmailJob.user_id == locked_user.id,
            SecurityEmailJob.kind == kind,
            SecurityEmailJob.completed_at.is_(None),
            SecurityEmailJob.cancelled_at.is_(None),
        )
        .values(cancelled_at=now, lease_expires_at=None)
    )
    _invalidate_active_action_tokens(locked_user.id, kind, now)
    if commit:
        db.session.commit()
    else:
        db.session.flush()
    return int(result.rowcount)


def enqueue_security_email(
    user: User,
    kind: str,
    *,
    commit: bool = True,
) -> SecurityEmailJob | None:
    """Queue one delivery intent without creating or retaining a raw token.

    Replacement verification and recovery requests supersede every older
    incomplete delivery for the same account and purpose. Password-change
    alerts are security events and are never coalesced. Active challenges are
    invalidated immediately so a replacement request also replaces any prior
    usable link.
    """

    kind = _validate_kind(kind)
    if user.id is None:
        db.session.flush()

    # Every operation which creates, consumes, or replaces an account-action
    # challenge takes the user lock first. This both avoids PostgreSQL
    # deadlocks and prevents concurrent requests from leaving two usable token
    # generations. ``populate_existing`` refreshes a caller-provided object
    # after waiting for another transaction.
    locked_user = db.session.execute(
        select(User)
        .where(User.id == user.id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one()
    if kind == EMAIL_VERIFICATION and locked_user.email_verified_at is not None:
        if commit:
            db.session.commit()
        return None

    now = utc_now()
    if kind in {EMAIL_VERIFICATION, PASSWORD_RESET}:
        # Cancel even an actively leased predecessor. A worker also checks the
        # job while holding this same user lock before issuing a usable token.
        # If delivery has already begun, token invalidation below makes the
        # stale message harmless.
        cancel_security_email_jobs(locked_user, kind, commit=False)

    job = SecurityEmailJob(
        user_id=locked_user.id,
        kind=kind,
        created_at=now,
        available_at=now,
    )
    db.session.add(job)
    if commit:
        db.session.commit()
    else:
        db.session.flush()
    return job


def _claim_eligibility(now: datetime):
    return (
        SecurityEmailJob.completed_at.is_(None),
        SecurityEmailJob.cancelled_at.is_(None),
        SecurityEmailJob.available_at <= now,
        or_(
            SecurityEmailJob.lease_expires_at.is_(None),
            SecurityEmailJob.lease_expires_at <= now,
        ),
    )


def claim_security_email_job(
    job_id: str | None = None,
) -> SecurityEmailClaim | None:
    """Atomically lease one available job, optionally by its UUID.

    The candidate selection and conditional update are one database statement.
    A competing worker can therefore receive the row only after its lease has
    expired. Incrementing ``attempts`` in that same statement makes retries
    durable even if a worker crashes immediately after claiming the job.
    """

    now = utc_now()
    lease_expires_at = now + timedelta(
        seconds=_positive_config_int("SECURITY_EMAIL_LEASE_SECONDS", 300)
    )
    eligibility = _claim_eligibility(now)
    candidate = select(SecurityEmailJob.id).where(*eligibility)
    if job_id is not None:
        candidate = candidate.where(SecurityEmailJob.id == job_id)
    candidate = candidate.order_by(
        SecurityEmailJob.available_at,
        SecurityEmailJob.created_at,
        SecurityEmailJob.id,
    ).limit(1)

    statement = (
        update(SecurityEmailJob)
        .where(
            SecurityEmailJob.id == candidate.scalar_subquery(),
            *eligibility,
        )
        .values(
            lease_expires_at=lease_expires_at,
            attempts=SecurityEmailJob.attempts + 1,
        )
        .returning(
            SecurityEmailJob.id,
            SecurityEmailJob.user_id,
            SecurityEmailJob.kind,
            SecurityEmailJob.attempts,
            SecurityEmailJob.lease_expires_at,
        )
    )
    row = db.session.execute(
        statement.execution_options(synchronize_session=False)
    ).one_or_none()
    db.session.commit()
    if row is None:
        return None
    return SecurityEmailClaim(
        job_id=row.id,
        user_id=row.user_id,
        kind=row.kind,
        attempts=row.attempts,
        lease_expires_at=row.lease_expires_at,
    )


def _transition_claim(
    claim: SecurityEmailClaim,
    *,
    completed_at: datetime | None = None,
    cancelled_at: datetime | None = None,
    available_at: datetime | None = None,
) -> bool:
    values: dict[str, object] = {"lease_expires_at": None}
    if completed_at is not None:
        values["completed_at"] = completed_at
    if cancelled_at is not None:
        values["cancelled_at"] = cancelled_at
    if available_at is not None:
        values["available_at"] = available_at

    result = db.session.execute(
        update(SecurityEmailJob)
        .where(
            SecurityEmailJob.id == claim.job_id,
            SecurityEmailJob.completed_at.is_(None),
            SecurityEmailJob.cancelled_at.is_(None),
            SecurityEmailJob.lease_expires_at == claim.lease_expires_at,
        )
        .values(**values)
    )
    db.session.commit()
    return result.rowcount == 1


def _finish_delivery(claim: SecurityEmailClaim) -> ProcessOutcome:
    if _transition_claim(claim, completed_at=utc_now()):
        return "completed"
    return "lost_lease"


def _cancel_delivery(claim: SecurityEmailClaim) -> ProcessOutcome:
    if _transition_claim(claim, cancelled_at=utc_now()):
        return "cancelled"
    return "lost_lease"


def _reschedule_delivery_failure(
    claim: SecurityEmailClaim,
    raw_token: str | None,
) -> ProcessOutcome:
    """Invalidate this worker's link and release or exhaust its lease."""

    now = utc_now()
    if raw_token is not None and claim.kind in {
        EMAIL_VERIFICATION,
        PASSWORD_RESET,
    }:
        # Local import keeps the outbox usable from account-token transactions
        # without creating a circular module dependency.
        from app.services.account_token_service import hash_account_token

        digest = hash_account_token(raw_token, claim.kind)
        db.session.execute(
            update(AccountActionToken)
            .where(
                AccountActionToken.user_id == claim.user_id,
                AccountActionToken.purpose == claim.kind,
                AccountActionToken.token_hash == digest,
                AccountActionToken.consumed_at.is_(None),
                AccountActionToken.invalidated_at.is_(None),
            )
            .values(invalidated_at=now)
        )

    maximum_attempts = _positive_config_int("SECURITY_EMAIL_MAX_ATTEMPTS", 5)
    if claim.attempts >= maximum_attempts:
        transitioned = _transition_claim(claim, cancelled_at=now)
        return "cancelled" if transitioned else "lost_lease"

    base_delay = _positive_config_int("SECURITY_EMAIL_RETRY_BASE_SECONDS", 30)
    maximum_delay = _positive_config_int("SECURITY_EMAIL_RETRY_MAX_SECONDS", 3600)
    exponent = min(max(claim.attempts - 1, 0), 30)
    delay_seconds = min(base_delay * (2**exponent), maximum_delay)
    transitioned = _transition_claim(
        claim,
        available_at=now + timedelta(seconds=delay_seconds),
    )
    return "retry_scheduled" if transitioned else "lost_lease"


def process_security_email_job(
    job_id: str | None = None,
) -> SecurityEmailProcessResult | None:
    """Claim and process one job without retaining a usable action token."""

    claim = claim_security_email_job(job_id)
    if claim is None:
        return None

    # Queue replacement, token issuance, and token consumption all use the
    # same user-first lock order. After acquiring it, re-check that the claimed
    # job was not cancelled while this worker was waiting.
    user = db.session.execute(
        select(User)
        .where(User.id == claim.user_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one_or_none()
    if user is None:
        outcome = _cancel_delivery(claim)
        return SecurityEmailProcessResult(claim.job_id, outcome)
    active_claim = db.session.execute(
        select(SecurityEmailJob.id).where(
            SecurityEmailJob.id == claim.job_id,
            SecurityEmailJob.completed_at.is_(None),
            SecurityEmailJob.cancelled_at.is_(None),
            SecurityEmailJob.lease_expires_at == claim.lease_expires_at,
        )
    ).scalar_one_or_none()
    if active_claim is None:
        db.session.rollback()
        return SecurityEmailProcessResult(claim.job_id, "lost_lease")

    raw_token: str | None = None
    try:
        if claim.kind == EMAIL_VERIFICATION:
            from app.services.account_token_service import (
                issue_email_verification_token,
            )

            raw_token = issue_email_verification_token(user)
            if raw_token is None:
                outcome = _cancel_delivery(claim)
                return SecurityEmailProcessResult(claim.job_id, outcome)
            delivered = send_verification_email(user, raw_token)
        elif claim.kind == PASSWORD_RESET:
            from app.services.account_token_service import issue_password_reset_token

            raw_token = issue_password_reset_token(user)
            delivered = send_password_reset_email(user, raw_token)
        elif claim.kind == PASSWORD_CHANGED:
            delivered = send_password_changed_email(user)
        else:  # The database constraint should make this unreachable.
            outcome = _cancel_delivery(claim)
            return SecurityEmailProcessResult(claim.job_id, outcome)

        if delivered is not True:
            raise EmailDeliveryError(
                "The configured email transport did not accept the message."
            )
    except EmailDeliveryError:
        db.session.rollback()
        outcome = _reschedule_delivery_failure(claim, raw_token)
        return SecurityEmailProcessResult(claim.job_id, outcome)
    finally:
        # Python strings cannot be reliably zeroed, but dropping this reference
        # ensures the usable token exists only for this worker call's lifetime.
        raw_token = None

    outcome = _finish_delivery(claim)
    return SecurityEmailProcessResult(claim.job_id, outcome)


def process_pending_security_email(
    limit: int = 100,
) -> list[SecurityEmailProcessResult]:
    """Process up to ``limit`` available jobs for a CLI or worker command."""

    if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
        raise ValueError("limit must be a positive integer.")

    results: list[SecurityEmailProcessResult] = []
    for _ in range(limit):
        result = process_security_email_job()
        if result is None:
            break
        results.append(result)
    return results


__all__ = [
    "SecurityEmailClaim",
    "SecurityEmailProcessResult",
    "cancel_security_email_jobs",
    "claim_security_email_job",
    "enqueue_security_email",
    "process_pending_security_email",
    "process_security_email_job",
]
