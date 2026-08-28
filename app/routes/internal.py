"""Authenticated, bounded processing of the existing durable email queue."""

from __future__ import annotations

import secrets
from collections import Counter

from flask import Blueprint, current_app, jsonify, request

from app.services.email_outbox_service import process_pending_security_email


internal_bp = Blueprint("internal", __name__, url_prefix="/api/internal")


@internal_bp.route("/email-worker", methods=["GET", "POST"])
def process_email_batch():
    configured = current_app.config.get("CRON_SECRET")
    if not isinstance(configured, str) or len(configured.strip()) < 32:
        return jsonify(error="Email worker endpoint is not configured."), 503
    provided = request.headers.get("Authorization", "")
    expected = f"Bearer {configured}"
    if not secrets.compare_digest(provided.encode("utf-8"), expected.encode("utf-8")):
        return jsonify(error="Worker authentication required."), 401
    # Ignore caller-supplied batch sizes/job IDs. Existing database leases and
    # retry transitions make duplicate scheduler invocations safe.
    results = process_pending_security_email(
        int(current_app.config["SECURITY_EMAIL_HTTP_BATCH_SIZE"])
    )
    return jsonify(
        processed=len(results),
        outcomes=dict(Counter(result.outcome for result in results)),
    )
