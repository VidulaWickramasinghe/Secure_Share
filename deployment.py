"""Safe WSGI startup when a hosted deployment is not configured yet.

This module must not import the app package at module scope: configuration can
fail while that package is being imported. It never substitutes development
credentials or storage, and the unavailable application exposes no API routes.
"""

from __future__ import annotations

import logging
import os

from flask import Flask, Response, jsonify, request


class DeploymentConfigurationError(RuntimeError):
    """A collection of operator-actionable, value-free setup problems."""

    def __init__(self, problems: list[str]):
        self.problems = tuple(dict.fromkeys(problems))
        super().__init__(
            "Deployment configuration is incomplete:\n- " + "\n- ".join(self.problems)
        )


def unavailable_application() -> Flask:
    """Return a real 503, never a working-looking app with unsafe defaults."""

    application = Flask("secure_share_unavailable", static_folder=None)

    @application.before_request
    def unavailable():
        # Do not read request bodies, render environment values, set cookies,
        # or expose the detailed operator checklist to unauthenticated users.
        if request.path.startswith("/api/") or request.path == "/healthz":
            response = jsonify(
                error="Secure Share is unavailable. Deployment setup is incomplete.",
                code="deployment_not_ready",
            )
        else:
            response = Response(
                "<!doctype html><html lang=en><meta charset=utf-8>"
                "<meta name=viewport content='width=device-width,initial-scale=1'>"
                "<title>Secure Share — setup required</title>"
                "<main><h1>Secure Share is not ready yet</h1>"
                "<p>The server is running, but deployment setup is incomplete.</p>"
                "<p>Sign-in, uploads and downloads are disabled.</p>"
                "<p>If you manage this site, check the Vercel runtime logs and "
                "the repository deployment guide, then redeploy.</p></main></html>",
                mimetype="text/html",
            )
        response.status_code = 503
        response.headers.update(
            {
                "Cache-Control": "no-store",
                "Retry-After": "300",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "no-referrer",
                "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            }
        )
        return response

    return application


def create_wsgi_application() -> Flask:
    try:
        from app import create_app

        return create_app()
    except DeploymentConfigurationError as exc:
        if os.getenv("VERCEL") != "1":
            raise
        logging.getLogger(__name__).error("%s", exc)
        return unavailable_application()
    # Unexpected programming/import errors deliberately retain their traceback.
    # They must not be mislabeled as a configuration problem or hidden by a
    # catch-all fallback. The known configuration failures above are value-free.
