"""Shared pytest fixtures for API and storage tests."""

from __future__ import annotations

import io
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

# Keep direct `pytest` invocation as reliable as `python -m pytest` without
# requiring this small application to be installed as a package first.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app import create_app
from app.extensions import db


@pytest.fixture()
def app(tmp_path: Path):
    """Create an isolated application, database, and upload store per test."""
    upload_folder = tmp_path / "uploads"
    application = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "test-only-secret-key-with-sufficient-entropy",
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'test.db'}",
            "SQLALCHEMY_TRACK_MODIFICATIONS": False,
            "UPLOAD_FOLDER": str(upload_folder),
            "MAX_CONTENT_LENGTH": 1024 * 1024,
            "SESSION_LIFETIME_SECONDS": 3600,
        }
    )

    with application.app_context():
        db.create_all()

    yield application

    with application.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def register_user(client) -> Callable[..., dict[str, Any]]:
    def _register(
        username: str,
        email: str | None = None,
        password: str = "CorrectHorseBatteryStaple!42",
    ) -> dict[str, Any]:
        response = client.post(
            "/api/auth/register",
            json={
                "username": username,
                "email": email or f"{username}@example.com",
                "password": password,
            },
        )
        assert response.status_code == 201, response.get_json()
        body = response.get_json()
        assert isinstance(body, dict) and isinstance(body.get("user"), dict)
        return body["user"]

    return _register


@pytest.fixture()
def login_user(client) -> Callable[..., str]:
    def _login(
        identifier: str,
        password: str = "CorrectHorseBatteryStaple!42",
    ) -> str:
        response = client.post(
            "/api/auth/login",
            json={"identifier": identifier, "password": password},
        )
        assert response.status_code == 200, response.get_json()
        body = response.get_json()
        assert isinstance(body, dict) and isinstance(body.get("token"), str)
        return body["token"]

    return _login


@pytest.fixture()
def bearer_headers() -> Callable[[str], dict[str, str]]:
    def _headers(token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}"}

    return _headers


@pytest.fixture()
def upload_file(client) -> Callable[..., Any]:
    def _upload(
        token: str,
        content: bytes = b"confidential contents\n",
        filename: str = "report.pdf",
    ):
        return client.post(
            "/api/files",
            headers={"Authorization": f"Bearer {token}"},
            data={"file": (io.BytesIO(content), filename)},
            content_type="multipart/form-data",
        )

    return _upload


@pytest.fixture()
def authenticated_alice(register_user, login_user) -> dict[str, Any]:
    user = register_user("alice", "alice@example.com")
    return {"user": user, "token": login_user("alice")}


@pytest.fixture()
def three_accounts(register_user, login_user) -> dict[str, dict[str, Any]]:
    accounts: dict[str, dict[str, Any]] = {}
    for username in ("alice", "bob", "charlie"):
        user = register_user(username, f"{username}@example.com")
        accounts[username] = {
            "user": user,
            "token": login_user(username),
        }
    return accounts
