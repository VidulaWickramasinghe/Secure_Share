"""Focused integration tests for the browser interface and its API boundary."""

from __future__ import annotations

import json
import re

import pytest

from app.extensions import db
from app.models.file import FileRecord


@pytest.mark.parametrize(
    ("path", "page_marker", "page_module"),
    (
        ("/", "Private file transfer with owner-controlled access.", "login.js"),
        ("/login", "Sign in", "login.js"),
        ("/register", "Create account", "register.js"),
        ("/forgot-password", "Request a reset link", "forgot_password.js"),
        ("/reset-password", "Choose a new password", "reset_password.js"),
        ("/verify-email", "Checking your secure link", "verify_email.js"),
        ("/dashboard", "My Files", "dashboard.js"),
    ),
)
def test_web_pages_render_the_expected_application_shell(
    client, path, page_marker, page_module
):
    response = client.get(path)

    assert response.status_code == 200
    assert response.mimetype == "text/html"
    html = response.get_data(as_text=True)
    assert "Secure Share" in html
    assert page_marker in html
    assert "/static/css/style.css" in html
    assert f"/static/js/{page_module}" in html


def test_rendered_pages_use_only_resolvable_external_assets(client):
    assets: set[str] = set()
    for path in (
        "/",
        "/login",
        "/register",
        "/forgot-password",
        "/reset-password",
        "/verify-email",
        "/dashboard",
    ):
        html = client.get(path).get_data(as_text=True)
        assets.update(re.findall(r'(?:href|src)="(/static/[^"?#]+)', html))

        # Keep the CSP meaningful: page behavior and styling belong in bundled
        # files rather than inline blocks or event-handler attributes.
        assert re.search(r"<script(?![^>]*\bsrc=)[^>]*>", html, re.IGNORECASE) is None
        assert re.search(r"\sstyle\s*=", html, re.IGNORECASE) is None
        assert re.search(r"\son[a-z]+\s*=", html, re.IGNORECASE) is None

    assert any(asset.endswith(".css") for asset in assets)
    assert any(asset.endswith(".js") for asset in assets)
    for asset in assets:
        response = client.get(asset)
        assert response.status_code == 200, asset


def test_password_forms_have_safe_post_fallbacks(client):
    """A blocked script must never make a password fall back to a GET URL."""

    for path in ("/", "/login", "/register", "/reset-password"):
        html = client.get(path).get_data(as_text=True)
        forms = re.findall(r"<form\b[^>]*>[\s\S]*?</form>", html, re.IGNORECASE)
        password_forms = [
            form
            for form in forms
            if re.search(r'type=["\']password["\']', form, re.IGNORECASE)
        ]

        assert password_forms
        for form in password_forms:
            opening_tag = form.split(">", 1)[0]
            assert re.search(
                r'\bmethod\s*=\s*["\']post["\']', opening_tag, re.IGNORECASE
            )
            assert re.search(
                r'\baction\s*=\s*["\']/api/auth/(?:browser-login|register|password-reset/confirm)["\']',
                opening_tag,
                re.IGNORECASE,
            )


def test_dashboard_shell_does_not_embed_account_file_or_token_data(
    app, client, register_user, login_user, upload_file
):
    user = register_user("rendercheck", "rendercheck@example.com")
    token = login_user("rendercheck")
    upload = upload_file(
        token,
        content=b"not for a server-rendered page",
        filename="render-check-private.pdf",
    )
    assert upload.status_code == 201
    file_id = upload.get_json()["file"]["id"]

    with app.app_context():
        record = db.session.get(FileRecord, file_id)
        assert record is not None
        stored_filename = record.stored_filename

    html = client.get("/dashboard").get_data(as_text=True)
    for private_value in (
        token,
        user["username"],
        user["email"],
        file_id,
        "render-check-private.pdf",
        stored_filename,
    ):
        assert private_value not in html

    # Password inputs must never be pre-populated by the server.
    for path in ("/", "/login", "/register", "/reset-password"):
        page = client.get(path).get_data(as_text=True)
        password_inputs = re.findall(
            r'<input\b[^>]*\btype=["\']password["\'][^>]*>',
            page,
            re.IGNORECASE,
        )
        assert password_inputs
        assert all("value=" not in element.lower() for element in password_inputs)


def test_private_storage_is_not_exposed_as_a_web_or_static_route(
    app, client, authenticated_alice, upload_file
):
    upload = upload_file(
        authenticated_alice["token"],
        content=b"private route isolation",
        filename="private-route.txt",
    )
    assert upload.status_code == 201
    file_id = upload.get_json()["file"]["id"]

    with app.app_context():
        record = db.session.get(FileRecord, file_id)
        assert record is not None
        stored_filename = record.stored_filename

    for path in (
        f"/storage/{stored_filename}",
        f"/static/{stored_filename}",
    ):
        response = client.get(path)
        assert response.status_code == 404
        assert response.data != b"private route isolation"


def test_web_and_api_responses_have_distinct_restrictive_csp(client):
    required_web_directives = {
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self'",
        "object-src 'none'",
        "base-uri 'self'",
        "frame-ancestors 'none'",
    }

    for path in (
        "/",
        "/login",
        "/register",
        "/forgot-password",
        "/reset-password",
        "/verify-email",
        "/dashboard",
    ):
        response = client.get(path)
        csp = response.headers["Content-Security-Policy"]
        directives = {item.strip() for item in csp.split(";") if item.strip()}
        assert required_web_directives <= directives
        assert "'unsafe-inline'" not in csp
        assert "'unsafe-eval'" not in csp
        assert response.headers["X-Frame-Options"] == "DENY"
        assert response.headers["X-Content-Type-Options"] == "nosniff"

    api_response = client.get("/api/files")
    api_csp = {
        item.strip()
        for item in api_response.headers["Content-Security-Policy"].split(";")
        if item.strip()
    }
    assert api_response.status_code == 401
    assert api_csp == {"default-src 'none'", "frame-ancestors 'none'"}
    assert "no-store" in api_response.headers["Cache-Control"]


def test_frontend_uses_cookie_session_and_separate_csrf_token(client):
    auth_response = client.get("/static/js/auth.js")
    api_response = client.get("/static/js/api.js")

    assert auth_response.status_code == 200
    assert api_response.status_code == 200
    source = auth_response.get_data(as_text=True)
    combined_source = source + "\n" + api_response.get_data(as_text=True)

    assert "sessionStorage" in source
    assert "secure-share.auth-notice" in source
    assert "authorizedFetch" in combined_source
    assert "/api/auth/browser-login" in source
    assert "document.cookie" in source
    assert "X-CSRF-Token" in combined_source
    assert "X-Secure-Share-CSRF-Restore" in combined_source
    assert "withCredentials = true" in combined_source
    assert 'credentials: "same-origin"' in combined_source
    assert re.search(r"status\s*===\s*401", combined_source)
    assert "removeItem" in source
    assert "/login" in source

    # JavaScript may store notices and read the non-credential CSRF cookie, but
    # it must never store or attach the HttpOnly session credential.
    assert "LEGACY_TOKEN_STORAGE_KEY" in source
    assert "removeSessionValue(LEGACY_TOKEN_STORAGE_KEY)" in source
    assert "storeAuthToken" not in combined_source
    assert "Authorization" not in combined_source
    assert "Bearer" not in combined_source
    assert "getAuthToken" not in combined_source
    assert re.search(r"\blocalStorage\b", combined_source) is None
    assert "URLSearchParams" not in combined_source
    assert re.search(r"[?&](?:access_)?token=", combined_source, re.IGNORECASE) is None
    assert re.search(r"console\.(?:log|debug)\s*\(", combined_source) is None


def test_account_action_frontend_keeps_tokens_out_of_urls_and_storage(client):
    reset_source = client.get("/static/js/reset_password.js").get_data(as_text=True)
    verify_source = client.get("/static/js/verify_email.js").get_data(as_text=True)
    api_source = client.get("/static/js/api.js").get_data(as_text=True)
    action_source = f"{reset_source}\n{verify_source}"

    assert 'window.location.hash.slice(1)' in action_source
    assert "window.history.replaceState" in action_source
    assert 'credentials: "omit"' in api_source
    assert "/api/auth/email-verification/confirm" in api_source
    assert "/api/auth/password-reset/request" in api_source
    assert "/api/auth/password-reset/confirm" in api_source
    assert "localStorage" not in action_source
    assert "sessionStorage" not in action_source
    assert re.search(r"[?&](?:access_)?token=", action_source, re.IGNORECASE) is None
    assert re.search(r"console\.(?:log|debug)\s*\(", action_source) is None


def test_dashboard_includes_email_verification_status_without_private_data(client):
    html = client.get("/dashboard").get_data(as_text=True)

    assert 'id="email-verification-banner"' in html
    assert 'id="resend-verification-button"' in html
    assert 'id="email-verification-status"' in html
    assert "#token=" not in html


def test_file_list_presentation_fields_are_safe_and_permission_derived(
    client, upload_file, three_accounts
):
    alice = three_accounts["alice"]
    bob = three_accounts["bob"]
    charlie = three_accounts["charlie"]
    alice_headers = {"Authorization": f"Bearer {alice['token']}"}
    bob_headers = {"Authorization": f"Bearer {bob['token']}"}
    charlie_headers = {"Authorization": f"Bearer {charlie['token']}"}

    content = b"dashboard permission integration"
    upload = upload_file(
        alice["token"], content=content, filename="dashboard-report.pdf"
    )
    assert upload.status_code == 201
    file_id = upload.get_json()["file"]["id"]

    grant = client.post(
        f"/api/files/{file_id}/permissions",
        headers=alice_headers,
        json={"user_id": bob["user"]["id"]},
    )
    assert grant.status_code == 201

    owner_list = client.get("/api/files", headers=alice_headers).get_json()["files"]
    shared_list = client.get("/api/files", headers=bob_headers).get_json()["files"]
    unrelated_list = client.get("/api/files", headers=charlie_headers).get_json()[
        "files"
    ]

    assert len(owner_list) == 1
    assert owner_list[0]["access_type"] == "owner"
    assert owner_list[0]["owner"] == {
        "id": alice["user"]["id"],
        "username": "alice",
    }
    assert owner_list[0]["authorized_user_count"] == 1

    assert len(shared_list) == 1
    assert shared_list[0]["id"] == file_id
    assert shared_list[0]["access_type"] == "shared"
    assert shared_list[0]["owner"] == {
        "id": alice["user"]["id"],
        "username": "alice",
    }
    assert "authorized_user_count" not in shared_list[0]
    assert unrelated_list == []

    serialized_lists = json.dumps(owner_list + shared_list).lower()
    for forbidden_field_or_value in (
        "stored_filename",
        "password",
        "alice@example.com",
        "bob@example.com",
    ):
        assert forbidden_field_or_value not in serialized_lists

    download = client.get(f"/api/files/{file_id}/download", headers=bob_headers)
    assert download.status_code == 200
    assert download.data == content

    revoke = client.delete(
        f"/api/files/{file_id}/permissions/{bob['user']['id']}",
        headers=alice_headers,
    )
    assert revoke.status_code == 200
    assert client.get("/api/files", headers=bob_headers).get_json()["files"] == []
    assert (
        client.get(f"/api/files/{file_id}/download", headers=bob_headers).status_code
        == 403
    )

    logout = client.post("/api/auth/logout", headers=bob_headers)
    assert logout.status_code == 200
    assert client.get("/api/auth/me", headers=bob_headers).status_code == 401
