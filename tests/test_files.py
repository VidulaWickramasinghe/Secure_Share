"""Private upload, metadata, listing, download, and deletion tests."""

from __future__ import annotations

import io
from pathlib import Path
from uuid import uuid4

import pytest

from app.extensions import db
from app.models.file import FileRecord


def test_file_endpoints_reject_unauthenticated_requests(client):
    upload = client.post(
        "/api/files",
        data={"file": (io.BytesIO(b"secret"), "report.pdf")},
        content_type="multipart/form-data",
    )

    assert upload.status_code == 401
    assert client.get("/api/files").status_code == 401
    assert client.get(f"/api/files/{uuid4()}").status_code == 401
    assert client.get(f"/api/files/{uuid4()}/download").status_code == 401
    assert client.delete(f"/api/files/{uuid4()}").status_code == 401


def test_authenticated_user_can_upload_and_metadata_is_stored(
    app, authenticated_alice, upload_file
):
    content = b"a private report\nwith two lines\n"

    response = upload_file(
        authenticated_alice["token"],
        content=content,
        filename="quarterly-report.pdf",
    )

    assert response.status_code == 201
    metadata = response.get_json()["file"]
    assert metadata["original_filename"] == "quarterly-report.pdf"
    assert metadata["owner_id"] == authenticated_alice["user"]["id"]
    assert metadata["file_size"] == len(content)
    assert metadata["created_at"]
    assert "stored_filename" not in metadata

    with app.app_context():
        record = db.session.get(FileRecord, metadata["id"])
        assert record is not None
        assert record.original_filename == "quarterly-report.pdf"
        assert record.owner_id == authenticated_alice["user"]["id"]
        assert record.file_size == len(content)
        assert record.stored_filename != record.original_filename
        assert "/" not in record.stored_filename
        assert "\\" not in record.stored_filename
        stored_path = Path(app.config["UPLOAD_FOLDER"]) / record.stored_filename
        assert stored_path.is_file()
        assert stored_path.read_bytes() == content


def test_upload_requires_a_real_file(client, authenticated_alice, bearer_headers):
    headers = bearer_headers(authenticated_alice["token"])

    missing = client.post("/api/files", headers=headers, data={})
    empty_name = client.post(
        "/api/files",
        headers=headers,
        data={"file": (io.BytesIO(b"data"), "")},
        content_type="multipart/form-data",
    )

    assert missing.status_code == 400
    assert empty_name.status_code == 400
    assert "error" in missing.get_json()
    assert "error" in empty_name.get_json()


def test_path_traversal_filenames_are_rejected_and_cannot_escape_storage(
    app, authenticated_alice, upload_file, tmp_path
):
    parent_target = tmp_path / "escape.txt"

    unix_traversal = upload_file(
        authenticated_alice["token"],
        filename="../escape.txt",
    )
    nested_traversal = upload_file(
        authenticated_alice["token"],
        filename="safe/../../escape.txt",
    )
    windows_traversal = upload_file(
        authenticated_alice["token"],
        filename="..\\escape.txt",
    )

    assert unix_traversal.status_code == 400
    assert nested_traversal.status_code == 400
    assert windows_traversal.status_code == 400
    assert not parent_target.exists()
    assert list(Path(app.config["UPLOAD_FOLDER"]).iterdir()) == []


def test_each_upload_gets_a_unique_server_side_name(
    app, authenticated_alice, upload_file
):
    first = upload_file(authenticated_alice["token"], filename="same-name.txt")
    second = upload_file(authenticated_alice["token"], filename="same-name.txt")

    assert first.status_code == 201
    assert second.status_code == 201
    with app.app_context():
        records = db.session.execute(db.select(FileRecord)).scalars().all()
        assert len(records) == 2
        assert records[0].stored_filename != records[1].stored_filename


def test_configured_maximum_request_size_is_enforced(
    app, authenticated_alice, upload_file
):
    too_large = b"x" * (app.config["MAX_CONTENT_LENGTH"] + 1)

    response = upload_file(
        authenticated_alice["token"],
        content=too_large,
        filename="too-large.bin",
    )

    assert response.status_code == 413
    assert "error" in response.get_json()
    with app.app_context():
        assert db.session.execute(db.select(FileRecord)).scalar_one_or_none() is None


def test_owner_can_view_list_and_file_metadata(
    client, authenticated_alice, upload_file, bearer_headers
):
    upload = upload_file(authenticated_alice["token"], filename="report.pdf")
    file_data = upload.get_json()["file"]
    headers = bearer_headers(authenticated_alice["token"])

    listing = client.get("/api/files", headers=headers)
    detail = client.get(f"/api/files/{file_data['id']}", headers=headers)

    assert listing.status_code == 200
    assert [item["id"] for item in listing.get_json()["files"]] == [file_data["id"]]
    assert detail.status_code == 200
    assert detail.get_json()["file"] == file_data


def test_owner_can_download_exact_original_bytes(
    client, authenticated_alice, upload_file, bearer_headers
):
    content = b"\x00\x01private binary contents\xff"
    upload = upload_file(
        authenticated_alice["token"], content=content, filename="archive.bin"
    )
    file_id = upload.get_json()["file"]["id"]

    response = client.get(
        f"/api/files/{file_id}/download",
        headers=bearer_headers(authenticated_alice["token"]),
    )

    assert response.status_code == 200
    assert response.data == content
    assert "attachment" in response.headers["Content-Disposition"].lower()
    assert "archive.bin" in response.headers["Content-Disposition"]
    assert response.content_length == len(content)


def test_uploaded_script_is_returned_as_inert_attachment(
    client, authenticated_alice, upload_file, bearer_headers
):
    script = b"raise RuntimeError('this content must never execute')\n"
    upload = upload_file(
        authenticated_alice["token"], content=script, filename="payload.py"
    )
    file_id = upload.get_json()["file"]["id"]

    response = client.get(
        f"/api/files/{file_id}/download",
        headers=bearer_headers(authenticated_alice["token"]),
    )

    assert response.status_code == 200
    assert response.data == script
    assert response.mimetype == "application/octet-stream"
    assert "attachment" in response.headers["Content-Disposition"].lower()
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert "no-store" in response.headers["Cache-Control"]


def test_symlinked_storage_entry_is_never_served(
    app, client, authenticated_alice, upload_file, bearer_headers, tmp_path
):
    upload = upload_file(
        authenticated_alice["token"],
        content=b"expected private content",
        filename="report.txt",
    )
    file_id = upload.get_json()["file"]["id"]

    with app.app_context():
        record = db.session.get(FileRecord, file_id)
        stored_path = Path(app.config["UPLOAD_FOLDER"]) / record.stored_filename

    outside_file = tmp_path / "outside-secret.txt"
    outside_file.write_bytes(b"must never be returned")
    stored_path.unlink()
    try:
        stored_path.symlink_to(outside_file)
    except (NotImplementedError, OSError):
        pytest.skip("Symbolic links are unavailable on this platform.")

    response = client.get(
        f"/api/files/{file_id}/download",
        headers=bearer_headers(authenticated_alice["token"]),
    )

    assert response.status_code == 404
    assert response.is_json
    assert outside_file.read_bytes() not in response.data


def test_owner_can_delete_database_record_and_physical_file(
    app, client, authenticated_alice, upload_file, bearer_headers
):
    upload = upload_file(authenticated_alice["token"], filename="delete-me.txt")
    file_id = upload.get_json()["file"]["id"]

    with app.app_context():
        record = db.session.get(FileRecord, file_id)
        stored_path = Path(app.config["UPLOAD_FOLDER"]) / record.stored_filename
        assert stored_path.exists()

    response = client.delete(
        f"/api/files/{file_id}",
        headers=bearer_headers(authenticated_alice["token"]),
    )

    assert response.status_code == 200
    assert not stored_path.exists()
    with app.app_context():
        assert db.session.get(FileRecord, file_id) is None


def test_invalid_and_unknown_file_ids_return_not_found(
    client, authenticated_alice, bearer_headers
):
    headers = bearer_headers(authenticated_alice["token"])
    unknown_id = str(uuid4())

    for path in (
        "/api/files/not-a-uuid",
        "/api/files/not-a-uuid/download",
        f"/api/files/{unknown_id}",
        f"/api/files/{unknown_id}/download",
    ):
        response = client.get(path, headers=headers)
        assert response.status_code == 404
        assert "error" in response.get_json()

    assert client.delete(
        f"/api/files/{unknown_id}", headers=headers
    ).status_code == 404


def test_cookie_authenticated_file_lifecycle_requires_csrf_for_mutations(
    app, client, register_user, browser_login_user
):
    register_user("alice", "alice@example.com")
    browser = browser_login_user("alice")

    rejected = client.post(
        "/api/files",
        data={"file": (io.BytesIO(b"must not persist"), "rejected.txt")},
        content_type="multipart/form-data",
    )

    assert rejected.status_code == 403
    with app.app_context():
        assert FileRecord.query.count() == 0
    assert list(Path(app.config["UPLOAD_FOLDER"]).iterdir()) == []

    uploaded = client.post(
        "/api/files",
        headers={"X-CSRF-Token": browser["csrf_token"]},
        data={"file": (io.BytesIO(b"cookie authorized"), "cookie.txt")},
        content_type="multipart/form-data",
    )
    assert uploaded.status_code == 201
    file_id = uploaded.get_json()["file"]["id"]

    download = client.get(f"/api/files/{file_id}/download")
    assert download.status_code == 200
    assert download.data == b"cookie authorized"

    missing_delete_csrf = client.delete(f"/api/files/{file_id}")
    assert missing_delete_csrf.status_code == 403
    assert client.delete(
        f"/api/files/{file_id}",
        headers={"X-CSRF-Token": browser["csrf_token"]},
    ).status_code == 200
