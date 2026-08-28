"""Private upload, metadata, listing, download, and deletion tests."""

from __future__ import annotations

import io
import json
import secrets
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
import httpx

from app.extensions import db
from app.models.file import FileRecord
from vercel.blob.errors import BlobError, BlobNotFoundError


@pytest.fixture()
def private_blob(app, monkeypatch):
    """Model one remote store shared by clients across separate API requests."""
    objects = {}
    operations = []

    class Client:
        def __init__(self, token):
            assert token == app.config["BLOB_READ_WRITE_TOKEN"]

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def put(self, key, content, **kwargs):
            assert kwargs["access"] == "private"
            assert kwargs["overwrite"] is False
            assert kwargs["add_random_suffix"] is False
            assert kwargs["content_type"] == "application/octet-stream"
            assert key.startswith("secure-share/")
            assert key not in objects
            objects[key] = content
            operations.append(("put", key))

        def head(self, key):
            operations.append(("head", key))
            if key not in objects:
                raise BlobNotFoundError()
            return SimpleNamespace(size=len(objects[key]))

        def get(self, key, **kwargs):
            assert kwargs["access"] == "private"
            assert kwargs["use_cache"] is False
            operations.append(("get", key))
            return SimpleNamespace(content=objects[key], status_code=200)

        def delete(self, key):
            operations.append(("delete", key))
            objects.pop(key, None)

    app.config.update(
        FILE_STORAGE_BACKEND="vercel_blob",
        BLOB_READ_WRITE_TOKEN=secrets.token_urlsafe(32),
    )
    monkeypatch.setattr("app.services.file_service.BlobClient", Client)
    return SimpleNamespace(objects=objects, operations=operations, client=Client)


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

    assert client.delete(f"/api/files/{unknown_id}", headers=headers).status_code == 404


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
    assert (
        client.delete(
            f"/api/files/{file_id}",
            headers={"X-CSRF-Token": browser["csrf_token"]},
        ).status_code
        == 200
    )


def test_private_blob_preserves_authorization_revocation_and_deletion(
    app,
    client,
    private_blob,
    three_accounts,
    upload_file,
    bearer_headers,
):
    alice, bob = three_accounts["alice"], three_accounts["bob"]
    alice_headers, bob_headers = (
        bearer_headers(alice["token"]),
        bearer_headers(bob["token"]),
    )
    content = b"private bytes that outlive a function instance"
    uploaded = upload_file(alice["token"], content=content, filename="private.txt")
    assert uploaded.status_code == 201
    metadata = uploaded.get_json()["file"]
    file_id = metadata["id"]
    assert "storage_backend" not in metadata
    assert "url" not in metadata
    assert list(Path(app.config["UPLOAD_FOLDER"]).iterdir()) == []
    with app.app_context():
        assert db.session.get(FileRecord, file_id).storage_backend == "vercel_blob"

    path = f"/api/files/{file_id}"
    assert client.get(path + "/download", headers=bob_headers).status_code == 403
    assert len(private_blob.operations) == 1  # Authorization precedes object access.
    assert (
        client.post(
            path + "/permissions",
            headers=alice_headers,
            json={"user_id": bob["user"]["id"]},
        ).status_code
        == 201
    )
    downloaded = client.get(path + "/download", headers=bob_headers)
    assert downloaded.status_code == 200
    assert downloaded.data == content
    assert "no-store" in downloaded.headers["Cache-Control"]
    assert "attachment" in downloaded.headers["Content-Disposition"]
    assert (
        client.delete(
            path + f"/permissions/{bob['user']['id']}", headers=alice_headers
        ).status_code
        == 200
    )
    operations = len(private_blob.operations)
    assert client.get(path + "/download", headers=bob_headers).status_code == 403
    assert client.delete(path, headers=bob_headers).status_code == 403
    assert len(private_blob.operations) == operations

    # Existing object locations are retained even when new writes change backend.
    app.config["FILE_STORAGE_BACKEND"] = "filesystem"
    assert client.get(path + "/download", headers=alice_headers).data == content
    assert client.delete(path, headers=alice_headers).status_code == 200
    assert private_blob.objects == {}
    with app.app_context():
        assert db.session.get(FileRecord, file_id) is None


def test_blob_size_validation_prevents_remote_writes(
    app,
    private_blob,
    authenticated_alice,
    upload_file,
):
    app.config["MAX_FILE_SIZE"] = 10
    result = upload_file(authenticated_alice["token"], content=b"x" * 11)
    assert result.status_code == 413
    assert private_blob.objects == {}


@pytest.mark.parametrize("missing", [False, True])
def test_blob_missing_or_changed_content_is_not_served(
    private_blob,
    client,
    authenticated_alice,
    upload_file,
    bearer_headers,
    missing,
):
    result = upload_file(authenticated_alice["token"], content=b"original")
    key = next(iter(private_blob.objects))
    if missing:
        private_blob.objects.clear()
    else:
        private_blob.objects[key] = b"corrupt size"
    response = client.get(
        f"/api/files/{result.get_json()['file']['id']}/download",
        headers=bearer_headers(authenticated_alice["token"]),
    )
    assert response.status_code == 404
    assert not any(op == "get" for op, _ in private_blob.operations)


@pytest.mark.parametrize("error_type", [BlobError, httpx.ConnectError])
def test_blob_failures_are_sanitized_and_do_not_persist_metadata(
    app,
    private_blob,
    monkeypatch,
    authenticated_alice,
    upload_file,
    error_type,
):
    canary = secrets.token_urlsafe(32)

    def reject_put(*args, **kwargs):
        raise error_type(canary)

    monkeypatch.setattr(private_blob.client, "put", reject_put)
    result = upload_file(authenticated_alice["token"])
    assert result.status_code == 503
    assert canary not in result.get_data(as_text=True)
    with app.app_context():
        assert FileRecord.query.count() == 0


def test_blob_is_cleaned_up_when_metadata_commit_fails(
    app,
    private_blob,
    monkeypatch,
    authenticated_alice,
):
    from werkzeug.datastructures import FileStorage
    from app.models.user import User
    from app.services.file_service import upload_file as save_upload

    with app.app_context():
        owner = db.session.get(User, authenticated_alice["user"]["id"])

        def reject_commit():
            raise RuntimeError("simulated metadata failure")

        monkeypatch.setattr(db.session, "commit", reject_commit)
        with pytest.raises(RuntimeError, match="simulated metadata failure"):
            save_upload(
                FileStorage(io.BytesIO(b"private"), filename="report.txt"), owner
            )
        assert private_blob.objects == {}
        assert FileRecord.query.count() == 0


def test_real_blob_sdk_sends_private_authenticated_requests(
    app, client, monkeypatch, authenticated_alice, upload_file, bearer_headers,
):
    # Exercise the installed SDK, replacing only its HTTP boundary. This checks
    # the adapter's actual API contract, not a second copy of its implementation.
    token = "_".join(("vercel", "blob", "rw", "teststore", secrets.token_hex(24)))
    app.config.update(FILE_STORAGE_BACKEND="vercel_blob", BLOB_READ_WRITE_TOKEN=token)
    monkeypatch.setenv("VERCEL_TELEMETRY_DISABLED", "1")
    objects = {}
    methods = []

    def send(_client, request, **kwargs):
        methods.append(request.method)
        assert request.headers["authorization"] == f"Bearer {token}"
        assert request.url.scheme == "https"
        if request.url.host == "teststore.private.blob.vercel-storage.com":
            return httpx.Response(200, content=objects[request.url.path.lstrip("/")],
                                  request=request)
        assert request.url.host == "vercel.com"
        if request.url.path.endswith("/delete"):
            for key in json.loads(request.read())["urls"]:
                objects.pop(key)
            return httpx.Response(200, json={}, request=request)
        if request.method == "PUT":
            assert request.headers["x-vercel-blob-access"] == "private"
            assert request.headers["x-allow-overwrite"] == "0"
            assert request.headers["x-add-random-suffix"] == "0"
            key = request.url.params["pathname"]
            objects[key] = request.read()
        else:
            key = request.url.params["url"]
        url = f"https://teststore.private.blob.vercel-storage.com/{key}"
        return httpx.Response(200, request=request, json={
            "url": url, "downloadUrl": url, "pathname": key,
            "contentType": "application/octet-stream", "contentDisposition": "attachment",
            "size": len(objects[key]), "uploadedAt": "2026-08-28T00:00:00Z",
            "cacheControl": "private, no-store",
        })

    monkeypatch.setattr(httpx.Client, "send", send)
    uploaded = upload_file(authenticated_alice["token"], content=b"SDK contract")
    assert uploaded.status_code == 201
    path = f"/api/files/{uploaded.get_json()['file']['id']}"
    headers = bearer_headers(authenticated_alice["token"])
    downloaded = client.get(path + "/download", headers=headers)
    assert downloaded.status_code == 200
    assert downloaded.data == b"SDK contract"
    assert client.delete(path, headers=headers).status_code == 200
    assert objects == {}
    assert methods == ["PUT", "GET", "GET", "POST"]


def test_blob_delete_failure_keeps_metadata_for_retry(
    app, client, private_blob, monkeypatch, authenticated_alice, upload_file, bearer_headers,
):
    uploaded = upload_file(authenticated_alice["token"])
    file_id = uploaded.get_json()["file"]["id"]

    def reject_delete(*args, **kwargs):
        raise BlobError("simulated remote failure")

    monkeypatch.setattr(private_blob.client, "delete", reject_delete)
    response = client.delete(f"/api/files/{file_id}",
                             headers=bearer_headers(authenticated_alice["token"]))
    assert response.status_code == 503
    assert private_blob.objects
    with app.app_context():
        assert db.session.get(FileRecord, file_id) is not None


def test_blob_download_transport_failure_is_a_sanitized_503(
    client, private_blob, monkeypatch, authenticated_alice, upload_file, bearer_headers,
):
    uploaded = upload_file(authenticated_alice["token"])
    canary = secrets.token_urlsafe(32)

    def fail_get(*args, **kwargs):
        raise httpx.ReadTimeout(canary)

    monkeypatch.setattr(private_blob.client, "get", fail_get)
    response = client.get(f"/api/files/{uploaded.get_json()['file']['id']}/download",
                          headers=bearer_headers(authenticated_alice["token"]))
    assert response.status_code == 503
    assert canary not in response.get_data(as_text=True)
