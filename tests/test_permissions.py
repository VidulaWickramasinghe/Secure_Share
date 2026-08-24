"""Owner-controlled, per-file authorization tests."""

from __future__ import annotations

from pathlib import Path

from app.extensions import db
from app.models.file import FileRecord
from app.models.permission import FilePermission


def _headers(account: dict) -> dict[str, str]:
    return {"Authorization": f"Bearer {account['token']}"}


def _upload_as_alice(upload_file, accounts, content=b"top secret") -> dict:
    response = upload_file(
        accounts["alice"]["token"],
        content=content,
        filename="project_report.pdf",
    )
    assert response.status_code == 201
    return response.get_json()["file"]


def test_required_file_authorization_lifecycle(client, upload_file, three_accounts):
    """Exercise the central Alice/Bob/Charlie security scenario end to end."""
    file_data = _upload_as_alice(upload_file, three_accounts)
    file_id = file_data["id"]
    alice = three_accounts["alice"]
    bob = three_accounts["bob"]
    charlie = three_accounts["charlie"]

    # Alice owns the file and can always download it.
    assert client.get(
        f"/api/files/{file_id}/download", headers=_headers(alice)
    ).status_code == 200

    # Knowledge of a file ID is never sufficient for Bob or Charlie.
    assert client.get(
        f"/api/files/{file_id}/download", headers=_headers(bob)
    ).status_code == 403
    assert client.get(
        f"/api/files/{file_id}/download", headers=_headers(charlie)
    ).status_code == 403

    grant = client.post(
        f"/api/files/{file_id}/permissions",
        headers=_headers(alice),
        json={"user_id": bob["user"]["id"]},
    )
    assert grant.status_code == 201

    assert client.get(
        f"/api/files/{file_id}/download", headers=_headers(bob)
    ).status_code == 200
    assert client.get(
        f"/api/files/{file_id}/download", headers=_headers(charlie)
    ).status_code == 403

    revoke = client.delete(
        f"/api/files/{file_id}/permissions/{bob['user']['id']}",
        headers=_headers(alice),
    )
    assert revoke.status_code == 200
    assert client.get(
        f"/api/files/{file_id}/download", headers=_headers(bob)
    ).status_code == 403


def test_only_owner_can_manage_permissions(client, upload_file, three_accounts):
    file_data = _upload_as_alice(upload_file, three_accounts)
    file_id = file_data["id"]
    bob = three_accounts["bob"]
    charlie_id = three_accounts["charlie"]["user"]["id"]

    assert client.get(
        f"/api/files/{file_id}/permissions", headers=_headers(bob)
    ).status_code == 403
    assert client.post(
        f"/api/files/{file_id}/permissions",
        headers=_headers(bob),
        json={"user_id": charlie_id},
    ).status_code == 403
    assert client.delete(
        f"/api/files/{file_id}/permissions/{charlie_id}",
        headers=_headers(bob),
    ).status_code == 403


def test_non_owner_cannot_delete_file(client, upload_file, three_accounts):
    file_data = _upload_as_alice(upload_file, three_accounts)

    response = client.delete(
        f"/api/files/{file_data['id']}",
        headers=_headers(three_accounts["bob"]),
    )

    assert response.status_code == 403
    assert client.get(
        f"/api/files/{file_data['id']}/download",
        headers=_headers(three_accounts["alice"]),
    ).status_code == 200


def test_owner_can_list_authorized_users(client, upload_file, three_accounts):
    file_data = _upload_as_alice(upload_file, three_accounts)
    alice = three_accounts["alice"]
    bob = three_accounts["bob"]
    charlie = three_accounts["charlie"]

    for account in (bob, charlie):
        response = client.post(
            f"/api/files/{file_data['id']}/permissions",
            headers=_headers(alice),
            json={"user_id": account["user"]["id"]},
        )
        assert response.status_code == 201

    response = client.get(
        f"/api/files/{file_data['id']}/permissions",
        headers=_headers(alice),
    )

    assert response.status_code == 200
    permissions = response.get_json()["permissions"]
    assert {permission["user_id"] for permission in permissions} == {
        bob["user"]["id"],
        charlie["user"]["id"],
    }
    assert all("password" not in str(permission).lower() for permission in permissions)
    assert all("email" not in permission["user"] for permission in permissions)


def test_owner_cannot_authorize_self(client, upload_file, three_accounts):
    file_data = _upload_as_alice(upload_file, three_accounts)
    alice = three_accounts["alice"]

    response = client.post(
        f"/api/files/{file_data['id']}/permissions",
        headers=_headers(alice),
        json={"user_id": alice["user"]["id"]},
    )

    assert response.status_code == 400
    assert "error" in response.get_json()


def test_duplicate_authorization_is_rejected(client, upload_file, three_accounts):
    file_data = _upload_as_alice(upload_file, three_accounts)
    alice = three_accounts["alice"]
    bob_id = three_accounts["bob"]["user"]["id"]
    endpoint = f"/api/files/{file_data['id']}/permissions"
    payload = {"user_id": bob_id}

    assert client.post(endpoint, headers=_headers(alice), json=payload).status_code == 201
    duplicate = client.post(endpoint, headers=_headers(alice), json=payload)

    assert duplicate.status_code == 409
    assert "error" in duplicate.get_json()


def test_authorizing_unknown_user_is_not_found(client, upload_file, three_accounts):
    file_data = _upload_as_alice(upload_file, three_accounts)

    response = client.post(
        f"/api/files/{file_data['id']}/permissions",
        headers=_headers(three_accounts["alice"]),
        json={"user_id": 999_999},
    )

    assert response.status_code == 404
    assert "error" in response.get_json()


def test_permission_payload_requires_a_positive_integer_user_id(
    client, upload_file, three_accounts
):
    file_data = _upload_as_alice(upload_file, three_accounts)
    endpoint = f"/api/files/{file_data['id']}/permissions"
    headers = _headers(three_accounts["alice"])

    for payload in ({}, {"user_id": "2"}, {"user_id": True}, {"user_id": 0}):
        response = client.post(endpoint, headers=headers, json=payload)
        assert response.status_code == 400
        assert "error" in response.get_json()


def test_private_metadata_and_lists_are_not_exposed_until_authorized(
    client, upload_file, three_accounts
):
    file_data = _upload_as_alice(upload_file, three_accounts)
    alice = three_accounts["alice"]
    bob = three_accounts["bob"]
    detail_url = f"/api/files/{file_data['id']}"

    before_list = client.get("/api/files", headers=_headers(bob))
    before_detail = client.get(detail_url, headers=_headers(bob))
    assert before_list.status_code == 200
    assert before_list.get_json()["files"] == []
    # Hiding existence on metadata endpoints prevents ID enumeration.
    assert before_detail.status_code == 404

    assert client.post(
        f"{detail_url}/permissions",
        headers=_headers(alice),
        json={"user_id": bob["user"]["id"]},
    ).status_code == 201

    after_list = client.get("/api/files", headers=_headers(bob))
    after_detail = client.get(detail_url, headers=_headers(bob))
    assert after_list.status_code == 200
    assert [entry["id"] for entry in after_list.get_json()["files"]] == [
        file_data["id"]
    ]
    assert after_detail.status_code == 200
    assert after_detail.get_json()["file"]["id"] == file_data["id"]


def test_deleting_file_cascades_permissions_and_removes_bytes(
    app, client, upload_file, three_accounts
):
    file_data = _upload_as_alice(upload_file, three_accounts)
    alice = three_accounts["alice"]
    bob_id = three_accounts["bob"]["user"]["id"]
    assert client.post(
        f"/api/files/{file_data['id']}/permissions",
        headers=_headers(alice),
        json={"user_id": bob_id},
    ).status_code == 201

    with app.app_context():
        record = db.session.get(FileRecord, file_data["id"])
        stored_path = Path(app.config["UPLOAD_FOLDER"]) / record.stored_filename

    assert client.delete(
        f"/api/files/{file_data['id']}", headers=_headers(alice)
    ).status_code == 200

    assert not stored_path.exists()
    with app.app_context():
        permissions = db.session.execute(db.select(FilePermission)).scalars().all()
        assert permissions == []


def test_permission_endpoints_require_authentication(client):
    file_id = "00000000-0000-0000-0000-000000000000"

    assert client.get(f"/api/files/{file_id}/permissions").status_code == 401
    assert client.post(
        f"/api/files/{file_id}/permissions", json={"user_id": 1}
    ).status_code == 401
    assert client.delete(
        f"/api/files/{file_id}/permissions/1"
    ).status_code == 401
