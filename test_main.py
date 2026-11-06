
import os
from datetime import date
import pytest
from fastapi.testclient import TestClient
import main

app = main.app

client = TestClient(app)


def login(email, password):
    response = client.post(
        "/login",
        data={
            "username": email,
            "password": password
        }
    )

    assert response.status_code == 200
    token = response.json()["access_token"]

    return {
        "Authorization": f"Bearer {token}"
    }


def require_integration_database():
    try:
        with main.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT is_active FROM users LIMIT 0")
    except Exception:
        pytest.skip("Apply schema.sql and configure the local test database first")


def test_owner_can_view_documents():
    password = os.getenv("TEST_OWNER_PASSWORD")
    if not password:
        pytest.skip("Set TEST_OWNER_PASSWORD to run database integration tests")
    require_integration_database()

    headers = login("owner.test@example.com", password)

    response = client.get("/documents", headers=headers)

    assert response.status_code == 200


def test_admin_can_view_audit_logs():
    password = os.getenv("TEST_ADMIN_PASSWORD")
    if not password:
        pytest.skip("Set TEST_ADMIN_PASSWORD to run database integration tests")
    require_integration_database()

    headers = login("admin.test@example.com", password)

    response = client.get("/admin/audit-logs", headers=headers)

    assert response.status_code == 200


class FakeCursor:
    def __init__(self, connection):
        self.connection = connection
        self.current_result = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def execute(self, query, params=None):
        normalized_query = " ".join(query.split()).lower()
        self.connection.queries.append((normalized_query, params))
        if normalized_query.startswith("select id, name, owner_id, storage_path from documents"):
            self.current_result = self.connection.document
        elif normalized_query.startswith("select id, full_name, email, role, is_active from users"):
            self.current_result = self.connection.auth_user
        elif normalized_query.startswith("select id, full_name, email, role, is_active, created_at from users"):
            self.current_result = None
        elif normalized_query.startswith("select count(*) as total_users"):
            self.current_result = self.connection.dashboard_stats
        elif normalized_query.startswith("select u.full_name, u.email, a.document_id"):
            self.current_result = self.connection.recent_activity
        elif normalized_query.startswith("select id, is_active from users"):
            self.current_result = self.connection.status_user
        elif normalized_query.startswith("select id, full_name, email, password_hash, role, is_active from users"):
            self.current_result = self.connection.login_user
        elif normalized_query.startswith("select id, full_name, email from users"):
            self.current_result = self.connection.recipient
        elif normalized_query.startswith("select id from documents where id = %s and owner_id = %s"):
            self.current_result = self.connection.owned_document
        elif normalized_query.startswith("select owner_id from documents"):
            self.current_result = self.connection.owner
        elif normalized_query.startswith("select name, storage_path from documents"):
            self.current_result = self.connection.delete_document
        elif normalized_query.startswith("select owner_id, storage_path from documents"):
            self.current_result = self.connection.replace_document
        elif normalized_query.startswith("insert into users"):
            self.current_result = (101, "New Viewer", "new@example.com", "viewer")
        elif normalized_query.startswith("delete from permissions"):
            self.current_result = self.connection.permission
            self.connection.permission = None
        elif "from permissions" in normalized_query:
            self.current_result = self.connection.permission
        else:
            self.current_result = None

    def fetchone(self):
        return self.current_result

    def fetchall(self):
        if self.connection.queries and self.connection.queries[-1][0].startswith(
            "select u.full_name, u.email, a.document_id"
        ):
            return self.connection.recent_activity
        if self.connection.queries and self.connection.queries[-1][0].startswith(
            "select id, full_name, email, role, is_active, created_at from users"
        ):
            return self.connection.users
        return self.connection.documents


class FakeConnection:
    def __init__(
        self,
        document=None,
        permission=None,
        documents=None,
        owner=None,
        auth_user=None,
        delete_document=None,
        owned_document=None,
        recipient=None,
        replace_document=None,
        users=None,
        status_user=None,
        login_user=None,
        dashboard_stats=None,
        recent_activity=None
    ):
        self.document = document
        self.permission = permission
        self.documents = documents or []
        self.owner = owner
        self.auth_user = auth_user
        self.delete_document = delete_document
        self.owned_document = owned_document
        self.recipient = recipient
        self.replace_document = replace_document
        self.users = users or []
        self.status_user = status_user
        self.login_user = login_user
        self.dashboard_stats = dashboard_stats
        self.recent_activity = recent_activity or []
        self.queries = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def cursor(self):
        return FakeCursor(self)


def authenticate_as(monkeypatch, user):
    monkeypatch.setitem(
        app.dependency_overrides,
        main.get_current_user,
        lambda: user
    )


def test_registration_always_creates_viewer(monkeypatch):
    connection = FakeConnection()
    monkeypatch.setattr(main, "get_connection", lambda: connection)

    response = client.post(
        "/register",
        json={
            "full_name": "New Viewer",
            "email": "new@example.com",
            "password": "long-enough-password",
            "role": "admin"
        }
    )

    assert response.status_code == 200
    assert response.json()["user"]["role"] == "viewer"
    assert any("insert into audit_logs" in query for query, _ in connection.queries)


def test_admin_without_document_grant_cannot_download(monkeypatch, tmp_path):
    private_file = tmp_path / "private.txt"
    private_file.write_text("private document", encoding="utf-8")
    connection = FakeConnection(
        document=(7, "private.txt", 42, str(private_file)),
        permission=None
    )
    monkeypatch.setattr(main, "UPLOAD_DIR", tmp_path)
    monkeypatch.setattr(main, "get_connection", lambda: connection)
    monkeypatch.setattr(main, "add_audit_log", lambda *args: None)
    authenticate_as(monkeypatch, {"id": 1, "role": "admin"})

    response = client.get("/documents/7/download")

    assert response.status_code == 403


def test_admin_document_search_is_scoped_to_grants(monkeypatch):
    connection = FakeConnection(documents=[])
    monkeypatch.setattr(main, "get_connection", lambda: connection)
    authenticate_as(monkeypatch, {"id": 1, "role": "admin"})

    response = client.get("/documents/search")

    assert response.status_code == 200
    query, parameters = connection.queries[0]
    assert "d.owner_id = %s" in query
    assert "p.user_id = %s" in query
    assert parameters[:2] == (1, 1)


def test_search_filters_owner_and_date_without_widening_access(monkeypatch):
    connection = FakeConnection(documents=[])
    monkeypatch.setattr(main, "get_connection", lambda: connection)
    authenticate_as(monkeypatch, {"id": 8, "role": "viewer"})

    response = client.get(
        "/documents/search",
        params={"owner": "Taylor", "date_from": "2026-04-02", "date_to": "2026-04-30"}
    )

    query, parameters = connection.queries[0]
    assert response.status_code == 200
    assert "d.owner_id = %s" in query
    assert "u.full_name ilike %s" in query
    assert "d.created_at::date >= %s::date" in query
    assert parameters[0:2] == (8, 8)
    assert parameters[-4:] == (
        date(2026, 4, 2), date(2026, 4, 2),
        date(2026, 4, 30), date(2026, 4, 30)
    )


def test_revoking_read_access_blocks_the_next_download(monkeypatch, tmp_path):
    private_file = tmp_path / "shared.txt"
    private_file.write_text("shared document", encoding="utf-8")
    connection = FakeConnection(
        document=(7, "shared.txt", 42, str(private_file)),
        permission=(1,),
        owned_document=(7,)
    )
    monkeypatch.setattr(main, "UPLOAD_DIR", tmp_path)
    monkeypatch.setattr(main, "get_connection", lambda: connection)
    monkeypatch.setattr(main, "add_audit_log", lambda *args: None)
    caller = {"id": 1, "role": "viewer"}
    authenticate_as(monkeypatch, caller)

    granted_response = client.get("/documents/7/download")
    caller.update({"id": 42, "role": "owner"})
    revoke_response = client.delete("/documents/7/permissions/1")
    caller.update({"id": 1, "role": "viewer"})
    revoked_response = client.get("/documents/7/download")

    assert granted_response.status_code == 200
    assert revoke_response.status_code == 200
    assert revoked_response.status_code == 403


def test_owner_can_grant_named_active_user_read_access(monkeypatch):
    connection = FakeConnection(
        owned_document=(7,),
        recipient=(2, "Viewer", "viewer@example.com")
    )
    monkeypatch.setattr(main, "get_connection", lambda: connection)
    monkeypatch.setattr(main, "add_audit_log", lambda *args: None)
    authenticate_as(monkeypatch, {"id": 42, "role": "owner"})

    response = client.post(
        "/documents/7/permissions",
        json={"user_email": "viewer@example.com", "access_type": "READ"}
    )

    assert response.status_code == 200
    assert response.json()["user_id"] == 2
    assert any("insert into permissions" in query for query, _ in connection.queries)


def test_viewer_without_edit_grant_cannot_change_document(monkeypatch):
    connection = FakeConnection(owner=(42,), permission=None)
    monkeypatch.setattr(main, "get_connection", lambda: connection)
    monkeypatch.setattr(main, "add_audit_log", lambda *args: None)
    authenticate_as(monkeypatch, {"id": 1, "role": "viewer"})

    response = client.put(
        "/documents/7",
        data={"new_name": "stolen.txt", "new_category": "Other"}
    )

    assert response.status_code == 403


def test_viewer_without_edit_grant_cannot_replace_document_file(monkeypatch, tmp_path):
    connection = FakeConnection(
        permission=None,
        replace_document=(42, str(tmp_path / "existing.txt"))
    )
    monkeypatch.setattr(main, "UPLOAD_DIR", tmp_path)
    monkeypatch.setattr(main, "get_connection", lambda: connection)
    monkeypatch.setattr(main, "add_audit_log", lambda *args: None)
    authenticate_as(monkeypatch, {"id": 1, "role": "viewer"})

    response = client.put(
        "/documents/7/file",
        files={"file": ("replacement.txt", b"new content", "text/plain")}
    )

    assert response.status_code == 403


def test_deactivated_user_token_is_rejected_immediately(monkeypatch):
    monkeypatch.setattr(main, "SECRET_KEY", "t" * 40)
    connection = FakeConnection(
        auth_user=(5, "Viewer", "viewer@example.com", "viewer", False)
    )
    monkeypatch.setattr(
        main,
        "get_connection",
        lambda: connection
    )
    token = main.create_access_token(5, "viewer")

    response = client.get(
        "/users/me",
        headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 401
    assert not any("insert into audit_logs" in query for query, _ in connection.queries)


def test_inactive_user_cannot_log_in(monkeypatch):
    connection = FakeConnection(
        login_user=(5, "Viewer", "viewer@example.com", "unused-hash", "viewer", False)
    )
    monkeypatch.setattr(main, "get_connection", lambda: connection)
    monkeypatch.setattr(main, "add_audit_log", lambda *args: None)

    response = client.post(
        "/login",
        data={"username": "viewer@example.com", "password": "any-password"}
    )

    assert response.status_code == 401


def test_admin_user_list_exposes_only_safe_fields(monkeypatch):
    created_at = date(2026, 1, 2)
    connection = FakeConnection(
        users=[(7, "Example User", "example@example.com", "viewer", True, created_at)]
    )
    monkeypatch.setattr(main, "get_connection", lambda: connection)
    monkeypatch.setattr(main, "add_audit_log", lambda *args: None)
    authenticate_as(monkeypatch, {"id": 1, "role": "admin"})

    response = client.get("/admin/users")

    assert response.status_code == 200
    assert set(response.json()["users"][0]) == {
        "id", "full_name", "email", "role", "is_active", "created_at"
    }
    assert "password_hash" not in connection.queries[0][0]


def test_non_admin_cannot_access_user_management(monkeypatch):
    connection = FakeConnection()
    monkeypatch.setattr(main, "get_connection", lambda: connection)
    authenticate_as(monkeypatch, {"id": 2, "role": "viewer"})

    list_response = client.get("/admin/users")
    update_response = client.patch(
        "/admin/users/7/status",
        json={"is_active": False}
    )

    assert list_response.status_code == 403
    assert update_response.status_code == 403
    assert connection.queries == []


@pytest.mark.parametrize("role", ["owner", "viewer"])
def test_non_admin_cannot_access_admin_endpoints(monkeypatch, role):
    connection = FakeConnection()
    monkeypatch.setattr(main, "get_connection", lambda: connection)
    authenticate_as(monkeypatch, {"id": 2, "role": role})

    users_response = client.get("/admin/users")
    audit_response = client.get("/admin/audit-logs")
    dashboard_response = client.get("/admin/dashboard")
    status_response = client.patch(
        "/admin/users/7/status",
        json={"is_active": False}
    )

    assert users_response.status_code == 403
    assert audit_response.status_code == 403
    assert dashboard_response.status_code == 403
    assert status_response.status_code == 403
    assert connection.queries == []


def test_admin_dashboard_returns_live_user_counts_and_recent_activity(monkeypatch):
    connection = FakeConnection(
        dashboard_stats=(8, 6, 2, 3, 4, 1),
        recent_activity=[
            (
                "Example Viewer",
                "viewer@example.com",
                6,
                "DOCUMENT_READ",
                "Read access granted",
                True,
                "2026-03-08T14:37:00"
            )
        ]
    )
    monkeypatch.setattr(main, "get_connection", lambda: connection)
    authenticate_as(monkeypatch, {"id": 1, "role": "admin"})

    response = client.get("/admin/dashboard")

    assert response.status_code == 200
    assert response.json()["stats"] == {
        "total_users": 8,
        "active_users": 6,
        "inactive_users": 2,
        "owners": 3,
        "viewers": 4,
        "admins": 1
    }
    assert response.json()["recent_activity"] == [{
        "user_name": "Example Viewer",
        "user_email": "viewer@example.com",
        "document_id": 6,
        "action": "DOCUMENT_READ",
        "details": "Read access granted",
        "success": True,
        "created_at": "2026-03-08T14:37:00"
    }]
    assert "password_hash" not in response.text
    assert "entry_hash" not in response.text
    assert connection.queries[0][0].startswith("select count(*) as total_users")
    assert "limit 8" in connection.queries[1][0]


def test_admin_can_update_user_status_and_audit_it(monkeypatch):
    connection = FakeConnection(status_user=(7, True))
    monkeypatch.setattr(main, "get_connection", lambda: connection)
    authenticate_as(monkeypatch, {"id": 1, "role": "admin"})

    response = client.patch(
        "/admin/users/7/status",
        json={"is_active": False}
    )

    assert response.status_code == 200
    assert response.json() == {"user_id": 7, "is_active": False}
    assert ("update users set is_active = %s where id = %s", (False, 7)) in connection.queries
    assert any(
        query.startswith("insert into audit_logs")
        and parameters[2] == "USER_DEACTIVATED"
        for query, parameters in connection.queries
    )


def test_admin_cannot_deactivate_self(monkeypatch):
    connection = FakeConnection()
    monkeypatch.setattr(main, "get_connection", lambda: connection)
    authenticate_as(monkeypatch, {"id": 1, "role": "admin"})

    response = client.patch(
        "/admin/users/1/status",
        json={"is_active": False}
    )

    assert response.status_code == 400
    assert connection.queries == []


def test_admin_status_update_returns_404_for_unknown_user(monkeypatch):
    connection = FakeConnection(status_user=None)
    monkeypatch.setattr(main, "get_connection", lambda: connection)
    authenticate_as(monkeypatch, {"id": 1, "role": "admin"})

    response = client.patch(
        "/admin/users/999/status",
        json={"is_active": True}
    )

    assert response.status_code == 404
    assert not any("update users" in query for query, _ in connection.queries)


def test_owner_cannot_delete_another_owners_document(monkeypatch):
    connection = FakeConnection(delete_document=None)
    monkeypatch.setattr(main, "get_connection", lambda: connection)
    monkeypatch.setattr(main, "add_audit_log", lambda *args: None)
    authenticate_as(monkeypatch, {"id": 1, "role": "owner"})

    response = client.delete("/documents/7")

    assert response.status_code == 404
    assert "owner_id = %s" in connection.queries[0][0]


def test_owner_cannot_grant_access_to_another_owners_document(monkeypatch):
    connection = FakeConnection()
    monkeypatch.setattr(main, "get_connection", lambda: connection)
    monkeypatch.setattr(main, "add_audit_log", lambda *args: None)
    authenticate_as(monkeypatch, {"id": 1, "role": "owner"})

    response = client.post(
        "/documents/7/permissions",
        json={"user_email": "viewer@example.com", "access_type": "READ"}
    )

    assert response.status_code == 404
    assert all("insert into permissions" not in query for query, _ in connection.queries)