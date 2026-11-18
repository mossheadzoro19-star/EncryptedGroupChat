import uuid

from fastapi.testclient import TestClient

from main import app


client = TestClient(app)


def test_registration_creates_authenticated_http_only_session():
    username = "session_test_" + uuid.uuid4().hex[:10]
    response = client.post(
        "/register",
        json={"username": username, "password": "correct horse battery"},
    )

    assert response.status_code == 200
    assert response.json()["message"] == "User registered successfully"
    cookie = response.cookies.get("egc_session")
    assert cookie
    assert "httponly" in response.headers.get("set-cookie", "").lower()

    me = client.get("/auth/me")
    assert me.status_code == 200
    assert me.json() == {"authenticated": True, "username": username}


def test_protected_api_rejects_missing_session():
    unauthenticated = TestClient(app)
    response = unauthenticated.get("/groups/list")
    assert response.status_code == 401


def test_request_cannot_impersonate_another_username():
    username = "identity_test_" + uuid.uuid4().hex[:10]
    register = client.post(
        "/register",
        json={"username": username, "password": "correct horse battery"},
    )
    assert register.status_code == 200

    response = client.post(
        "/groups/create",
        json={"group_name": "Impersonation attempt", "username": "someone_else"},
    )
    assert response.status_code == 403
    assert "does not match" in response.json()["detail"]


def test_logout_revokes_server_side_session():
    username = "logout_test_" + uuid.uuid4().hex[:10]
    register = client.post(
        "/register",
        json={"username": username, "password": "correct horse battery"},
    )
    assert register.status_code == 200

    logout = client.post("/logout", json={})
    assert logout.status_code == 200
    me = client.get("/auth/me")
    assert me.status_code == 401
