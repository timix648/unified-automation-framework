"""
Tests for the authentication system (JWT, RBAC, user management).
"""
import pytest
from datetime import timedelta
from app.core.security import (
    hash_password,
    verify_password,
    create_access_token,
    decode_access_token,
    user_db,
    RoleChecker,
)


# ── Password hashing ──────────────────────────────────────────────────────

class TestPasswordHashing:
    def test_hash_and_verify(self):
        hashed = hash_password("s3cret")
        assert verify_password("s3cret", hashed)

    def test_wrong_password_rejected(self):
        hashed = hash_password("correct")
        assert not verify_password("wrong", hashed)

    def test_hash_is_not_plaintext(self):
        hashed = hash_password("plaintext")
        assert hashed != "plaintext"


# ── JWT tokens ─────────────────────────────────────────────────────────────

class TestJWT:
    def test_create_and_decode_token(self):
        token = create_access_token(data={"sub": "alice", "role": "admin"})
        payload = decode_access_token(token)
        assert payload["sub"] == "alice"
        assert payload["role"] == "admin"

    def test_expired_token_raises(self):
        token = create_access_token(
            data={"sub": "bob"},
            expires_delta=timedelta(seconds=-1),
        )
        with pytest.raises(Exception):
            decode_access_token(token)

    def test_invalid_token_raises(self):
        with pytest.raises(Exception):
            decode_access_token("this.is.garbage")


# ── User database ─────────────────────────────────────────────────────────

class TestUserDatabase:
    def test_authenticate_admin(self):
        user = user_db.authenticate_user("admin", "admin123")
        assert user is not None
        assert user["role"] == "admin"

    def test_authenticate_wrong_password(self):
        assert user_db.authenticate_user("admin", "wrong") is None

    def test_authenticate_nonexistent_user(self):
        assert user_db.authenticate_user("nobody", "pass") is None

    def test_get_user(self):
        user = user_db.get_user("operator")
        assert user["role"] == "operator"


# ── Auth endpoints via TestClient ──────────────────────────────────────────

class TestAuthEndpoints:
    def test_login_success(self, client):
        resp = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
        assert resp.status_code == 200
        body = resp.json()
        assert "access_token" in body
        assert body["user"]["role"] == "admin"

    def test_login_failure(self, client):
        resp = client.post("/api/auth/login", json={"username": "admin", "password": "wrong"})
        assert resp.status_code == 401

    def test_me_requires_auth(self, client):
        resp = client.get("/api/auth/me")
        assert resp.status_code == 401  # no token

    def test_me_returns_user(self, client, auth_headers):
        resp = client.get("/api/auth/me", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json()["username"] == "admin"

    def test_validate_token(self, client, auth_headers):
        resp = client.get("/api/auth/validate", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json()["valid"] is True

    def test_list_users_admin_only(self, client, viewer_headers):
        resp = client.get("/api/auth/users", headers=viewer_headers)
        assert resp.status_code == 403

    def test_list_users_as_admin(self, client, auth_headers):
        resp = client.get("/api/auth/users", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json()["count"] >= 3
