"""Tests for Auth Module."""
from __future__ import annotations

import pytest
from modules.auth.provider import AuthProvider, User
from modules.auth.config import AuthConfig


@pytest.fixture
def auth_provider() -> AuthProvider:
    """Create AuthProvider for testing."""
    config = AuthConfig(
        jwt_secret="test-secret",
        jwt_expiration_hours=1,
        password_min_length=8,
        password_require_uppercase=True,
        password_require_digit=True,
        max_login_attempts=3,
        lockout_duration_minutes=5,
    )
    return AuthProvider(config=config)


class TestUserManagement:
    """Tests for user CRUD operations."""

    def test_create_user(self, auth_provider: AuthProvider):
        user = auth_provider.create_user("admin", "SecurePass123")
        assert user.username == "admin"
        assert user.id is not None
        assert user.is_active is True

    def test_get_user(self, auth_provider: AuthProvider):
        created = auth_provider.create_user("admin", "SecurePass123")
        found = auth_provider.get_user(created.id)
        assert found is not None
        assert found.username == "admin"

    def test_get_user_by_username(self, auth_provider: AuthProvider):
        auth_provider.create_user("admin", "SecurePass123")
        found = auth_provider.get_user_by_username("admin")
        assert found is not None
        assert found.username == "admin"

    def test_update_user(self, auth_provider: AuthProvider):
        user = auth_provider.create_user("admin", "SecurePass123")
        updated = auth_provider.update_user(user.id, {"email": "admin@example.com"})
        assert updated is not None
        assert updated.email == "admin@example.com"

    def test_delete_user(self, auth_provider: AuthProvider):
        user = auth_provider.create_user("admin", "SecurePass123")
        assert auth_provider.delete_user(user.id) is True
        assert auth_provider.get_user(user.id) is None

    def test_create_duplicate_user(self, auth_provider: AuthProvider):
        auth_provider.create_user("admin", "SecurePass123")
        with pytest.raises(ValueError, match="already exists"):
            auth_provider.create_user("admin", "SecurePass123")


class TestAuthentication:
    """Tests for login/logout."""

    def test_login_success(self, auth_provider: AuthProvider):
        auth_provider.create_user("admin", "SecurePass123")
        token = auth_provider.login("admin", "SecurePass123")
        assert token is not None
        assert token.username == "admin"

    def test_login_wrong_password(self, auth_provider: AuthProvider):
        auth_provider.create_user("admin", "SecurePass123")
        token = auth_provider.login("admin", "WrongPassword")
        assert token is None

    def test_login_nonexistent_user(self, auth_provider: AuthProvider):
        token = auth_provider.login("nobody", "SecurePass123")
        assert token is None

    def test_logout(self, auth_provider: AuthProvider):
        auth_provider.create_user("admin", "SecurePass123")
        token = auth_provider.login("admin", "SecurePass123")
        assert auth_provider.logout(token) is True

    def test_account_lockout(self, auth_provider: AuthProvider):
        auth_provider.create_user("admin", "SecurePass123")
        
        # Failed attempts
        for _ in range(3):
            auth_provider.login("admin", "WrongPassword")
        
        # Account should be locked
        token = auth_provider.login("admin", "SecurePass123")
        assert token is None


class TestAuthorization:
    """Tests for RBAC and permissions."""

    def test_authorize_with_permission(self, auth_provider: AuthProvider):
        user = auth_provider.create_user("admin", "SecurePass123", roles=["admin"])
        user.permissions = ["users:read", "users:write"]
        token = auth_provider.login("admin", "SecurePass123")
        
        assert auth_provider.authorize(token, "users:read") is True

    def test_authorize_without_permission(self, auth_provider: AuthProvider):
        user = auth_provider.create_user("admin", "SecurePass123", roles=["user"])
        token = auth_provider.login("admin", "SecurePass123")
        
        assert auth_provider.authorize(token, "admin:write") is False

    def test_has_role(self, auth_provider: AuthProvider):
        user = auth_provider.create_user("admin", "SecurePass123", roles=["admin"])
        token = auth_provider.login("admin", "SecurePass123")
        
        assert auth_provider.has_role(token, "admin") is True
        assert auth_provider.has_role(token, "user") is False


class TestPasswordHashing:
    """Tests for password hashing."""

    def test_hash_password(self, auth_provider: AuthProvider):
        hash1 = auth_provider._hash_password("SecurePass123")
        hash2 = auth_provider._hash_password("SecurePass123")
        
        # Different salts
        assert hash1 != hash2
        
        # Both verify
        assert auth_provider._verify_password("SecurePass123", hash1) is True
        assert auth_provider._verify_password("SecurePass123", hash2) is True

    def test_verify_wrong_password(self, auth_provider: AuthProvider):
        password_hash = auth_provider._hash_password("SecurePass123")
        assert auth_provider._verify_password("WrongPassword", password_hash) is False


class TestPasswordValidation:
    """Tests for password validation."""

    def test_valid_password(self, auth_provider: AuthProvider):
        # Should not raise
        auth_provider._validate_password("SecurePass123")

    def test_too_short(self, auth_provider: AuthProvider):
        with pytest.raises(ValueError, match="at least 8"):
            auth_provider._validate_password("Short1")

    def test_no_uppercase(self, auth_provider: AuthProvider):
        with pytest.raises(ValueError, match="uppercase"):
            auth_provider._validate_password("nouppercase123")

    def test_no_digit(self, auth_provider: AuthProvider):
        with pytest.raises(ValueError, match="digit"):
            auth_provider._validate_password("NoDigitsHere")
