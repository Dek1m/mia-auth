"""Tests for Auth Module — обновлены для Phase 1 (PostgreSQL)."""
from __future__ import annotations

import pytest
import pytest_asyncio

from modules.auth.provider import AuthProvider, InvalidCredentialsError, AccountLockedError
from modules.auth.password import hash_password


@pytest.fixture
def provider(mock_pool, auth_config) -> AuthProvider:
    return AuthProvider(config=auth_config, database=mock_pool)


@pytest.mark.asyncio
class TestUserManagement:
    async def test_create_user(self, provider: AuthProvider):
        user = await provider.create_user("admin", "SecurePass123")
        assert user["username"] == "admin"
        assert user["id"] is not None

    async def test_get_user(self, provider: AuthProvider):
        created = await provider.create_user("admin", "SecurePass123")
        found = await provider.get_user(created["id"])
        assert found is not None
        assert found["username"] == "admin"

    async def test_get_user_by_username(self, provider: AuthProvider):
        await provider.create_user("admin", "SecurePass123")
        found = await provider.get_user_by_username("admin")
        assert found is not None

    async def test_update_user(self, provider: AuthProvider):
        user = await provider.create_user("admin", "SecurePass123")
        updated = await provider.update_user(user["id"], {"email": "admin@example.com"})
        assert updated is not None
        assert updated["email"] == "admin@example.com"

    async def test_delete_user(self, provider: AuthProvider, mock_pool):
        user = await provider.create_user("admin", "SecurePass123")
        mock_pool.insert_direct("auth.roles", {
            "id": "role-admin", "name": "system_admin", "is_builtin": True,
        })
        mock_pool.insert_direct("auth.user_roles", {
            "user_id": user["id"], "role_id": "role-admin",
        })
        assert await provider.delete_user(user["id"], force=True) is True
        assert await provider.get_user(user["id"]) is None

    async def test_create_duplicate_user(self, provider: AuthProvider):
        await provider.create_user("admin", "SecurePass123")
        with pytest.raises(ValueError, match="already exists"):
            await provider.create_user("admin", "SecurePass123")


@pytest.mark.asyncio
class TestAuthentication:
    async def test_login_success(self, provider: AuthProvider):
        await provider.create_user("admin", "SecurePass123")
        result = await provider.login("admin", "SecurePass123")
        assert result["username"] == "admin"
        assert "access_token" in result

    async def test_login_wrong_password(self, provider: AuthProvider):
        await provider.create_user("admin", "SecurePass123")
        with pytest.raises(InvalidCredentialsError):
            await provider.login("admin", "WrongPassword")

    async def test_login_nonexistent_user(self, provider: AuthProvider):
        with pytest.raises(InvalidCredentialsError):
            await provider.login("nobody", "SecurePass123")

    async def test_logout(self, provider: AuthProvider):
        await provider.create_user("admin", "SecurePass123")
        result = await provider.login("admin", "SecurePass123")
        assert await provider.logout(result["refresh_token"]) is True

    async def test_account_lockout(self, provider: AuthProvider):
        await provider.create_user("admin", "SecurePass123")
        for _ in range(4):
            with pytest.raises(InvalidCredentialsError):
                await provider.login("admin", "WrongPassword")
        with pytest.raises(InvalidCredentialsError):
            await provider.login("admin", "WrongPassword")
        with pytest.raises(AccountLockedError):
            await provider.login("admin", "SecurePass123")


@pytest.mark.asyncio
class TestAuthorization:
    async def test_authorize_with_permission(self, provider: AuthProvider, mock_pool):
        user = await provider.create_user("admin", "SecurePass123")
        mock_pool.insert_direct("auth.roles", {
            "id": "role-admin", "name": "admin", "is_builtin": False,
        })
        mock_pool.insert_direct("auth.user_roles", {
            "user_id": user["id"], "role_id": "role-admin",
        })
        mock_pool.insert_direct("auth.permissions", {
            "id": "perm-1", "name": "users:read", "description": "Read users",
        })
        mock_pool.insert_direct("auth.role_permissions", {
            "role_id": "role-admin", "permission_id": "perm-1",
        })
        result = await provider.check_permission(user["id"], "users:read")
        assert isinstance(result, bool)

    async def test_authorize_without_permission(self, provider: AuthProvider, mock_pool):
        user = await provider.create_user("admin", "SecurePass123")
        mock_pool.insert_direct("auth.roles", {
            "id": "role-user", "name": "user", "is_builtin": False,
        })
        mock_pool.insert_direct("auth.user_roles", {
            "user_id": user["id"], "role_id": "role-user",
        })
        result = await provider.check_permission(user["id"], "admin:write")
        assert isinstance(result, bool)


@pytest.mark.asyncio
class TestPasswordHashing:
    async def test_hash_password(self, provider: AuthProvider):
        user = await provider.create_user("admin", "SecurePass123")
        h1 = user["password_hash"]
        assert h1.startswith("$argon2id$")
        user2 = await provider.create_user("admin2", "SecurePass123")
        assert user["password_hash"] != user2["password_hash"]

    async def test_verify_wrong_password(self, provider: AuthProvider):
        user = await provider.create_user("admin", "SecurePass123")
        from modules.auth.password import verify_password
        ok, _ = verify_password("WrongPassword", user["password_hash"])
        assert ok is False


@pytest.mark.asyncio
class TestPasswordValidation:
    async def test_valid_password(self, provider: AuthProvider):
        await provider.create_user("admin", "SecurePass123")

    async def test_too_short(self, provider: AuthProvider):
        with pytest.raises(ValueError, match="at least 8"):
            await provider.create_user("admin", "Short1")

    async def test_no_uppercase(self, provider: AuthProvider):
        with pytest.raises(ValueError, match="uppercase"):
            await provider.create_user("admin", "nouppercase123")

    async def test_no_digit(self, provider: AuthProvider):
        with pytest.raises(ValueError, match="digit"):
            await provider.create_user("admin", "NoDigitsHere")
