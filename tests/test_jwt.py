"""Tests for Auth JWT — создание и валидация токенов."""
from __future__ import annotations

import time

import pytest

from modules.auth.jwt import (
    create_access_token,
    create_refresh_token,
    validate_access_token,
    hash_token,
    compare_tokens,
    TokenExpiredError,
    TokenInvalidError,
)


class TestAccessToken:
    """Тесты access token."""

    def test_create_returns_string(self):
        """create_access_token возвращает строку."""
        token = create_access_token(
            user_id="user-123",
            username="admin",
            perms_version=1,
            secret="test-secret",
        )
        assert isinstance(token, str)
        assert len(token) > 0

    def test_validate_returns_payload(self):
        """validate_access_token возвращает payload dict."""
        token = create_access_token(
            user_id="user-123",
            username="admin",
            perms_version=1,
            secret="test-secret",
        )
        payload = validate_access_token(token, "test-secret")
        assert payload["sub"] == "user-123"
        assert payload["username"] == "admin"
        assert payload["perms_version"] == 1
        assert "jti" in payload
        assert "iat" in payload
        assert "exp" in payload

    def test_validate_wrong_secret_raises(self):
        """Неверная подпись → TokenInvalidError."""
        token = create_access_token(
            user_id="user-123",
            username="admin",
            perms_version=1,
            secret="correct-secret",
        )
        with pytest.raises(TokenInvalidError):
            validate_access_token(token, "wrong-secret")

    def test_validate_expired_token_raises(self):
        """Истёкший токен → TokenExpiredError."""
        token = create_access_token(
            user_id="user-123",
            username="admin",
            perms_version=1,
            secret="test-secret",
            expires_in_minutes=-1,  # Уже истёк
        )
        with pytest.raises(TokenExpiredError):
            validate_access_token(token, "test-secret")

    def test_validate_tampered_token_raises(self):
        """Подменённый токен → TokenInvalidError."""
        token = create_access_token(
            user_id="user-123",
            username="admin",
            perms_version=1,
            secret="test-secret",
        )
        # Подменяем последний символ
        tampered = token[:-1] + ("A" if token[-1] != "A" else "B")
        with pytest.raises(TokenInvalidError):
            validate_access_token(tampered, "test-secret")

    def test_jti_is_required(self):
        """Токен без jti → TokenInvalidError."""
        import jwt
        payload = {
            "sub": "user-123",
            "username": "admin",
            "perms_version": 1,
            "iat": time.time(),
            "exp": time.time() + 3600,
            # Нет jti!
        }
        token = jwt.encode(payload, "test-secret", algorithm="HS256")
        with pytest.raises(TokenInvalidError, match="jti"):
            validate_access_token(token, "test-secret")

    def test_token_with_custom_algorithm(self):
        """Токен с другим алгоритмом."""
        token = create_access_token(
            user_id="user-123",
            username="admin",
            perms_version=1,
            secret="test-secret",
            algorithm="HS256",
        )
        payload = validate_access_token(token, "test-secret", algorithm="HS256")
        assert payload["sub"] == "user-123"


class TestRefreshToken:
    """Тесты refresh token."""

    def test_create_refresh_token_returns_uuid(self):
        """Refresh token — UUID4 строка."""
        token = create_refresh_token()
        assert isinstance(token, str)
        # Проверяем формат UUID
        parts = token.split("-")
        assert len(parts) == 5
        assert len(token) == 36

    def test_refresh_tokens_are_unique(self):
        """Два refresh token должны быть разными."""
        t1 = create_refresh_token()
        t2 = create_refresh_token()
        assert t1 != t2


class TestHashToken:
    """Тесты хеширования токенов."""

    def test_hash_returns_64_char_hex(self):
        """SHA-256 hex — 64 символа."""
        h = hash_token("test-token")
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_hash_is_deterministic(self):
        """Одинаковый токен → одинаковый хеш."""
        h1 = hash_token("test-token")
        h2 = hash_token("test-token")
        assert h1 == h2


class TestCompareTokens:
    """Тесты безопасного сравнения."""

    def test_compare_same_tokens(self):
        """Одинаковые токены → True."""
        assert compare_tokens("abc", "abc") is True

    def test_compare_different_tokens(self):
        """Разные токены → False."""
        assert compare_tokens("abc", "def") is False

    def test_compare_empty_strings(self):
        """Пустые строки."""
        assert compare_tokens("", "") is True
