"""Tests for Auth Password — argon2id hash/verify."""
from __future__ import annotations

import pytest

from modules.auth.password import hash_password, verify_password, needs_rehash


class TestHashPassword:
    """Тесты хеширования паролей."""

    def test_hash_returns_argon2id(self):
        """Хеш должен начинаться с $argon2id$."""
        result = hash_password("SecurePass123")
        assert result.startswith("$argon2id$")

    def test_hash_is_deterministic_for_different_salts(self):
        """Два хеша одного пароля должны отличаться (разные соли)."""
        h1 = hash_password("SecurePass123")
        h2 = hash_password("SecurePass123")
        assert h1 != h2  # Разные соли


class TestVerifyPassword:
    """Тесты проверки паролей."""

    def test_verify_correct_password(self):
        """Верный пароль → True, без rehash."""
        h = hash_password("SecurePass123")
        ok, new_hash = verify_password("SecurePass123", h)
        assert ok is True
        assert new_hash is None  # Хеш актуален

    def test_verify_wrong_password(self):
        """Неверный пароль → False."""
        h = hash_password("SecurePass123")
        ok, new_hash = verify_password("WrongPassword", h)
        assert ok is False
        assert new_hash is None

    def test_verify_pbkdf2_legacy_triggers_rehash(self):
        """Legacy PBKDF2 хеш → True + новый argon2id хеш."""
        import hashlib
        salt = "abcdef1234567890"
        key = hashlib.pbkdf2_hmac(
            "sha256",
            "SecurePass123".encode(),
            salt.encode(),
            iterations=100000,
        )
        legacy_hash = f"{salt}:{key.hex()}"

        ok, new_hash = verify_password("SecurePass123", legacy_hash)
        assert ok is True
        assert new_hash is not None
        assert new_hash.startswith("$argon2id$")

    def test_verify_invalid_format(self):
        """Невалидный формат хеша → False."""
        ok, new_hash = verify_password("SecurePass123", "invalid-hash")
        assert ok is False
        assert new_hash is None

    def test_verify_empty_password(self):
        """Пустой пароль."""
        h = hash_password("SecurePass123")
        ok, _ = verify_password("", h)
        assert ok is False


class TestNeedsRehash:
    """Тесты определения необходимости rehash."""

    def test_argon2id_with_default_params_no_rehash(self):
        """Актуальный argon2id хеш → False."""
        h = hash_password("SecurePass123")
        assert needs_rehash(h) is False

    def test_pbkdf2_legacy_needs_rehash(self):
        """PBKDF2 хеш → True."""
        import hashlib
        salt = "abcdef1234567890"
        key = hashlib.pbkdf2_hmac(
            "sha256", "SecurePass123".encode(), salt.encode(), iterations=100000,
        )
        legacy_hash = f"{salt}:{key.hex()}"
        assert needs_rehash(legacy_hash) is True

    def test_invalid_hash_needs_rehash(self):
        """Невалидный хеш → True."""
        assert needs_rehash("not-a-hash") is True

    def test_empty_hash_needs_rehash(self):
        """Пустой хеш → True."""
        assert needs_rehash("") is True
