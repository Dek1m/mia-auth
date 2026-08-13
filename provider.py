"""Auth Provider — реализация авторизации для Mia Framework.

Предоставляет:
- Управление пользователями (CRUD)
- Аутентификацию (login/logout)
- Авторизацию (RBAC, permissions)
- JWT токены
- Шифрование паролей
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from argenta_logging import get_logger
from core.task_decorator import task
from .config import AuthConfig

log = get_logger(__name__)

__all__ = ["AuthProvider"]


@dataclass
class User:
    """Пользователь."""

    id: str
    username: str
    password_hash: str
    email: str | None = None
    roles: list[str] = field(default_factory=list)
    permissions: list[str] = field(default_factory=list)
    is_active: bool = True
    created_at: float = field(default_factory=time.time)
    last_login: float | None = None
    login_attempts: int = 0
    locked_until: float | None = None


@dataclass
class AuthToken:
    """JWT токен."""

    user_id: str
    username: str
    roles: list[str]
    permissions: list[str]
    expires_at: float
    issued_at: float = field(default_factory=time.time)


class AuthProvider:
    """Провайдер авторизации.

    Предоставляет методы для:
    - Управления пользователями (CRUD)
    - Аутентификации (login/logout)
    - Авторизации (RBAC, permissions)
    - JWT токенов
    - Шифрования паролей
    """

    def __init__(self, config: AuthConfig | None = None) -> None:
        self._config = config or AuthConfig()
        self._users: dict[str, User] = {}  # In-memory storage (для примера)
        self._tokens: dict[str, AuthToken] = {}  # Active tokens

    # ============================================
    # Пользователи (CRUD)
    # ============================================

    @task(type="database", timeout=5.0)
    def get_user(self, user_id: str) -> User | None:
        """Получить пользователя по ID."""
        return self._users.get(user_id)

    @task(type="database", timeout=5.0)
    def get_user_by_username(self, username: str) -> User | None:
        """Получить пользователя по username."""
        for user in self._users.values():
            if user.username == username:
                return user
        return None

    @task(type="database", timeout=5.0)
    def create_user(
        self,
        username: str,
        password: str,
        email: str | None = None,
        roles: list[str] | None = None,
    ) -> User:
        """Создать пользователя."""
        # Валидация
        if self.get_user_by_username(username):
            raise ValueError(f"User '{username}' already exists")

        self._validate_password(password)

        # Хеширование пароля
        password_hash = self._hash_password(password)

        # Создание пользователя
        user_id = secrets.token_hex(16)
        user = User(
            id=user_id,
            username=username,
            password_hash=password_hash,
            email=email,
            roles=roles or ["user"],
        )
        self._users[user_id] = user

        log.info(
            "User created",
            extra={"user_id": user_id, "username": username},
        )

        return user

    @task(type="database", timeout=5.0)
    def update_user(self, user_id: str, data: dict[str, Any]) -> User | None:
        """Обновить пользователя."""
        user = self._users.get(user_id)
        if not user:
            return None

        if "username" in data:
            user.username = data["username"]
        if "email" in data:
            user.email = data["email"]
        if "roles" in data:
            user.roles = data["roles"]
        if "permissions" in data:
            user.permissions = data["permissions"]
        if "is_active" in data:
            user.is_active = data["is_active"]

        log.info("User updated", extra={"user_id": user_id})

        return user

    @task(type="database", timeout=5.0)
    def delete_user(self, user_id: str) -> bool:
        """Удалить пользователя."""
        if user_id in self._users:
            del self._users[user_id]
            log.info("User deleted", extra={"user_id": user_id})
            return True
        return False

    # ============================================
    # Аутентификация
    # ============================================

    @task(type="database", timeout=5.0)
    def login(self, username: str, password: str) -> AuthToken | None:
        """Аутентификация пользователя."""
        user = self.get_user_by_username(username)
        if not user:
            log.warning("Login failed: user not found", extra={"username": username})
            return None

        # Проверка блокировки
        if user.locked_until and time.time() < user.locked_until:
            log.warning(
                "Login failed: account locked",
                extra={"username": username, "locked_until": user.locked_until},
            )
            return None

        # Проверка пароля
        if not self._verify_password(password, user.password_hash):
            user.login_attempts += 1
            if user.login_attempts >= self._config.max_login_attempts:
                user.locked_until = time.time() + (
                    self._config.lockout_duration_minutes * 60
                )
                log.warning(
                    "Account locked due to too many attempts",
                    extra={"username": username, "attempts": user.login_attempts},
                )
            return None

        # Успешный вход
        user.login_attempts = 0
        user.locked_until = None
        user.last_login = time.time()

        # Создание токена
        token = self._create_token(user)

        log.info(
            "User logged in",
            extra={"user_id": user.id, "username": username},
        )

        return token

    @task(type="database", timeout=5.0)
    def logout(self, token: AuthToken) -> bool:
        """Выход пользователя."""
        token_key = f"{token.user_id}:{token.issued_at}"
        if token_key in self._tokens:
            del self._tokens[token_key]
            log.info("User logged out", extra={"user_id": token.user_id})
            return True
        return False

    # ============================================
    # Авторизация
    # ============================================

    @task(type="database", timeout=5.0)
    def authorize(self, token: AuthToken, permission: str) -> bool:
        """Проверить разрешение."""
        # Проверка срока действия
        if time.time() > token.expires_at:
            return False

        # Проверка разрешения
        return permission in token.permissions

    @task(type="database", timeout=5.0)
    def has_role(self, token: AuthToken, role: str) -> bool:
        """Проверить роль."""
        return role in token.roles

    @task(type="database", timeout=5.0)
    def check_permission(self, user_id: str, permission: str) -> bool:
        """Проверить разрешение пользователя (без токена)."""
        user = self._users.get(user_id)
        if not user or not user.is_active:
            return False
        return permission in user.permissions

    # ============================================
    # JWT
    # ============================================

    def _create_token(self, user: User) -> AuthToken:
        """Создать JWT токен."""
        expires_at = time.time() + (self._config.jwt_expiration_hours * 3600)

        token = AuthToken(
            user_id=user.id,
            username=user.username,
            roles=user.roles,
            permissions=user.permissions,
            expires_at=expires_at,
        )

        # Сохраняем токен
        token_key = f"{user.id}:{token.issued_at}"
        self._tokens[token_key] = token

        return token

    def validate_token(self, token: AuthToken) -> bool:
        """Проверить валидность токена."""
        # Проверка срока действия
        if time.time() > token.expires_at:
            return False

        # Проверка وجود в списке активных
        token_key = f"{token.user_id}:{token.issued_at}"
        return token_key in self._tokens

    # ============================================
    # Шифрование паролей
    # ============================================

    def _hash_password(self, password: str) -> str:
        """Хешировать пароль (PBKDF2)."""
        salt = secrets.token_hex(16)
        key = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(),
            salt.encode(),
            iterations=100000,
        )
        return f"{salt}:{key.hex()}"

    def _verify_password(self, password: str, password_hash: str) -> bool:
        """Проверить пароль."""
        try:
            salt, key_hex = password_hash.split(":")
            key = hashlib.pbkdf2_hmac(
                "sha256",
                password.encode(),
                salt.encode(),
                iterations=100000,
            )
            return hmac.compare_digest(key.hex(), key_hex)
        except (ValueError, AttributeError):
            return False

    def _validate_password(self, password: str) -> None:
        """Валидация пароля."""
        if len(password) < self._config.password_min_length:
            raise ValueError(
                f"Password must be at least {self._config.password_min_length} characters"
            )

        if self._config.password_require_uppercase and not any(
            c.isupper() for c in password
        ):
            raise ValueError("Password must contain at least one uppercase letter")

        if self._config.password_require_digit and not any(
            c.isdigit() for c in password
        ):
            raise ValueError("Password must contain at least one digit")
