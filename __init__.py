"""Auth Module — модуль авторизации для Mia Framework.

Предоставляет:
- Управление пользователями (CRUD)
- Аутентификацию (login/logout)
- Авторизацию (RBAC, permissions)
- JWT токены
- Шифрование паролей

Использование:
    app.load_module("auth")

    # Доступ через Application
    user = app.services.resolve(AuthProvider).get_user("user:123")
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from modules_system.module_base import ModuleBase
from .provider import AuthProvider
from .config import AuthConfig

__all__ = [
    "AuthModule",
    "AuthProvider",
    "AuthConfig",
]

from argenta_logging import get_logger

log = get_logger(__name__)

MODULE_VERSION = "1.0.0"


class AuthModule(ModuleBase):
    """Auth-модуль для Mia Framework.

    Предоставляет:
    - Управление пользователями
    - Аутентификацию (JWT)
    - Авторизацию (RBAC)
    - Шифрование паролей

    Пул соединений создаётся внутри модуля (asyncpg).
    Ядро mia НЕ знает про БД — только фасад Database.
    """

    @property
    def name(self) -> str:
        return "auth"

    @property
    def version(self) -> str:
        return MODULE_VERSION

    def __init__(self, config: AuthConfig | None = None) -> None:
        self._config = config or AuthConfig.from_env()
        self._provider: AuthProvider | None = None

    def on_load(self, state: Any) -> None:
        """Инициализация модуля: создаёт провайдер и регистрирует в DI."""
        # Создание провайдера и регистрация в DI
        self._provider = AuthProvider(config=self._config)
        state.services.register(AuthProvider, self._provider)

        log.info("AuthModule loaded")

    def on_unload(self) -> None:
        """Очистка ресурсов."""
        log.info("AuthModule unloaded")
