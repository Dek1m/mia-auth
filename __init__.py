"""Auth Module — модуль авторизации для Mia Framework.

Предоставляет:
- Управление пользователями (CRUD)
- Аутентификацию (login/logout/refresh)
- Авторизацию (RBAC, permissions)
- JWT токены (access + refresh)
- Шифрование паролей (argon2id)

Использование:
    app.load_module("auth")

    # Доступ через Application
    user = await app.services.resolve(AuthProvider).get_user("user:123")
"""
from __future__ import annotations

import asyncio
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

MODULE_VERSION = "2.0.0"


class AuthModule(ModuleBase):
    """Auth-модуль для Mia Framework.

    Phase 1: PostgreSQL + argon2id + JWT HS256 + permissions cache.
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
        # Получаем Database Provider из State
        from modules.db.provider import DatabaseProvider

        database = state.services.resolve(DatabaseProvider)

        # Создание провайдера и регистрация в DI
        self._provider = AuthProvider(config=self._config, database=database)
        state.services.register(AuthProvider, self._provider)

        # Регистрация AUTH_CORE_SCHEMA (идемпотентно)
        async def _init_auth_schema() -> None:
            await self._provider.initialize()

        # Выполняем в event loop (on_load вызывается синхронно)
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # Если loop уже запущен — планируем coroutine
            asyncio.ensure_future(_init_auth_schema())
        else:
            loop.run_until_complete(_init_auth_schema())

        log.info("AuthModule loaded (Phase 1: PostgreSQL)")

    def on_unload(self) -> None:
        """Очистка ресурсов."""
        if self._provider and self._provider.cache:
            self._provider.cache.invalidate_all()
        log.info("AuthModule unloaded")
