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
from typing import Any

from modules_system.module_base import ModuleBase, ModuleMeta
from .provider import AuthProvider
from .config import AuthConfig

__all__ = [
    "AuthModule",
    "AuthProvider",
    "AuthConfig",
]

MODULE_VERSION = "2.0.0"


class AuthModule(ModuleBase):
    """Auth-модуль для Mia Framework.

    Phase 1: PostgreSQL + argon2id + JWT HS256 + permissions cache.
    Метаданные модуля (permissions, cache, lock, timeout) описаны декларативно.
    """

    @property
    def name(self) -> str:
        return "auth"

    @property
    def version(self) -> str:
        return MODULE_VERSION

    @property
    def meta(self) -> ModuleMeta:
        return ModuleMeta(
            dependencies=["log", "db"],
            permissions={
                "login": "auth.login",
                "create_user": "auth.create_user",
                "check_permission": "auth.check",
            },
            cache_rules={
                "get_user": 300,
                "check_permission": 60,
            },
            lock_rules={
                "login": "user:{username}",
            },
            timeout_defaults={
                "login": 10.0,
                "create_user": 5.0,
            },
        )

    def __init__(self, config: AuthConfig | None = None) -> None:
        self._config = config or AuthConfig.from_env()
        self._provider: AuthProvider | None = None
        self._log = None

    def on_load(self, state: Any) -> None:
        """Инициализация модуля: создаёт провайдер и регистрирует в DI."""
        self._log = state.log

        # Получаем Database Provider из State
        from modules.db.provider import DatabaseProvider
        from modules.auth.schemas import DB_SCHEMA

        database = state.services.resolve(DatabaseProvider)

        # Создание таблиц auth (идемпотентно)
        database.register_schema("auth", DB_SCHEMA, schema_name="auth")

        # Создание провайдера и регистрация в DI
        self._provider = AuthProvider(config=self._config, database=database, log=self._log)
        state.services.register(AuthProvider, self._provider)

        # Регистрация AUTH_CORE_SCHEMA (идемпотентно)
        self._provider.initialize_sync()

        self._log.info("AuthModule loaded (Phase 1: PostgreSQL)")

    def on_unload(self) -> None:
        """Очистка ресурсов."""
        if self._provider and self._provider.cache:
            self._provider.cache.invalidate_all()
        self._log.info("AuthModule unloaded")
        self._log = None
