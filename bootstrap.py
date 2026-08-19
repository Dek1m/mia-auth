"""Auth Bootstrap — начальная настройка системы авторизации.

Проверяет наличие system_admin и создаёт первого пользователя при необходимости.
"""
from __future__ import annotations

from typing import Any

from .password import hash_password

__all__ = ["AuthBootstrap"]


class AuthBootstrap:
    """Хелпер для начальной настройки auth-системы.

    Используется для:
    - Проверки необходимости bootstrap (нет пользователей с system_admin)
    - Создания первого администратора
    """

    def __init__(self, repository: Any, registry: Any, log: Any | None = None) -> None:
        """Args:
            repository: AuthRepository instance.
            registry: AuthSchemaRegistry instance.
            log: Log facade (optional).
        """
        self._repo = repository
        self._registry = registry
        self._log = log

    async def needs_bootstrap(self) -> bool:
        """Проверить, нужен ли bootstrap.

        Returns:
            True если нет ни одного активного пользователя с ролью system_admin.
        """
        count = await self._repo.get_active_admin_count()
        return count == 0

    async def bootstrap(
        self,
        username: str,
        password: str,
        email: str | None = None,
    ) -> dict[str, Any]:
        """Атомарно создать первого системного администратора.

        1. Проверяет что bootstrap ещё не выполнен
        2. Создаёт пользователя
        3. Назначает роль system_admin
        4. Добавляет в группу Administrators (если существует)

        Args:
            username: Имя пользователя.
            password: Пароль.
            email: Email (опционально).

        Returns:
            dict с user_id, username.

        Raises:
            ValueError: Если bootstrap уже выполнен (есть system_admin).
        """
        if not await self.needs_bootstrap():
            raise ValueError(
                "Bootstrap already completed: system_admin user already exists."
            )

        # Хешируем пароль
        password_hashed = hash_password(password)

        # Создаём пользователя
        user = await self._repo.create_user(
            username=username,
            password_hash=password_hashed,
            email=email,
        )
        user_id = user["id"]

        # Находим role_id для system_admin
        role_row = await self._repo.find_role_by_name("system_admin")
        if role_row:
            await self._repo.assign_role_to_user(user_id, role_row["id"])

        # Находим группу Administrators (если существует)
        group_row = await self._repo.find_group_by_name("Administrators")
        if group_row:
            await self._repo.add_user_to_group(user_id, group_row["id"])

        if self._log is not None:
            self._log.info(
                "Bootstrap completed",
                extra={"user_id": user_id, "username": username},
            )

        return {"user_id": user_id, "username": username}
