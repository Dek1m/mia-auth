"""User — lazy-loading обёртка над пользователем Belle.

Загружает данные из PostgreSQL только при первом обращении.
Кэширует результат в内存 для повторных запросов.

Пример использования::

    user = User(uuid="u_123", repo=repository)
    username = await user.username()  # первый запрос в БД
    username = await user.username()  # из кэша

    # Группы и permissions всегда идут через repo (они могут меняться)
    groups = await user.groups()
    perms = await user.permissions()
"""
from __future__ import annotations

from typing import Any

__all__ = ["User"]


class User:
    """Lazy-loading обёртка для пользователя.

    Не хранит данные — загружает их по требованию через AuthRepository.
    Базовые поля (username, email, is_active) кэшируются после первого
    обращения. Группы и permissions запрашиваются每次都, т.к. они
    могут меняться между вызовами.

    Attributes:
        _uuid: UUID пользователя (immutable).
        _repo: AuthRepository для запросов.
        _data: Кэш данных пользователя (None = ещё не загружен).
        _loaded: Флаг загрузки.
    """

    __slots__ = ("_uuid", "_repo", "_data", "_loaded")

    def __init__(self, uuid: str, repo: Any) -> None:
        """Args:
            uuid: UUID пользователя.
            repo: AuthRepository instance (предоставляет get_user, get_user_groups и т.д.).
        """
        self._uuid = uuid
        self._repo = repo
        self._data: dict[str, Any] | None = None
        self._loaded = False

    async def _ensure_loaded(self) -> None:
        """Загрузить данные из БД, если ещё не загружены."""
        if not self._loaded:
            self._data = await self._repo.get_user(self._uuid) or {}
            self._loaded = True

    @property
    def uuid(self) -> str:
        """UUID пользователя (immutable, доступен без запроса в БД)."""
        return self._uuid

    async def username(self) -> str:
        """Имя пользователя."""
        await self._ensure_loaded()
        return self._data.get("username", "")  # type: ignore[union-attr]

    async def email(self) -> str | None:
        """Email пользователя."""
        await self._ensure_loaded()
        return self._data.get("email")  # type: ignore[union-attr]

    async def is_active(self) -> bool:
        """Активен ли пользователь."""
        await self._ensure_loaded()
        return self._data.get("is_active", False)  # type: ignore[union-attr]

    async def is_disabled(self) -> bool:
        """Заблокирован ли пользователь."""
        await self._ensure_loaded()
        return self._data.get("is_disabled", False)  # type: ignore[union-attr]

    async def first_name(self) -> str | None:
        """Имя."""
        await self._ensure_loaded()
        return self._data.get("first_name")  # type: ignore[union-attr]

    async def last_name(self) -> str | None:
        """Фамилия."""
        await self._ensure_loaded()
        return self._data.get("last_name")  # type: ignore[union-attr]

    async def description(self) -> str | None:
        """Описание профиля."""
        await self._ensure_loaded()
        return self._data.get("description")  # type: ignore[union-attr]

    async def login_attempts(self) -> int:
        """Количество неудачных попыток входа."""
        await self._ensure_loaded()
        return self._data.get("login_attempts", 0)  # type: ignore[union-attr]

    # ── Группы и Permissions (всегда через repo) ──────────────────

    async def groups(self) -> list[dict[str, Any]]:
        """Группы пользователя (запрос в БД каждый раз).

        Returns:
            Список dict с ключами: id, name, description, is_builtin, added_at.
        """
        return await self._repo.get_user_groups(self._uuid)

    async def permissions(self) -> frozenset[str]:
        """Эффективные permissions (запрос в БД каждый раз).

        Включает permissions из:
        - Прямых ролей пользователя
        - Ролей групп (включая иерархию)
        - Ролей родительских групп

        Returns:
            frozenset имён permissions.
        """
        return await self._repo.get_user_effective_permissions(self._uuid)

    async def has_permission(self, permission: str) -> bool:
        """Проверить наличие конкретного permission.

        Args:
            permission: Имя permission (например, "user.read").

        Returns:
            True если permission есть.
        """
        perms = await self.permissions()
        return permission in perms

    async def has_active_session(self) -> bool:
        """Есть ли активная сессия (не отозванная).

        Returns:
            True если есть хотя бы одна активная сессия.
        """
        count = await self._repo.count_user_sessions(self._uuid)
        return count > 0

    async def is_admin(self) -> bool:
        """Является ли пользователь system_admin."""
        return await self._repo.is_user_admin(self._uuid)

    # ── Магические методы ─────────────────────────────────────────

    def __repr__(self) -> str:
        return f"User(uuid={self._uuid!r})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, User):
            return NotImplemented
        return self._uuid == other._uuid

    def __hash__(self) -> int:
        return hash(self._uuid)
