"""Auth Permissions Cache — in-memory кеш прав пользователей.

Кеширует набор permissions по user_id с TTL.
При изменении прав (perms_version) кеш инвалидируется.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

__all__ = ["PermissionsCache"]


@dataclass
class _CacheEntry:
    """Запись в кеше."""
    perms_version: int
    permissions: frozenset[str]
    expire_at: float


class PermissionsCache:
    """In-memory кеш permissions с TTL.

    Хранит {user_id: CacheEntry}. TTL определяется конфигом.
    """

    def __init__(self, ttl: int = 300) -> None:
        """Args:
            ttl: Время жизни записи в секундах.
        """
        self._ttl = ttl
        self._cache: dict[str, _CacheEntry] = {}

    def get(self, user_id: str) -> tuple[int, frozenset[str]] | None:
        """Получить кешированные permissions.

        Returns:
            (perms_version, permissions) или None если не найдено/истекло.
        """
        entry = self._cache.get(user_id)
        if entry is None:
            return None
        if time.time() > entry.expire_at:
            del self._cache[user_id]
            return None
        return entry.perms_version, entry.permissions

    def set(self, user_id: str, perms_version: int, permissions: frozenset[str]) -> None:
        """Сохранить permissions в кеш."""
        self._cache[user_id] = _CacheEntry(
            perms_version=perms_version,
            permissions=permissions,
            expire_at=time.time() + self._ttl,
        )

    def invalidate(self, user_id: str) -> None:
        """Удалить кеш для конкретного пользователя."""
        self._cache.pop(user_id, None)

    def invalidate_all(self) -> None:
        """Полная очистка кеша."""
        self._cache.clear()

    def cleanup(self) -> int:
        """Удалить истёкшие записи. Возвращает количество удалённых."""
        now = time.time()
        expired = [uid for uid, entry in self._cache.items() if now > entry.expire_at]
        for uid in expired:
            del self._cache[uid]
        return len(expired)

    @property
    def size(self) -> int:
        """Текущий размер кеша."""
        return len(self._cache)
