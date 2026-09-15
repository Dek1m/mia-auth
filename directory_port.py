"""Порт DirectoryConnectorPort: контракт синхронизации внешнего каталога (AD).

Конфиг подключения — auth.domains.ad_config (urls, base_dn, схемы).
Bind-пароль в ad_config НЕ хранится — только secrets-механизм приложения.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

__all__ = ["SyncReport", "DirectoryConnectorPort"]


@dataclass(frozen=True)
class SyncReport:
    """Итог синхронизации каталога. Value Object — immutable."""

    created: int = 0
    updated: int = 0
    skipped: int = 0
    errors: tuple[str, ...] = ()


class DirectoryConnectorPort(Protocol):
    """Контракт коннектора каталога для домена kind='ad'."""

    async def test_connection(self, config: dict[str, Any]) -> bool:
        """Проверить связность с каталогом по ad_config (без записи данных).

        Args:
            config: Словарь ad_config домена; секрет берётся из
                secrets-механизма по ключу домена, не из config.

        Returns:
            True — каталог доступен и bind прошёл.
        """
        ...

    async def sync_users(self, domain_id: str) -> SyncReport:
        """Импорт/обновление пользователей каталога в auth.users (domain_id).

        Идемпотентно: повторный запуск обновляет, не дублирует
        (сопоставление по sAMAccountName → username).
        """
        ...

    async def sync_groups(self, domain_id: str) -> SyncReport:
        """Импорт/обновление групп каталога в auth.groups (scope='domain')."""
        ...
