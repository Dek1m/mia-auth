"""Порт IdentityProviderPort: контракт аутентификации по identity_kind домена.

Impl-ы живут в auth/identity/ (local, basic, oidc, ad). Порт — Protocol
(структурная типизация), как FolderRepository в folder_port.py.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

__all__ = ["IdentityResult", "IdentityProviderPort"]


@dataclass(frozen=True)
class IdentityResult:
    """Идентичность, подтверждённая провайдером. Value Object — immutable.

    Attributes:
        user_id: UUID auth.users.
        username: Имя входа (каноническое, по нему нашли пользователя).
        domain_id: Домен идентичности (None — builtin).
        new_password_hash: Новый argon2id-хеш, если старый требовал rehash
            (миграция PBKDF2 → argon2id); caller обязан записать его в БД.
    """

    user_id: str
    username: str
    domain_id: str | None = None
    new_password_hash: str | None = None


class IdentityProviderPort(Protocol):
    """Контракт провайдера идентичности для auth.domains.identity_kind.

    Секреты (client_secret, bind-пароли) провайдер НЕ хранит в
    auth.domains.auth_config — только существующий secrets-механизм.
    """

    async def authenticate(self, credentials: dict[str, Any]) -> IdentityResult | None:
        """Проверить учётные данные.

        Args:
            credentials: Словарь вида {"username": ..., "password": ...}
                (local/basic) или {"token": ...} (oidc/ad).

        Returns:
            IdentityResult при успехе; None — учётные данные не подошли
            (не бросаем исключение на неверный пароль — это штатный отказ).
        """
        ...

    async def discover(self, hint: str) -> str | None:
        """Резолв identity_kind по подсказке входа.

        Подсказка — email-домен (user@corp.example → 'oidc'), UPN-суффикс
        (user@corp.local → 'ad') или пусто (→ 'local').

        Returns:
            'local' | 'basic' | 'oidc' | 'ad' | None (не удалось определить).
        """
        ...
