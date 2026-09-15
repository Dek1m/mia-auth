"""BasicIdentity — identity_kind='basic': делегирование внешнему Basic-прокси.

Каркас Части 2. Контракт: credentials {username, password} проверяются
внешним сервисом (endpoint из auth.domains.auth_config['verify_url']),
пароли в auth.users НЕ хранятся. Секрет прокси — secrets-механизм.
"""
from __future__ import annotations

from typing import Any

from ..identity_port import IdentityResult

__all__ = ["BasicIdentity"]


class BasicIdentity:
    """Скелет: сетевая верификация против внешнего прокси."""

    def __init__(self, auth_config: dict[str, Any]) -> None:
        self._config = dict(auth_config)

    async def authenticate(self, credentials: dict[str, Any]) -> IdentityResult | None:
        raise NotImplementedError(
            "basic-identity: внешняя верификация — волна после Части 2"
        )

    async def discover(self, hint: str) -> str | None:
        # Basic-домены назначает админ конфигурацией, не подсказкой входа.
        return None
