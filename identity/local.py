"""LocalIdentity — identity_kind='local': обёртка над password.py (argon2id).

Рабочий код: та же схема верификации, что в AuthProvider.login,
вынесенная за порт, чтобы Tenant с другим identity_kind подменял стратегию.
"""
from __future__ import annotations

from typing import Any

from ..identity_port import IdentityResult
from ..password import verify_password

__all__ = ["LocalIdentity"]


class LocalIdentity:
    """Верификация локального пароля из auth.users.password_hash."""

    def __init__(self, repo: Any) -> None:
        """Args:
            repo: AuthRepository — доступ к auth.users (только чтение).
        """
        self._repo = repo

    async def authenticate(self, credentials: dict[str, Any]) -> IdentityResult | None:
        username = str(credentials.get("username") or "").strip()
        password = str(credentials.get("password") or "")
        if not username or not password:
            return None
        row = await self._repo.get_user_by_username(username)
        if not row or not row.get("password_hash"):
            return None
        ok, new_hash = verify_password(password, str(row["password_hash"]))
        if not ok:
            return None
        domain_id = row.get("domain_id")
        return IdentityResult(
            user_id=str(row["id"]),
            username=username,
            domain_id=str(domain_id) if domain_id else None,
            new_password_hash=new_hash,
        )

    async def discover(self, hint: str) -> str | None:
        # Локальный провайдер — домен по умолчанию: без суффикса вход локальный.
        return "local"
