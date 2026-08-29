"""Role — lazy-сущность auth.roles. Маска UI остаётся в AdminProvider."""
from __future__ import annotations

from typing import Any

from .errors import DomainError

__all__ = ["Role"]


class Role:
    """Конструктор без SQL; поля и permissions — после load."""

    __slots__ = ("_uuid", "_repo", "_domain", "_data", "_loaded")

    def __init__(
        self,
        uuid: str,
        repo: Any,
        domain: Any | None = None,
        data: dict[str, Any] | None = None,
    ) -> None:
        self._uuid = uuid
        self._repo = repo
        self._domain = domain
        self._data: dict[str, Any] | None = data
        self._loaded = data is not None

    async def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        if self._repo is None:
            raise DomainError("Auth not initialized", "VALIDATION")
        row = await self._repo.get_role(self._uuid)
        if not row:
            raise DomainError("Role not found", "NOT_FOUND", entity="Role")
        self._data = row
        self._loaded = True

    def _require_data(self) -> dict[str, Any]:
        if not self._loaded or self._data is None:
            raise RuntimeError(f"Role {self._uuid!r} is not loaded")
        return self._data

    @property
    def uuid(self) -> str:
        return self._uuid

    async def name(self) -> str:
        await self._ensure_loaded()
        return str(self._require_data().get("name") or "")

    async def description(self) -> str | None:
        await self._ensure_loaded()
        value = self._require_data().get("description")
        return None if value is None else str(value)

    async def is_builtin(self) -> bool:
        await self._ensure_loaded()
        return bool(self._require_data().get("is_builtin"))

    async def capability_mask(self) -> int:
        await self._ensure_loaded()
        return int(self._require_data().get("capability_mask") or 0)

    async def permissions(self) -> list[str]:
        await self._ensure_loaded()
        if self._repo is None:
            return []
        rows = await self._repo.get_role_permissions(self._uuid)
        return [str(row["name"]) for row in rows]

    def __repr__(self) -> str:
        return f"Role(uuid={self._uuid!r})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Role):
            return NotImplemented
        return self._uuid == other._uuid

    def __hash__(self) -> int:
        return hash(self._uuid)
