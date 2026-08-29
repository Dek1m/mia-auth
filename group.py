"""Group — lazy-сущность auth.groups."""
from __future__ import annotations

from typing import Any

from .errors import DomainError, is_duplicate, require_name

__all__ = ["Group"]


class Group:
    """Конструктор без SQL; поля — после load."""

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
        row = await self._repo.get_group(self._uuid)
        if not row:
            raise DomainError("Group not found", "NOT_FOUND", entity="Group")
        self._data = row
        self._loaded = True

    def _require_data(self) -> dict[str, Any]:
        if not self._loaded or self._data is None:
            raise RuntimeError(f"Group {self._uuid!r} is not loaded")
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

    async def rename(self, name: str) -> None:
        """UPDATE auth.groups через %s. Builtin — FORBIDDEN."""
        cleaned = require_name(name)
        await self._ensure_loaded()
        if self._require_data().get("is_builtin"):
            raise DomainError("Cannot rename a builtin group", "FORBIDDEN")
        if self._repo is None:
            raise DomainError("Auth not initialized", "VALIDATION")
        clash = await self._repo.find_group_by_name(cleaned)
        if clash and str(clash["id"]) != self._uuid:
            raise DomainError(
                f"Group {cleaned!r} exists",
                "DUPLICATE_NAME",
                human="Name already exists",
            )
        try:
            updated = await self._repo.set_group_name(self._uuid, cleaned)
        except Exception as exc:
            if is_duplicate(exc):
                raise DomainError(
                    str(exc), "DUPLICATE_NAME", human="Name already exists",
                ) from exc
            raise
        if not updated:
            raise DomainError("Group not found", "NOT_FOUND", entity="Group")
        self._data = updated
        self._loaded = True

    def __repr__(self) -> str:
        return f"Group(uuid={self._uuid!r})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Group):
            return NotImplemented
        return self._uuid == other._uuid

    def __hash__(self) -> int:
        return hash(self._uuid)
