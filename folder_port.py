"""Порт FolderRepository: SQL OU живёт в admin, auth его не импортирует."""
from __future__ import annotations

from typing import Any, Protocol

__all__ = ["FolderRepository", "FolderStoreUnbound"]


class FolderStoreUnbound(Exception):
    """FolderRepository не привязан — admin.on_load не вызвал bind_folders."""


class FolderRepository(Protocol):
    """Контракт дерева OU и привязок user/group. Impl — admin.folder_repository."""

    async def list_ous(self) -> list[dict[str, Any]]:
        """Все OU: id, parent_id, name, is_builtin, is_system, kind, sort_order."""
        ...

    async def get_ou(self, ou_id: str) -> dict[str, Any] | None:
        """Одна OU или None."""
        ...

    async def list_user_bindings(self) -> list[dict[str, Any]]:
        """Привязки: id, name/username, ou_id, workspace_db. Без password_hash."""
        ...

    async def list_group_bindings(self) -> list[dict[str, Any]]:
        """Привязки групп: id, name, is_builtin, ou_id."""
        ...

    async def get_user_ou(self, user_id: str) -> dict[str, Any] | None:
        """OU пользователя: строка ou или None."""
        ...

    async def create_ou(self, parent_id: str, name: str) -> dict[str, Any]:
        """INSERT folder. unique (parent_id, name) — исключение наружу."""
        ...

    async def rename_ou(self, ou_id: str, name: str) -> dict[str, Any] | None:
        """UPDATE name. None если узла нет."""
        ...

    async def delete_ou(self, ou_id: str) -> None:
        """DELETE ou. Инварианты — на Folder, не здесь."""
        ...

    async def insert_user_ou(
        self, user_id: str, ou_id: str, workspace_db: str,
    ) -> None:
        """Привязка user → ou. Не CREATE DATABASE."""
        ...

    async def insert_group_ou(self, group_id: str, ou_id: str) -> None:
        """Привязка group → ou."""
        ...

    async def get_system_ou_by_kind(self, kind: str) -> dict[str, Any] | None:
        """Builtin bin: users_bin / groups_bin."""
        ...

    async def count_children(self, ou_id: str) -> int:
        ...

    async def count_user_ou(self, ou_id: str) -> int:
        ...

    async def count_group_ou(self, ou_id: str) -> int:
        ...
