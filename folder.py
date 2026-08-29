"""Folder — lazy-сущность OU. Инварианты ADR-001 здесь, не в Provider."""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .errors import DomainError, is_duplicate, require_name
from .password import hash_password

if TYPE_CHECKING:
    from .domain import Domain
    from .group import Group
    from .user import User

__all__ = ["Folder"]


class Folder:
    """Папка каталога. Конструктор без SQL; поля — после load / tree()."""

    __slots__ = (
        "_uuid",
        "_domain",
        "_data",
        "_loaded",
        "_children",
        "_user_bindings",
        "_group_bindings",
    )

    def __init__(
        self,
        uuid: str,
        domain: Domain,
        data: dict[str, Any] | None = None,
    ) -> None:
        self._uuid = uuid
        self._domain = domain
        self._data: dict[str, Any] | None = data
        self._loaded = data is not None
        self._children: list[Folder] | None = None
        self._user_bindings: list[dict[str, Any]] | None = None
        self._group_bindings: list[dict[str, Any]] | None = None

    def _attach_tree(
        self,
        children: list[Folder],
        user_bindings: list[dict[str, Any]],
        group_bindings: list[dict[str, Any]],
    ) -> None:
        """Кэш tree(): один list_* на всё дерево, без N+1."""
        self._children = children
        self._user_bindings = user_bindings
        self._group_bindings = group_bindings

    async def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        row = await self._domain._folders().get_ou(self._uuid)
        if not row:
            raise DomainError("OU not found", "NOT_FOUND", entity="OU")
        self._data = row
        self._loaded = True

    def _require_data(self) -> dict[str, Any]:
        if not self._loaded or self._data is None:
            raise RuntimeError(f"Folder {self._uuid!r} is not loaded")
        return self._data

    def _auth(self) -> Any:
        repo = self._domain._auth_repo
        if repo is None:
            raise DomainError("Auth not initialized", "VALIDATION")
        return repo

    def _assert_can_create_folder(self) -> None:
        if self.kind in ("users_bin", "groups_bin"):
            raise DomainError("Cannot create a folder here", "FORBIDDEN")

    def _assert_can_place_user(self) -> None:
        if self.kind == "users_bin":
            return
        if self.kind == "folder" and not self.is_system:
            return
        raise DomainError("Cannot create a user here", "FORBIDDEN")

    def _assert_can_place_group(self) -> None:
        if self.kind == "groups_bin":
            return
        if self.kind == "folder" and not self.is_system:
            return
        raise DomainError("Cannot create a group here", "FORBIDDEN")

    @property
    def uuid(self) -> str:
        return self._uuid

    @property
    def kind(self) -> str:
        return str(self._require_data().get("kind") or "folder")

    @property
    def name(self) -> str:
        return str(self._require_data().get("name") or "")

    @property
    def is_system(self) -> bool:
        return bool(self._require_data().get("is_system"))

    @property
    def is_builtin(self) -> bool:
        return bool(self._require_data().get("is_builtin"))

    @property
    def parent_id(self) -> str | None:
        value = self._require_data().get("parent_id")
        return None if value is None else str(value)

    @property
    def sort_order(self) -> int:
        return int(self._require_data().get("sort_order") or 0)

    async def children(self) -> list[Folder]:
        if self._children is not None:
            return self._children
        return await self._domain.folders(parent_id=self._uuid)

    async def users(self) -> list[User]:
        if self._user_bindings is not None:
            return [self._domain.user(str(row["id"])) for row in self._user_bindings]
        return await self._domain.users(ou_id=self._uuid)

    async def groups(self) -> list[Group]:
        if self._group_bindings is not None:
            return [self._domain.group(str(row["id"])) for row in self._group_bindings]
        return await self._domain.groups(ou_id=self._uuid)

    async def user_bindings(self) -> list[dict[str, Any]]:
        """Листья user для JSON: id, name, ou_id, workspace_db."""
        if self._user_bindings is not None:
            return self._user_bindings
        rows = await self._domain._folders().list_user_bindings()
        matched = [row for row in rows if str(row["ou_id"]) == self._uuid]
        self._user_bindings = matched
        return matched

    async def group_bindings(self) -> list[dict[str, Any]]:
        """Листья group для JSON."""
        if self._group_bindings is not None:
            return self._group_bindings
        rows = await self._domain._folders().list_group_bindings()
        matched = [row for row in rows if str(row["ou_id"]) == self._uuid]
        self._group_bindings = matched
        return matched

    async def create_folder(self, name: str) -> Folder:
        cleaned = require_name(name)
        await self._ensure_loaded()
        self._assert_can_create_folder()
        try:
            row = await self._domain._folders().create_ou(self._uuid, cleaned)
        except Exception as exc:
            if is_duplicate(exc):
                raise DomainError(
                    str(exc), "DUPLICATE_NAME", human="Name already exists",
                ) from exc
            raise
        return Folder(str(row["id"]), self._domain, data=row)

    async def rename(self, name: str) -> None:
        cleaned = require_name(name)
        await self._ensure_loaded()
        if self.is_system:
            raise DomainError("Cannot rename a system OU", "FORBIDDEN")
        try:
            updated = await self._domain._folders().rename_ou(self._uuid, cleaned)
        except Exception as exc:
            if is_duplicate(exc):
                raise DomainError(
                    str(exc), "DUPLICATE_NAME", human="Name already exists",
                ) from exc
            raise
        if not updated:
            raise DomainError("OU not found", "NOT_FOUND", entity="OU")
        self._data = updated

    async def delete(self) -> None:
        await self._ensure_loaded()
        if self.is_system:
            raise DomainError("Cannot delete a system OU", "FORBIDDEN")
        repo = self._domain._folders()
        if await repo.count_children(self._uuid):
            raise DomainError(
                "OU has children", "OU_NOT_EMPTY", human="Folder is not empty",
            )
        if await repo.count_user_ou(self._uuid) or await repo.count_group_ou(self._uuid):
            raise DomainError(
                "OU has members", "OU_NOT_EMPTY", human="Folder is not empty",
            )
        await repo.delete_ou(self._uuid)

    async def create_user(
        self,
        username: str,
        password: str,
        email: str | None = None,
    ) -> User:
        cleaned = require_name(username)
        if not password:
            raise DomainError("Password is empty", "VALIDATION", human="Password is required")
        await self._ensure_loaded()
        self._assert_can_place_user()
        auth = self._auth()
        if await auth.get_user_by_username(cleaned):
            raise DomainError(
                f"User {cleaned!r} exists",
                "DUPLICATE_NAME",
                human="User already exists",
            )
        user = await auth.create_user(
            username=cleaned,
            password_hash=hash_password(password),
            email=email,
        )
        from modules.workspace.schemas import user_dbname

        workspace = user_dbname(str(user["id"]))
        await self._domain._folders().insert_user_ou(
            str(user["id"]), self._uuid, workspace,
        )
        return self._domain.user(str(user["id"]))

    async def create_group(
        self, name: str, description: str | None = None,
    ) -> Group:
        cleaned = require_name(name)
        await self._ensure_loaded()
        self._assert_can_place_group()
        auth = self._auth()
        if await auth.find_group_by_name(cleaned):
            raise DomainError(
                f"Group {cleaned!r} exists",
                "DUPLICATE_NAME",
                human="Group already exists",
            )
        group = await auth.create_group(cleaned, description)
        await self._domain._folders().insert_group_ou(str(group["id"]), self._uuid)
        return self._domain.group(str(group["id"]))

    def __repr__(self) -> str:
        return f"Folder(uuid={self._uuid!r})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Folder):
            return NotImplemented
        return self._uuid == other._uuid

    def __hash__(self) -> int:
        return hash(self._uuid)
