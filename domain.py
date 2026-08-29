"""Domain — фасад state.domain. Aggregate-вход, не DTO-сервис."""
from __future__ import annotations

from typing import Any, Callable

from .errors import DomainError
from .folder import Folder
from .folder_port import FolderRepository, FolderStoreUnbound
from .group import Group
from .role import Role
from .user import User

__all__ = ["Domain"]


class Domain:
    """Каталог User/Group/Role/Folder. Folder-порт вешает admin через bind_folders."""

    def __init__(self, auth_repo: Any | None) -> None:
        self._auth_repo = auth_repo
        self._folder_repo: FolderRepository | None = None

    def bind_folders(self, repo: FolderRepository) -> None:
        self._folder_repo = repo

    def _folders(self) -> FolderRepository:
        if self._folder_repo is None:
            raise FolderStoreUnbound("FolderRepository is not bound")
        return self._folder_repo

    def user(self, uuid: str) -> User:
        return User(uuid, self._auth_repo, domain=self)

    def group(self, uuid: str) -> Group:
        return Group(uuid, self._auth_repo, domain=self)

    def role(self, uuid: str) -> Role:
        return Role(uuid, self._auth_repo, domain=self)

    def folder(self, uuid: str) -> Folder:
        return Folder(uuid, self)

    async def get_bin(self, kind: str) -> Folder:
        """Builtin Users/Groups по kind (users_bin / groups_bin)."""
        row = await self._folders().get_system_ou_by_kind(kind)
        if not row:
            raise DomainError("OU not found", "NOT_FOUND", entity="OU")
        return Folder(str(row["id"]), self, data=row)

    async def users(
        self,
        search: str | None = None,
        ou_id: str | None = None,
    ) -> list[User]:
        if ou_id is not None:
            return self._users_in_ou(await self._folders().list_user_bindings(), ou_id, search)
        if self._auth_repo is None:
            return []
        listed = await self._auth_repo.list_users(search=search)
        items = listed[0] if isinstance(listed, tuple) else listed
        return [self.user(str(row["id"])) for row in items]

    def _users_in_ou(
        self,
        bindings: list[dict[str, Any]],
        ou_id: str,
        search: str | None,
    ) -> list[User]:
        needle = search.lower() if search else None
        found: list[User] = []
        for row in bindings:
            if str(row["ou_id"]) != str(ou_id):
                continue
            label = str(row.get("name") or row.get("username") or "")
            if needle and needle not in label.lower():
                continue
            found.append(self.user(str(row["id"])))
        return found

    async def groups(
        self,
        search: str | None = None,
        ou_id: str | None = None,
    ) -> list[Group]:
        if ou_id is not None:
            return self._named_in_ou(
                await self._folders().list_group_bindings(), ou_id, search, self.group,
            )
        if self._auth_repo is None:
            return []
        listed = await self._auth_repo.list_groups()
        items = listed[0] if isinstance(listed, tuple) else listed
        return self._filter_named(items, search, self.group)

    async def roles(self, search: str | None = None) -> list[Role]:
        if self._auth_repo is None:
            return []
        listed = await self._auth_repo.list_roles()
        items = listed[0] if isinstance(listed, tuple) else listed
        return self._filter_named(items, search, self.role)

    def _filter_named(
        self,
        items: list[dict[str, Any]],
        search: str | None,
        factory: Callable[[str], Any],
    ) -> list[Any]:
        needle = search.lower() if search else None
        found: list[Any] = []
        for row in items:
            label = str(row.get("name") or "")
            if needle and needle not in label.lower():
                continue
            found.append(factory(str(row["id"])))
        return found

    def _named_in_ou(
        self,
        bindings: list[dict[str, Any]],
        ou_id: str,
        search: str | None,
        factory: Callable[[str], Any],
    ) -> list[Any]:
        needle = search.lower() if search else None
        found: list[Any] = []
        for row in bindings:
            if str(row["ou_id"]) != str(ou_id):
                continue
            label = str(row.get("name") or "")
            if needle and needle not in label.lower():
                continue
            found.append(factory(str(row["id"])))
        return found

    async def folders(self, parent_id: str | None = None) -> list[Folder]:
        want = None if parent_id is None else str(parent_id)
        result: list[Folder] = []
        for row in await self._folders().list_ous():
            raw_parent = row.get("parent_id")
            have = None if raw_parent is None else str(raw_parent)
            if have == want:
                result.append(Folder(str(row["id"]), self, data=row))
        return result

    async def tree(self) -> Folder:
        """Корень parent_id is None (имя Argenta); дети из памяти, не N+1."""
        repo = self._folders()
        ous = await repo.list_ous()
        users = await repo.list_user_bindings()
        groups = await repo.list_group_bindings()
        return self._assemble_tree(ous, users, groups)

    def _assemble_tree(
        self,
        ous: list[dict[str, Any]],
        users: list[dict[str, Any]],
        groups: list[dict[str, Any]],
    ) -> Folder:
        by_parent: dict[str | None, list[dict[str, Any]]] = {}
        for row in ous:
            raw_parent = row.get("parent_id")
            key = None if raw_parent is None else str(raw_parent)
            by_parent.setdefault(key, []).append(row)
        users_by = _group_by_ou(users)
        groups_by = _group_by_ou(groups)
        roots = by_parent.get(None, [])
        if not roots:
            raise LookupError("Domain root OU is missing")
        root_row = next((row for row in roots if row.get("name") == "Argenta"), roots[0])
        return self._build_folder(root_row, by_parent, users_by, groups_by)

    def _build_folder(
        self,
        row: dict[str, Any],
        by_parent: dict[str | None, list[dict[str, Any]]],
        users_by: dict[str, list[dict[str, Any]]],
        groups_by: dict[str, list[dict[str, Any]]],
    ) -> Folder:
        node = Folder(str(row["id"]), self, data=row)
        oid = str(row["id"])
        children = [
            self._build_folder(child, by_parent, users_by, groups_by)
            for child in by_parent.get(oid, [])
        ]
        node._attach_tree(children, users_by.get(oid, []), groups_by.get(oid, []))
        return node


def _group_by_ou(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(str(row["ou_id"]), []).append(row)
    return grouped
