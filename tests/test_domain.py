"""Domain.tree / Folder / User.folder без PostgreSQL."""
from __future__ import annotations

from typing import Any

import pytest

from modules.auth.domain import Domain
from modules.auth.errors import DomainError
from modules.auth.folder import Folder
from modules.auth.folder_port import FolderStoreUnbound
from modules.auth.user import User

ARGENTA = "ou-argenta"
BUILTIN = "ou-builtin"
USERS_BIN = "ou-users"
GROUPS_BIN = "ou-groups"
SALES = "ou-sales"
ALICE = "user-alice"


class FakeFolderRepo:
    def __init__(self) -> None:
        self.ous: list[dict[str, Any]] = [
            {
                "id": ARGENTA, "parent_id": None, "name": "Argenta",
                "kind": "folder", "is_system": True, "is_builtin": True, "sort_order": 0,
            },
            {
                "id": BUILTIN, "parent_id": ARGENTA, "name": "Built-in",
                "kind": "folder", "is_system": True, "is_builtin": True, "sort_order": 0,
            },
            {
                "id": USERS_BIN, "parent_id": BUILTIN, "name": "Users",
                "kind": "users_bin", "is_system": True, "is_builtin": True, "sort_order": 0,
            },
            {
                "id": GROUPS_BIN, "parent_id": BUILTIN, "name": "Groups",
                "kind": "groups_bin", "is_system": True, "is_builtin": True, "sort_order": 1,
            },
            {
                "id": SALES, "parent_id": ARGENTA, "name": "Sales",
                "kind": "folder", "is_system": False, "is_builtin": False, "sort_order": 1,
            },
        ]
        self.user_binds: list[dict[str, Any]] = [
            {
                "id": ALICE, "name": "alice", "ou_id": SALES,
                "workspace_db": "belle_workspace_alice",
            },
        ]
        self.group_binds: list[dict[str, Any]] = [
            {"id": "g1", "name": "ops", "is_builtin": False, "ou_id": SALES},
        ]

    async def list_ous(self) -> list[dict[str, Any]]:
        return list(self.ous)

    async def get_ou(self, ou_id: str) -> dict[str, Any] | None:
        return next((row for row in self.ous if row["id"] == ou_id), None)

    async def list_user_bindings(self) -> list[dict[str, Any]]:
        return list(self.user_binds)

    async def list_group_bindings(self) -> list[dict[str, Any]]:
        return list(self.group_binds)

    async def get_user_ou(self, user_id: str) -> dict[str, Any] | None:
        bind = next((row for row in self.user_binds if row["id"] == user_id), None)
        if bind is None:
            return None
        return await self.get_ou(str(bind["ou_id"]))

    async def get_system_ou_by_kind(self, kind: str) -> dict[str, Any] | None:
        return next(
            (
                row for row in self.ous
                if row["kind"] == kind and row["is_system"] and row["is_builtin"]
            ),
            None,
        )

    async def create_ou(self, parent_id: str, name: str) -> dict[str, Any]:
        for row in self.ous:
            if row.get("parent_id") == parent_id and row["name"] == name:
                raise Exception("duplicate key value violates unique constraint")
        created = {
            "id": f"ou-{name}",
            "parent_id": parent_id,
            "name": name,
            "kind": "folder",
            "is_system": False,
            "is_builtin": False,
            "sort_order": 0,
        }
        self.ous.append(created)
        return dict(created)

    async def rename_ou(self, ou_id: str, name: str) -> dict[str, Any] | None:
        row = next((item for item in self.ous if item["id"] == ou_id), None)
        if row is None:
            return None
        row["name"] = name
        return dict(row)

    async def delete_ou(self, ou_id: str) -> None:
        self.ous = [row for row in self.ous if row["id"] != ou_id]

    async def insert_user_ou(
        self, user_id: str, ou_id: str, workspace_db: str,
    ) -> None:
        self.user_binds.append({
            "id": user_id, "name": user_id, "ou_id": ou_id, "workspace_db": workspace_db,
        })

    async def insert_group_ou(self, group_id: str, ou_id: str) -> None:
        self.group_binds.append({
            "id": group_id, "name": group_id, "is_builtin": False, "ou_id": ou_id,
        })

    async def count_children(self, ou_id: str) -> int:
        return sum(1 for row in self.ous if row.get("parent_id") == ou_id)

    async def count_user_ou(self, ou_id: str) -> int:
        return sum(1 for row in self.user_binds if row["ou_id"] == ou_id)

    async def count_group_ou(self, ou_id: str) -> int:
        return sum(1 for row in self.group_binds if row["ou_id"] == ou_id)


class FakeAuthRepo:
    def __init__(self) -> None:
        self.users: dict[str, dict[str, Any]] = {}
        self.groups: dict[str, dict[str, Any]] = {}

    async def get_user(self, user_id: str) -> dict[str, Any] | None:
        return self.users.get(str(user_id))

    async def get_user_by_username(self, username: str) -> dict[str, Any] | None:
        for row in self.users.values():
            if row.get("username") == username:
                return row
        return None

    async def create_user(
        self, username: str, password_hash: str, email: str | None = None,
    ) -> dict[str, Any]:
        row = {
            "id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "username": username,
            "email": email,
            "password_hash": password_hash,
        }
        self.users[row["id"]] = row
        return row

    async def find_group_by_name(self, name: str) -> dict[str, Any] | None:
        for row in self.groups.values():
            if row.get("name") == name:
                return row
        return None

    async def create_group(
        self, name: str, description: str | None = None,
    ) -> dict[str, Any]:
        row = {
            "id": "group-new",
            "name": name,
            "description": description,
            "is_builtin": False,
        }
        self.groups[row["id"]] = row
        return row

    async def get_group(self, group_id: str) -> dict[str, Any] | None:
        return self.groups.get(str(group_id))


def _bound_domain() -> Domain:
    domain = Domain(auth_repo=None)
    domain.bind_folders(FakeFolderRepo())
    return domain


@pytest.mark.asyncio
async def test_tree_without_bind_raises() -> None:
    domain = Domain(auth_repo=None)
    with pytest.raises(FolderStoreUnbound):
        await domain.tree()


@pytest.mark.asyncio
async def test_tree_root_argenta_and_children() -> None:
    root = await _bound_domain().tree()
    assert isinstance(root, Folder)
    assert root.name == "Argenta"
    assert root.parent_id is None
    assert root.is_system is True
    children = await root.children()
    names = {child.name for child in children}
    assert names == {"Built-in", "Sales"}


@pytest.mark.asyncio
async def test_tree_nested_users_and_groups() -> None:
    root = await _bound_domain().tree()
    sales = next(child for child in await root.children() if child.name == "Sales")
    users = await sales.users()
    assert [user.uuid for user in users] == [ALICE]
    binds = await sales.user_bindings()
    assert binds[0]["workspace_db"] == "belle_workspace_alice"
    assert "password_hash" not in binds[0]
    groups = await sales.group_bindings()
    assert groups[0]["name"] == "ops"


@pytest.mark.asyncio
async def test_user_folder_via_domain() -> None:
    domain = _bound_domain()
    user = domain.user(ALICE)
    folder = await user.folder()
    assert folder is not None
    assert folder.uuid == SALES
    assert folder.name == "Sales"


@pytest.mark.asyncio
async def test_user_folder_without_domain_raises() -> None:
    user = User(ALICE, repo=None)
    with pytest.raises(FolderStoreUnbound):
        await user.folder()


@pytest.mark.asyncio
async def test_folders_by_parent() -> None:
    domain = _bound_domain()
    roots = await domain.folders(parent_id=None)
    assert [folder.name for folder in roots] == ["Argenta"]
    nested = await domain.folders(parent_id=ARGENTA)
    assert {folder.name for folder in nested} == {"Built-in", "Sales"}


def _mutating_domain() -> Domain:
    domain = Domain(auth_repo=FakeAuthRepo())
    domain.bind_folders(FakeFolderRepo())
    return domain


@pytest.mark.asyncio
async def test_folder_groups_from_bindings() -> None:
    sales = (await _bound_domain().tree())
    node = next(child for child in await sales.children() if child.name == "Sales")
    groups = await node.groups()
    assert [group.uuid for group in groups] == ["g1"]


@pytest.mark.asyncio
async def test_create_folder_forbidden_on_bins() -> None:
    domain = _mutating_domain()
    with pytest.raises(DomainError) as exc:
        await domain.folder(USERS_BIN).create_folder("Nested")
    assert exc.value.code == "FORBIDDEN"
    with pytest.raises(DomainError) as exc:
        await domain.folder(GROUPS_BIN).create_folder("Nested")
    assert exc.value.code == "FORBIDDEN"


@pytest.mark.asyncio
async def test_create_folder_under_ordinary() -> None:
    folder = await _mutating_domain().folder(SALES).create_folder("Team")
    assert folder.name == "Team"
    assert folder.parent_id == SALES
    assert folder.kind == "folder"


@pytest.mark.asyncio
async def test_rename_delete_forbidden_on_system() -> None:
    domain = _mutating_domain()
    with pytest.raises(DomainError) as exc:
        await domain.folder(ARGENTA).rename("Nope")
    assert exc.value.code == "FORBIDDEN"
    with pytest.raises(DomainError) as exc:
        await domain.folder(USERS_BIN).delete()
    assert exc.value.code == "FORBIDDEN"


@pytest.mark.asyncio
async def test_create_user_only_users_bin_or_folder(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("modules.auth.folder.hash_password", lambda _p: "hashed")
    domain = _mutating_domain()
    with pytest.raises(DomainError) as exc:
        await domain.folder(ARGENTA).create_user("kate", "secret-pass")
    assert exc.value.code == "FORBIDDEN"
    with pytest.raises(DomainError) as exc:
        await domain.folder(GROUPS_BIN).create_user("kate", "secret-pass")
    assert exc.value.code == "FORBIDDEN"
    user = await domain.folder(USERS_BIN).create_user("alice", "secret-pass")
    assert user.uuid == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    sales_user = await domain.folder(SALES).create_user("bob", "secret-pass")
    assert sales_user.uuid == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


@pytest.mark.asyncio
async def test_get_bin_users_and_groups() -> None:
    domain = _mutating_domain()
    users = await domain.get_bin("users_bin")
    assert users.uuid == USERS_BIN
    groups = await domain.get_bin("groups_bin")
    assert groups.uuid == GROUPS_BIN
