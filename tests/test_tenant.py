"""Tenant.create: subtree → домен → сид групп; компенсация при отказе."""
from __future__ import annotations

from typing import Any

import pytest

from modules.auth.domain import Domain
from modules.auth.errors import DomainError
from modules.auth.tenant import Tenant

ROOT = "ou-root"
CREATOR = "user-creator"


class FakeFolders:
    """Мок FolderRepository: только ветка Tenant.create."""

    def __init__(self, *, fail_domain: Exception | None = None) -> None:
        self.subtrees: list[dict[str, str]] = []
        self.deleted: list[str] = []
        self.group_bins: list[tuple[str, str]] = []
        self._fail_domain = fail_domain
        self._seq = 0

    async def get_root_ou(self) -> dict[str, Any]:
        return {"id": ROOT, "parent_id": None, "kind": "root"}

    async def create_domain_subtree(
        self, parent_id: str, name: str, display_name: str | None = None,
    ) -> dict[str, str]:
        self._seq += 1
        ids = {
            "domain_ou_id": f"ou-domain-{self._seq}",
            "builtin_ou_id": f"ou-builtin-{self._seq}",
            "users_bin_id": f"ou-users-{self._seq}",
            "groups_bin_id": f"ou-groups-{self._seq}",
        }
        self.subtrees.append(ids)
        return ids

    async def delete_ou(self, ou_id: str) -> None:
        self.deleted.append(ou_id)

    async def insert_group_ou(self, group_id: str, ou_id: str) -> None:
        self.group_bins.append((group_id, ou_id))


class FakeAuthRepo:
    def __init__(self) -> None:
        self.domains: dict[str, dict[str, Any]] = {}
        self.groups: dict[str, dict[str, Any]] = {}
        self.group_roles: list[tuple[str, str]] = []
        self.user_roles: list[tuple[str, str]] = []
        self.members: list[tuple[str, str]] = []
        self._fail_domain: Exception | None = None

    def fail_domain_with(self, exc: Exception) -> None:
        self._fail_domain = exc

    async def get_domain_by_name(self, name: str) -> dict[str, Any] | None:
        return self.domains.get(name)

    async def create_domain(
        self, name: str, display_name: str | None = None, kind: str = "user",
        owner_id: str | None = None, root_ou_id: str | None = None,
    ) -> dict[str, Any]:
        if self._fail_domain is not None:
            raise self._fail_domain
        row = {
            "id": "domain-acme", "name": name, "display_name": display_name,
            "kind": kind, "status": "active", "owner_id": owner_id,
            "root_ou_id": root_ou_id,
        }
        self.domains[name] = row
        return row

    async def create_group(
        self, name: str, description: str | None = None,
        domain_id: str | None = None, scope: str | None = None,
    ) -> dict[str, Any]:
        row = {"id": f"group-{name}", "name": name, "domain_id": domain_id}
        self.groups[name] = row
        return row

    async def find_role_by_name(self, name: str) -> dict[str, Any] | None:
        return {"id": f"role-{name}"}

    async def assign_role_to_group(self, group_id: str, role_id: str) -> None:
        self.group_roles.append((group_id, role_id))

    async def assign_role_to_user(self, user_id: str, role_id: str) -> None:
        self.user_roles.append((user_id, role_id))

    async def find_group_by_name(self, name: str) -> dict[str, Any] | None:
        return self.groups.get(name)

    async def add_user_to_group(self, user_id: str, group_id: str) -> None:
        self.members.append((user_id, group_id))


def _tenant(repo: FakeAuthRepo, folders: FakeFolders) -> Tenant:
    domain = Domain(auth_repo=repo)
    domain.bind_folders(folders)
    return domain.tenant()


@pytest.mark.asyncio
async def test_create_builds_subtree_domain_and_seed() -> None:
    repo, folders = FakeAuthRepo(), FakeFolders()
    tenant = await _tenant(repo, folders).create("Acme", CREATOR, display_name="Acme Corp")

    assert tenant.uuid == "domain-acme"
    # поддерево создано под Root, домен ссылается на его корень
    assert folders.subtrees[0]["domain_ou_id"] == tenant._data["root_ou_id"]
    # встроенные группы — в groups_bin поддерева, scope-поля домена заполнены
    assert {name for name in repo.groups} == {"acme-admins", "acme-users"}
    assert {gid for gid, _ in folders.group_bins} == {
        "group-acme-admins", "group-acme-users",
    }
    assert all(bin_id == folders.subtrees[0]["groups_bin_id"] for _, bin_id in folders.group_bins)
    # creator: domain_owner + member admins
    assert ("user-creator", "role-domain_owner") in repo.user_roles
    assert (CREATOR, "group-acme-admins") in repo.members


@pytest.mark.asyncio
async def test_create_duplicate_name_short_circuits() -> None:
    repo, folders = FakeAuthRepo(), FakeFolders()
    repo.domains["acme"] = {"id": "domain-acme"}
    with pytest.raises(DomainError) as exc:
        await _tenant(repo, folders).create("Acme", CREATOR)
    assert exc.value.code == "DUPLICATE_NAME"
    # pre-check до первой записи: ни OU, ни групп
    assert folders.subtrees == []
    assert repo.groups == {}


@pytest.mark.asyncio
async def test_create_drops_subtree_when_domain_insert_fails() -> None:
    repo, folders = FakeAuthRepo(), FakeFolders()
    repo.fail_domain_with(RuntimeError("connection lost"))
    with pytest.raises(RuntimeError, match="connection lost"):
        await _tenant(repo, folders).create("Acme", CREATOR)
    subtree = folders.subtrees[0]
    # компенсация: листья первыми, все четыре узла
    assert folders.deleted == [
        subtree["users_bin_id"], subtree["groups_bin_id"],
        subtree["builtin_ou_id"], subtree["domain_ou_id"],
    ]
    assert repo.groups == {}
