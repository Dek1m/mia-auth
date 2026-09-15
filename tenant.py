"""Tenant — домен-тенант (auth.domains), Aggregate Root scope-модели.

Имя Domain занято DDD-фасадом auth/domain.py — сущность домена
называется Tenant. Паттерн lazy-фасада как у User/Group/Role;
create() — единственная точка создания агрегата (домен + встроенные
группы + владелец), мутации дочерних объектов — через корень.
"""
from __future__ import annotations

from typing import Any

from .errors import DomainError, is_duplicate, require_name

__all__ = ["Tenant"]

_IDENTITY_KINDS = frozenset({"local", "basic", "oidc", "ad"})

# Встроенные группы нового домена: (суффикс имени, роль на группу).
# Глобальная уникальность groups.name — префиксом слагом домена.
_BUILTIN_GROUP_ROLES = (("admins", "domain_admin"), ("users", "domain_member"))


class Tenant:
    """Каталог домена: встроенные группы, владелец, identity_kind, статус."""

    __slots__ = ("_uuid", "_repo", "_domain", "_data", "_loaded")

    def __init__(
        self,
        uuid: str | None,
        repo: Any,
        domain: Any | None = None,
        data: dict[str, Any] | None = None,
    ) -> None:
        """Args:
            uuid: UUID auth.domains; None — несохранённый Tenant для create().
            repo: AuthRepository.
            domain: Domain-фасад (для связки с OU-деревом).
        """
        self._uuid = uuid
        self._repo = repo
        self._domain = domain
        self._data: dict[str, Any] | None = data
        self._loaded = data is not None

    async def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        if self._repo is None or not self._uuid:
            raise DomainError("Auth not initialized", "VALIDATION")
        row = await self._repo.get_domain(self._uuid)
        if not row:
            raise DomainError("Tenant not found", "NOT_FOUND", entity="Tenant")
        self._data = row
        self._loaded = True

    def _require_data(self) -> dict[str, Any]:
        if not self._loaded or self._data is None:
            raise RuntimeError(f"Tenant {self._uuid!r} is not loaded")
        return self._data

    def _require_repo(self) -> Any:
        if self._repo is None:
            raise DomainError("Auth not initialized", "VALIDATION")
        return self._repo

    @property
    def uuid(self) -> str:
        return self._uuid or ""

    async def name(self) -> str:
        await self._ensure_loaded()
        return str(self._require_data().get("name") or "")

    async def display_name(self) -> str | None:
        await self._ensure_loaded()
        value = self._require_data().get("display_name")
        return None if value is None else str(value)

    async def kind(self) -> str:
        await self._ensure_loaded()
        return str(self._require_data().get("kind") or "user")

    async def status(self) -> str:
        await self._ensure_loaded()
        return str(self._require_data().get("status") or "active")

    async def identity_kind(self) -> str:
        await self._ensure_loaded()
        return str(self._require_data().get("identity_kind") or "local")

    async def root_ou_id(self) -> str | None:
        await self._ensure_loaded()
        value = self._require_data().get("root_ou_id")
        return None if value is None else str(value)

    # ── Создание агрегата ────────────────────────────────

    async def create(
        self, name: str, creator_id: str, display_name: str | None = None,
    ) -> Tenant:
        """Создать домен kind='user': OU-поддерево + строка + группы + владелец.

        Порядок: subtree (одна транзакция) → create_domain(root_ou_id) →
        сид групп в groups_bin поддерева → creator → domain_owner.

        Атомарность: auto-commit вне database.transaction() делает
        cross-репозиторий rollback невозможным — если create_domain упал
        после subtree, поддерево сносится компенсирующим DELETE (best-effort,
        лог). Идемпотентность повтором не гарантируется — дубль имени
        отсекается pre-check'ом до первой записи.
        """
        repo = self._require_repo()
        if self._domain is None:
            raise DomainError("Folder tree is not bound", "VALIDATION")
        slug = require_name(name).lower()
        label = require_name(display_name) if display_name else require_name(name)
        if await repo.get_domain_by_name(slug):
            raise DomainError(
                f"Tenant {slug!r} exists", "DUPLICATE_NAME", human="Domain already exists",
            )
        folders = self._domain._folders()
        root = await folders.get_root_ou()
        if root is None:
            raise DomainError(
                "Root OU is missing", "NOT_FOUND", human="Directory root is not initialized",
            )
        subtree = await folders.create_domain_subtree(
            str(root["id"]), slug, label,
        )
        try:
            row = await repo.create_domain(
                name=slug,
                display_name=label,
                kind="user",
                owner_id=creator_id,
                root_ou_id=subtree["domain_ou_id"],
            )
        except Exception as exc:
            await self._drop_subtree(subtree)
            if is_duplicate(exc):
                raise DomainError(
                    f"Tenant {slug!r} exists", "DUPLICATE_NAME", human="Domain already exists",
                ) from exc
            raise
        self._uuid = str(row["id"])
        self._data = row
        self._loaded = True
        await self._seed_builtin_groups(creator_id, subtree["groups_bin_id"])
        return self

    async def _drop_subtree(self, subtree: dict[str, str]) -> None:
        """Компенсация: листья первыми. Best-effort — падение глотаем в лог."""
        try:
            folders = self._domain._folders()
            for key in ("users_bin_id", "groups_bin_id", "builtin_ou_id", "domain_ou_id"):
                await folders.delete_ou(subtree[key])
        except Exception:
            # Остаток поддерева чинит оператор: домен не создан, сид не шёл
            pass

    async def _seed_builtin_groups(self, creator_id: str, groups_bin_id: str) -> None:
        """Встроенные группы домена (в groups_bin поддерева) + роли + владелец."""
        repo = self._require_repo()
        folders = self._domain._folders()
        for suffix, role_name in _BUILTIN_GROUP_ROLES:
            group = await repo.create_group(
                f"{await self.name()}-{suffix}",
                description=f"Builtin group of domain {await self.name()!r}",
                domain_id=self.uuid,
            )
            await folders.insert_group_ou(str(group["id"]), groups_bin_id)
            role = await repo.find_role_by_name(role_name)
            if role:
                await repo.assign_role_to_group(str(group["id"]), str(role["id"]))
        owner_role = await repo.find_role_by_name("domain_owner")
        if owner_role:
            await repo.assign_role_to_user(creator_id, str(owner_role["id"]))
        admins = await repo.find_group_by_name(f"{await self.name()}-admins")
        if admins:
            await repo.add_user_to_group(creator_id, str(admins["id"]))

    # ── Жизненный цикл ───────────────────────────────────

    async def suspend(self) -> None:
        """Приостановить домен: вход identity_kind и федерация блокируются."""
        await self._ensure_loaded()
        await self._require_repo().set_domain_status(self.uuid, "suspended")
        self._data = dict(self._data or {}, status="suspended")

    async def resume(self) -> None:
        """Вернуть домен в строй."""
        await self._ensure_loaded()
        await self._require_repo().set_domain_status(self.uuid, "active")
        self._data = dict(self._data or {}, status="active")

    async def update(
        self,
        name: str | None = None,
        display_name: str | None = None,
    ) -> None:
        """Переименовать слаг/display_name. Builtin — FORBIDDEN."""
        await self._ensure_loaded()
        repo = self._require_repo()
        if self._require_data().get("kind") == "builtin":
            raise DomainError("Cannot rename a builtin domain", "FORBIDDEN")
        patch: dict[str, Any] = {}
        if name is not None:
            slug = require_name(name).lower()
            clash = await repo.get_domain_by_name(slug)
            if clash and str(clash["id"]) != self.uuid:
                raise DomainError(
                    f"Tenant {slug!r} exists", "DUPLICATE_NAME", human="Domain already exists",
                )
            patch["name"] = slug
        if display_name is not None:
            patch["display_name"] = require_name(display_name)
        if not patch:
            return
        updated = await repo.update_domain(self.uuid, patch)
        if updated:
            self._data = updated

    async def set_identity_kind(
        self,
        identity_kind: str,
        auth_config: dict[str, Any] | None = None,
    ) -> None:
        """Сменить способ входа домена. Секреты — вне auth_config."""
        if identity_kind not in _IDENTITY_KINDS:
            raise DomainError(
                f"identity_kind must be one of {sorted(_IDENTITY_KINDS)}",
                "VALIDATION",
            )
        await self._ensure_loaded()
        patch: dict[str, Any] = {"identity_kind": identity_kind}
        if auth_config is not None:
            patch["auth_config"] = auth_config
        updated = await self._require_repo().update_domain(self.uuid, patch)
        if updated:
            self._data = updated

    def __repr__(self) -> str:
        return f"Tenant(uuid={self._uuid!r})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Tenant):
            return NotImplemented
        return self._uuid == other._uuid

    def __hash__(self) -> int:
        return hash(self._uuid)
