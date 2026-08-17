"""Тесты AuthSchemaRegistry — валидация, идемпотентность, wildcard, roles.

КЛЮЧЕВОЙ БАГ: AUTH_CORE_SCHEMA НЕ МОЖЕТ быть зарегистрирован через Registry,
поскольку permissions (users:create, groups:create, ...) не начинаются с "auth:".
Это делает Registry бесполезным для собственного модуля auth.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, call

import pytest

from modules.auth.schema_registry import AuthSchemaRegistry, _RESERVED_ROLES
from modules.auth.schema import AUTH_CORE_SCHEMA


# ── Мок-пул для Registry ────────────────────────────────


class RegistryMockPool:
    """Мок pool для AuthSchemaRegistry: хранит permissions и roles в памяти."""

    def __init__(self) -> None:
        self._permissions: dict[str, dict] = {}  # name → {id, source_module, description, is_builtin}
        self._roles: dict[str, dict] = {}  # name → {id, source_module, description, is_builtin}
        self._role_permissions: dict[str, list[str]] = {}  # role_name → [perm_names]
        self._seq = 0

    async def fetchrow(self, query: str, *args):
        if "SELECT source_module FROM auth.permissions" in query:
            name = args[0]
            p = self._permissions.get(name)
            if p:
                return {"source_module": p["source_module"]}
            return None
        if "SELECT source_module FROM auth.roles" in query:
            name = args[0]
            r = self._roles.get(name)
            if r:
                return {"source_module": r["source_module"]}
            return None
        if "SELECT id FROM auth.roles" in query:
            name = args[0]
            r = self._roles.get(name)
            if r:
                return {"id": r["id"]}
            return None
        if "SELECT id FROM auth.permissions" in query:
            name = args[0]
            p = self._permissions.get(name)
            if p:
                return {"id": p["id"]}
            return None
        return None

    async def execute(self, query: str, *args) -> str:
        if "INSERT INTO auth.permissions" in query and "ON CONFLICT" in query:
            name = args[0]
            description = args[1]
            is_builtin = args[2]
            source_module = args[3]
            if name in self._permissions:
                # UPDATE
                self._permissions[name]["description"] = description
                self._permissions[name]["is_builtin"] = is_builtin
                self._permissions[name]["source_module"] = source_module
            else:
                # INSERT
                self._seq += 1
                self._permissions[name] = {
                    "id": str(self._seq),
                    "description": description,
                    "is_builtin": is_builtin,
                    "source_module": source_module,
                }
        elif "INSERT INTO auth.roles" in query and "ON CONFLICT" in query:
            name = args[0]
            description = args[1]
            is_builtin = args[2]
            source_module = args[3]
            if name in self._roles:
                self._roles[name]["description"] = description
                self._roles[name]["is_builtin"] = is_builtin
                self._roles[name]["source_module"] = source_module
            else:
                self._seq += 1
                self._roles[name] = {
                    "id": str(self._seq),
                    "description": description,
                    "is_builtin": is_builtin,
                    "source_module": source_module,
                }
        elif "DELETE FROM auth.role_permissions" in query:
            role_id = args[0]
            # Находим role_name по id
            for rn, rv in self._roles.items():
                if rv["id"] == role_id:
                    self._role_permissions[rn] = []
                    break
        elif "INSERT INTO auth.role_permissions" in query and "ON CONFLICT" in query:
            role_id = args[0]
            perm_id = args[1]
            # Находим role_name и perm_name
            role_name = next((rn for rn, rv in self._roles.items() if rv["id"] == role_id), None)
            perm_name = next((pn for pn, pv in self._permissions.items() if pv["id"] == perm_id), None)
            if role_name and perm_name:
                if role_name not in self._role_permissions:
                    self._role_permissions[role_name] = []
                if perm_name not in self._role_permissions[role_name]:
                    self._role_permissions[role_name].append(perm_name)
        return "OK"

    async def fetch(self, query: str, *args) -> list[dict]:
        """Аналог DatabaseProvider.fetch — возвращает список строк."""
        if "SELECT source_module FROM auth.permissions" in query:
            name = args[0]
            p = self._permissions.get(name)
            return [{"source_module": p["source_module"]}] if p else []
        if "SELECT source_module FROM auth.roles" in query:
            name = args[0]
            r = self._roles.get(name)
            return [{"source_module": r["source_module"]}] if r else []
        if "SELECT id FROM auth.roles" in query:
            name = args[0]
            r = self._roles.get(name)
            return [{"id": r["id"]}] if r else []
        if "SELECT id FROM auth.permissions" in query:
            name = args[0]
            p = self._permissions.get(name)
            return [{"id": p["id"]}] if p else []
        return []


# ── Фикстуры ────────────────────────────────────────────


@pytest.fixture
def pool() -> RegistryMockPool:
    return RegistryMockPool()


@pytest.fixture
def registry(pool: RegistryMockPool) -> AuthSchemaRegistry:
    return AuthSchemaRegistry(pool)


# ── BUG: AUTH_CORE_SCHEMA не может быть зарегистрирован ──


@pytest.mark.asyncio
async def test_bug_auth_core_schema_cannot_be_registered(
    registry: AuthSchemaRegistry, pool: RegistryMockPool
):
    """FIXED: AUTH_CORE_SCHEMA может быть зарегистрирован через Registry.
    
    Auth — владелец системы прав, ему разрешены любые ресурсы.
    Namespace-проверка пропускается для module_name == "auth".
    """
    result = await registry.register("auth", AUTH_CORE_SCHEMA, is_builtin=True)
    assert len(result["created_permissions"]) == 21
    assert len(result["created_roles"]) == 4
    assert "users:create" in result["created_permissions"]
    assert "system_admin" in result["created_roles"]


# ── Валидация namespace (для обычных модулей) ────────────


@pytest.mark.asyncio
async def test_namespace_mismatch_raises_error(
    registry: AuthSchemaRegistry, pool: RegistryMockPool
):
    """Permission 'users:create' от модуля 'workspace' → ошибка."""
    schema = {
        "permissions": [
            {"name": "users:create", "description": "Create users"},
        ],
    }
    with pytest.raises(ValueError, match="must start with 'workspace:'"):
        await registry.register("workspace", schema)


@pytest.mark.asyncio
async def test_correct_namespace_passes(
    registry: AuthSchemaRegistry, pool: RegistryMockPool
):
    """Permission 'workspace:create_users' от модуля 'workspace' → ОК."""
    schema = {
        "permissions": [
            {"name": "workspace:create_users", "description": "Create users in workspace"},
        ],
    }
    result = await registry.register("workspace", schema)
    assert "workspace:create_users" in result["created_permissions"]


# ── Идемпотентность (с корректными схемами) ─────────────


@pytest.mark.asyncio
async def test_idempotent_registration(
    registry: AuthSchemaRegistry, pool: RegistryMockPool
):
    """Двойная регистрация — вторая идём в updated, не в created."""
    schema = {
        "permissions": [
            {"name": "ws:read", "description": "Read"},
            {"name": "ws:write", "description": "Write"},
        ],
        "roles": [
            {
                "name": "editor",
                "description": "Editor",
                "permissions": ["ws:read", "ws:write"],
            },
        ],
    }
    result1 = await registry.register("ws", schema)
    result2 = await registry.register("ws", schema)

    # Первая регистрация — created
    assert len(result1["created_permissions"]) == 2
    assert len(result1["created_roles"]) == 1

    # Вторая регистрация — updated
    assert len(result2["created_permissions"]) == 0
    assert len(result2["updated_permissions"]) == 2
    assert len(result2["created_roles"]) == 0
    assert len(result2["updated_roles"]) == 1


@pytest.mark.asyncio
async def test_idempotent_permissions_not_duplicated(
    registry: AuthSchemaRegistry, pool: RegistryMockPool
):
    """Идемпотентная регистрация не дублирует permissions."""
    schema = {
        "permissions": [
            {"name": "ws:read", "description": "Read"},
        ],
    }
    await registry.register("ws", schema)
    count_first = len(pool._permissions)

    await registry.register("ws", schema)
    assert len(pool._permissions) == count_first


@pytest.mark.asyncio
async def test_idempotent_roles_not_duplicated(
    registry: AuthSchemaRegistry, pool: RegistryMockPool
):
    """Идемпотентная регистрация не дублирует roles."""
    schema = {
        "permissions": [
            {"name": "ws:read", "description": "Read"},
        ],
        "roles": [
            {
                "name": "reader",
                "description": "Reader",
                "permissions": ["ws:read"],
            },
        ],
    }
    await registry.register("ws", schema)
    count_first = len(pool._roles)

    await registry.register("ws", schema)
    assert len(pool._roles) == count_first


# ── Дубликат permission между модулями ───────────────────


@pytest.mark.asyncio
async def test_duplicate_permission_across_modules_updates(
    registry: AuthSchemaRegistry, pool: RegistryMockPool
):
    """ON CONFLICT: повторная регистрация同一permission обновляет source_module."""
    schema1 = {"permissions": [{"name": "module_a:perm", "description": "v1"}]}
    await registry.register("module_a", schema1)

    schema2 = {"permissions": [{"name": "module_a:perm", "description": "v2"}]}
    result = await registry.register("module_a", schema2)

    assert "module_a:perm" in result["updated_permissions"]
    assert pool._permissions["module_a:perm"]["description"] == "v2"


# ── system_admin только для auth ─────────────────────────


@pytest.mark.asyncio
async def test_system_admin_from_non_auth_module_raises(
    registry: AuthSchemaRegistry, pool: RegistryMockPool
):
    """Роль system_admin от модуля ≠ auth → ValueError."""
    schema = {
        "permissions": [
            {"name": "workspace:admin", "description": "Admin"},
        ],
        "roles": [
            {
                "name": "system_admin",
                "description": "Full admin",
                "permissions": ["workspace:admin"],
            },
        ],
    }
    with pytest.raises(ValueError, match="reserved for the 'auth' module only"):
        await registry.register("workspace", schema)


@pytest.mark.asyncio
async def test_non_reserved_role_from_any_module_passes(
    registry: AuthSchemaRegistry, pool: RegistryMockPool
):
    """Не-зарезервированная роль доступна любому модулю."""
    schema = {
        "permissions": [
            {"name": "workspace:read", "description": "Read"},
        ],
        "roles": [
            {
                "name": "editor",
                "description": "Editor",
                "permissions": ["workspace:read"],
            },
        ],
    }
    result = await registry.register("workspace", schema)
    assert "editor" in result["created_roles"]


# ── Permission в роли не существует в схеме ──────────────


@pytest.mark.asyncio
async def test_role_permission_not_in_schema_raises(
    registry: AuthSchemaRegistry, pool: RegistryMockPool
):
    """Permission в роли которого нет в схеме модуля → ValueError."""
    schema = {
        "permissions": [
            {"name": "workspace:read", "description": "Read"},
        ],
        "roles": [
            {
                "name": "reader",
                "description": "Reader role",
                "permissions": ["workspace:read", "workspace:write"],  # write не определена
            },
        ],
    }
    with pytest.raises(ValueError, match="does not exist in module 'workspace' schema"):
        await registry.register("workspace", schema)


# ── Отсутствие description → ошибка ─────────────────────


@pytest.mark.asyncio
async def test_permission_without_description_raises(
    registry: AuthSchemaRegistry, pool: RegistryMockPool
):
    """Permission без description → ValueError."""
    schema = {
        "permissions": [
            {"name": "workspace:read"},  # нет description
        ],
    }
    with pytest.raises(ValueError, match="requires a description"):
        await registry.register("workspace", schema)


@pytest.mark.asyncio
async def test_role_without_description_raises(
    registry: AuthSchemaRegistry, pool: RegistryMockPool
):
    """Роль без description → ValueError."""
    schema = {
        "permissions": [
            {"name": "workspace:read", "description": "Read"},
        ],
        "roles": [
            {
                "name": "reader",
                "permissions": ["workspace:read"],
                # нет description
            },
        ],
    }
    with pytest.raises(ValueError, match="requires a description"):
        await registry.register("workspace", schema)


# ── Wildcard ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_wildcard_star_bypasses_permission_check(
    registry: AuthSchemaRegistry, pool: RegistryMockPool
):
    """Wildcard '*:*' пропускает проверку permissions в роли."""
    schema = {
        "permissions": [
            {"name": "workspace:admin", "description": "Admin"},
        ],
        "roles": [
            {
                "name": "superadmin",
                "description": "Super admin",
                "permissions": ["*:*"],  # Wildcard — пропускает проверку
            },
        ],
    }
    # *:* не проверяется через schema_perm_names — просто пропускается
    result = await registry.register("workspace", schema)
    assert "superadmin" in result["created_roles"]


@pytest.mark.asyncio
async def test_wildcard_resource_star_valid(
    registry: AuthSchemaRegistry, pool: RegistryMockPool
):
    """Wildcard 'resource:*' — ОК если хотя бы одна permission ресурса существует.
    
    Формат wildcard: "resource:*" — action = "*" (ровно один символ "*").
    """
    schema = {
        "permissions": [
            {"name": "workspace:users_create", "description": "Create users"},
            {"name": "workspace:users_read", "description": "Read users"},
        ],
        "roles": [
            {
                "name": "user_manager",
                "description": "User manager",
                "permissions": ["workspace:*"],  # Все действия workspace
            },
        ],
    }
    result = await registry.register("workspace", schema)
    assert "user_manager" in result["created_roles"]


@pytest.mark.asyncio
async def test_wildcard_resource_star_no_permissions_found(
    registry: AuthSchemaRegistry, pool: RegistryMockPool
):
    """Wildcard 'resource:*' — ОШИБКА если нет ни одной permission ресурса.
    
    Permission в схеме должны начинаться с module_name:"workspace:".
    Workspace:* требует хотя бы одной permission с префиксом "workspace:".
    """
    schema = {
        "permissions": [
            {"name": "workspace:other_action", "description": "Other action"},
        ],
        "roles": [
            {
                "name": "reader",
                "description": "Reader",
                "permissions": ["workspace:*"],  # workspace:* — ОК, есть workspace:other_action
            },
        ],
    }
    # workspace:* — проверяем чтохотя бы одна permission workspace:* существует
    # workspace:other_action → any(p.startswith("workspace:") for p in schema_perm_names) → True
    # Поэтому ошибки НЕ будет — wildcard проходит
    
    # Чтобы протестировать ошибку, нужно чтобы НЕ БЫЛО ни одной workspace: permission
    # Но тогда roles permissions тоже не пройдут... 
    
    # Протестируем через отдельный сценарий: role ссылается на wildcard
    # несуществующего ресурса
    schema2 = {
        "permissions": [
            {"name": "workspace:read", "description": "Read"},
        ],
        "roles": [
            {
                "name": "reader",
                "description": "Reader",
                "permissions": ["nonexistent:*"],  # nonexistent permissions нет
            },
        ],
    }
    with pytest.raises(ValueError, match="no permissions found for resource"):
        await registry.register("workspace", schema2)


@pytest.mark.asyncio
async def test_wildcard_non_star_action_treated_as_literal(
    registry: AuthSchemaRegistry, pool: RegistryMockPool
):
    """Действие типа 'users_*' (не ровно "*") treated as literal permission name.
    
    Код проверяет action == "*", поэтому "workspace:users_*" — это НЕ wildcard,
    а литеральное имя permission, которое должно существовать в схеме.
    """
    schema = {
        "permissions": [
            {"name": "workspace:users_create", "description": "Create"},
        ],
        "roles": [
            {
                "name": "user_admin",
                "description": "User admin",
                "permissions": ["workspace:users_*"],  # Не wildcard!
            },
        ],
    }
    # "workspace:users_*" не существует в schema_perm_names → ошибка
    with pytest.raises(ValueError, match="does not exist in module 'workspace' schema"):
        await registry.register("workspace", schema)


# ── Пересборка role_permissions ──────────────────────────


@pytest.mark.asyncio
async def test_role_permissions_rebuilt_on_reregistration(
    registry: AuthSchemaRegistry, pool: RegistryMockPool
):
    """При повторной регистрации роли role_permissions пересобирается."""
    schema1 = {
        "permissions": [
            {"name": "ws:read", "description": "Read"},
            {"name": "ws:write", "description": "Write"},
        ],
        "roles": [
            {
                "name": "editor",
                "description": "Editor",
                "permissions": ["ws:read", "ws:write"],
            },
        ],
    }
    await registry.register("ws", schema1)
    assert pool._role_permissions["editor"] == ["ws:read", "ws:write"]

    # Перерегистрация с другим набором permissions
    schema2 = {
        "permissions": [
            {"name": "ws:read", "description": "Read"},
            {"name": "ws:write", "description": "Write"},
            {"name": "ws:delete", "description": "Delete"},
        ],
        "roles": [
            {
                "name": "editor",
                "description": "Editor v2",
                "permissions": ["ws:read"],  # Только read
            },
        ],
    }
    await registry.register("ws", schema2)
    assert pool._role_permissions["editor"] == ["ws:read"]


# ── is_builtin ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_is_builtin_true(
    registry: AuthSchemaRegistry, pool: RegistryMockPool
):
    """is_builtin=True проставляется корректно."""
    schema = {
        "permissions": [
            {"name": "core:read", "description": "Read"},
        ],
        "roles": [
            {
                "name": "reader",
                "description": "Reader",
                "permissions": ["core:read"],
            },
        ],
    }
    await registry.register("core", schema, is_builtin=True)

    assert pool._permissions["core:read"]["is_builtin"] is True
    assert pool._roles["reader"]["is_builtin"] is True


@pytest.mark.asyncio
async def test_is_builtin_false_for_custom_module(
    registry: AuthSchemaRegistry, pool: RegistryMockPool
):
    """is_builtin=False для не auth модулей."""
    schema = {
        "permissions": [
            {"name": "workspace:read", "description": "Read"},
        ],
    }
    await registry.register("workspace", schema)
    assert pool._permissions["workspace:read"]["is_builtin"] is False


# ── Return value: created/updated ────────────────────────


@pytest.mark.asyncio
async def test_return_value_first_registration(
    registry: AuthSchemaRegistry, pool: RegistryMockPool
):
    """Первая регистрация: все permissions/roles в created_*."""
    schema = {
        "permissions": [
            {"name": "ws:read", "description": "Read"},
            {"name": "ws:write", "description": "Write"},
        ],
        "roles": [
            {
                "name": "editor",
                "description": "Editor",
                "permissions": ["ws:read", "ws:write"],
            },
        ],
    }
    result = await registry.register("ws", schema)

    assert sorted(result["created_permissions"]) == ["ws:read", "ws:write"]
    assert result["updated_permissions"] == []
    assert result["created_roles"] == ["editor"]
    assert result["updated_roles"] == []


@pytest.mark.asyncio
async def test_return_value_second_registration(
    registry: AuthSchemaRegistry, pool: RegistryMockPool
):
    """Вторая регистрация: все в updated_*."""
    schema = {
        "permissions": [
            {"name": "ws:read", "description": "Read v2"},
        ],
        "roles": [
            {
                "name": "editor",
                "description": "Editor v2",
                "permissions": ["ws:read"],
            },
        ],
    }
    await registry.register("ws", schema)
    result = await registry.register("ws", schema)

    assert result["created_permissions"] == []
    assert result["updated_permissions"] == ["ws:read"]
    assert result["created_roles"] == []
    assert result["updated_roles"] == ["editor"]


# ── Повторная регистрация с изменёнными описаниями ──────


@pytest.mark.asyncio
async def test_reregistration_updates_description(
    registry: AuthSchemaRegistry, pool: RegistryMockPool
):
    """Повторная регистрация с новым description → UPDATE."""
    schema1 = {
        "permissions": [{"name": "ws:read", "description": "Original"}],
    }
    await registry.register("ws", schema1)

    schema2 = {
        "permissions": [{"name": "ws:read", "description": "Updated"}],
    }
    await registry.register("ws", schema2)

    assert pool._permissions["ws:read"]["description"] == "Updated"


# ── Invalid permission format ────────────────────────────


@pytest.mark.asyncio
async def test_invalid_permission_format_in_role(
    registry: AuthSchemaRegistry, pool: RegistryMockPool
):
    """Permission без двоеточия в role → ValueError."""
    schema = {
        "permissions": [
            {"name": "workspace:read", "description": "Read"},
        ],
        "roles": [
            {
                "name": "reader",
                "description": "Reader",
                "permissions": ["invalidformat"],  # нет ":"
            },
        ],
    }
    with pytest.raises(ValueError, match="Expected format: 'resource:action'"):
        await registry.register("workspace", schema)


# ── Reserved roles list ─────────────────────────────────


def test_reserved_roles_contains_system_admin():
    """_RESERVED_ROLES содержит system_admin."""
    assert "system_admin" in _RESERVED_ROLES


# ── BUG: source_module overwrite без проверки ────────────


@pytest.mark.asyncio
async def test_bug_cross_module_role_overwrite(
    registry: AuthSchemaRegistry, pool: RegistryMockPool
):
    """FIXED: Модуль НЕ может перезаписать роль другого модуля.
    
    При конфликте имён проверяется source_module — если роль/пермишен
    принадлежит другому модулю → ValueError.
    """
    schema_a = {
        "permissions": [{"name": "module_a:read", "description": "Read"}],
        "roles": [{
            "name": "editor",
            "description": "Module A editor",
            "permissions": ["module_a:read"],
        }],
    }
    await registry.register("module_a", schema_a)
    assert pool._roles["editor"]["source_module"] == "module_a"

    # Module B пытается перезаписать роль с тем же именем
    schema_b = {
        "permissions": [{"name": "module_b:write", "description": "Write"}],
        "roles": [{
            "name": "editor",
            "description": "Module B editor",
            "permissions": ["module_b:write"],
        }],
    }
    with pytest.raises(ValueError, match="already belongs to module 'module_a'"):
        await registry.register("module_b", schema_b)


@pytest.mark.asyncio
async def test_same_module_can_update_own_role(
    registry: AuthSchemaRegistry, pool: RegistryMockPool
):
    """Тот же модуль может обновить свою роль."""
    schema1 = {
        "permissions": [{"name": "ws:read", "description": "Read"}],
        "roles": [{
            "name": "editor",
            "description": "Editor v1",
            "permissions": ["ws:read"],
        }],
    }
    await registry.register("ws", schema1)

    schema2 = {
        "permissions": [{"name": "ws:read", "description": "Read"}],
        "roles": [{
            "name": "editor",
            "description": "Editor v2",
            "permissions": ["ws:read"],
        }],
    }
    result = await registry.register("ws", schema2)
    assert "editor" in result["updated_roles"]
    assert pool._roles["editor"]["description"] == "Editor v2"


@pytest.mark.asyncio
async def test_cross_module_permission_overwrite_blocked(
    registry: AuthSchemaRegistry, pool: RegistryMockPool
):
    """Модуль НЕ может перезаписать permission другого модуля."""
    schema_a = {"permissions": [{"name": "module_a:read", "description": "Read"}]}
    await registry.register("module_a", schema_a)

    # module_a пытается перерегистрировать свой permission с тем же именем — ОК
    schema_a2 = {"permissions": [{"name": "module_a:read", "description": "Read v2"}]}
    result = await registry.register("module_a", schema_a2)
    assert "module_a:read" in result["updated_permissions"]

    # module_a не может зарегистрировать permission с именем module_b:write
    # — namespace check блокирует (не auth)
    schema_a3 = {"permissions": [{"name": "module_b:write", "description": "Write"}]}
    with pytest.raises(ValueError, match="must start with 'module_a:'"):
        await registry.register("module_a", schema_a3)
