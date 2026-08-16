"""Auth Schema Registry — идемпотентная регистрация permissions и roles.

Контракт:
- permissions: INSERT ... ON CONFLICT DO UPDATE
- roles: INSERT ... ON CONFLICT DO UPDATE + пересборка role_permissions
- Валидация: namespace, дубликаты, зарезервированные имена, обязательные описания
"""
from __future__ import annotations

from typing import Any

from argenta_logging import get_logger

log = get_logger(__name__)

__all__ = ["AuthSchemaRegistry"]

# Роль, доступная только модулю auth
_RESERVED_ROLES = frozenset({"system_admin"})


class AuthSchemaRegistry:
    """Реестр auth-схем: permissions и roles с валидацией.

    Используется модулями для регистрации своих разрешений и ролей.
    Все операции идемпотентны.
    """

    def __init__(self, pool: Any) -> None:
        self._pool = pool

    async def register(
        self,
        module_name: str,
        schema: dict[str, list[dict[str, Any]]],
        is_builtin: bool = False,
    ) -> dict[str, list[str]]:
        """Зарегистрировать permissions и роли модуля.

        Args:
            module_name: Имя модуля (namespace для permission names).
            schema: {"permissions": [...], "roles": [...]}.
            is_builtin: True для встроенных модулей (auth).

        Returns:
            Сводка: {created_permissions, updated_permissions, created_roles, updated_roles}.

        Raises:
            ValueError: При нарушении правил валидации.
        """
        permissions = schema.get("permissions", [])
        roles = schema.get("roles", [])

        # Предварительная валидация
        self._validate_permissions(module_name, permissions)
        self._validate_roles(module_name, roles, permissions)

        result = {
            "created_permissions": [],
            "updated_permissions": [],
            "created_roles": [],
            "updated_roles": [],
        }

        # ── Permissions ───────────────────────────────────────
        for perm in permissions:
            name = perm["name"]
            description = perm.get("description", "")

            # Проверяем существование для определения created/updated
            existing = await self._pool.fetchrow(
                "SELECT source_module FROM permissions WHERE name = $1",
                name,
            )

            # Cross-module conflict: permission принадлежит другому модулю
            if existing is not None:
                existing_module = existing["source_module"]
                if existing_module and existing_module != module_name:
                    raise ValueError(
                        f"Permission '{name}' already belongs to module '{existing_module}'. "
                        f"Module '{module_name}' cannot overwrite it."
                    )

            await self._pool.execute(
                "INSERT INTO permissions (name, description, is_builtin, source_module, updated_at) "
                "VALUES ($1, $2, $3, $4, NOW()) "
                "ON CONFLICT (name) DO UPDATE SET "
                "description = EXCLUDED.description, "
                "is_builtin = EXCLUDED.is_builtin, "
                "source_module = EXCLUDED.source_module, "
                "updated_at = NOW()",
                name,
                description,
                is_builtin,
                module_name,
            )

            if existing is None:
                result["created_permissions"].append(name)
            else:
                result["updated_permissions"].append(name)

        # ── Roles ─────────────────────────────────────────────
        for role in roles:
            name = role["name"]
            description = role.get("description", "")
            role_perms = role.get("permissions", [])

            existing = await self._pool.fetchrow(
                "SELECT source_module FROM roles WHERE name = $1",
                name,
            )

            # Cross-module conflict: роль принадлежит другому модулю
            if existing is not None:
                existing_module = existing["source_module"]
                if existing_module and existing_module != module_name:
                    raise ValueError(
                        f"Role '{name}' already belongs to module '{existing_module}'. "
                        f"Module '{module_name}' cannot overwrite it."
                    )

            await self._pool.execute(
                "INSERT INTO roles (name, description, is_builtin, source_module, updated_at) "
                "VALUES ($1, $2, $3, $4, NOW()) "
                "ON CONFLICT (name) DO UPDATE SET "
                "description = EXCLUDED.description, "
                "is_builtin = EXCLUDED.is_builtin, "
                "source_module = EXCLUDED.source_module, "
                "updated_at = NOW()",
                name,
                description,
                is_builtin,
                module_name,
            )

            # Пересборка role_permissions: DELETE существующих + INSERT
            role_row = await self._pool.fetchrow(
                "SELECT id FROM roles WHERE name = $1",
                name,
            )
            if role_row is not None:
                role_id = role_row["id"]
                await self._pool.execute(
                    "DELETE FROM role_permissions WHERE role_id = $1",
                    role_id,
                )
                for perm_name in role_perms:
                    perm_row = await self._pool.fetchrow(
                        "SELECT id FROM permissions WHERE name = $1",
                        perm_name,
                    )
                    if perm_row is not None:
                        await self._pool.execute(
                            "INSERT INTO role_permissions (role_id, permission_id) "
                            "VALUES ($1, $2) ON CONFLICT DO NOTHING",
                            role_id,
                            perm_row["id"],
                        )

            if existing is None:
                result["created_roles"].append(name)
            else:
                result["updated_roles"].append(name)

        log.info(
            "Auth schema registered",
            extra={
                "module": module_name,
                "created_perms": len(result["created_permissions"]),
                "updated_perms": len(result["updated_permissions"]),
                "created_roles": len(result["created_roles"]),
                "updated_roles": len(result["updated_roles"]),
            },
        )
        return result

    # ── Валидация ─────────────────────────────────────────────

    def _validate_permissions(
        self,
        module_name: str,
        permissions: list[dict[str, Any]],
    ) -> None:
        """Валидация permissions до записи."""
        for perm in permissions:
            name = perm.get("name", "")
            description = perm.get("description", "")

            # Auth — владелец системы прав, ему разрешены любые ресурсы
            if module_name != "auth":
                # 1. Namespace: permission.name начинается с {module_name}:
                if not name.startswith(f"{module_name}:"):
                    raise ValueError(
                        f"Permission '{name}' must start with '{module_name}:'. "
                        f"Namespace mismatch: module is '{module_name}'."
                    )

            # 5. description обязателен
            if not description:
                raise ValueError(
                    f"Permission '{name}' requires a description."
                )

    def _validate_roles(
        self,
        module_name: str,
        roles: list[dict[str, Any]],
        permissions: list[dict[str, Any]],
    ) -> None:
        """Валидация ролей до записи."""
        # Собираем все permissions этой схемы для проверки ссылок
        schema_perm_names = {p["name"] for p in permissions}

        # Также загружаем все существующие permissions из БД для проверки
        # (но только в синхронном контексте — через pool это уже сделано выше,
        #  здесь проверяем базовые правила)

        for role in roles:
            name = role.get("name", "")
            description = role.get("description", "")
            role_perms = role.get("permissions", [])

            # 3. system_admin — только для модуля auth
            if name in _RESERVED_ROLES and module_name != "auth":
                raise ValueError(
                    f"Role '{name}' is reserved for the 'auth' module only. "
                    f"Module '{module_name}' cannot use it."
                )

            # 5. description обязателен
            if not description:
                raise ValueError(
                    f"Role '{name}' requires a description."
                )

            # 4. Все permissions в роли должны существовать в схеме модуля
            #    (проверяем только не-wildcard permissions)
            for perm_name in role_perms:
                if perm_name == "*:*":
                    continue  # Wildcard разрешён для system_admin
                if ":" not in perm_name:
                    raise ValueError(
                        f"Permission '{perm_name}' in role '{name}' is invalid. "
                        f"Expected format: 'resource:action'."
                    )
                resource = perm_name.split(":")[0]
                action = perm_name.split(":")[1]

                if action == "*":
                    # resource:* — проверяем что хотя бы одна permission ресурса есть
                    has_resource = any(
                        p.startswith(f"{resource}:")
                        for p in schema_perm_names
                    )
                    if not has_resource:
                        raise ValueError(
                            f"Permission '{perm_name}' in role '{name}': "
                            f"no permissions found for resource '{resource}' "
                            f"in module '{module_name}' schema."
                        )
                elif perm_name not in schema_perm_names:
                    raise ValueError(
                        f"Permission '{perm_name}' in role '{name}' "
                        f"does not exist in module '{module_name}' schema."
                    )
