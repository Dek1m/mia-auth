"""Auth Repository — все запросы к БД через asyncpg pool.

Разделение ответственности:
- AuthSchemaRegistry = системные permissions/roles (AUTH_SCHEMA)
- AuthRepository = пользовательские объекты (users, groups, sessions, memberships, password_history)

Все запросы параметризованы ($1, $2...) для защиты от SQL-injection.
"""
from __future__ import annotations

from typing import Any

from argenta_logging import get_logger

log = get_logger(__name__)

__all__ = ["AuthRepository"]


class AuthRepository:
    """Репозиторий для работы с auth-таблицами через asyncpg pool."""

    def __init__(self, pool: Any) -> None:
        self._pool = pool

    # ─────────────────────────────────────────────
    # Пользователи
    # ─────────────────────────────────────────────

    async def create_user(
        self,
        username: str,
        password_hash: str,
        email: str | None = None,
        first_name: str | None = None,
        last_name: str | None = None,
        description: str | None = None,
    ) -> dict[str, Any]:
        """Создать пользователя. Возвращает запись."""
        row = await self._pool.fetchrow(
            "INSERT INTO auth.users "
            "(username, password_hash, email, first_name, last_name, description) "
            "VALUES ($1, $2, $3, $4, $5, $6) "
            "RETURNING *",
            username, password_hash, email, first_name, last_name, description,
        )
        return dict(row) if row else {}

    async def get_user(self, user_id: str) -> dict[str, Any] | None:
        """Получить пользователя по ID."""
        row = await self._pool.fetchrow(
            "SELECT * FROM auth.users WHERE id = $1", user_id,
        )
        return dict(row) if row else None

    async def get_user_by_username(self, username: str) -> dict[str, Any] | None:
        """Получить пользователя по username."""
        row = await self._pool.fetchrow(
            "SELECT * FROM auth.users WHERE username = $1", username,
        )
        return dict(row) if row else None

    async def get_user_by_email(self, email: str) -> dict[str, Any] | None:
        """Получить пользователя по email."""
        row = await self._pool.fetchrow(
            "SELECT * FROM auth.users WHERE email = $1", email,
        )
        return dict(row) if row else None

    async def update_user(self, user_id: str, data: dict[str, Any]) -> dict[str, Any] | None:
        """Обновить пользователя. data = {field: value}."""
        if not data:
            return await self.get_user(user_id)

        set_clauses = []
        values: list[Any] = []
        for i, (field, value) in enumerate(data.items(), 1):
            set_clauses.append(f"{field} = ${i}")
            values.append(value)

        values.append(user_id)
        idx = len(values)

        query = (
            f"UPDATE auth.users SET {', '.join(set_clauses)} "
            f"WHERE id = ${idx} RETURNING *"
        )
        row = await self._pool.fetchrow(query, *values)
        return dict(row) if row else None

    async def delete_user(self, user_id: str) -> bool:
        """Удалить пользователя."""
        result = await self._pool.execute(
            "DELETE FROM auth.users WHERE id = $1", user_id,
        )
        return result == "DELETE 1"

    async def list_users(
        self,
        offset: int = 0,
        limit: int = 100,
        search: str | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        """Список пользователей с пагинацией и поиском.

        Returns:
            (items, total) — список и общее количество.
        """
        params: list[Any] = []
        where = ""
        if search:
            params = [f"%{search}%"]
            where = "WHERE username ILIKE $1 OR email ILIKE $1 OR first_name ILIKE $1 OR last_name ILIKE $1"

        total = await self._pool.fetchval(
            f"SELECT COUNT(*) FROM auth.users {where}", *params,
        )

        params.extend([limit, offset])
        rows = await self._pool.fetch(
            f"SELECT * FROM auth.users {where} ORDER BY created_at DESC "
            f"LIMIT ${len(params) - 1} OFFSET ${len(params)}",
            *params,
        )
        return [dict(r) for r in rows], total

    async def get_active_admin_count(self) -> int:
        """Количество активных пользователей с ролью system_admin."""
        return await self._pool.fetchval(
            "SELECT COUNT(*) FROM auth.users u "
            "JOIN auth.user_roles ur ON ur.user_id = u.id "
            "JOIN auth.roles r ON r.id = ur.role_id "
            "WHERE r.name = 'system_admin' AND u.is_active = TRUE AND u.is_disabled = FALSE"
        ) or 0

    # ─────────────────────────────────────────────
    # Состояние пользователей
    # ─────────────────────────────────────────────

    async def block_user(self, user_id: str, until: Any) -> None:
        """Заблокировать пользователя до указанного времени."""
        await self._pool.execute(
            "UPDATE auth.users SET locked_until = $1 WHERE id = $2", until, user_id,
        )

    async def unblock_user(self, user_id: str) -> None:
        """Разблокировать пользователя."""
        await self._pool.execute(
            "UPDATE auth.users SET locked_until = NULL, login_attempts = 0 WHERE id = $1",
            user_id,
        )

    async def disable_user(self, user_id: str) -> None:
        """Деактивировать пользователя."""
        from datetime import datetime, timezone
        await self._pool.execute(
            "UPDATE auth.users SET is_disabled = TRUE, disabled_at = $1, is_active = FALSE "
            "WHERE id = $2",
            datetime.now(timezone.utc), user_id,
        )

    async def enable_user(self, user_id: str) -> None:
        """Активировать пользователя."""
        from datetime import datetime, timezone
        await self._pool.execute(
            "UPDATE auth.users SET is_disabled = FALSE, enabled_at = $1, is_active = TRUE "
            "WHERE id = $2",
            datetime.now(timezone.utc), user_id,
        )

    async def record_login_failure(self, user_id: str) -> int:
        """Зафиксировать неудачную попытку входа. Возвращает новое количество."""
        from datetime import datetime, timedelta, timezone
        row = await self._pool.fetchrow(
            "UPDATE auth.users SET login_attempts = login_attempts + 1 "
            "WHERE id = $1 RETURNING login_attempts",
            user_id,
        )
        return row["login_attempts"] if row else 0

    async def reset_login_failures(self, user_id: str) -> None:
        """Сбросить счётчик попыток входа."""
        await self._pool.execute(
            "UPDATE auth.users SET login_attempts = 0, locked_until = NULL WHERE id = $1",
            user_id,
        )

    async def set_last_login(self, user_id: str) -> None:
        """Установить время последнего входа."""
        from datetime import datetime, timezone
        await self._pool.execute(
            "UPDATE auth.users SET last_login = $1 WHERE id = $2",
            datetime.now(timezone.utc), user_id,
        )

    async def set_password_hash(self, user_id: str, password_hash: str) -> None:
        """Установить хеш пароля."""
        await self._pool.execute(
            "UPDATE auth.users SET password_hash = $1 WHERE id = $2",
            password_hash, user_id,
        )

    # ─────────────────────────────────────────────
    # История паролей
    # ─────────────────────────────────────────────

    async def check_password_history(self, user_id: str, new_hash: str, keep: int = 10) -> bool:
        """Проверить, есть ли хеш в последние N записях истории.

        Returns:
            True если хеш уже использовался (нельзя менять).
        """
        count = await self._pool.fetchval(
            "SELECT COUNT(*) FROM auth.password_history "
            "WHERE user_id = $1 AND password_hash = $2",
            user_id, new_hash,
        )
        return (count or 0) > 0

    async def save_password_history(self, user_id: str, password_hash: str) -> None:
        """Сохранить хеш в историю паролей."""
        await self._pool.execute(
            "INSERT INTO auth.password_history (user_id, password_hash) VALUES ($1, $2)",
            user_id, password_hash,
        )

    async def prune_password_history(self, user_id: str, keep: int = 10) -> None:
        """Оставить только последние N записей истории."""
        await self._pool.execute(
            "DELETE FROM auth.password_history "
            "WHERE user_id = $1 AND id NOT IN ("
            "  SELECT id FROM auth.password_history "
            "  WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2"
            ")",
            user_id, keep,
        )

    # ─────────────────────────────────────────────
    # Группы
    # ─────────────────────────────────────────────

    async def create_group(
        self, name: str, description: str | None = None, is_builtin: bool = False,
    ) -> dict[str, Any]:
        """Создать группу."""
        row = await self._pool.fetchrow(
            "INSERT INTO auth.groups (name, description, is_builtin) "
            "VALUES ($1, $2, $3) RETURNING *",
            name, description, is_builtin,
        )
        return dict(row) if row else {}

    async def get_group(self, group_id: str) -> dict[str, Any] | None:
        """Получить группу по ID."""
        row = await self._pool.fetchrow(
            "SELECT * FROM auth.groups WHERE id = $1", group_id,
        )
        return dict(row) if row else None

    async def update_group(self, group_id: str, data: dict[str, Any]) -> dict[str, Any] | None:
        """Обновить группу."""
        if not data:
            return await self.get_group(group_id)

        set_clauses = []
        values: list[Any] = []
        for i, (field, value) in enumerate(data.items(), 1):
            set_clauses.append(f"{field} = ${i}")
            values.append(value)

        values.append(group_id)
        idx = len(values)
        query = (
            f"UPDATE auth.groups SET {', '.join(set_clauses)} "
            f"WHERE id = ${idx} RETURNING *"
        )
        row = await self._pool.fetchrow(query, *values)
        return dict(row) if row else None

    async def delete_group(self, group_id: str) -> bool:
        """Удалить группу."""
        result = await self._pool.execute(
            "DELETE FROM auth.groups WHERE id = $1", group_id,
        )
        return result == "DELETE 1"

    async def list_groups(
        self, offset: int = 0, limit: int = 100,
    ) -> tuple[list[dict[str, Any]], int]:
        """Список групп с пагинацией."""
        total = await self._pool.fetchval("SELECT COUNT(*) FROM auth.groups")
        rows = await self._pool.fetch(
            "SELECT * FROM auth.groups ORDER BY name LIMIT $1 OFFSET $2",
            limit, offset,
        )
        return [dict(r) for r in rows], total

    async def get_group_members(self, group_id: str) -> list[dict[str, Any]]:
        """Получить участников группы."""
        rows = await self._pool.fetch(
            "SELECT u.id, u.username, u.email, ugm.added_at, ugm.added_by "
            "FROM auth.user_group_membership ugm "
            "JOIN auth.users u ON u.id = ugm.user_id "
            "WHERE ugm.group_id = $1",
            group_id,
        )
        return [dict(r) for r in rows]

    async def count_group_dependencies(self, group_id: str) -> dict[str, int]:
        """Подсчитать зависимости группы."""
        members = await self._pool.fetchval(
            "SELECT COUNT(*) FROM auth.user_group_membership WHERE group_id = $1",
            group_id,
        ) or 0
        children = await self._pool.fetchval(
            "SELECT COUNT(*) FROM auth.group_group_membership WHERE parent_group_id = $1",
            group_id,
        ) or 0
        roles = await self._pool.fetchval(
            "SELECT COUNT(*) FROM auth.group_roles WHERE group_id = $1",
            group_id,
        ) or 0
        return {"members": members, "children": children, "roles": roles}

    # ─────────────────────────────────────────────
    # Роли
    # ─────────────────────────────────────────────

    async def create_role(
        self,
        name: str,
        description: str | None = None,
        is_builtin: bool = False,
        source_module: str | None = None,
    ) -> dict[str, Any]:
        """Создать роль."""
        row = await self._pool.fetchrow(
            "INSERT INTO auth.roles (name, description, is_builtin, source_module) "
            "VALUES ($1, $2, $3, $4) RETURNING *",
            name, description, is_builtin, source_module,
        )
        return dict(row) if row else {}

    async def get_role(self, role_id: str) -> dict[str, Any] | None:
        """Получить роль по ID."""
        row = await self._pool.fetchrow(
            "SELECT * FROM auth.roles WHERE id = $1", role_id,
        )
        return dict(row) if row else None

    async def update_role(self, role_id: str, data: dict[str, Any]) -> dict[str, Any] | None:
        """Обновить роль."""
        if not data:
            return await self.get_role(role_id)

        set_clauses = []
        values: list[Any] = []
        for i, (field, value) in enumerate(data.items(), 1):
            set_clauses.append(f"{field} = ${i}")
            values.append(value)

        values.append(role_id)
        idx = len(values)
        query = (
            f"UPDATE auth.roles SET {', '.join(set_clauses)} "
            f"WHERE id = ${idx} RETURNING *"
        )
        row = await self._pool.fetchrow(query, *values)
        return dict(row) if row else None

    async def delete_role(self, role_id: str) -> bool:
        """Удалить роль."""
        result = await self._pool.execute(
            "DELETE FROM auth.roles WHERE id = $1", role_id,
        )
        return result == "DELETE 1"

    async def list_roles(
        self, offset: int = 0, limit: int = 100,
    ) -> tuple[list[dict[str, Any]], int]:
        """Список ролей с пагинацией."""
        total = await self._pool.fetchval("SELECT COUNT(*) FROM auth.roles")
        rows = await self._pool.fetch(
            "SELECT * FROM auth.roles ORDER BY name LIMIT $1 OFFSET $2",
            limit, offset,
        )
        return [dict(r) for r in rows], total

    async def count_role_assignments(self, role_id: str) -> dict[str, int]:
        """Подсчитать назначения роли."""
        user_roles = await self._pool.fetchval(
            "SELECT COUNT(*) FROM auth.user_roles WHERE role_id = $1", role_id,
        ) or 0
        group_roles = await self._pool.fetchval(
            "SELECT COUNT(*) FROM auth.group_roles WHERE role_id = $1", role_id,
        ) or 0
        return {"user_roles": user_roles, "group_roles": group_roles}

    # ─────────────────────────────────────────────
    # Связи: пользователи ↔ группы
    # ─────────────────────────────────────────────

    async def add_user_to_group(
        self, user_id: str, group_id: str, added_by: str | None = None,
    ) -> None:
        """Добавить пользователя в группу."""
        await self._pool.execute(
            "INSERT INTO auth.user_group_membership (user_id, group_id, added_by) "
            "VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
            user_id, group_id, added_by,
        )

    async def remove_user_from_group(self, user_id: str, group_id: str) -> None:
        """Удалить пользователя из группы."""
        await self._pool.execute(
            "DELETE FROM auth.user_group_membership WHERE user_id = $1 AND group_id = $2",
            user_id, group_id,
        )

    async def get_user_groups(self, user_id: str) -> list[dict[str, Any]]:
        """Получить группы пользователя."""
        rows = await self._pool.fetch(
            "SELECT g.id, g.name, g.description, g.is_builtin, ugm.added_at "
            "FROM auth.user_group_membership ugm "
            "JOIN auth.groups g ON g.id = ugm.group_id "
            "WHERE ugm.user_id = $1",
            user_id,
        )
        return [dict(r) for r in rows]

    # ─────────────────────────────────────────────
    # Связи: группы ↔ группы (иерархия)
    # ─────────────────────────────────────────────

    async def add_group_to_group(self, parent_group_id: str, child_group_id: str) -> None:
        """Добавить дочернюю группу к родительской."""
        await self._pool.execute(
            "INSERT INTO auth.group_group_membership (parent_group_id, child_group_id) "
            "VALUES ($1, $2) ON CONFLICT DO NOTHING",
            parent_group_id, child_group_id,
        )

    async def remove_group_from_group(self, parent_group_id: str, child_group_id: str) -> None:
        """Удалить дочернюю группу из родительской."""
        await self._pool.execute(
            "DELETE FROM auth.group_group_membership "
            "WHERE parent_group_id = $1 AND child_group_id = $2",
            parent_group_id, child_group_id,
        )

    # ─────────────────────────────────────────────
    # Связи: группы ↔ роли
    # ─────────────────────────────────────────────

    async def assign_role_to_group(self, group_id: str, role_id: str) -> None:
        """Назначить роль группе."""
        await self._pool.execute(
            "INSERT INTO auth.group_roles (group_id, role_id) "
            "VALUES ($1, $2) ON CONFLICT DO NOTHING",
            group_id, role_id,
        )

    async def remove_role_from_group(self, group_id: str, role_id: str) -> None:
        """Убрать роль у группы."""
        await self._pool.execute(
            "DELETE FROM auth.group_roles WHERE group_id = $1 AND role_id = $2",
            group_id, role_id,
        )

    async def get_group_roles(self, group_id: str) -> list[dict[str, Any]]:
        """Получить роли группы."""
        rows = await self._pool.fetch(
            "SELECT r.id, r.name, r.description, r.is_builtin "
            "FROM auth.group_roles gr "
            "JOIN auth.roles r ON r.id = gr.role_id "
            "WHERE gr.group_id = $1",
            group_id,
        )
        return [dict(r) for r in rows]

    # ─────────────────────────────────────────────
    # Связи: пользователи ↔ роли (прямые)
    # ─────────────────────────────────────────────

    async def assign_role_to_user(
        self, user_id: str, role_id: str, granted_by: str | None = None,
    ) -> None:
        """Назначить роль пользователю."""
        await self._pool.execute(
            "INSERT INTO auth.user_roles (user_id, role_id, granted_by) "
            "VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
            user_id, role_id, granted_by,
        )

    async def remove_role_from_user(self, user_id: str, role_id: str) -> None:
        """Убрать роль у пользователя."""
        await self._pool.execute(
            "DELETE FROM auth.user_roles WHERE user_id = $1 AND role_id = $2",
            user_id, role_id,
        )

    async def get_user_roles(self, user_id: str) -> list[dict[str, Any]]:
        """Получить прямые роли пользователя."""
        rows = await self._pool.fetch(
            "SELECT r.id, r.name, r.description, r.is_builtin "
            "FROM auth.user_roles ur "
            "JOIN auth.roles r ON r.id = ur.role_id "
            "WHERE ur.user_id = $1",
            user_id,
        )
        return [dict(r) for r in rows]

    # ─────────────────────────────────────────────
    # Эффективные права (рекурсивный CTE)
    # ─────────────────────────────────────────────

    async def get_user_effective_roles(self, user_id: str) -> list[dict[str, Any]]:
        """Получить все эффективные роли пользователя (прямые + через группы).

        Рекурсивный CTE с глубиной ≤ 10.
        """
        rows = await self._pool.fetch(
            "WITH RECURSIVE group_hierarchy AS ("
            "  -- Начинаем с прямых групп пользователя"
            "  SELECT ugm.group_id, 0 AS depth "
            "  FROM auth.user_group_membership ugm "
            "  WHERE ugm.user_id = $1 "
            "  UNION "
            "  -- Рекурсивно поднимаемся по иерархии"
            "  SELECT ggm.parent_group_id, gh.depth + 1 "
            "  FROM auth.group_group_membership ggm "
            "  JOIN group_hierarchy gh ON ggm.child_group_id = gh.group_id "
            "  WHERE gh.depth < 10"
            ") "
            "SELECT DISTINCT r.id, r.name, r.description, r.is_builtin, "
            "  MIN(gh.depth) AS min_depth "
            "FROM auth.group_roles gr "
            "JOIN group_hierarchy gh ON gr.group_id = gh.group_id "
            "JOIN auth.roles r ON r.id = gr.role_id "
            "GROUP BY r.id, r.name, r.description, r.is_builtin "
            "UNION "
            "-- Прямые роли пользователя"
            "SELECT r.id, r.name, r.description, r.is_builtin, -1 AS min_depth "
            "FROM auth.user_roles ur "
            "JOIN auth.roles r ON r.id = ur.role_id "
            "WHERE ur.user_id = $1 "
            "ORDER BY min_depth",
            user_id,
        )
        return [dict(r) for r in rows]

    async def get_user_effective_permissions(self, user_id: str) -> frozenset[str]:
        """Получить все эффективные permissions пользователя.

        Собирает permissions из:
        1. Прямых ролей пользователя
        2. Ролей групп (включая иерархию)
        3. Ролей родительских групп
        """
        rows = await self._pool.fetch(
            "WITH RECURSIVE group_hierarchy AS ("
            "  SELECT ugm.group_id "
            "  FROM auth.user_group_membership ugm "
            "  WHERE ugm.user_id = $1 "
            "  UNION "
            "  SELECT ggm.parent_group_id "
            "  FROM auth.group_group_membership ggm "
            "  JOIN group_hierarchy gh ON ggm.child_group_id = gh.group_id "
            ") "
            "SELECT DISTINCT p.name "
            "FROM auth.role_permissions rp "
            "JOIN auth.permissions p ON p.id = rp.permission_id "
            "WHERE rp.role_id IN ("
            "  -- Прямые роли пользователя"
            "  SELECT ur.role_id FROM auth.user_roles ur WHERE ur.user_id = $1 "
            "  UNION "
            "  -- Роли групп"
            "  SELECT gr.role_id FROM auth.group_roles gr "
            "  WHERE gr.group_id IN (SELECT group_id FROM group_hierarchy)"
            ")",
            user_id,
        )
        return frozenset(row["name"] for row in rows)

    async def get_permissions_version(self, user_id: str) -> int:
        """Получить версию прав пользователя.

        Простая стратегия: COUNT уникальных permissions + Unix timestamp
        последнего изменения roles/memberships.

        Если permissions не менялись — версия стабильна для кеша.
        """
        perms_count = await self._pool.fetchval(
            "WITH RECURSIVE group_hierarchy AS ("
            "  SELECT ugm.group_id FROM auth.user_group_membership ugm "
            "  WHERE ugm.user_id = $1 "
            "  UNION "
            "  SELECT ggm.parent_group_id FROM auth.group_group_membership ggm "
            "  JOIN group_hierarchy gh ON ggm.child_group_id = gh.group_id "
            ") "
            "SELECT COUNT(DISTINCT p.name) "
            "FROM auth.role_permissions rp "
            "JOIN auth.permissions p ON p.id = rp.permission_id "
            "WHERE rp.role_id IN ("
            "  SELECT ur.role_id FROM auth.user_roles ur WHERE ur.user_id = $1 "
            "  UNION "
            "  SELECT gr.role_id FROM auth.group_roles gr "
            "  WHERE gr.group_id IN (SELECT group_id FROM group_hierarchy)"
            ")",
            user_id,
        ) or 0

        # Берём максимальное updated_at среди ролей и membership
        max_updated = await self._pool.fetchval(
            "SELECT EXTRACT(EPOCH FROM MAX(updated_at))::bigint "
            "FROM auth.roles WHERE id IN ("
            "  SELECT role_id FROM auth.user_roles WHERE user_id = $1 "
            "  UNION "
            "  SELECT gr.role_id FROM auth.group_roles gr "
            "  JOIN auth.user_group_membership ugm ON ugm.group_id = gr.group_id "
            "  WHERE ugm.user_id = $1"
            ")",
            user_id,
        ) or 0

        return perms_count * 1_000_000 + (max_updated % 1_000_000)

    # ─────────────────────────────────────────────
    # Сессии
    # ─────────────────────────────────────────────

    async def create_session(
        self,
        user_id: str,
        access_hash: str,
        access_expires_at: Any,
        refresh_hash: str,
        refresh_expires_at: Any,
        user_agent: str | None = None,
        ip_address: str | None = None,
        family_id: str | None = None,
    ) -> dict[str, Any]:
        """Создать сессию."""
        row = await self._pool.fetchrow(
            "INSERT INTO auth.auth_sessions "
            "(user_id, access_token_hash, access_expires_at, "
            "refresh_token_hash, refresh_expires_at, user_agent, ip_address, family_id) "
            "VALUES ($1, $2, $3, $4, $5, $6, $7, $8) "
            "RETURNING *",
            user_id, access_hash, access_expires_at,
            refresh_hash, refresh_expires_at, user_agent, ip_address, family_id,
        )
        return dict(row) if row else {}

    async def get_session_by_refresh(self, refresh_hash: str) -> dict[str, Any] | None:
        """Найти сессию по refresh token hash (только не отозванные)."""
        row = await self._pool.fetchrow(
            "SELECT * FROM auth.auth_sessions "
            "WHERE refresh_token_hash = $1 AND is_revoked = FALSE",
            refresh_hash,
        )
        return dict(row) if row else None

    async def get_session_by_access(self, access_hash: str) -> dict[str, Any] | None:
        """Найти сессию по access token hash."""
        row = await self._pool.fetchrow(
            "SELECT * FROM auth.auth_sessions "
            "WHERE access_token_hash = $1 AND is_revoked = FALSE",
            access_hash,
        )
        return dict(row) if row else None

    async def revoke_session(self, session_id: str) -> None:
        """Отозвать сессию."""
        from datetime import datetime, timezone
        await self._pool.execute(
            "UPDATE auth.auth_sessions SET is_revoked = TRUE, revoked_at = $1 "
            "WHERE id = $2",
            datetime.now(timezone.utc), session_id,
        )

    async def revoke_all_user_sessions(self, user_id: str) -> None:
        """Отозвать все сессии пользователя."""
        from datetime import datetime, timezone
        await self._pool.execute(
            "UPDATE auth.auth_sessions SET is_revoked = TRUE, revoked_at = $1 "
            "WHERE user_id = $2 AND is_revoked = FALSE",
            datetime.now(timezone.utc), user_id,
        )

    async def revoke_family(self, family_id: str) -> None:
        """Отозвать всю семью токенов (для обнаружения reuse)."""
        from datetime import datetime, timezone
        await self._pool.execute(
            "UPDATE auth.auth_sessions SET is_revoked = TRUE, revoked_at = $1 "
            "WHERE family_id = $2 AND is_revoked = FALSE",
            datetime.now(timezone.utc), family_id,
        )

    async def update_session_last_used(self, session_id: str) -> None:
        """Обновить время последнего использования."""
        from datetime import datetime, timezone
        await self._pool.execute(
            "UPDATE auth.auth_sessions SET last_used_at = $1 WHERE id = $2",
            datetime.now(timezone.utc), session_id,
        )
