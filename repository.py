"""Auth Repository — все запросы к БД через Database Provider.

Разделение ответственности:
- AuthSchemaRegistry = системные permissions/roles (AUTH_SCHEMA)
- AuthRepository = пользовательские объекты (users, groups, sessions, memberships, password_history)

Все запросы параметризованы (%s, %s...) для защиты от SQL-injection.
"""
from __future__ import annotations

from typing import Any

__all__ = ["AuthRepository"]

# Колонки профиля — password_hash сюда не входит (ADR-001 §5.3)
_PROFILE_COLUMNS = (
    "id",
    "username",
    "nickname",
    "first_name",
    "last_name",
    "date_of_birth",
    "email",
    "phone",
    "user_prompt",
    "chip_display_mode",
    "is_bootstrap_admin",
)
_PROFILE_UPDATE_FIELDS = frozenset({
    "nickname",
    "first_name",
    "last_name",
    "date_of_birth",
    "email",
    "phone",
    "user_prompt",
    "chip_display_mode",
})
# Имена колонок — не из клиента. password_hash / id сюда не входят.
_USER_UPDATE_FIELDS = frozenset({
    "username",
    "first_name",
    "last_name",
    "email",
    "description",
    "is_active",
    "locked_until",
    "is_disabled",
    "disabled_at",
    "enabled_at",
    "last_login",
    "login_attempts",
    "custom_fields",
    "nickname",
    "phone",
    "user_prompt",
    "chip_display_mode",
    "ui_windows",
})
_GROUP_UPDATE_FIELDS = frozenset({"name", "description", "is_builtin"})
_ROLE_UPDATE_FIELDS = frozenset({
    "name", "description", "is_builtin", "source_module", "capability_mask",
})


class AuthRepository:
    """Репозиторий для работы с auth-таблицами через Database Provider."""

    def __init__(self, database: Any, log: Any | None = None) -> None:
        self._database = database
        self._log = log
        # Builtin-домен не удаётся удалить (kind-инвариант) — кеш живёт вечно.
        self._builtin_domain_id: str | None = None

    async def _update_filtered(
        self,
        table: str,
        row_id: str,
        data: dict[str, Any],
        allowed: frozenset[str],
        fallback: Any,
    ) -> dict[str, Any] | None:
        """UPDATE только whitelist колонок, плейсхолдеры %s."""
        filtered = {key: value for key, value in data.items() if key in allowed}
        if not filtered:
            return await fallback(row_id)
        assignments = ", ".join(f"{field} = %s" for field in filtered)
        values: list[Any] = list(filtered.values())
        values.append(row_id)
        return await self._fetchrow(
            f"UPDATE {table} SET {assignments} WHERE id = %s RETURNING *",
            *values,
        )

    async def _fetchrow(self, query: str, *params: Any) -> dict[str, Any] | None:
        """Получить одну строку или None (аналог pool.fetchrow)."""
        rows = self._database.fetch(query, *params)
        return dict(rows[0]) if rows else None

    async def _fetchval(self, query: str, *params: Any) -> Any:
        """Получить одно значение (аналог pool.fetchval).

        Работает для запросов с единственным столбцом: COUNT(*), EXISTS, MAX и т.д.
        """
        rows = self._database.fetch(query, *params)
        if not rows:
            return None
        first = rows[0]
        keys = list(first.keys())
        return first[keys[0]] if keys else None

    # ─────────────────────────────────────────────
    # Пользователи
    # ─────────────────────────────────────────────

    async def get_builtin_domain_id(self) -> str | None:
        """UUID builtin-домена ('argenta'). Кеш — домен несменяем."""
        if self._builtin_domain_id is None:
            row = await self._fetchrow(
                "SELECT id FROM auth.domains WHERE kind = 'builtin' "
                "ORDER BY created_at, id LIMIT 1",
            )
            self._builtin_domain_id = str(row["id"]) if row else None
        return self._builtin_domain_id

    async def create_user(
        self,
        username: str,
        password_hash: str,
        email: str | None = None,
        first_name: str | None = None,
        last_name: str | None = None,
        description: str | None = None,
        domain_id: str | None = None,
    ) -> dict[str, Any]:
        """Создать пользователя. Возвращает запись.

        domain_id обязателен (ddl/009 SET NOT NULL): без явного значения
        пользователь попадает в builtin-домен 'argenta'.
        """
        # Резолв отдельным SELECT, не подзапросом в INSERT — mock-слой тестов
        # не парсит подзапросы, а кеш делает повторные создания бесплатными.
        resolved = domain_id or await self.get_builtin_domain_id()
        return await self._fetchrow(
            "INSERT INTO auth.users "
            "(username, password_hash, email, first_name, last_name, description, domain_id) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s) "
            "RETURNING *",
            username, password_hash, email, first_name, last_name, description, resolved,
        ) or {}

    async def get_user(self, user_id: str) -> dict[str, Any] | None:
        """Получить пользователя по ID."""
        return await self._fetchrow(
            "SELECT * FROM auth.users WHERE id = %s", user_id,
        )

    async def get_profile(self, user_id: str) -> dict[str, Any] | None:
        """Профиль без password_hash. Список колонок — контракт, не SELECT *."""
        cols = ", ".join(_PROFILE_COLUMNS)
        return await self._fetchrow(
            f"SELECT {cols} FROM auth.users WHERE id = %s", user_id,
        )

    async def update_profile(
        self, user_id: str, data: dict[str, Any],
    ) -> dict[str, Any] | None:
        """UPDATE только whitelist полей профиля."""
        filtered = {key: value for key, value in data.items() if key in _PROFILE_UPDATE_FIELDS}
        if not filtered:
            return await self.get_profile(user_id)
        assignments = ", ".join(f"{field} = %s" for field in filtered)
        values: list[Any] = list(filtered.values())
        values.append(user_id)
        cols = ", ".join(_PROFILE_COLUMNS)
        return await self._fetchrow(
            f"UPDATE auth.users SET {assignments} WHERE id = %s RETURNING {cols}",
            *values,
        )

    async def set_username(self, user_id: str, username: str) -> None:
        self._database.execute(
            "UPDATE auth.users SET username = %s WHERE id = %s",
            username, user_id,
        )

    async def get_primary_group_id(self, user_id: str) -> str | None:
        row = await self._fetchrow(
            "SELECT group_id FROM auth.user_group_membership "
            "WHERE user_id = %s AND is_primary = TRUE",
            user_id,
        )
        if not row or row.get("group_id") is None:
            return None
        return str(row["group_id"])

    async def get_ui_windows(self, user_id: str) -> dict[str, Any]:
        row = await self._fetchrow(
            "SELECT ui_windows FROM auth.users WHERE id = %s", user_id,
        )
        raw = row.get("ui_windows") if row else None
        return dict(raw) if isinstance(raw, dict) else {}

    async def merge_ui_window(
        self, user_id: str, window_id: str, geom: dict[str, float],
    ) -> dict[str, Any]:
        import json

        patch = json.dumps({window_id: geom})
        row = await self._fetchrow(
            "UPDATE auth.users SET ui_windows = COALESCE(ui_windows, jsonb_build_object()) || %s::jsonb "
            "WHERE id = %s RETURNING ui_windows",
            patch,
            user_id,
        )
        raw = row.get("ui_windows") if row else None
        return dict(raw) if isinstance(raw, dict) else {}

    async def get_avatar(self, user_id: str) -> dict[str, Any] | None:
        return await self._fetchrow(
            "SELECT user_id, bytes, content_type, updated_at "
            "FROM auth.user_avatars WHERE user_id = %s",
            user_id,
        )

    async def has_avatar(self, user_id: str) -> bool:
        row = await self._fetchrow(
            "SELECT user_id FROM auth.user_avatars WHERE user_id = %s",
            user_id,
        )
        return row is not None

    async def upsert_avatar(self, user_id: str, data: bytes, content_type: str) -> None:
        if await self.has_avatar(user_id):
            self._database.execute(
                "UPDATE auth.user_avatars "
                "SET bytes = %s, content_type = %s, updated_at = NOW() "
                "WHERE user_id = %s",
                data, content_type, user_id,
            )
            return
        self._database.execute(
            "INSERT INTO auth.user_avatars (user_id, bytes, content_type) "
            "VALUES (%s, %s, %s)",
            user_id, data, content_type,
        )

    async def delete_avatar(self, user_id: str) -> None:
        self._database.execute(
            "DELETE FROM auth.user_avatars WHERE user_id = %s", user_id,
        )

    async def get_membership(
        self, user_id: str, group_id: str,
    ) -> dict[str, Any] | None:
        return await self._fetchrow(
            "SELECT user_id, group_id, is_primary, added_at, added_by "
            "FROM auth.user_group_membership "
            "WHERE user_id = %s AND group_id = %s",
            user_id, group_id,
        )

    async def get_user_by_username(self, username: str) -> dict[str, Any] | None:
        """Получить пользователя по username."""
        return await self._fetchrow(
            "SELECT * FROM auth.users WHERE username = %s", username,
        )

    async def get_user_by_email(self, email: str) -> dict[str, Any] | None:
        """Получить пользователя по email."""
        return await self._fetchrow(
            "SELECT * FROM auth.users WHERE email = %s", email,
        )

    async def update_user(self, user_id: str, data: dict[str, Any]) -> dict[str, Any] | None:
        """Обновить пользователя. data = {field: value}."""
        return await self._update_filtered(
            "auth.users", user_id, data, _USER_UPDATE_FIELDS, self.get_user,
        )

    async def delete_user(self, user_id: str) -> bool:
        """Удалить пользователя."""
        result = self._database.execute(
            "DELETE FROM auth.users WHERE id = %s", user_id,
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
            where = "WHERE username ILIKE %s OR email ILIKE %s OR first_name ILIKE %s OR last_name ILIKE %s"

        total = await self._fetchval(
            f"SELECT COUNT(*) FROM auth.users {where}", *params,
        )

        params.extend([limit, offset])
        rows = self._database.fetch(
            f"SELECT * FROM auth.users {where} ORDER BY created_at DESC "
            f"LIMIT ${len(params) - 1} OFFSET ${len(params)}",
            *params,
        )
        return [dict(r) for r in rows], total or 0

    async def get_active_admin_count(self) -> int:
        """Количество активных пользователей с ролью system_admin."""
        return await self._fetchval(
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
        self._database.execute(
            "UPDATE auth.users SET locked_until = %s WHERE id = %s", until, user_id,
        )

    async def unblock_user(self, user_id: str) -> None:
        """Разблокировать пользователя."""
        self._database.execute(
            "UPDATE auth.users SET locked_until = NULL, login_attempts = 0 WHERE id = %s",
            user_id,
        )

    async def disable_user(self, user_id: str) -> None:
        """Деактивировать пользователя."""
        from datetime import datetime, timezone
        self._database.execute(
            "UPDATE auth.users SET is_disabled = TRUE, disabled_at = %s, is_active = FALSE "
            "WHERE id = %s",
            datetime.now(timezone.utc), user_id,
        )

    async def enable_user(self, user_id: str) -> None:
        """Активировать пользователя."""
        from datetime import datetime, timezone
        self._database.execute(
            "UPDATE auth.users SET is_disabled = FALSE, enabled_at = %s, is_active = TRUE "
            "WHERE id = %s",
            datetime.now(timezone.utc), user_id,
        )

    async def record_login_failure(self, user_id: str) -> int:
        """Зафиксировать неудачную попытку входа. Возвращает новое количество."""
        row = await self._fetchrow(
            "UPDATE auth.users SET login_attempts = login_attempts + 1 "
            "WHERE id = %s RETURNING login_attempts",
            user_id,
        )
        return row["login_attempts"] if row else 0

    async def reset_login_failures(self, user_id: str) -> None:
        """Сбросить счётчик попыток входа."""
        self._database.execute(
            "UPDATE auth.users SET login_attempts = 0, locked_until = NULL WHERE id = %s",
            user_id,
        )

    async def set_last_login(self, user_id: str) -> None:
        """Установить время последнего входа."""
        from datetime import datetime, timezone
        self._database.execute(
            "UPDATE auth.users SET last_login = %s WHERE id = %s",
            datetime.now(timezone.utc), user_id,
        )

    async def set_password_hash(self, user_id: str, password_hash: str) -> None:
        """Установить хеш пароля."""
        self._database.execute(
            "UPDATE auth.users SET password_hash = %s WHERE id = %s",
            password_hash, user_id,
        )

    # ─────────────────────────────────────────────
    # История паролей
    # ─────────────────────────────────────────────

    async def check_password_history(self, user_id: str, new_hash: str, keep: int = 10) -> bool:
        """Проверить, есть ли хеш в последние N записей истории.

        Returns:
            True если хеш уже использовался (нельзя менять).
        """
        count = await self._fetchval(
            "SELECT COUNT(*) FROM auth.password_history "
            "WHERE user_id = %s AND password_hash = %s",
            user_id, new_hash,
        )
        return (count or 0) > 0

    async def save_password_history(self, user_id: str, password_hash: str) -> None:
        """Сохранить хеш в историю паролей."""
        self._database.execute(
            "INSERT INTO auth.password_history (user_id, password_hash) VALUES (%s, %s)",
            user_id, password_hash,
        )

    async def prune_password_history(self, user_id: str, keep: int = 10) -> None:
        """Оставить только последние N записей истории."""
        # Три %s — user_id дважды (outer + subquery) и keep. Раньше передавалось
        # (user_id, keep) → psycopg падал на числе параметров, prune не работал.
        self._database.execute(
            "DELETE FROM auth.password_history "
            "WHERE user_id = %s AND id NOT IN ("
            "  SELECT id FROM auth.password_history "
            "  WHERE user_id = %s ORDER BY created_at DESC LIMIT %s"
            ")",
            user_id, user_id, keep,
        )

    # ─────────────────────────────────────────────
    # Группы
    # ─────────────────────────────────────────────

    async def create_group(
        self,
        name: str,
        description: str | None = None,
        is_builtin: bool = False,
        domain_id: str | None = None,
        scope: str | None = None,
        owner_id: str | None = None,
        link_id: str | None = None,
    ) -> dict[str, Any]:
        """Создать группу с явным scope-тройником (ddl/009 CHECK shape).

        Дефолты обратной совместимости (как backfill 009): builtin →
        scope='system'; остальные → scope='domain' в builtin-домен 'argenta'.
        Доменные группы тенанта передают domain_id; федеративные — link_id.
        """
        if scope is None:
            scope = "system" if is_builtin else "domain"
        if domain_id is None and scope == "domain":
            domain_id = await self.get_builtin_domain_id()
        return await self._fetchrow(
            "INSERT INTO auth.groups "
            "(name, description, is_builtin, scope, domain_id, owner_id, link_id) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING *",
            name, description, is_builtin, scope, domain_id, owner_id, link_id,
        ) or {}

    async def get_group(self, group_id: str) -> dict[str, Any] | None:
        """Получить группу по ID."""
        return await self._fetchrow(
            "SELECT * FROM auth.groups WHERE id = %s", group_id,
        )

    async def update_group(self, group_id: str, data: dict[str, Any]) -> dict[str, Any] | None:
        """Обновить группу."""
        return await self._update_filtered(
            "auth.groups", group_id, data, _GROUP_UPDATE_FIELDS, self.get_group,
        )

    async def set_group_name(
        self, group_id: str, name: str,
    ) -> dict[str, Any] | None:
        """Переименовать группу. %s — не $1 (DatabaseProvider)."""
        return await self._fetchrow(
            "UPDATE auth.groups SET name = %s WHERE id = %s "
            "RETURNING id, name, description, is_builtin",
            name,
            group_id,
        )

    async def delete_group(self, group_id: str) -> bool:
        """Удалить группу."""
        result = self._database.execute(
            "DELETE FROM auth.groups WHERE id = %s", group_id,
        )
        return result == "DELETE 1"

    async def list_groups(
        self, offset: int = 0, limit: int = 100,
    ) -> tuple[list[dict[str, Any]], int]:
        """Список групп с пагинацией."""
        total = await self._fetchval("SELECT COUNT(*) FROM auth.groups")
        rows = self._database.fetch(
            "SELECT * FROM auth.groups ORDER BY name LIMIT %s OFFSET %s",
            limit, offset,
        )
        return [dict(r) for r in rows], total or 0

    async def get_group_members(self, group_id: str) -> list[dict[str, Any]]:
        """Получить участников группы."""
        rows = self._database.fetch(
            "SELECT u.id, u.username, u.email, ugm.added_at, ugm.added_by "
            "FROM auth.user_group_membership ugm "
            "JOIN auth.users u ON u.id = ugm.user_id "
            "WHERE ugm.group_id = %s",
            group_id,
        )
        return [dict(r) for r in rows]

    async def count_group_dependencies(self, group_id: str) -> dict[str, int]:
        """Подсчитать зависимости группы."""
        members = await self._fetchval(
            "SELECT COUNT(*) FROM auth.user_group_membership WHERE group_id = %s",
            group_id,
        ) or 0
        children = await self._fetchval(
            "SELECT COUNT(*) FROM auth.group_group_membership WHERE parent_group_id = %s",
            group_id,
        ) or 0
        roles = await self._fetchval(
            "SELECT COUNT(*) FROM auth.group_roles WHERE group_id = %s",
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
        return await self._fetchrow(
            "INSERT INTO auth.roles (name, description, is_builtin, source_module) "
            "VALUES (%s, %s, %s, %s) RETURNING *",
            name, description, is_builtin, source_module,
        ) or {}

    async def get_role(self, role_id: str) -> dict[str, Any] | None:
        """Получить роль по ID."""
        return await self._fetchrow(
            "SELECT * FROM auth.roles WHERE id = %s", role_id,
        )

    async def update_role(self, role_id: str, data: dict[str, Any]) -> dict[str, Any] | None:
        """Обновить роль."""
        return await self._update_filtered(
            "auth.roles", role_id, data, _ROLE_UPDATE_FIELDS, self.get_role,
        )

    async def delete_role(self, role_id: str) -> bool:
        """Удалить роль."""
        result = self._database.execute(
            "DELETE FROM auth.roles WHERE id = %s", role_id,
        )
        return result == "DELETE 1"

    async def list_roles(
        self, offset: int = 0, limit: int = 100,
    ) -> tuple[list[dict[str, Any]], int]:
        """Список ролей с пагинацией."""
        total = await self._fetchval("SELECT COUNT(*) FROM auth.roles")
        rows = self._database.fetch(
            "SELECT * FROM auth.roles ORDER BY name LIMIT %s OFFSET %s",
            limit, offset,
        )
        return [dict(r) for r in rows], total or 0

    async def count_role_assignments(self, role_id: str) -> dict[str, int]:
        """Подсчитать назначения роли."""
        user_roles = await self._fetchval(
            "SELECT COUNT(*) FROM auth.user_roles WHERE role_id = %s", role_id,
        ) or 0
        group_roles = await self._fetchval(
            "SELECT COUNT(*) FROM auth.group_roles WHERE role_id = %s", role_id,
        ) or 0
        return {"user_roles": user_roles, "group_roles": group_roles}

    # ─────────────────────────────────────────────
    # Связи: пользователи ↔ группы
    # ─────────────────────────────────────────────

    async def add_user_to_group(
        self,
        user_id: str,
        group_id: str,
        added_by: str | None = None,
        is_primary: bool = False,
    ) -> None:
        """Добавить пользователя в группу. is_primary — только при создании."""
        self._database.execute(
            "INSERT INTO auth.user_group_membership "
            "(user_id, group_id, added_by, is_primary) "
            "VALUES (%s, %s, %s, %s) ON CONFLICT DO NOTHING",
            user_id, group_id, added_by, is_primary,
        )

    async def remove_user_from_group(self, user_id: str, group_id: str) -> None:
        """Удалить пользователя из группы."""
        self._database.execute(
            "DELETE FROM auth.user_group_membership WHERE user_id = %s AND group_id = %s",
            user_id, group_id,
        )

    async def get_user_groups(self, user_id: str) -> list[dict[str, Any]]:
        """Группы пользователя с is_primary. Два запроса — mock JOIN ломается."""
        memberships = self._database.fetch(
            "SELECT group_id, is_primary, added_at "
            "FROM auth.user_group_membership WHERE user_id = %s",
            user_id,
        )
        groups: list[dict[str, Any]] = []
        for item in memberships:
            group = await self.get_group(str(item["group_id"]))
            if group is None:
                continue
            groups.append({
                "id": group["id"],
                "name": group["name"],
                "description": group.get("description"),
                "is_builtin": bool(group.get("is_builtin")),
                "is_primary": bool(item.get("is_primary")),
                "added_at": item.get("added_at"),
            })
        return groups

    # ─────────────────────────────────────────────
    # Связи: группы ↔ группы (иерархия)
    # ─────────────────────────────────────────────

    async def add_group_to_group(self, parent_group_id: str, child_group_id: str) -> None:
        """Добавить дочернюю группу к родительской."""
        self._database.execute(
            "INSERT INTO auth.group_group_membership (parent_group_id, child_group_id) "
            "VALUES (%s, %s) ON CONFLICT DO NOTHING",
            parent_group_id, child_group_id,
        )

    async def remove_group_from_group(self, parent_group_id: str, child_group_id: str) -> None:
        """Удалить дочернюю группу из родительской."""
        self._database.execute(
            "DELETE FROM auth.group_group_membership "
            "WHERE parent_group_id = %s AND child_group_id = %s",
            parent_group_id, child_group_id,
        )

    # ─────────────────────────────────────────────
    # Связи: группы ↔ роли
    # ─────────────────────────────────────────────

    async def assign_role_to_group(self, group_id: str, role_id: str) -> None:
        """Назначить роль группе."""
        self._database.execute(
            "INSERT INTO auth.group_roles (group_id, role_id) "
            "VALUES (%s, %s) ON CONFLICT DO NOTHING",
            group_id, role_id,
        )

    async def remove_role_from_group(self, group_id: str, role_id: str) -> None:
        """Убрать роль у группы."""
        self._database.execute(
            "DELETE FROM auth.group_roles WHERE group_id = %s AND role_id = %s",
            group_id, role_id,
        )

    async def get_group_roles(self, group_id: str) -> list[dict[str, Any]]:
        """Получить роли группы."""
        rows = self._database.fetch(
            "SELECT r.id, r.name, r.description, r.is_builtin "
            "FROM auth.group_roles gr "
            "JOIN auth.roles r ON r.id = gr.role_id "
            "WHERE gr.group_id = %s",
            group_id,
        )
        return [dict(r) for r in rows]

    async def get_role_groups(self, role_id: str) -> list[dict[str, Any]]:
        """Группы, которым назначена роль."""
        rows = self._database.fetch(
            "SELECT g.id, g.name, g.description, g.is_builtin "
            "FROM auth.group_roles gr "
            "JOIN auth.groups g ON g.id = gr.group_id "
            "WHERE gr.role_id = %s",
            role_id,
        )
        return [dict(row) for row in rows]

    # ─────────────────────────────────────────────
    # Связи: пользователи ↔ роли (прямые)
    # ─────────────────────────────────────────────

    async def assign_role_to_user(
        self, user_id: str, role_id: str, granted_by: str | None = None,
    ) -> None:
        """Назначить роль пользователю."""
        self._database.execute(
            "INSERT INTO auth.user_roles (user_id, role_id, granted_by) "
            "VALUES (%s, %s, %s) ON CONFLICT DO NOTHING",
            user_id, role_id, granted_by,
        )

    async def remove_role_from_user(self, user_id: str, role_id: str) -> None:
        """Убрать роль у пользователя."""
        self._database.execute(
            "DELETE FROM auth.user_roles WHERE user_id = %s AND role_id = %s",
            user_id, role_id,
        )

    async def get_user_roles(self, user_id: str) -> list[dict[str, Any]]:
        """Получить прямые роли пользователя."""
        rows = self._database.fetch(
            "SELECT r.id, r.name, r.description, r.is_builtin "
            "FROM auth.user_roles ur "
            "JOIN auth.roles r ON r.id = ur.role_id "
            "WHERE ur.user_id = %s",
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
        rows = self._database.fetch(
            "WITH RECURSIVE group_hierarchy AS ("
            "  SELECT ugm.group_id, 0 AS depth "
            "  FROM auth.user_group_membership ugm "
            "  WHERE ugm.user_id = %s "
            "  UNION "
            "  SELECT g.id, 0 AS depth FROM auth.groups g "
            "  WHERE g.name = 'Everyone' AND g.is_builtin "
            "  UNION "
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
            "SELECT r.id, r.name, r.description, r.is_builtin, -1 AS min_depth "
            "FROM auth.user_roles ur "
            "JOIN auth.roles r ON r.id = ur.role_id "
            "WHERE ur.user_id = %s "
            "ORDER BY min_depth",
            user_id,
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
        rows = self._database.fetch(
            "WITH RECURSIVE group_hierarchy AS ("
            "  SELECT ugm.group_id "
            "  FROM auth.user_group_membership ugm "
            "  WHERE ugm.user_id = %s "
            "  UNION "
            "  SELECT g.id FROM auth.groups g "
            "  WHERE g.name = 'Everyone' AND g.is_builtin "
            "  UNION "
            "  SELECT ggm.parent_group_id "
            "  FROM auth.group_group_membership ggm "
            "  JOIN group_hierarchy gh ON ggm.child_group_id = gh.group_id "
            ") "
            "SELECT DISTINCT p.name "
            "FROM auth.role_permissions rp "
            "JOIN auth.permissions p ON p.id = rp.permission_id "
            "WHERE rp.role_id IN ("
            "  SELECT ur.role_id FROM auth.user_roles ur WHERE ur.user_id = %s "
            "  UNION "
            "  SELECT gr.role_id FROM auth.group_roles gr "
            "  WHERE gr.group_id IN (SELECT group_id FROM group_hierarchy)"
            ")",
            user_id,
            user_id,
        )
        return frozenset(row["name"] for row in rows)

    async def get_permissions_version(self, user_id: str) -> int:
        """Получить версию прав пользователя.

        Простая стратегия: COUNT уникальных permissions + Unix timestamp
        последнего изменения roles/memberships.

        Если permissions не менялись — версия стабильна для кеша.
        """
        perms_count = await self._fetchval(
            "WITH RECURSIVE group_hierarchy AS ("
            "  SELECT ugm.group_id FROM auth.user_group_membership ugm "
            "  WHERE ugm.user_id = %s "
            "  UNION "
            "  SELECT g.id FROM auth.groups g "
            "  WHERE g.name = 'Everyone' AND g.is_builtin "
            "  UNION "
            "  SELECT ggm.parent_group_id FROM auth.group_group_membership ggm "
            "  JOIN group_hierarchy gh ON ggm.child_group_id = gh.group_id "
            ") "
            "SELECT COUNT(DISTINCT p.name) "
            "FROM auth.role_permissions rp "
            "JOIN auth.permissions p ON p.id = rp.permission_id "
            "WHERE rp.role_id IN ("
            "  SELECT ur.role_id FROM auth.user_roles ur WHERE ur.user_id = %s "
            "  UNION "
            "  SELECT gr.role_id FROM auth.group_roles gr "
            "  WHERE gr.group_id IN (SELECT group_id FROM group_hierarchy)"
            ")",
            user_id, user_id,
        ) or 0

        # Берём максимальное updated_at среди ролей и membership
        max_updated = await self._fetchval(
            "SELECT EXTRACT(EPOCH FROM MAX(updated_at))::bigint "
            "FROM auth.roles WHERE id IN ("
            "  SELECT role_id FROM auth.user_roles WHERE user_id = %s "
            "  UNION "
            "  SELECT gr.role_id FROM auth.group_roles gr "
            "  JOIN auth.user_group_membership ugm ON ugm.group_id = gr.group_id "
            "  WHERE ugm.user_id = %s"
            ")",
            user_id, user_id,
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
        return await self._fetchrow(
            "INSERT INTO auth.auth_sessions "
            "(user_id, access_token_hash, access_expires_at, "
            "refresh_token_hash, refresh_expires_at, user_agent, ip_address, family_id) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s) "
            "RETURNING *",
            user_id, access_hash, access_expires_at,
            refresh_hash, refresh_expires_at, user_agent, ip_address, family_id,
        ) or {}

    async def get_session_by_refresh(self, refresh_hash: str) -> dict[str, Any] | None:
        """Найти сессию по refresh token hash (только не отозванные)."""
        return await self._fetchrow(
            "SELECT * FROM auth.auth_sessions "
            "WHERE refresh_token_hash = %s AND is_revoked = FALSE",
            refresh_hash,
        )

    async def get_session_by_access(self, access_hash: str) -> dict[str, Any] | None:
        """Найти сессию по access token hash."""
        return await self._fetchrow(
            "SELECT * FROM auth.auth_sessions "
            "WHERE access_token_hash = %s AND is_revoked = FALSE",
            access_hash,
        )

    async def revoke_session(self, session_id: str) -> None:
        """Отозвать сессию."""
        from datetime import datetime, timezone
        self._database.execute(
            "UPDATE auth.auth_sessions SET is_revoked = TRUE, revoked_at = %s "
            "WHERE id = %s",
            datetime.now(timezone.utc), session_id,
        )

    async def revoke_all_user_sessions(self, user_id: str) -> None:
        """Отозвать все сессии пользователя."""
        from datetime import datetime, timezone
        self._database.execute(
            "UPDATE auth.auth_sessions SET is_revoked = TRUE, revoked_at = %s "
            "WHERE user_id = %s AND is_revoked = FALSE",
            datetime.now(timezone.utc), user_id,
        )

    async def revoke_family(self, family_id: str) -> None:
        """Отозвать всю семью токенов (для обнаружения reuse)."""
        from datetime import datetime, timezone
        self._database.execute(
            "UPDATE auth.auth_sessions SET is_revoked = TRUE, revoked_at = %s "
            "WHERE family_id = %s AND is_revoked = FALSE",
            datetime.now(timezone.utc), family_id,
        )

    async def update_session_last_used(self, session_id: str) -> None:
        """Обновить время последнего использования."""
        from datetime import datetime, timezone
        self._database.execute(
            "UPDATE auth.auth_sessions SET last_used_at = %s WHERE id = %s",
            datetime.now(timezone.utc), session_id,
        )

    # ─────────────────────────────────────────────
    # Прямые SQL-запросы (для provider.py)
    # ─────────────────────────────────────────────

    async def is_user_admin(self, user_id: str) -> bool:
        """Проверить, является ли пользователь system_admin."""
        row = await self._fetchrow(
            "SELECT EXISTS(SELECT 1 FROM auth.user_roles ur "
            "JOIN auth.roles r ON r.id = ur.role_id "
            "WHERE ur.user_id = %s AND r.name = 'system_admin')",
            user_id,
        )
        return row.get("exists", False) if row else False

    async def count_user_sessions(self, user_id: str) -> int:
        """Количество сессий пользователя."""
        return await self._fetchval(
            "SELECT COUNT(*) FROM auth.auth_sessions WHERE user_id = %s",
            user_id,
        ) or 0

    async def delete_user_roles(self, user_id: str) -> None:
        """Удалить все роли пользователя."""
        self._database.execute(
            "DELETE FROM auth.user_roles WHERE user_id = %s", user_id,
        )

    async def delete_user_group_memberships(self, user_id: str) -> None:
        """Удалить все групповые связи пользователя."""
        self._database.execute(
            "DELETE FROM auth.user_group_membership WHERE user_id = %s", user_id,
        )

    async def delete_user_password_history(self, user_id: str) -> None:
        """Удалить историю паролей пользователя."""
        self._database.execute(
            "DELETE FROM auth.password_history WHERE user_id = %s", user_id,
        )

    async def delete_group_memberships(self, group_id: str) -> None:
        """Удалить все связи участников группы."""
        self._database.execute(
            "DELETE FROM auth.user_group_membership WHERE group_id = %s", group_id,
        )

    async def delete_group_hierarchy(self, group_id: str) -> None:
        """Удалить все иерархические связи группы."""
        self._database.execute(
            "DELETE FROM auth.group_group_membership "
            "WHERE parent_group_id = %s OR child_group_id = %s",
            group_id,
        )

    async def delete_group_role_assignments(self, group_id: str) -> None:
        """Удалить все назначения ролей группы."""
        self._database.execute(
            "DELETE FROM auth.group_roles WHERE group_id = %s", group_id,
        )

    async def delete_role_user_assignments(self, role_id: str) -> None:
        """Удалить все пользовательские назначения роли."""
        self._database.execute(
            "DELETE FROM auth.user_roles WHERE role_id = %s", role_id,
        )

    async def delete_role_group_assignments(self, role_id: str) -> None:
        """Удалить все групповые назначения роли."""
        self._database.execute(
            "DELETE FROM auth.group_roles WHERE role_id = %s", role_id,
        )

    async def delete_role_permissions(self, role_id: str) -> None:
        """Удалить все permissions роли."""
        self._database.execute(
            "DELETE FROM auth.role_permissions WHERE role_id = %s", role_id,
        )

    async def get_role_permissions(self, role_id: str) -> list[dict[str, Any]]:
        """Получить permissions роли."""
        rows = self._database.fetch(
            "SELECT p.name, p.description FROM auth.role_permissions rp "
            "JOIN auth.permissions p ON p.id = rp.permission_id "
            "WHERE rp.role_id = %s",
            role_id,
        )
        return [dict(p) for p in rows]

    async def copy_role_permissions(self, source_id: str, target_id: str) -> None:
        """Скопировать все role_permissions, не только mapped."""
        self._database.execute(
            "INSERT INTO auth.role_permissions (role_id, permission_id) "
            "SELECT %s, rp.permission_id FROM auth.role_permissions rp "
            "WHERE rp.role_id = %s "
            "ON CONFLICT DO NOTHING",
            target_id,
            source_id,
        )

    async def find_role_by_name(self, name: str) -> dict[str, Any] | None:
        """Найти роль по имени."""
        return await self._fetchrow(
            "SELECT id FROM auth.roles WHERE name = %s", name,
        )

    async def find_group_by_name(self, name: str) -> dict[str, Any] | None:
        """Найти группу по имени."""
        return await self._fetchrow(
            "SELECT id FROM auth.groups WHERE name = %s", name,
        )

    # ─────────────────────────────────────────────
    # Домены (scope-модель, Часть 2)
    # ─────────────────────────────────────────────

    async def create_domain(
        self,
        name: str,
        kind: str = "user",
        owner_id: str | None = None,
        display_name: str | None = None,
        identity_kind: str = "local",
        auth_config: dict[str, Any] | None = None,
        ad_config: dict[str, Any] | None = None,
        root_ou_id: str | None = None,
    ) -> dict[str, Any]:
        """Создать домен-тенант. Секреты в конфиги не пишем (§10.2).

        root_ou_id — OU-узел домена в system.ou (DDL-008 FK).
        """
        import json

        return await self._fetchrow(
            "INSERT INTO auth.domains "
            "(name, display_name, kind, owner_id, identity_kind, auth_config, "
            "ad_config, root_ou_id) "
            "VALUES (%s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s) "
            "RETURNING *",
            name, display_name, kind, owner_id, identity_kind,
            json.dumps(auth_config or {}), json.dumps(ad_config or {}), root_ou_id,
        ) or {}

    async def get_domain(self, domain_id: str) -> dict[str, Any] | None:
        """Домен по ID."""
        return await self._fetchrow(
            "SELECT * FROM auth.domains WHERE id = %s", domain_id,
        )

    async def get_domain_by_root_ou(self, root_ou_id: str) -> dict[str, Any] | None:
        """Домен по корневому OU (обратная сторона root_ou_id)."""
        return await self._fetchrow(
            "SELECT * FROM auth.domains WHERE root_ou_id = %s", root_ou_id,
        )

    async def get_domain_by_name(self, name: str) -> dict[str, Any] | None:
        """Домен по слагу."""
        return await self._fetchrow(
            "SELECT * FROM auth.domains WHERE name = %s", name,
        )

    async def list_domains(self, kind: str | None = None) -> list[dict[str, Any]]:
        """Все домены; kind-фильтр опционален."""
        if kind:
            rows = self._database.fetch(
                "SELECT * FROM auth.domains WHERE kind = %s ORDER BY created_at",
                kind,
            )
        else:
            rows = self._database.fetch(
                "SELECT * FROM auth.domains ORDER BY created_at",
            )
        return [dict(row) for row in rows]

    # Колонки, которые Tenant.update/set_identity_kind вправе менять
    _DOMAIN_UPDATE_FIELDS = frozenset({
        "name", "display_name", "identity_kind", "auth_config", "ad_config",
    })

    async def update_domain(
        self, domain_id: str, data: dict[str, Any],
    ) -> dict[str, Any] | None:
        """UPDATE домена по whitelist; kind/owner — только через DDL-инварианты."""
        import json

        filtered = {
            key: (json.dumps(value) if key in ("auth_config", "ad_config") else value)
            for key, value in data.items()
            if key in self._DOMAIN_UPDATE_FIELDS
        }
        if not filtered:
            return await self.get_domain(domain_id)
        assignments = ", ".join(
            f"{field} = %s::jsonb" if field in ("auth_config", "ad_config") else f"{field} = %s"
            for field in filtered
        )
        values: list[Any] = list(filtered.values())
        values.append(domain_id)
        return await self._fetchrow(
            f"UPDATE auth.domains SET {assignments}, updated_at = NOW() "
            "WHERE id = %s RETURNING *",
            *values,
        )

    async def set_domain_status(self, domain_id: str, status: str) -> None:
        """Сменить статус домена (active/suspended)."""
        self._database.execute(
            "UPDATE auth.domains SET status = %s, updated_at = NOW() WHERE id = %s",
            status, domain_id,
        )

    # ─────────────────────────────────────────────
    # Федеративные линки (handshake pending → active → revoked)
    # ─────────────────────────────────────────────

    async def create_domain_link(
        self,
        domain_a_id: str,
        domain_b_id: str,
        created_by: str | None = None,
    ) -> dict[str, Any]:
        """Создать линк в статусе 'pending'.

        Канонический порядок (a < b) — требование CHECK ddl/008:
        сортируем UUID сами, дубль пары отсеет uq_domain_links_pair.
        """
        low, high = sorted((domain_a_id, domain_b_id))
        return await self._fetchrow(
            "INSERT INTO auth.domain_links (domain_a_id, domain_b_id, created_by) "
            "VALUES (%s, %s, %s) RETURNING *",
            low, high, created_by,
        ) or {}

    async def list_links_for_domain(self, domain_id: str) -> list[dict[str, Any]]:
        """Линки домена (обе стороны — canon-порядок не задаёт роль)."""
        rows = self._database.fetch(
            "SELECT * FROM auth.domain_links "
            "WHERE domain_a_id = %s OR domain_b_id = %s ORDER BY created_at DESC",
            domain_id, domain_id,
        )
        return [dict(row) for row in rows]

    async def set_link_status(self, link_id: str, status: str) -> dict[str, Any] | None:
        """Handshake-переход: pending→active, *→revoked. Revoked не воскресает.

        None — линка нет; строка с прежним status — переход отклонён.
        """
        current = await self._fetchrow(
            "SELECT * FROM auth.domain_links WHERE id = %s", link_id,
        )
        if not current:
            return None
        if current.get("status") == "revoked" and status != "revoked":
            return current
        return await self._fetchrow(
            "UPDATE auth.domain_links SET status = %s WHERE id = %s RETURNING *",
            status, link_id,
        )

    # ─────────────────────────────────────────────
    # Доменный скоупинг прав и видимости
    # ─────────────────────────────────────────────

    async def check_permission_in_domain(
        self, user_id: str, permission: str, domain_id: str,
    ) -> bool:
        """Право через роль, назначенную группе ЭТОГО домена (или федеративной).

        Прямые user_roles не скоупятся доменом (решение Эны): только
        группы scope='domain' домена и группы активных линков домена.
        Wildcard: '*:*' и 'resource:*'.
        """
        resource = permission.split(":", 1)[0]
        row = await self._fetchrow(
            "SELECT EXISTS("
            "  SELECT 1 FROM auth.user_group_membership ugm "
            "  JOIN auth.groups g ON g.id = ugm.group_id "
            "  JOIN auth.group_roles gr ON gr.group_id = g.id "
            "  JOIN auth.role_permissions rp ON rp.role_id = gr.role_id "
            "  JOIN auth.permissions p ON p.id = rp.permission_id "
            "  WHERE ugm.user_id = %s "
            "    AND (p.name = %s OR p.name = '*:*' OR p.name = %s) "
            "    AND ("
            "      g.domain_id = %s "
            "      OR g.link_id IN ("
            "        SELECT id FROM auth.domain_links "
            "        WHERE status = 'active' AND (domain_a_id = %s OR domain_b_id = %s)"
            "      )"
            "    )"
            ")",
            user_id, permission, f"{resource}:*", domain_id, domain_id, domain_id,
        )
        return bool(row.get("exists")) if row else False

    async def get_user_visible_domains(self, user_id: str) -> list[str]:
        """Домены юзера: свой + партнёры активных линков (федерация).

        Предикат видимости llm-каталога: scope='system' OR
        (scope='domain' AND domain_id IN visible_domains).
        """
        rows = self._database.fetch(
            "SELECT u.domain_id AS own, other.domain_id AS peer FROM auth.users u "
            "LEFT JOIN LATERAL ("
            "  SELECT CASE WHEN l.domain_a_id = u.domain_id THEN l.domain_b_id "
            "              ELSE l.domain_a_id END AS domain_id "
            "  FROM auth.domain_links l "
            "  WHERE l.status = 'active' "
            "    AND (l.domain_a_id = u.domain_id OR l.domain_b_id = u.domain_id)"
            ") other ON TRUE "
            "WHERE u.id = %s",
            user_id,
        )
        found: set[str] = set()
        for row in rows:
            for key in ("own", "peer"):
                value = row.get(key)
                if value:
                    found.add(str(value))
        return list(found)
