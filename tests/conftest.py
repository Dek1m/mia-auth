"""Auth Tests — конфигурация и фикстуры.

PostgreSQL недоступен локально → используем mock pool.
"""
from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Any

import pytest


# ── Mock Pool ────────────────────────────────────────────


class MockRow:
    """Мок строки результата запроса."""

    def __init__(self, data: dict[str, Any]) -> None:
        self._data = data

    def __getitem__(self, key: str) -> Any:
        return self._data[key]

    def __contains__(self, key: str) -> bool:
        return key in self._data

    def keys(self):
        return self._data.keys()

    def __iter__(self):
        return iter(self._data)

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)

    def dict(self):
        return dict(self._data)


class MockPool:
    """Мок Database Provider для unit-тестов.

    Sync API (psycopg v3 compatible): execute, fetchrow, fetch, fetchval.
    Поддерживает SELECT, INSERT, UPDATE, DELETE, RETURNING.
    """

    def __init__(self) -> None:
        self._data: dict[str, dict[str, dict[str, Any]]] = {
            "auth.users": {},
            "auth.groups": {},
            "auth.roles": {},
            "auth.permissions": {},
            "auth.user_roles": {},
            "auth.group_roles": {},
            "auth.user_group_membership": {},
            "auth.group_group_membership": {},
            "auth.role_permissions": {},
            "auth.auth_sessions": {},
            "auth.password_history": {},
            "auth.user_avatars": {},
        }
        self._seq: int = 0

    def _next_id(self) -> str:
        self._seq += 1
        return str(uuid.uuid4())

    def _find_table(self, query: str) -> str | None:
        # Самое длинное имя: auth.users не должен ловить auth.user_avatars
        q = query.lower()
        found: str | None = None
        for table in self._data:
            if table in q and (found is None or len(table) > len(found)):
                found = table
        return found

    def execute(self, query: str, *params: Any) -> str:
        q = query.lower().strip()
        if "insert into" in q:
            return self._do_insert(query, params)
        if "update " in q and " set " in q:
            return self._do_update(query, params)
        if "delete from" in q:
            return self._do_delete(query, params)
        return "OK"

    def fetchrow(self, query: str, *params: Any) -> MockRow | None:
        rows = self.fetch(query, *params)
        return rows[0] if rows else None

    def fetchval(self, query: str, *params: Any) -> Any:
        rows = self.fetch(query, *params)
        if not rows:
            return None
        if "count(*)" in query.lower():
            return rows[0].get("count", 0)
        keys = list(rows[0].keys()) if rows else []
        return rows[0][keys[0]] if keys else None

    def fetch(self, query: str, *params: Any) -> list[MockRow]:
        q = query.lower().strip()
        if "insert into" in q and "returning" in q:
            table = self._find_table(query)
            if not table:
                return []
            self._do_insert(query, params)
            if table in self._data and self._data[table]:
                last_id = list(self._data[table].keys())[-1]
                return [MockRow(self._data[table][last_id])]
            return []
        if "update " in q and "returning" in q:
            table = self._find_table(query)
            if not table:
                return []
            return [MockRow(r) for r in self._do_update_returning(query, params)]
        if "with recursive" in q or "with " in q:
            return []
        if " union " in q:
            return []
        table = self._find_table(query)
        if table is None:
            return []
        # WHERE clause
        where_idx = q.find(" where ")
        if where_idx >= 0:
            where_clause = q[where_idx + 7:]
            return [
                MockRow(row) for row in self._data[table].values()
                if self._match_where(row, where_clause, params)
            ]
        return [MockRow(row) for row in self._data[table].values()]

    def _match_where(self, row: dict, where_clause: str, params: tuple) -> bool:
        """Проверяет row по WHERE clause."""
        conditions = self._extract_conditions_from_where(where_clause, params)
        return self._match(row, conditions)
    
    def _extract_conditions_from_where(self, where_clause: str, params: tuple) -> list:
        """Извлечь условия из WHERE clause."""
        conditions = []
        parts = where_clause.split(" and ")
        param_idx = 0
        for part in parts:
            part = part.strip()
            if "=" in part:
                col, val = part.split("=", 1)
                col = col.strip()
                val = val.strip()
                if val.startswith("%s") or val.startswith("$"):
                    if param_idx < len(params):
                        conditions.append((col, params[param_idx]))
                        param_idx += 1
                else:
                    val = val.strip("'")
                    # Конвертируем SQL boolean в Python
                    if val.upper() == "TRUE":
                        val = True
                    elif val.upper() == "FALSE":
                        val = False
                    conditions.append((col, val))
        return conditions

    def _match(self, row: dict, conditions: list) -> bool:
        """Проверяет row по AND условиям."""
        for field, value in conditions:
            row_val = row.get(field)
            if isinstance(value, (list, tuple)):
                if row_val not in value:
                    return False
            else:
                if row_val != value:
                    if isinstance(value, str) and isinstance(row_val, str):
                        if value.startswith("%") and value.endswith("%"):
                            search = value[1:-1]
                            if search.lower() not in row_val.lower():
                                return False
                        elif value.startswith("%"):
                            search = value[1:]
                            if not row_val.lower().endswith(search.lower()):
                                return False
                        elif value.endswith("%"):
                            search = value[:-1]
                            if not row_val.lower().startswith(search.lower()):
                                return False
                        else:
                            return False
                    elif row_val is None and value is not None:
                        return False
                    elif row_val is not None and value is None:
                        return False
                    else:
                        return False
        return True

    def _extract_conditions(self, query: str, params: tuple) -> list:
        """Извлечь условия из WHERE clause в запросе."""
        q = query.lower()
        where_idx = q.find(" where ")
        if where_idx < 0:
            return []
        where_clause = q[where_idx + 7:]
        # Считаем количество %s в SET (до WHERE)
        set_part = q[:where_idx]
        set_params_count = set_part.count("%s")
        # Передаём только WHERE параметры
        where_params = params[set_params_count:] if set_params_count > 0 else params
        return self._extract_conditions_from_where(where_clause, where_params)

    def _do_insert(self, query: str, params: tuple) -> str:
        """Вставка записи."""
        m = re.search(r'insert\s+into\s+(\S+)\s*\(([^)]+)\)', query.lower())
        if not m:
            return "INSERT 0 1"

        table = m.group(1)
        cols_str = m.group(2)
        columns = [c.strip() for c in cols_str.split(",")]

        if table not in self._data:
            self._data[table] = {}

        row_id = self._next_id()
        row: dict[str, Any] = {"id": row_id}

        for i, col in enumerate(columns):
            if col == "id" and i < len(params) and params[i]:
                row_id = params[i]
                row["id"] = row_id
            elif i < len(params):
                row[col] = params[i]

        # ON CONFLICT
        if "on conflict" in query.lower():
            if "do nothing" in query.lower():
                for _, existing in self._data[table].items():
                    for col in columns:
                        if col in row and col in existing and existing.get(col) == row.get(col):
                            if col in ("username", "name", "email", "refresh_token_hash",
                                       "access_token_hash"):
                                return "INSERT 0 1"

            # ON CONFLICT DO UPDATE
            for _, existing in self._data[table].items():
                conflict = False
                for col in columns:
                    if col in row and col in existing and existing.get(col) == row.get(col):
                        if col in ("username", "name", "email", "refresh_token_hash",
                                   "access_token_hash"):
                            conflict = True
                            break
                if conflict:
                    for key, value in row.items():
                        if key != "id":
                            existing[key] = value
                    return "INSERT 0 1"

        self._data[table][row_id] = row

        # Apply DEFAULT values for known columns
        _defaults = {
            "auth.users": {
                "is_active": True,
                "is_disabled": False,
                "login_attempts": 0,
                "locked_until": None,
                "nickname": None,
                "phone": None,
                "user_prompt": None,
                "chip_display_mode": "nickname",
                "is_bootstrap_admin": False,
                "created_at": datetime.now(timezone.utc),
                "updated_at": datetime.now(timezone.utc),
            },
            "auth.user_group_membership": {
                "is_primary": False,
            },
            "auth.groups": {
                "is_builtin": False,
                "created_at": datetime.now(timezone.utc),
                "updated_at": datetime.now(timezone.utc),
            },
            "auth.roles": {
                "is_builtin": False,
                "created_at": datetime.now(timezone.utc),
                "updated_at": datetime.now(timezone.utc),
            },
            "auth.auth_sessions": {
                "is_revoked": False,
                "created_at": datetime.now(timezone.utc),
            },
        }
        if table in _defaults:
            for col, default_val in _defaults[table].items():
                if col not in row:
                    row[col] = default_val

        return "INSERT 0 1"

    def _do_update(self, query: str, params: tuple) -> str:
        """UPDATE без RETURNING."""
        table = self._find_table(query)
        if not table or table not in self._data:
            return "UPDATE 0"

        conditions = self._extract_conditions(query, params)
        q = query.lower()

        set_match = re.search(r'set\s+(.*?)\s+where', q, re.DOTALL)
        if not set_match:
            set_match = re.search(r'set\s+(.*?)$', q, re.DOTALL)
        if not set_match:
            return "UPDATE 0"

        set_part = set_match.group(1)
        updated = 0
        for _, row in self._data[table].items():
            if self._match(row, conditions):
                self._apply_set(row, set_part, params)
                updated += 1

        return f"UPDATE {updated}"

    def _do_update_returning(self, query: str, params: tuple) -> list[dict]:
        """UPDATE ... RETURNING — возвращает обновлённые строки."""
        table = self._find_table(query)
        if not table or table not in self._data:
            return []

        conditions = self._extract_conditions(query, params)
        q = query.lower()

        # Парсим SET
        set_match = re.search(r'set\s+(.*?)\s+where', q, re.DOTALL)
        if not set_match:
            set_match = re.search(r'set\s+(.*?)$', q, re.DOTALL)
        if not set_match:
            return []

        set_part = set_match.group(1)

        updated_rows = []
        for _, row in self._data[table].items():
            if self._match(row, conditions):
                self._apply_set(row, set_part, params)
                updated_rows.append(dict(row))

        return updated_rows

    def _apply_set(self, row: dict, set_part: str, params: tuple) -> None:
        """Применить SET операции к строке."""
        # field = $N (numbered parameters, 1-indexed)
        for match in re.finditer(r'(\w+)\s*=\s*\$(\d+)', set_part):
            field = match.group(1)
            param_idx = int(match.group(2)) - 1
            if 0 <= param_idx < len(params):
                row[field] = params[param_idx]

        # field = %s (sequential parameters, consumed from params start)
        percent_s_idx = 0
        for match in re.finditer(r'(\w+)\s*=\s*%s', set_part):
            field = match.group(1)
            if percent_s_idx < len(params):
                row[field] = params[percent_s_idx]
                percent_s_idx += 1

        # field = field + $N (increment)
        for match in re.finditer(r'(\w+)\s*=\s*(\w+)\s*\+\s*(?:\$(\d+)|(\d+))', set_part):
            field = match.group(1)
            if match.group(3):  # $N — параметр
                param_idx = int(match.group(3)) - 1
                if 0 <= param_idx < len(params):
                    increment = params[param_idx]
                else:
                    increment = 0
            elif match.group(4):  # Literal число
                increment = int(match.group(4))
            else:
                increment = 0
            current = row.get(field, 0) or 0
            row[field] = current + increment

        # field = N (literal number assignment)
        for match in re.finditer(r'(\w+)\s*=\s*(\d+)(?!\s*\+)', set_part):
            field = match.group(1)
            row[field] = int(match.group(2))

        # field = NOW() / field = NULL / field = TRUE / field = FALSE
        for match in re.finditer(r'(\w+)\s*=\s*(now\(\)|null|true|false)', set_part):
            field = match.group(1)
            value_str = match.group(2).lower()
            if value_str == "now()":
                row[field] = datetime.now(timezone.utc)
            elif value_str == "null":
                row[field] = None
            elif value_str == "true":
                row[field] = True
            elif value_str == "false":
                row[field] = False

    def _do_delete(self, query: str, params: tuple) -> str:
        """DELETE."""
        table = self._find_table(query)
        if not table or table not in self._data:
            return "DELETE 0"

        conditions = self._extract_conditions(query, params)
        to_delete = [
            row_id for row_id, row in self._data[table].items()
            if self._match(row, conditions)
        ]

        for row_id in to_delete:
            del self._data[table][row_id]

        return f"DELETE {len(to_delete)}"

    # Утилиты для тестов

    def insert_direct(self, table: str, row: dict[str, Any]) -> None:
        """Прямая вставка в mock pool."""
        if "id" not in row:
            row["id"] = self._next_id()
        if table not in self._data:
            self._data[table] = {}
        self._data[table][row["id"]] = row

    def get_all(self, table: str) -> dict[str, dict]:
        return self._data.get(table, {})

    def clear(self) -> None:
        for table in self._data:
            self._data[table].clear()
        self._seq = 0


# ── Фикстуры ────────────────────────────────────────────


class MockLogger:
    """Мок логера — ничего не делает, но не падает на вызовах."""

    def info(self, *args: Any, **kwargs: Any) -> None:
        pass

    def warning(self, *args: Any, **kwargs: Any) -> None:
        pass

    def error(self, *args: Any, **kwargs: Any) -> None:
        pass

    def debug(self, *args: Any, **kwargs: Any) -> None:
        pass


@pytest.fixture
def mock_pool() -> MockPool:
    return MockPool()


@pytest.fixture
def mock_logger() -> MockLogger:
    return MockLogger()


@pytest.fixture
def auth_config():
    from modules.auth.config import AuthConfig
    return AuthConfig(
        jwt_secret="test-secret-key-for-testing-12345",
        jwt_algorithm="HS256",
        jwt_access_expiration_minutes=15,
        jwt_refresh_expiration_days=30,
        password_min_length=8,
        password_require_uppercase=True,
        password_require_digit=True,
        password_history_size=10,
        login_attempts_limit=5,
        login_block_minutes=15,
        perms_cache_ttl=300,
        refresh_grace_seconds=0,
    )
