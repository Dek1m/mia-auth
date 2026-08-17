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
    """Мок asyncpg pool для unit-тестов.

    Поддерживает SELECT, INSERT, UPDATE, DELETE, JOIN, UNION, CTE (упрощённо).
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
        }
        self._seq: int = 0

    def _next_id(self) -> str:
        self._seq += 1
        return str(uuid.uuid4())

    def _find_table(self, query: str) -> str | None:
        q = query.lower()
        for table in self._data:
            if table in q:
                return table
        return None

    def _find_all_tables(self, query: str) -> list[str]:
        q = query.lower()
        found = []
        for table in self._data:
            if table in q:
                found.append(table)
        return found

    async def execute(self, query: str, *params: Any) -> str:
        q = query.lower().strip()
        if "insert into" in q:
            return self._do_insert(query, params)
        if "update " in q and " set " in q:
            return self._do_update(query, params)
        if "delete from" in q:
            return self._do_delete(query, params)
        return "OK"

    async def fetchval(self, query: str, *params: Any) -> Any:
        if "count(*)" in query.lower():
            rows = await self.fetch(query, *params)
            if rows:
                return rows[0]["count"] if isinstance(rows[0], MockRow) else rows[0]
            return 0
        row = await self.fetchrow(query, *params)
        if row is None:
            return None
        keys = list(row.keys())
        return row[keys[0]] if keys else None

    async def fetchrow(self, query: str, *params: Any) -> MockRow | None:
        q = query.lower().strip()
        # INSERT ... RETURNING
        if "insert into" in q and "returning" in q:
            table = self._find_table(query)
            if not table:
                return None
            self._do_insert(query, params)
            if table in self._data and self._data[table]:
                last_id = list(self._data[table].keys())[-1]
                return MockRow(self._data[table][last_id])
            return None
        # UPDATE ... RETURNING
        if "update " in q and "returning" in q:
            table = self._find_table(query)
            if not table:
                return None
            updated_rows = self._do_update_returning(query, params)
            return MockRow(updated_rows[0]) if updated_rows else None
        rows = await self.fetch(query, *params)
        return rows[0] if rows else None

    async def fetch(self, query: str, *params: Any) -> list[MockRow]:
        q = query.lower().strip()

        # INSERT ... RETURNING — выполняем вставку и возвращаем строку
        if "insert into" in q and "returning" in q:
            table = self._find_table(query)
            if not table:
                return []
            self._do_insert(query, params)
            if table in self._data and self._data[table]:
                last_id = list(self._data[table].keys())[-1]
                return [MockRow(self._data[table][last_id])]
            return []

        # UPDATE ... RETURNING — выполняем обновление и возвращаем строки
        if "update " in q and "returning" in q:
            table = self._find_table(query)
            if not table:
                return []
            updated_rows = self._do_update_returning(query, params)
            return [MockRow(r) for r in updated_rows]

        # CTE (WITH RECURSIVE) — упрощённая поддержка
        if "with recursive" in q or "with " in q:
            return await self._handle_cte(query, params)

        # UNION — разбиваем и объединяем
        if " union " in q:
            return await self._handle_union(query, params)

        table = self._find_table(query)
        if not table:
            return []

        all_rows = list(self._data[table].values())

        # COUNT(*) без WHERE
        if "count(*)" in q and "where" not in q:
            return [MockRow({"count": len(all_rows)})]

        # WHERE фильтрация
        if "where" in q:
            # Проверяем наличие OR в WHERE
            where_idx = q.index("where")
            where_part = q[where_idx + 5:]
            for keyword in ("order by", "limit", "offset", "group by"):
                if keyword in where_part:
                    where_part = where_part.split(keyword)[0]
            if " or " in where_part:
                # OR условия: собираем все field=value пары
                or_conditions = []
                for match in re.finditer(r'(\w+)\s*(?:=|ilike)\s*\$(\d+)', where_part):
                    field = match.group(1)
                    param_idx = int(match.group(2)) - 1
                    if 0 <= param_idx < len(params):
                        or_conditions.append((field, params[param_idx]))
                all_rows = [r for r in all_rows if self._match_any_field(r, or_conditions)]
            else:
                conditions = self._extract_conditions(query, params)
                all_rows = [r for r in all_rows if self._match(r, conditions)]

        # COUNT с WHERE
        if "count(*)" in q:
            return [MockRow({"count": len(all_rows)})]

        # ORDER BY
        if "order by" in q:
            desc = "desc" in q
            all_rows.sort(key=lambda r: r.get("created_at", ""), reverse=desc)

        # LIMIT
        m = re.search(r'limit\s+\$?\d+', q)
        if m:
            limit_str = m.group(0).split()[-1]
            if limit_str.startswith("$"):
                idx = int(limit_str[1:]) - 1
                if idx < len(params):
                    all_rows = all_rows[:params[idx]]
            else:
                all_rows = all_rows[:int(limit_str)]

        # OFFSET
        m = re.search(r'offset\s+\$?\d+', q)
        if m:
            offset_str = m.group(0).split()[-1]
            if offset_str.startswith("$"):
                idx = int(offset_str[1:]) - 1
                if idx < len(params):
                    all_rows = all_rows[params[idx]:]

        return [MockRow(r) for r in all_rows]

    async def _handle_cte(self, query: str, params: tuple) -> list[MockRow]:
        """Упрощённая поддержка CTE запросов.

        Обрабатывает:
        - SELECT с JOIN через CTE
        - GROUP BY + COUNT
        - UNION в CTE
        """
        q = query.lower()

        # Определяем целевую таблицу (из FROM после CTE)
        # Простая эвристика: ищем FROM <table> после всех CTE
        main_table = None
        for table in self._data:
            # Ищем "FROM auth.XXX" или "JOIN auth.XXX" в финальном SELECT
            if f"from {table}" in q or f"join {table}" in q:
                main_table = table
                break

        if not main_table:
            # Fallback: берём первую найденную таблицу
            tables = self._find_all_tables(query)
            main_table = tables[0] if tables else None

        if not main_table:
            return []

        # Собираем все данные из вовлечённых таблиц
        all_rows = list(self._data[main_table].values())

        # WHERE фильтрация
        if "where" in q:
            conditions = self._extract_conditions(query, params)
            all_rows = [r for r in all_rows if self._match(r, conditions)]

        # GROUP BY — группировка
        if "group by" in q:
            return self._handle_group_by(query, all_rows)

        # UNION — собираем данные из всех таблиц
        if "union" in q:
            return await self._handle_union(query, params)

        # DISTINCT
        if "select distinct" in q:
            seen = set()
            unique = []
            for row in all_rows:
                key = str(sorted(row.items()))
                if key not in seen:
                    seen.add(key)
                    unique.append(row)
            all_rows = unique

        # ORDER BY
        if "order by" in q:
            desc = "desc" in q
            # Определяем поле для сортировки
            order_match = re.search(r'order by\s+(\w+)', q)
            if order_match:
                field = order_match.group(1)
                all_rows.sort(key=lambda r: r.get(field, ""), reverse=desc)

        return [MockRow(r) for r in all_rows]

    def _handle_group_by(self, query: str, rows: list[dict]) -> list[MockRow]:
        """Обработка GROUP BY."""
        q = query.lower()
        # COUNT(*) + GROUP BY → количество уникальных групп
        if "count(*)" in q:
            return [MockRow({"count": len(rows)})]
        return [MockRow(r) for r in rows]

    async def _handle_union(self, query: str, params: tuple) -> list[MockRow]:
        """Обработка UNION запросов."""
        # Разбиваем по UNION
        parts = re.split(r'\bunion\b', query, flags=re.IGNORECASE)
        all_results = []
        for part in parts:
            part = part.strip()
            if not part:
                continue
            rows = await self.fetch(part, *params)
            all_results.extend(rows)

        # DISTINCT по id если есть
        seen_ids = set()
        unique = []
        for row in all_results:
            row_dict = row._data if isinstance(row, MockRow) else row
            row_id = row_dict.get("id", str(row_dict))
            if row_id not in seen_ids:
                seen_ids.add(row_id)
                unique.append(row)

        return unique

    def _extract_conditions(self, query: str, params: tuple) -> list[tuple[str, Any]]:
        """Извлекает WHERE условия. Возвращает (field, value) для AND условий."""
        conditions = []
        q = query.lower()
        if "where" not in q:
            return conditions

        where_part = q.split("where", 1)[1]
        for keyword in ("order by", "limit", "offset", "group by"):
            if keyword in where_part:
                where_part = where_part.split(keyword)[0]

        # field = $N or field ILIKE $N
        for match in re.finditer(r'(\w+)\s*(?:=|ilike)\s*\$(\d+)', where_part):
            field = match.group(1)
            param_idx = int(match.group(2)) - 1
            if 0 <= param_idx < len(params):
                conditions.append((field, params[param_idx]))

        # field IN ($N, $2, ...)
        in_pattern = re.compile(r'(\w+)\s+in\s*\(([^)]+)\)')
        for match in in_pattern.finditer(where_part):
            field = match.group(1)
            params_str = match.group(2)
            param_nums = re.findall(r'\$(\d+)', params_str)
            values = []
            for pnum in param_nums:
                pidx = int(pnum) - 1
                if 0 <= pidx < len(params):
                    val = params[pidx]
                    if isinstance(val, (list, tuple)):
                        values.extend(val)
                    else:
                        values.append(val)
            if values:
                conditions.append((field, values))

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

    def _match_any_field(self, row: dict, field_value_pairs: list[tuple[str, Any]]) -> bool:
        """Проверяет row по OR условиям: хотя бы одно поле должно совпасть."""
        for field, value in field_value_pairs:
            row_val = row.get(field)
            if row_val is None:
                continue
            if isinstance(value, str) and isinstance(row_val, str):
                if value.startswith("%") and value.endswith("%"):
                    search = value[1:-1]
                    if search.lower() in row_val.lower():
                        return True
                elif value.startswith("%"):
                    search = value[1:]
                    if row_val.lower().endswith(search.lower()):
                        return True
                elif value.endswith("%"):
                    search = value[:-1]
                    if row_val.lower().startswith(search.lower()):
                        return True
                elif row_val == value:
                    return True
            elif row_val == value:
                return True
        return False

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
            if col == "id":
                continue
            if i < len(params):
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
                "created_at": datetime.now(timezone.utc),
                "updated_at": datetime.now(timezone.utc),
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
        # field = $N
        for match in re.finditer(r'(\w+)\s*=\s*\$(\d+)', set_part):
            field = match.group(1)
            param_idx = int(match.group(2)) - 1
            if 0 <= param_idx < len(params):
                row[field] = params[param_idx]

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


@pytest.fixture
def mock_pool() -> MockPool:
    return MockPool()


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
    )
