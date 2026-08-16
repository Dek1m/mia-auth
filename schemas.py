"""Auth DB Schema — 11 таблиц модуля авторизации.

Формат Schema-first: dict с ключом "columns".
Колонки описаны строками SQL-типов и约束.
Ключ "schema" указывает PostgreSQL-схему для всех таблиц.
Ключ "auto_id": False отключает автодобавление id UUID PK.
Ключ "primary_key": [...] задаёт составной PK.
"""
from __future__ import annotations

__all__ = ["DB_SCHEMA"]

DB_SCHEMA: dict[str, dict[str, Any]] = {
    "schema": "auth",

    # ── Пользователи ──────────────────────────────────────────
    "users": {
        "columns": {
            "id": "UUID PRIMARY KEY DEFAULT gen_random_uuid()",
            "username": "VARCHAR(255) UNIQUE NOT NULL",
            "password_hash": "TEXT NOT NULL",
            "first_name": "VARCHAR(255)",
            "last_name": "VARCHAR(255)",
            "email": "VARCHAR(255) UNIQUE",
            "description": "TEXT",
            "is_active": "BOOLEAN DEFAULT TRUE",
            "locked_until": "TIMESTAMPTZ",
            "is_disabled": "BOOLEAN DEFAULT FALSE",
            "disabled_at": "TIMESTAMPTZ",
            "enabled_at": "TIMESTAMPTZ",
            "last_login": "TIMESTAMPTZ",
            "login_attempts": "INT DEFAULT 0",
            "custom_fields": "JSONB DEFAULT '{}'",
            "created_at": "TIMESTAMPTZ DEFAULT NOW()",
            "updated_at": "TIMESTAMPTZ DEFAULT NOW()",
        },
    },
    # ── Группы ────────────────────────────────────────────────
    "groups": {
        "columns": {
            "id": "UUID PRIMARY KEY DEFAULT gen_random_uuid()",
            "name": "VARCHAR(255) UNIQUE NOT NULL",
            "description": "TEXT",
            "is_builtin": "BOOLEAN DEFAULT FALSE",
            "created_at": "TIMESTAMPTZ DEFAULT NOW()",
            "updated_at": "TIMESTAMPTZ DEFAULT NOW()",
        },
    },
    # ── Роли ──────────────────────────────────────────────────
    "roles": {
        "columns": {
            "id": "UUID PRIMARY KEY DEFAULT gen_random_uuid()",
            "name": "VARCHAR(255) UNIQUE NOT NULL",
            "description": "TEXT",
            "is_builtin": "BOOLEAN DEFAULT FALSE",
            "source_module": "VARCHAR(100)",
            "created_at": "TIMESTAMPTZ DEFAULT NOW()",
            "updated_at": "TIMESTAMPTZ DEFAULT NOW()",
        },
    },
    # ── Разрешения ────────────────────────────────────────────
    "permissions": {
        "columns": {
            "id": "UUID PRIMARY KEY DEFAULT gen_random_uuid()",
            "name": "VARCHAR(255) UNIQUE NOT NULL",
            "description": "TEXT",
            "is_builtin": "BOOLEAN DEFAULT FALSE",
            "source_module": "VARCHAR(100)",
            "created_at": "TIMESTAMPTZ DEFAULT NOW()",
            "updated_at": "TIMESTAMPTZ DEFAULT NOW()",
        },
    },
    # ── Связь пользователи ↔ группы ───────────────────────────
    "user_group_membership": {
        "auto_id": False,
        "primary_key": ["user_id", "group_id"],
        "columns": {
            "user_id": "UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE",
            "group_id": "UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE",
            "added_at": "TIMESTAMPTZ DEFAULT NOW()",
            "added_by": "UUID REFERENCES users(id)",
        },
    },
    # ── Связь группы ↔ группы (иерархия) ──────────────────────
    "group_group_membership": {
        "auto_id": False,
        "primary_key": ["parent_group_id", "child_group_id"],
        "columns": {
            "parent_group_id": "UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE",
            "child_group_id": "UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE",
            "created_at": "TIMESTAMPTZ DEFAULT NOW()",
        },
    },
    # ── Связь группы ↔ роли ───────────────────────────────────
    "group_roles": {
        "auto_id": False,
        "primary_key": ["group_id", "role_id"],
        "columns": {
            "group_id": "UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE",
            "role_id": "UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE",
            "created_at": "TIMESTAMPTZ DEFAULT NOW()",
        },
    },
    # ── Связь пользователи ↔ роли (прямые) ────────────────────
    "user_roles": {
        "auto_id": False,
        "primary_key": ["user_id", "role_id"],
        "columns": {
            "user_id": "UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE",
            "role_id": "UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE",
            "granted_at": "TIMESTAMPTZ DEFAULT NOW()",
            "granted_by": "UUID REFERENCES users(id)",
        },
    },
    # ── Связь роли ↔ разрешения ───────────────────────────────
    "role_permissions": {
        "auto_id": False,
        "primary_key": ["role_id", "permission_id"],
        "columns": {
            "role_id": "UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE",
            "permission_id": "UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE",
        },
    },
    # ── Сессии ────────────────────────────────────────────────
    "auth_sessions": {
        "columns": {
            "id": "UUID PRIMARY KEY DEFAULT gen_random_uuid()",
            "user_id": "UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE",
            "access_token_hash": "VARCHAR(64)",
            "access_expires_at": "TIMESTAMPTZ",
            "refresh_token_hash": "VARCHAR(64)",
            "refresh_expires_at": "TIMESTAMPTZ",
            "user_agent": "TEXT",
            "ip_address": "INET",
            "is_revoked": "BOOLEAN DEFAULT FALSE",
            "revoked_at": "TIMESTAMPTZ",
            "family_id": "UUID",
            "created_at": "TIMESTAMPTZ DEFAULT NOW()",
            "last_used_at": "TIMESTAMPTZ",
        },
    },
    # ── История паролей ───────────────────────────────────────
    "password_history": {
        "columns": {
            "id": "UUID PRIMARY KEY DEFAULT gen_random_uuid()",
            "user_id": "UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE",
            "password_hash": "TEXT NOT NULL",
            "created_at": "TIMESTAMPTZ DEFAULT NOW()",
        },
    },
}
