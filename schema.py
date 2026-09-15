"""Auth Core Schema — базовые permissions и роли модуля auth.

Описания на русском. Каждая permission и роль имеет description.
"""
from __future__ import annotations

from typing import Any

__all__ = ["AUTH_CORE_SCHEMA"]

AUTH_CORE_SCHEMA: dict[str, list[dict[str, Any]]] = {
    "permissions": [
        {"name": "*:*", "description": "Полный доступ ко всем ресурсам"},
        # === users ===
        {"name": "users:create", "description": "Создание пользователей"},
        {"name": "users:update", "description": "Обновление данных пользователей"},
        {"name": "users:delete", "description": "Удаление пользователей"},
        {"name": "users:list", "description": "Получение списка пользователей"},
        {"name": "users:read", "description": "Просмотр данных пользователя"},
        # === user_state ===
        {"name": "user_state:block", "description": "Блокировка пользователей"},
        {"name": "user_state:toggle", "description": "Переключение состояния активности пользователя"},
        # === passwords ===
        {"name": "passwords:manage", "description": "Управление паролями (сброс, принудительное изменение)"},
        # === groups ===
        {"name": "groups:create", "description": "Создание групп пользователей"},
        {"name": "groups:update", "description": "Обновление данных групп"},
        {"name": "groups:delete", "description": "Удаление групп"},
        {"name": "groups:list", "description": "Получение списка групп"},
        {"name": "groups:read", "description": "Просмотр данных группы"},
        {"name": "groups:manage_membership", "description": "Управление составом групп (добавление/удаление участников)"},
        # === roles ===
        {"name": "roles:create", "description": "Создание ролей"},
        {"name": "roles:update", "description": "Обновление данных ролей"},
        {"name": "roles:delete", "description": "Удаление ролей"},
        {"name": "roles:list", "description": "Получение списка ролей"},
        {"name": "roles:manage", "description": "Назначение ролей пользователям и группам"},
        {"name": "roles:inspect", "description": "Просмотр разрешений роли"},
        # === profile (свой профиль; не users:read — иначе дыра на чужие записи) ===
        {"name": "profile:self", "description": "Чтение и изменение собственного профиля"},
        {"name": "ui:windows", "description": "Сохранение размеров окон своего интерфейса"},
        # === system ===
        {"name": "system:force_delete", "description": "Принудительное удаление любых данных (только для system_admin)"},
        # === domains (scope-модель, Часть 2) ===
        {"name": "domains:create", "description": "Создание доменов-тенантов"},
        {"name": "domains:read", "description": "Просмотр доменов и их конфигурации"},
        {"name": "domains:update", "description": "Обновление доменов (имя, display_name)"},
        {"name": "domains:delete", "description": "Удаление доменов"},
        # === domain (внутри конкретного домена; enforcement — check_permission_in_domain) ===
        {"name": "domain:admin", "description": "Администрирование своего домена"},
        {"name": "domain:users_invite", "description": "Приглашение пользователей в домен"},
        {"name": "domain:users_remove", "description": "Исключение пользователей из домена"},
        {"name": "domain:groups_create", "description": "Создание групп в домене"},
        {"name": "domain:groups_manage", "description": "Управление группами домена и составом"},
        {"name": "domain:providers_manage", "description": "Управление LLM-провайдерами домена"},
        {"name": "domain:agents_manage", "description": "Управление агентами домена"},
        {"name": "domain:share", "description": "Расшаривание ресурсов домена соседям по федерации"},
        {"name": "domain:identity_configure", "description": "Настройка способа входа домена (identity_kind)"},
        # === federation (междоменные линки) ===
        {"name": "federation:propose", "description": "Предложение федеративного линка доменам"},
        {"name": "federation:approve", "description": "Подтверждение федеративного линка (handshake)"},
        {"name": "federation:revoke", "description": "Отзыв федеративного линка"},
    ],
    "roles": [
        {
            "name": "system_admin",
            "description": "Системный администратор — полный доступ ко всем ресурсам",
            "permissions": ["*:*"],
        },
        {
            "name": "user_manager",
            "description": "Менеджер пользователей — управление пользователями и их состоянием",
            "permissions": ["users:*", "user_state:*", "passwords:manage", "profile:self", "ui:windows"],
        },
        {
            "name": "group_manager",
            "description": "Менеджер групп — управление группами и их составом",
            "permissions": ["groups:*", "groups:manage_membership", "profile:self", "ui:windows"],
        },
        {
            "name": "role_manager",
            "description": "Менеджер ролей — управление ролями и назначение разрешений",
            "permissions": ["roles:*", "profile:self", "ui:windows"],
        },
        # ── Scope-модель (Часть 2): каркасы-записи; enforcement доменных
        # прав — через role_permissions + check_permission_in_domain,
        # существующие llm/auth-роли не затрагиваются.
        {
            "name": "domain_owner",
            "description": "Владелец домена-тенанта: полный контроль над доменом и федерацией",
            "permissions": [
                "domains:read", "domains:update", "domains:delete",
                "domain:*", "federation:*", "profile:self", "ui:windows",
            ],
        },
        {
            "name": "domain_admin",
            "description": "Администратор домена: пользователи, группы, агенты — без федерации",
            "permissions": [
                "domains:read",
                "domain:admin", "domain:users_invite", "domain:users_remove",
                "domain:groups_create", "domain:groups_manage",
                "domain:agents_manage", "domain:identity_configure",
                "profile:self", "ui:windows",
            ],
        },
        {
            "name": "domain_member",
            "description": "Участник домена: базовый доступ к системе",
            "permissions": ["profile:self", "ui:windows"],
        },
        {
            "name": "group_creator",
            "description": "Создание групп в домене (узкая делегация domain_admin)",
            "permissions": ["domain:groups_create", "profile:self", "ui:windows"],
        },
        {
            "name": "provider_sharer",
            "description": "Расшаривание ресурсов домена по федерации",
            "permissions": ["domain:share", "profile:self", "ui:windows"],
        },
    ],
}
