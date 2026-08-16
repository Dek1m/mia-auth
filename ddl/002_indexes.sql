-- 002_indexes.sql: Индексы для auth модуля
-- Все индексы используют IF NOT EXISTS для идемпотентности

-- Сессии: активные сессии пользователя
CREATE INDEX IF NOT EXISTS idx_sessions_user_active
    ON auth.auth_sessions (user_id, is_revoked, refresh_expires_at)
    WHERE NOT is_revoked;

-- Сессии: family_id для ротации токенов
CREATE INDEX IF NOT EXISTS idx_sessions_family
    ON auth.auth_sessions (family_id)
    WHERE NOT is_revoked;

-- Сессии: поиск по refresh_token_hash
CREATE INDEX IF NOT EXISTS idx_sessions_refresh_hash
    ON auth.auth_sessions (refresh_token_hash)
    WHERE NOT is_revoked;

-- Пользователи: GIN индекс по custom_fields
CREATE INDEX IF NOT EXISTS idx_users_custom_fields
    ON auth.users USING GIN (custom_fields);

-- Пользователи: только активные
CREATE INDEX IF NOT EXISTS idx_users_is_active
    ON auth.users (is_active)
    WHERE is_active;

-- Группы: только встроенные
CREATE INDEX IF NOT EXISTS idx_groups_is_builtin
    ON auth.groups (is_builtin)
    WHERE is_builtin;

-- История паролей: по пользователю, убывание по дате
CREATE INDEX IF NOT EXISTS idx_password_history_user
    ON auth.password_history (user_id, created_at DESC);
