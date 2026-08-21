-- 004_albedo_profile.sql: профиль albedo (ADR-001)
-- Идемпотентно: ADD COLUMN IF NOT EXISTS, CREATE INDEX IF NOT EXISTS, сид ON CONFLICT.
-- Не DROP TABLE. Для уже существующей БД: колонки не появятся из CREATE TABLE IF NOT EXISTS.

-- ── Колонки auth.users ───────────────────────────────────
ALTER TABLE auth.users
    ADD COLUMN IF NOT EXISTS nickname VARCHAR(255);

ALTER TABLE auth.users
    ADD COLUMN IF NOT EXISTS phone VARCHAR(32);

ALTER TABLE auth.users
    ADD COLUMN IF NOT EXISTS user_prompt TEXT;

ALTER TABLE auth.users
    ADD COLUMN IF NOT EXISTS chip_display_mode VARCHAR(16) NOT NULL DEFAULT 'nickname';

ALTER TABLE auth.users
    ADD COLUMN IF NOT EXISTS is_bootstrap_admin BOOLEAN NOT NULL DEFAULT FALSE;

-- ── Колонка primary membership ───────────────────────────
ALTER TABLE auth.user_group_membership
    ADD COLUMN IF NOT EXISTS is_primary BOOLEAN NOT NULL DEFAULT FALSE;

-- ── Таблица аватаров (байты; SVG запрещён на уровне приложения) ─
CREATE TABLE IF NOT EXISTS auth.user_avatars (
    user_id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    bytes BYTEA NOT NULL,
    content_type VARCHAR(64) NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ── Индексы ──────────────────────────────────────────────
-- Ровно одна primary-группа на пользователя (ADR-001 §7.3)
CREATE UNIQUE INDEX IF NOT EXISTS idx_user_group_membership_is_primary
    ON auth.user_group_membership (user_id)
    WHERE is_primary;

-- ── CHECK ────────────────────────────────────────────────
DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'chk_users_chip_display_mode'
          AND conrelid = 'auth.users'::regclass
    ) THEN
        ALTER TABLE auth.users
            ADD CONSTRAINT chk_users_chip_display_mode
            CHECK (chip_display_mode IN ('nickname', 'full_name'));
    END IF;
END $$;

-- ── Сид Administrators ───────────────────────────────────
INSERT INTO auth.groups (name, description, is_builtin)
VALUES ('Administrators', 'Встроенная группа системных администраторов', TRUE)
ON CONFLICT (name) DO UPDATE SET is_builtin = TRUE;

-- ── Backfill уже существующего первого system_admin ──────
-- Нужен, если bootstrap уже был до колонки is_bootstrap_admin.
UPDATE auth.users u
SET is_bootstrap_admin = TRUE
WHERE u.id = (
    SELECT u2.id
    FROM auth.users u2
    JOIN auth.user_roles ur ON ur.user_id = u2.id
    JOIN auth.roles r ON r.id = ur.role_id
    WHERE r.name = 'system_admin'
    ORDER BY u2.created_at ASC
    LIMIT 1
)
AND NOT EXISTS (
    SELECT 1 FROM auth.users WHERE is_bootstrap_admin
);

INSERT INTO auth.user_group_membership (user_id, group_id, is_primary)
SELECT u.id, g.id, TRUE
FROM auth.users u
CROSS JOIN auth.groups g
WHERE u.is_bootstrap_admin
  AND g.name = 'Administrators'
ON CONFLICT (user_id, group_id) DO NOTHING;

UPDATE auth.user_group_membership ugm
SET is_primary = TRUE
FROM auth.groups g
WHERE ugm.group_id = g.id
  AND g.name = 'Administrators'
  AND ugm.user_id IN (SELECT id FROM auth.users WHERE is_bootstrap_admin)
  AND NOT EXISTS (
      SELECT 1
      FROM auth.user_group_membership x
      WHERE x.user_id = ugm.user_id
        AND x.is_primary
  );

-- Down (ручной; _applied_ddl не откатывает файлы, Alembic в проекте нет):
--   DROP INDEX IF EXISTS auth.idx_user_group_membership_is_primary;
--   ALTER TABLE auth.users DROP CONSTRAINT IF EXISTS chk_users_chip_display_mode;
--   ALTER TABLE auth.user_group_membership DROP COLUMN IF EXISTS is_primary;
--   ALTER TABLE auth.users DROP COLUMN IF EXISTS nickname;
--   ALTER TABLE auth.users DROP COLUMN IF EXISTS phone;
--   ALTER TABLE auth.users DROP COLUMN IF EXISTS user_prompt;
--   ALTER TABLE auth.users DROP COLUMN IF EXISTS chip_display_mode;
--   ALTER TABLE auth.users DROP COLUMN IF EXISTS is_bootstrap_admin;
--   -- user_avatars не DROP без бэкапа байтов
--   DELETE FROM _applied_ddl WHERE db_name = 'auth' AND ddl_file = '004_albedo_profile.sql';
