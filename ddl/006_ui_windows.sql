-- Геометрия окон albedo в профиле пользователя (не cookies).
ALTER TABLE auth.users
    ADD COLUMN IF NOT EXISTS ui_windows JSONB NOT NULL DEFAULT '{}'::jsonb;
