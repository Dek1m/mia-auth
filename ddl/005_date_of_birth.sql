-- date_of_birth для профиля пользователя
ALTER TABLE auth.users
    ADD COLUMN IF NOT EXISTS date_of_birth DATE;
