-- 003_checks.sql: CHECK constraints для auth модуля
-- Все constraints используют IF NOT EXISTS / DO $$ для идемпотентности

DO $$ BEGIN
    -- Email regex constraint
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'chk_users_email' AND conrelid = 'auth.users'::regclass
    ) THEN
        ALTER TABLE auth.users
            ADD CONSTRAINT chk_users_email
            CHECK (email IS NULL OR email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$');
    END IF;
END $$;

DO $$ BEGIN
    -- login_attempts >= 0
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'chk_users_login_attempts' AND conrelid = 'auth.users'::regclass
    ) THEN
        ALTER TABLE auth.users
            ADD CONSTRAINT chk_users_login_attempts
            CHECK (login_attempts >= 0);
    END IF;
END $$;

DO $$ BEGIN
    -- groups.name длина >= 2
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'chk_groups_name_len' AND conrelid = 'auth.groups'::regclass
    ) THEN
        ALTER TABLE auth.groups
            ADD CONSTRAINT chk_groups_name_len
            CHECK (LENGTH(name) >= 2);
    END IF;
END $$;

DO $$ BEGIN
    -- group_group_membership: нет самосвязей
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'chk_group_group_no_self' AND conrelid = 'auth.group_group_membership'::regclass
    ) THEN
        ALTER TABLE auth.group_group_membership
            ADD CONSTRAINT chk_group_group_no_self
            CHECK (parent_group_id <> child_group_id);
    END IF;
END $$;
