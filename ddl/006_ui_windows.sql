ALTER TABLE auth.users
    ADD COLUMN IF NOT EXISTS ui_windows JSONB NOT NULL DEFAULT jsonb_build_object();
