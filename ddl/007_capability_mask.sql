-- 007_capability_mask.sql: денормализация маски ролей для UI (ADR-001 §5.3)
-- Enforcement остаётся на auth.role_permissions; колонка для чекбоксов.
ALTER TABLE auth.roles
    ADD COLUMN IF NOT EXISTS capability_mask BIGINT NOT NULL DEFAULT 0;
