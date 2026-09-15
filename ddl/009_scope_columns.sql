-- 009_scope_columns.sql: scope-модель на существующих таблицах (Часть 2).
-- users: domain_id (двухшагово: NULL → backfill Argenta → SET NOT NULL).
-- groups: тройник scope/domain_id/owner_id + link_id (федеративные группы).
-- Бэкфилл: builtin-группы (Administrators, Everyone) → scope='system';
-- остальные → scope='domain' + domain_id = builtin-домен Argenta (сид 008).
-- Идемпотентно. Транзакция DDLTracker: backfill и SET NOT NULL атомарны.

-- ── users.domain_id: шаг 1 — колонка nullable ──────────
ALTER TABLE auth.users
    ADD COLUMN IF NOT EXISTS domain_id UUID REFERENCES auth.domains(id) ON DELETE RESTRICT;

-- ── users.domain_id: шаг 2 — backfill builtin-доменом ──
UPDATE auth.users u
SET domain_id = (
    SELECT d.id FROM auth.domains d
    WHERE d.kind = 'builtin'
    ORDER BY d.created_at, d.id
    LIMIT 1
)
WHERE u.domain_id IS NULL;

-- ── users.domain_id: шаг 3 — обязательность ────────────
-- С этого момента INSERT без domain_id невозможен: код создания пользователей
-- (Tenant.create) обязан указывать домен явно.
ALTER TABLE auth.users
    ALTER COLUMN domain_id SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_users_domain
    ON auth.users (domain_id);

-- ── groups: scope-тройник + федеративный link_id ───────
ALTER TABLE auth.groups
    ADD COLUMN IF NOT EXISTS scope TEXT NOT NULL DEFAULT 'user',
    ADD COLUMN IF NOT EXISTS domain_id UUID REFERENCES auth.domains(id) ON DELETE RESTRICT,
    ADD COLUMN IF NOT EXISTS owner_id UUID REFERENCES auth.users(id) ON DELETE RESTRICT,
    ADD COLUMN IF NOT EXISTS link_id UUID REFERENCES auth.domain_links(id) ON DELETE RESTRICT;

-- ── groups: бэкфилл ────────────────────────────────────
-- Встроенные группы (Administrators, Everyone) — системные, вне доменов.
UPDATE auth.groups g
SET scope = 'system'
WHERE g.is_builtin AND g.scope IS DISTINCT FROM 'system';

-- Прочие существующие группы относим к builtin-домену Argenta
-- (до scope-модели весь инстанс — один неявный домен Argenta).
UPDATE auth.groups g
SET scope = 'domain',
    domain_id = (
        SELECT d.id FROM auth.domains d
        WHERE d.kind = 'builtin'
        ORDER BY d.created_at, d.id
        LIMIT 1
    )
WHERE NOT g.is_builtin
  AND g.scope IS DISTINCT FROM 'domain';

-- ── groups: CHECK-инварианты тройника ──────────────────
DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'chk_groups_scope_values' AND conrelid = 'auth.groups'::regclass
    ) THEN
        ALTER TABLE auth.groups
            ADD CONSTRAINT chk_groups_scope_values
            CHECK (scope IN ('system', 'domain', 'user'));
    END IF;
END $$;

DO $$ BEGIN
    -- system → вне домена и без владельца; domain → в домене; user → с владельцем
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'chk_groups_scope_shape' AND conrelid = 'auth.groups'::regclass
    ) THEN
        ALTER TABLE auth.groups
            ADD CONSTRAINT chk_groups_scope_shape
            CHECK (
                (scope <> 'system' OR (domain_id IS NULL AND owner_id IS NULL))
                AND (scope <> 'domain' OR domain_id IS NOT NULL)
                AND (scope <> 'user' OR owner_id IS NOT NULL)
            );
    END IF;
END $$;

-- ── groups: индексы под предикаты видимости ────────────
CREATE INDEX IF NOT EXISTS idx_groups_scope_domain
    ON auth.groups (scope, domain_id);
-- Федеративные группы по линку (partial: link_id редок, полный индекс не нужен)
CREATE INDEX IF NOT EXISTS idx_groups_link
    ON auth.groups (link_id)
    WHERE link_id IS NOT NULL;

-- Down (ручной; _applied_ddl не откатывает файлы, Alembic в проекте нет):
--   DROP INDEX IF EXISTS auth.idx_groups_link;
--   DROP INDEX IF EXISTS auth.idx_groups_scope_domain;
--   ALTER TABLE auth.groups DROP CONSTRAINT IF EXISTS chk_groups_scope_shape;
--   ALTER TABLE auth.groups DROP CONSTRAINT IF EXISTS chk_groups_scope_values;
--   ALTER TABLE auth.groups DROP COLUMN IF EXISTS link_id;
--   ALTER TABLE auth.groups DROP COLUMN IF EXISTS owner_id;
--   ALTER TABLE auth.groups DROP COLUMN IF EXISTS domain_id;
--   ALTER TABLE auth.groups DROP COLUMN IF EXISTS scope;
--   DROP INDEX IF EXISTS auth.idx_users_domain;
--   ALTER TABLE auth.users ALTER COLUMN domain_id DROP NOT NULL;
--   ALTER TABLE auth.users DROP COLUMN IF EXISTS domain_id;
--   DELETE FROM _applied_ddl WHERE db_name = 'auth' AND ddl_file = '009_scope_columns.sql';
