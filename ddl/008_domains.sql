-- 008_domains.sql: сущность домена и федерация — scope-модель, Часть 2 (дизайн Эны).
-- Таблицы: auth.domains (домены-тенанты), auth.domain_links (федеративные линки).
-- Сид: builtin-домен Argenta из корня OU-дерева (system.ou, сид 003_seed_ou).
-- Идемпотентно: CREATE TABLE IF NOT EXISTS, DO $$, ON CONFLICT.
-- Только системная БД: ddl/ auth применяется через register_schema(ddl_dir) —
-- в per-user БД (belle_workspace_{hex}) auth-схемы нет.

-- ── Домены ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS auth.domains (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Машинный слаг (lowercase), человекочитаемое — display_name
    name TEXT NOT NULL UNIQUE,
    display_name TEXT,
    -- 'builtin' | 'user' | 'ad'
    kind TEXT NOT NULL,
    -- Владелец домена kind='user'; для builtin — NULL (инвариант ниже)
    owner_id UUID REFERENCES auth.users(id) ON DELETE RESTRICT,
    -- Корень OU-дерева домена. FK на system.ou невозможен здесь:
    -- system применяется ПОСЛЕ auth (topo). Ограничение докатывает
    -- system/007_backfill_domain_root.sql вместе с backfill.
    root_ou_id UUID,
    -- 'local' | 'basic' | 'oidc' | 'ad'
    identity_kind TEXT NOT NULL DEFAULT 'local',
    -- Настройки аутентификации (OIDC endpoints, client_id и т.п.)
    auth_config JSONB NOT NULL DEFAULT '{}'::jsonb,
    -- Подключение AD: адреса, DN, схемы. БЕЗ СЕКРЕТОВ:
    -- bind-пароль хранит secrets-механизм, НЕ эта колонка.
    ad_config JSONB NOT NULL DEFAULT '{}'::jsonb,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ── Федеративные линки (неориентированное ребро, канонический порядок) ──
CREATE TABLE IF NOT EXISTS auth.domain_links (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain_a_id UUID NOT NULL REFERENCES auth.domains(id) ON DELETE CASCADE,
    domain_b_id UUID NOT NULL REFERENCES auth.domains(id) ON DELETE CASCADE,
    -- 'pending' | 'active' | 'revoked' — отзыв через status, не через DELETE
    status TEXT NOT NULL DEFAULT 'pending',
    created_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
    -- Уникальность пары — uq_domain_links_pair ниже (индексом, не inline:
    -- на fresh таблицу создаёт register_schema из schemas.py, где table-level
    -- UNIQUE не выражается форматом Schema-first)
);

-- ── CHECK: перечисления и инварианты ───────────────────
DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'chk_domains_kind' AND conrelid = 'auth.domains'::regclass
    ) THEN
        ALTER TABLE auth.domains
            ADD CONSTRAINT chk_domains_kind
            CHECK (kind IN ('builtin', 'user', 'ad'));
    END IF;
END $$;

DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'chk_domains_identity_kind' AND conrelid = 'auth.domains'::regclass
    ) THEN
        ALTER TABLE auth.domains
            ADD CONSTRAINT chk_domains_identity_kind
            CHECK (identity_kind IN ('local', 'basic', 'oidc', 'ad'));
    END IF;
END $$;

DO $$ BEGIN
    -- builtin-домен принадлежит системе, user-домен обязан иметь владельца
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'chk_domains_owner_shape' AND conrelid = 'auth.domains'::regclass
    ) THEN
        ALTER TABLE auth.domains
            ADD CONSTRAINT chk_domains_owner_shape
            CHECK (
                (kind <> 'builtin' OR owner_id IS NULL)
                AND (kind <> 'user' OR owner_id IS NOT NULL)
            );
    END IF;
END $$;

DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'chk_domain_links_ordered' AND conrelid = 'auth.domain_links'::regclass
    ) THEN
        ALTER TABLE auth.domain_links
            ADD CONSTRAINT chk_domain_links_ordered
            CHECK (domain_a_id < domain_b_id);
    END IF;
END $$;

DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'chk_domain_links_status' AND conrelid = 'auth.domain_links'::regclass
    ) THEN
        ALTER TABLE auth.domain_links
            ADD CONSTRAINT chk_domain_links_status
            CHECK (status IN ('pending', 'active', 'revoked'));
    END IF;
END $$;

-- ── Индексы ────────────────────────────────────────────
-- Пара доменов уникальна; canonical order (a < b) защищает от дублей A→B / B→A
CREATE UNIQUE INDEX IF NOT EXISTS uq_domain_links_pair
    ON auth.domain_links (domain_a_id, domain_b_id);
-- Линки домена X: X может быть и в a, и в b (canon порядок не задаёт роль)
CREATE INDEX IF NOT EXISTS idx_domain_links_a_id
    ON auth.domain_links (domain_a_id);
CREATE INDEX IF NOT EXISTS idx_domain_links_b_id
    ON auth.domain_links (domain_b_id);
-- Активная федерация: предикат видимости проверяет status
CREATE INDEX IF NOT EXISTS idx_domain_links_status
    ON auth.domain_links (status);
-- Обратные проверки FK owner_id при удалении пользователя
CREATE INDEX IF NOT EXISTS idx_domains_owner
    ON auth.domains (owner_id)
    WHERE owner_id IS NOT NULL;
-- Выборка builtin/user-доменов
CREATE INDEX IF NOT EXISTS idx_domains_kind
    ON auth.domains (kind);

-- ── Документация колонок-хранилищ конфигов ────────────
COMMENT ON COLUMN auth.domains.ad_config IS
    'Параметры подключения AD (urls, base_dn, схемы). СЕКРЕТЫ НЕ ХРАНИТЬ: bind-пароль — в secrets-механизме приложения';
COMMENT ON COLUMN auth.domains.auth_config IS
    'Настройки identity_kind=oidc/basic (endpoints, client_id). client_secret не хранить здесь';

-- ── Сид builtin-домена Argenta ─────────────────────────
-- На существующей БД system.ou уже есть — берём корень сразу.
-- На fresh-инсталле auth применяется РАНЬШЕ system (topo): system.ou ещё
-- не существует — создаём домен с root_ou_id NULL, system/007 дозаполнит.
DO $seed_argenta$
BEGIN
    IF to_regclass('system.ou') IS NOT NULL THEN
        INSERT INTO auth.domains (name, display_name, kind, root_ou_id, identity_kind, status)
        SELECT 'argenta', 'Argenta', 'builtin', r.id, 'local', 'active'
        FROM system.ou r
        WHERE r.parent_id IS NULL AND r.name = 'Argenta'
          AND r.is_builtin AND r.is_system
        ON CONFLICT (name) DO NOTHING;
    ELSE
        INSERT INTO auth.domains (name, display_name, kind, identity_kind, status)
        VALUES ('argenta', 'Argenta', 'builtin', 'local', 'active')
        ON CONFLICT (name) DO NOTHING;
    END IF;
END $seed_argenta$;

-- Down (ручной; _applied_ddl не откатывает файлы, Alembic в проекте нет):
--   DROP INDEX IF EXISTS auth.uq_domain_links_pair;
--   DROP INDEX IF EXISTS auth.idx_domain_links_a_id;
--   DROP INDEX IF EXISTS auth.idx_domain_links_b_id;
--   DROP INDEX IF EXISTS auth.idx_domain_links_status;
--   DROP INDEX IF EXISTS auth.idx_domains_owner;
--   DROP INDEX IF EXISTS auth.idx_domains_kind;
--   ALTER TABLE auth.domain_links DROP CONSTRAINT IF EXISTS chk_domain_links_status;
--   ALTER TABLE auth.domain_links DROP CONSTRAINT IF EXISTS chk_domain_links_ordered;
--   ALTER TABLE auth.domains DROP CONSTRAINT IF EXISTS chk_domains_owner_shape;
--   ALTER TABLE auth.domains DROP CONSTRAINT IF EXISTS chk_domains_identity_kind;
--   ALTER TABLE auth.domains DROP CONSTRAINT IF EXISTS chk_domains_kind;
--   -- domain_links и domains не DROP TABLE без бэкапа: до 009 в groups/users
--   -- остаются FK на них. Порядок отката: сначала Down 009, потом Down 008.
--   DELETE FROM _applied_ddl WHERE db_name = 'auth' AND ddl_file = '008_domains.sql';
