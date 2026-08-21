-- 001_triggers.sql: Триггеры для auth модуля
-- Триггер check_group_cycle: предотвращение циклов в иерархии групп
-- Триггер update_updated_at: автоматическое обновление updated_at

DO $$ BEGIN
    -- Триггер: проверка циклов в auth.group_group_membership
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'check_group_cycle') THEN
        CREATE OR REPLACE FUNCTION check_group_cycle_fn()
        RETURNS TRIGGER AS $fn$
        DECLARE
            cycle_found BOOLEAN;
        BEGIN
            -- Рекурсивный обход предков через CTE
            WITH RECURSIVE ancestors AS (
                SELECT parent_group_id AS gid
                FROM auth.group_group_membership
                WHERE child_group_id = NEW.parent_group_id
                UNION ALL
                SELECT ggm.parent_group_id
                FROM auth.group_group_membership ggm
                JOIN ancestors a ON ggm.child_group_id = a.gid
            )
            SELECT EXISTS(
                SELECT 1 FROM ancestors WHERE gid = NEW.child_group_id
            ) INTO cycle_found;

            IF cycle_found THEN
                RAISE EXCEPTION 'Cycle detected in group hierarchy: group % is an ancestor of group %',
                    NEW.child_group_id, NEW.parent_group_id;
            END IF;

            RETURN NEW;
        END;
        $fn$ LANGUAGE plpgsql;

        CREATE TRIGGER check_group_cycle
            BEFORE INSERT OR UPDATE ON auth.group_group_membership
            FOR EACH ROW
            EXECUTE FUNCTION check_group_cycle_fn();
    END IF;
END $$;

DO $$ BEGIN
    -- Триггер: автоматическое обновление updated_at в users
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'update_users_updated_at') THEN
        CREATE OR REPLACE FUNCTION update_users_updated_at_fn()
        RETURNS TRIGGER AS $fn$
        BEGIN
            NEW.updated_at = NOW();
            RETURN NEW;
        END;
        $fn$ LANGUAGE plpgsql;

        CREATE TRIGGER update_users_updated_at
            BEFORE UPDATE ON auth.users
            FOR EACH ROW
            EXECUTE FUNCTION update_users_updated_at_fn();
    END IF;
END $$;
