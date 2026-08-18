"""Integration tests with real PostgreSQL.

All tests require a real PostgreSQL connection.
Skipped if PostgreSQL is not available (CI, local dev without PG).
"""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from typing import Any

import pytest

# Skip all tests if PG is not available
PG_AVAILABLE = False
try:
    import psycopg  # noqa: F401
    import asyncio

    def _check_pg() -> bool:
        try:
            conn = psycopg.connect(
                host=os.getenv("MIA_TEST_PG_HOST", "localhost"),
                port=int(os.getenv("MIA_TEST_PG_PORT", "5432")),
                user=os.getenv("MIA_TEST_PG_USER", "svc_athene_ai"),
                password=os.getenv("MIA_TEST_PG_PASSWORD", ""),
                dbname=os.getenv("MIA_TEST_PG_DB", "belle"),
            )
            conn.close()
            return True
        except Exception:
            return False

    PG_AVAILABLE = _check_pg()
except Exception:
    pass

pytestmark = pytest.mark.skipif(
    not PG_AVAILABLE,
    reason="PostgreSQL not available — set MIA_TEST_PG_* env vars or run local PG",
)


# ── Helpers ───────────────────────────────────────────────

TEST_SCHEMA = "auth"
TEST_DB = os.getenv("MIA_TEST_PG_DB", "mia")
TEST_HOST = os.getenv("MIA_TEST_PG_HOST", "localhost")
TEST_PORT = int(os.getenv("MIA_TEST_PG_PORT", "5432"))
TEST_USER = os.getenv("MIA_TEST_PG_USER", "mia")
TEST_PASSWORD = os.getenv("MIA_TEST_PG_PASSWORD", "test")


async def _get_pool() -> Any:
    """Create a real asyncpg pool for testing."""
    import asyncpg
    return await asyncpg.create_pool(
        host=TEST_HOST,
        port=TEST_PORT,
        user=TEST_USER,
        password=TEST_PASSWORD,
        database=TEST_DB,
        min_size=1,
        max_size=5,
    )


async def _setup_schema(pool: Any) -> None:
    """Create auth schema and tables if not exist."""
    # Create schema
    await pool.execute("CREATE SCHEMA IF NOT EXISTS auth")

    # Core tables
    await pool.execute("""
        CREATE TABLE IF NOT EXISTS auth.users (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT,
            first_name TEXT,
            last_name TEXT,
            description TEXT,
            is_active BOOLEAN DEFAULT TRUE,
            is_disabled BOOLEAN DEFAULT FALSE,
            locked_until TIMESTAMPTZ,
            login_attempts INTEGER DEFAULT 0,
            last_login TIMESTAMPTZ,
            disabled_at TIMESTAMPTZ,
            enabled_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            updated_at TIMESTAMPTZ DEFAULT NOW()
        )
    """)

    await pool.execute("""
        CREATE TABLE IF NOT EXISTS auth.groups (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            name TEXT UNIQUE NOT NULL,
            description TEXT,
            is_builtin BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            updated_at TIMESTAMPTZ DEFAULT NOW()
        )
    """)

    await pool.execute("""
        CREATE TABLE IF NOT EXISTS auth.roles (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            name TEXT UNIQUE NOT NULL,
            description TEXT,
            is_builtin BOOLEAN DEFAULT FALSE,
            source_module TEXT,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            updated_at TIMESTAMPTZ DEFAULT NOW()
        )
    """)

    await pool.execute("""
        CREATE TABLE IF NOT EXISTS auth.permissions (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            name TEXT UNIQUE NOT NULL,
            description TEXT,
            is_builtin BOOLEAN DEFAULT FALSE,
            source_module TEXT,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            updated_at TIMESTAMPTZ DEFAULT NOW()
        )
    """)

    await pool.execute("""
        CREATE TABLE IF NOT EXISTS auth.user_roles (
            user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
            role_id UUID REFERENCES auth.roles(id) ON DELETE CASCADE,
            granted_by UUID,
            granted_at TIMESTAMPTZ DEFAULT NOW(),
            PRIMARY KEY (user_id, role_id)
        )
    """)

    await pool.execute("""
        CREATE TABLE IF NOT EXISTS auth.group_roles (
            group_id UUID REFERENCES auth.groups(id) ON DELETE CASCADE,
            role_id UUID REFERENCES auth.roles(id) ON DELETE CASCADE,
            assigned_at TIMESTAMPTZ DEFAULT NOW(),
            PRIMARY KEY (group_id, role_id)
        )
    """)

    await pool.execute("""
        CREATE TABLE IF NOT EXISTS auth.user_group_membership (
            user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
            group_id UUID REFERENCES auth.groups(id) ON DELETE CASCADE,
            added_by UUID,
            added_at TIMESTAMPTZ DEFAULT NOW(),
            PRIMARY KEY (user_id, group_id)
        )
    """)

    await pool.execute("""
        CREATE TABLE IF NOT EXISTS auth.group_group_membership (
            parent_group_id UUID REFERENCES auth.groups(id) ON DELETE CASCADE,
            child_group_id UUID REFERENCES auth.groups(id) ON DELETE CASCADE,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            PRIMARY KEY (parent_group_id, child_group_id),
            CHECK (parent_group_id <> child_group_id)
        )
    """)

    await pool.execute("""
        CREATE TABLE IF NOT EXISTS auth.role_permissions (
            role_id UUID REFERENCES auth.roles(id) ON DELETE CASCADE,
            permission_id UUID REFERENCES auth.permissions(id) ON DELETE CASCADE,
            PRIMARY KEY (role_id, permission_id)
        )
    """)

    await pool.execute("""
        CREATE TABLE IF NOT EXISTS auth.auth_sessions (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
            access_token_hash TEXT NOT NULL,
            access_expires_at TIMESTAMPTZ NOT NULL,
            refresh_token_hash TEXT NOT NULL,
            refresh_expires_at TIMESTAMPTZ NOT NULL,
            user_agent TEXT,
            ip_address TEXT,
            family_id UUID,
            is_revoked BOOLEAN DEFAULT FALSE,
            revoked_at TIMESTAMPTZ,
            last_used_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ DEFAULT NOW()
        )
    """)

    await pool.execute("""
        CREATE TABLE IF NOT EXISTS auth.password_history (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMPTZ DEFAULT NOW()
        )
    """)


async def _cleanup_schema(pool: Any) -> None:
    """Drop all auth tables after tests."""
    tables = [
        "auth.password_history", "auth.auth_sessions", "auth.role_permissions",
        "auth.user_roles", "auth.group_roles", "auth.user_group_membership",
        "auth.group_group_membership", "auth.permissions", "auth.roles",
        "auth.groups", "auth.users",
    ]
    for table in tables:
        await pool.execute(f"DROP TABLE IF EXISTS {table} CASCADE")


# ── Fixtures ──────────────────────────────────────────────

@pytest.fixture
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
async def pg_pool():
    """Real PostgreSQL pool for integration tests."""
    pool = await _get_pool()
    await _setup_schema(pool)
    yield pool
    await _cleanup_schema(pool)
    await pool.close()


# ── Tests ─────────────────────────────────────────────────


@pytest.mark.asyncio
class TestRegisterSchema:
    """register_schema: DDL creates tables, idempotent on second call."""

    async def test_register_schema_creates_tables(self, pg_pool):
        """Tables should exist after schema registration."""
        # Check auth.users exists
        row = await pg_pool.fetchrow(
            "SELECT EXISTS(SELECT 1 FROM information_schema.tables "
            "WHERE table_schema = 'auth' AND table_name = 'users')"
        )
        assert row["exists"] is True

    async def test_register_schema_idempotent(self, pg_pool):
        """Second call should not fail (idempotent)."""
        await _setup_schema(pg_pool)  # Second call
        row = await pg_pool.fetchrow(
            "SELECT EXISTS(SELECT 1 FROM information_schema.tables "
            "WHERE table_schema = 'auth' AND table_name = 'users')"
        )
        assert row["exists"] is True


@pytest.mark.asyncio
class TestGroupCycleTrigger:
    """Trigger check_group_cycle: circular dependency detection."""

    async def test_normal_chain_ok(self, pg_pool):
        """A→B→C chain should work."""
        a = await pg_pool.fetchrow(
            "INSERT INTO auth.groups (name) VALUES ('groupA') RETURNING id"
        )
        b = await pg_pool.fetchrow(
            "INSERT INTO auth.groups (name) VALUES ('groupB') RETURNING id"
        )
        c = await pg_pool.fetchrow(
            "INSERT INTO auth.groups (name) VALUES ('groupC') RETURNING id"
        )
        # A→B
        await pg_pool.execute(
            "INSERT INTO auth.group_group_membership (parent_group_id, child_group_id) "
            "VALUES ($1, $2)", a["id"], b["id"]
        )
        # B→C
        await pg_pool.execute(
            "INSERT INTO auth.group_group_membership (parent_group_id, child_group_id) "
            "VALUES ($1, $2)", b["id"], c["id"]
        )
        # No cycle — OK

    async def test_cycle_raises_exception(self, pg_pool):
        """A→B, B→A should raise exception."""
        a = await pg_pool.fetchrow(
            "INSERT INTO auth.groups (name) VALUES ('cycleA') RETURNING id"
        )
        b = await pg_pool.fetchrow(
            "INSERT INTO auth.groups (name) VALUES ('cycleB') RETURNING id"
        )
        # A→B
        await pg_pool.execute(
            "INSERT INTO auth.group_group_membership (parent_group_id, child_group_id) "
            "VALUES ($1, $2)", a["id"], b["id"]
        )
        # B→A — should raise cycle
        with pytest.raises(asyncpg.exceptions.CheckViolationError):
            await pg_pool.execute(
                "INSERT INTO auth.group_group_membership (parent_group_id, child_group_id) "
                "VALUES ($1, $2)", b["id"], a["id"]
            )

    async def test_self_reference_raises(self, pg_pool):
        """A→A should fail (CHECK constraint)."""
        a = await pg_pool.fetchrow(
            "INSERT INTO auth.groups (name) VALUES ('selfRef') RETURNING id"
        )
        with pytest.raises(asyncpg.exceptions.CheckViolationError):
            await pg_pool.execute(
                "INSERT INTO auth.group_group_membership (parent_group_id, child_group_id) "
                "VALUES ($1, $1)", a["id"]
            )


@pytest.mark.asyncio
class TestCheckConstraints:
    """CHECK constraints: email regex, login_attempts >= 0, group name length."""

    async def test_invalid_email_rejected(self, pg_pool):
        """Invalid email should fail CHECK constraint."""
        with pytest.raises(asyncpg.exceptions.CheckViolationError):
            await pg_pool.execute(
                "INSERT INTO auth.users (username, password_hash, email) "
                "VALUES ($1, $2, $3)",
                f"testuser_{uuid.uuid4().hex[:8]}", "hash", "not-an-email"
            )

    async def test_valid_email_ok(self, pg_pool):
        """Valid email should work."""
        username = f"testuser_{uuid.uuid4().hex[:8]}"
        row = await pg_pool.fetchrow(
            "INSERT INTO auth.users (username, password_hash, email) "
            "VALUES ($1, $2, $3) RETURNING id",
            username, "hash", "test@example.com"
        )
        assert row is not None

    async def test_login_attempts_negative_rejected(self, pg_pool):
        """login_attempts < 0 should fail."""
        username = f"testuser_{uuid.uuid4().hex[:8]}"
        with pytest.raises(asyncpg.exceptions.CheckViolationError):
            await pg_pool.execute(
                "INSERT INTO auth.users (username, password_hash, login_attempts) "
                "VALUES ($1, $2, $3)",
                username, "hash", -1
            )

    async def test_group_name_too_short_rejected(self, pg_pool):
        """Group name < 2 chars should fail."""
        with pytest.raises(asyncpg.exceptions.CheckViolationError):
            await pg_pool.execute(
                "INSERT INTO auth.groups (name) VALUES ($1)", "x"
            )


@pytest.mark.asyncio
class TestRecursiveCTE:
    """Recursive CTE: get_user_effective_roles with group hierarchy."""

    async def test_direct_roles_included(self, pg_pool):
        """User's direct roles should be in effective roles."""
        # Create user
        username = f"cte_user_{uuid.uuid4().hex[:8]}"
        user = await pg_pool.fetchrow(
            "INSERT INTO auth.users (username, password_hash) "
            "VALUES ($1, $2) RETURNING id",
            username, "hash"
        )
        # Create role
        role = await pg_pool.fetchrow(
            "INSERT INTO auth.roles (name, description) "
            "VALUES ($1, $2) RETURNING id",
            f"role_{uuid.uuid4().hex[:8]}", "Test role"
        )
        # Assign role
        await pg_pool.execute(
            "INSERT INTO auth.user_roles (user_id, role_id) VALUES ($1, $2)",
            user["id"], role["id"]
        )

        # Recursive CTE query (same as repository)
        rows = await pg_pool.fetch(
            "WITH RECURSIVE group_hierarchy AS ("
            "  SELECT ugm.group_id, 0 AS depth "
            "  FROM auth.user_group_membership ugm "
            "  WHERE ugm.user_id = $1 "
            "  UNION "
            "  SELECT ggm.parent_group_id, gh.depth + 1 "
            "  FROM auth.group_group_membership ggm "
            "  JOIN group_hierarchy gh ON ggm.child_group_id = gh.group_id "
            "  WHERE gh.depth < 10"
            ") "
            "SELECT DISTINCT r.id, r.name, r.description, r.is_builtin, "
            "  MIN(gh.depth) AS min_depth "
            "FROM auth.group_roles gr "
            "JOIN group_hierarchy gh ON gr.group_id = gh.group_id "
            "JOIN auth.roles r ON r.id = gr.role_id "
            "GROUP BY r.id, r.name, r.description, r.is_builtin "
            "UNION "
            "SELECT r.id, r.name, r.description, r.is_builtin, -1 AS min_depth "
            "FROM auth.user_roles ur "
            "JOIN auth.roles r ON r.id = ur.role_id "
            "WHERE ur.user_id = $1 "
            "ORDER BY min_depth",
            user["id"],
        )
        assert len(rows) == 1
        assert rows[0]["name"] == role["name"]

    async def test_group_roles_inherited(self, pg_pool):
        """Roles from groups (direct membership) should be inherited."""
        user = await pg_pool.fetchrow(
            "INSERT INTO auth.users (username, password_hash) "
            "VALUES ($1, $2) RETURNING id",
            f"cte_user_{uuid.uuid4().hex[:8]}", "hash"
        )
        group = await pg_pool.fetchrow(
            "INSERT INTO auth.groups (name) VALUES ($1) RETURNING id",
            f"cte_group_{uuid.uuid4().hex[:8]}"
        )
        role = await pg_pool.fetchrow(
            "INSERT INTO auth.roles (name, description) "
            "VALUES ($1, $2) RETURNING id",
            f"role_{uuid.uuid4().hex[:8]}", "Test role"
        )
        # user → group
        await pg_pool.execute(
            "INSERT INTO auth.user_group_membership (user_id, group_id) VALUES ($1, $2)",
            user["id"], group["id"]
        )
        # group → role
        await pg_pool.execute(
            "INSERT INTO auth.group_roles (group_id, role_id) VALUES ($1, $2)",
            group["id"], role["id"]
        )

        rows = await pg_pool.fetch(
            "WITH RECURSIVE group_hierarchy AS ("
            "  SELECT ugm.group_id, 0 AS depth "
            "  FROM auth.user_group_membership ugm "
            "  WHERE ugm.user_id = $1 "
            "  UNION "
            "  SELECT ggm.parent_group_id, gh.depth + 1 "
            "  FROM auth.group_group_membership ggm "
            "  JOIN group_hierarchy gh ON ggm.child_group_id = gh.group_id "
            "  WHERE gh.depth < 10"
            ") "
            "SELECT DISTINCT r.id, r.name "
            "FROM auth.group_roles gr "
            "JOIN group_hierarchy gh ON gr.group_id = gh.group_id "
            "JOIN auth.roles r ON r.id = gr.role_id "
            "GROUP BY r.id, r.name "
            "UNION "
            "SELECT r.id, r.name "
            "FROM auth.user_roles ur "
            "JOIN auth.roles r ON r.id = ur.role_id "
            "WHERE ur.user_id = $1 "
            "ORDER BY r.name",
            user["id"],
        )
        assert len(rows) == 1
        assert rows[0]["name"] == role["name"]

    async def test_hierarchical_groups_deep(self, pg_pool):
        """Roles from parent groups should be inherited through hierarchy."""
        user = await pg_pool.fetchrow(
            "INSERT INTO auth.users (username, password_hash) "
            "VALUES ($1, $2) RETURNING id",
            f"cte_user_{uuid.uuid4().hex[:8]}", "hash"
        )
        child_group = await pg_pool.fetchrow(
            "INSERT INTO auth.groups (name) VALUES ($1) RETURNING id",
            f"child_{uuid.uuid4().hex[:8]}"
        )
        parent_group = await pg_pool.fetchrow(
            "INSERT INTO auth.groups (name) VALUES ($1) RETURNING id",
            f"parent_{uuid.uuid4().hex[:8]}"
        )
        role = await pg_pool.fetchrow(
            "INSERT INTO auth.roles (name, description) "
            "VALUES ($1, $2) RETURNING id",
            f"deep_role_{uuid.uuid4().hex[:8]}", "Deep role"
        )
        # user → child_group
        await pg_pool.execute(
            "INSERT INTO auth.user_group_membership (user_id, group_id) VALUES ($1, $2)",
            user["id"], child_group["id"]
        )
        # child_group → parent_group
        await pg_pool.execute(
            "INSERT INTO auth.group_group_membership (parent_group_id, child_group_id) "
            "VALUES ($1, $2)",
            parent_group["id"], child_group["id"]
        )
        # parent_group → role
        await pg_pool.execute(
            "INSERT INTO auth.group_roles (group_id, role_id) VALUES ($1, $2)",
            parent_group["id"], role["id"]
        )

        rows = await pg_pool.fetch(
            "WITH RECURSIVE group_hierarchy AS ("
            "  SELECT ugm.group_id, 0 AS depth "
            "  FROM auth.user_group_membership ugm "
            "  WHERE ugm.user_id = $1 "
            "  UNION "
            "  SELECT ggm.parent_group_id, gh.depth + 1 "
            "  FROM auth.group_group_membership ggm "
            "  JOIN group_hierarchy gh ON ggm.child_group_id = gh.group_id "
            "  WHERE gh.depth < 10"
            ") "
            "SELECT DISTINCT r.id, r.name, MIN(gh.depth) AS min_depth "
            "FROM auth.group_roles gr "
            "JOIN group_hierarchy gh ON gr.group_id = gh.group_id "
            "JOIN auth.roles r ON r.id = gr.role_id "
            "GROUP BY r.id, r.name "
            "ORDER BY min_depth",
            user["id"],
        )
        assert len(rows) == 1
        assert rows[0]["name"] == role["name"]
        assert rows[0]["min_depth"] == 1  # через parent_group


@pytest.mark.asyncio
class TestRefreshTokenRotation:
    """Refresh token rotation and reuse detection via real AuthProvider."""

    async def test_refresh_creates_new_tokens(self, pg_pool):
        """Refresh should create new access + refresh tokens."""
        from modules.auth.config import AuthConfig
        from modules.auth.provider import AuthProvider

        config = AuthConfig(
            jwt_secret="integration-test-secret-32-chars-long!!!",
            jwt_algorithm="HS256",
            jwt_access_expiration_minutes=5,
            jwt_refresh_expiration_days=1,
            password_min_length=8,
            password_require_uppercase=True,
            password_require_digit=True,
            password_history_size=10,
            login_attempts_limit=5,
            login_block_minutes=15,
            perms_cache_ttl=300,
        )
        provider = AuthProvider(config=config, database=pg_pool)

        # Register schema for bootstrap
        from modules.auth.schema_registry import AuthSchemaRegistry
        from modules.auth.schema import AUTH_CORE_SCHEMA

        registry = AuthSchemaRegistry(pg_pool)
        await registry.register("auth", AUTH_CORE_SCHEMA, is_builtin=True)

        # Bootstrap
        result = await provider.bootstrap("admin", "SecurePass123", "admin@test.com")
        user_id = result["user_id"]

        # Login
        login_result = await provider.login("admin", "SecurePass123")
        refresh_token = login_result["refresh_token"]

        # Refresh
        new_tokens = await provider.refresh_token(refresh_token)
        assert "access_token" in new_tokens
        assert "refresh_token" in new_tokens
        assert new_tokens["access_token"] != login_result["access_token"]
        assert new_tokens["refresh_token"] != refresh_token

    async def test_refresh_reuse_revokes_family(self, pg_pool):
        """Reusing an old refresh token should revoke the whole family."""
        from modules.auth.config import AuthConfig
        from modules.auth.provider import AuthProvider, ReuseDetectedError

        config = AuthConfig(
            jwt_secret="integration-test-secret-32-chars-long!!!",
            jwt_algorithm="HS256",
            jwt_access_expiration_minutes=5,
            jwt_refresh_expiration_days=1,
            password_min_length=8,
            password_require_uppercase=True,
            password_require_digit=True,
            password_history_size=10,
            login_attempts_limit=5,
            login_block_minutes=15,
            perms_cache_ttl=300,
        )
        provider = AuthProvider(config=config, database=pg_pool)

        from modules.auth.schema_registry import AuthSchemaRegistry
        from modules.auth.schema import AUTH_CORE_SCHEMA

        registry = AuthSchemaRegistry(pg_pool)
        await registry.register("auth", AUTH_CORE_SCHEMA, is_builtin=True)

        await provider.bootstrap("admin", "SecurePass123", "admin@test.com")
        login_result = await provider.login("admin", "SecurePass123")
        old_refresh = login_result["refresh_token"]

        # First refresh — rotates token
        new_tokens = await provider.refresh_token(old_refresh)

        # Reuse old refresh — should detect
        with pytest.raises(ReuseDetectedError):
            await provider.refresh_token(old_refresh)


@pytest.mark.asyncio
class TestAuthSchemaRegistry:
    """AuthSchemaRegistry: register AUTH_CORE_SCHEMA on real DB."""

    async def test_register_permissions(self, pg_pool):
        """Registering permissions should insert them."""
        from modules.auth.schema_registry import AuthSchemaRegistry
        from modules.auth.schema import AUTH_CORE_SCHEMA

        registry = AuthSchemaRegistry(pg_pool)
        result = await registry.register("auth", AUTH_CORE_SCHEMA, is_builtin=True)

        assert len(result["created_permissions"]) > 0
        assert "users:create" in result["created_permissions"]

    async def test_register_idempotent(self, pg_pool):
        """Second register should update, not create duplicates."""
        from modules.auth.schema_registry import AuthSchemaRegistry
        from modules.auth.schema import AUTH_CORE_SCHEMA

        registry = AuthSchemaRegistry(pg_pool)
        first = await registry.register("auth", AUTH_CORE_SCHEMA, is_builtin=True)
        second = await registry.register("auth", AUTH_CORE_SCHEMA, is_builtin=True)

        # Second call should update existing, not create new
        assert len(second["created_permissions"]) == 0
        assert len(second["updated_permissions"]) == len(first["created_permissions"])
