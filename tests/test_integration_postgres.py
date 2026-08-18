"""Integration tests with real PostgreSQL via psycopg v3 + WorkerManager dispatch.

Tests the full chain: AuthProvider → SharedMemory → WorkerManager → ThreadPool → psycopg v3 → PostgreSQL.
"""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from typing import Any

import psycopg
import psycopg_pool
import pytest

# Skip all tests if PG is not available
PG_AVAILABLE = False
try:
    def _check_pg() -> bool:
        try:
            conn = psycopg.connect(
                host=os.getenv("MIA_TEST_PG_HOST", "postgres"),
                port=int(os.getenv("MIA_TEST_PG_PORT", "5432")),
                user=os.getenv("MIA_TEST_PG_USER", "svc_athene_ai"),
                password=os.getenv("MIA_TEST_PG_PASSWORD", "GUNW7ryP3V8kgLXFHQvm"),
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

TEST_HOST = os.getenv("MIA_TEST_PG_HOST", "postgres")
TEST_PORT = int(os.getenv("MIA_TEST_PG_PORT", "5432"))
TEST_USER = os.getenv("MIA_TEST_PG_USER", "svc_athene_ai")
TEST_PASSWORD = os.getenv("MIA_TEST_PG_PASSWORD", "GUNW7ryP3V8kgLXFHQvm")
TEST_DB = os.getenv("MIA_TEST_PG_DB", "belle")


def _get_pool() -> psycopg_pool.ConnectionPool:
    """Create a real psycopg v3 ConnectionPool for testing."""
    return psycopg_pool.ConnectionPool(
        conninfo=f"host={TEST_HOST} port={TEST_PORT} user={TEST_USER} password={TEST_PASSWORD} dbname={TEST_DB}",
        min_size=1,
        max_size=5,
    )


def _setup_schema(pool: psycopg_pool.ConnectionPool) -> None:
    """Create auth schema and tables if not exist."""
    with pool.connection() as conn:
        conn.execute("CREATE SCHEMA IF NOT EXISTS auth")
        
        conn.execute("""
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
                custom_fields JSONB DEFAULT '{}',
                created_at TIMESTAMPTZ DEFAULT NOW(),
                updated_at TIMESTAMPTZ DEFAULT NOW()
            )
        """)
        
        conn.execute("""
            CREATE TABLE IF NOT EXISTS auth.groups (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                name TEXT UNIQUE NOT NULL,
                description TEXT,
                is_builtin BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                updated_at TIMESTAMPTZ DEFAULT NOW()
            )
        """)
        
        conn.execute("""
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
        
        conn.execute("""
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


def _cleanup_schema(pool: psycopg_pool.ConnectionPool) -> None:
    """Drop auth schema."""
    with pool.connection() as conn:
        conn.execute("DROP SCHEMA IF EXISTS auth CASCADE")


# ── Fixtures ───────────────────────────────────────────────

@pytest.fixture
def pg_pool():
    """Real psycopg v3 pool for integration tests."""
    pool = _get_pool()
    _setup_schema(pool)
    yield pool
    _cleanup_schema(pool)
    pool.close()


@pytest.fixture
def auth_provider(pg_pool):
    """AuthProvider with real PostgreSQL via psycopg v3."""
    from modules.auth.provider import AuthProvider
    from modules.auth.config import AuthConfig
    from modules.log import Log
    
    config = AuthConfig(
        jwt_secret="test-secret-key-for-testing-12345",
        jwt_algorithm="HS256",
        jwt_access_expiration_minutes=15,
        jwt_refresh_expiration_days=30,
        password_min_length=8,
        password_require_uppercase=True,
        password_require_digit=True,
        password_history_size=10,
        login_attempts_limit=5,
        login_block_minutes=15,
        perms_cache_ttl=300,
    )
    log = Log(level="WARNING", format="posix")
    
    # Database Provider с реальным psycopg v3 pool
    from modules.db.provider import DatabaseProvider
    from modules.db.config import DatabaseConfig
    
    db_config = DatabaseConfig()
    db_provider = DatabaseProvider(pool=pg_pool, config=db_config, log=log)
    
    return AuthProvider(config=config, database=db_provider, log=log)


# ── Tests ─────────────────────────────────────────────────


@pytest.mark.asyncio
class TestRegisterSchema:
    """register_schema: DDL creates tables, idempotent on second call."""

    def test_register_schema_creates_tables(self, pg_pool):
        """Tables should exist after schema registration."""
        from modules.auth.schemas import DB_SCHEMA
        from modules.db.provider import DatabaseProvider
        from modules.db.config import DatabaseConfig
        from modules.log import Log
        
        log = Log(level="WARNING", format="posix")
        db_config = DatabaseConfig()
        db_provider = DatabaseProvider(pool=pg_pool, config=db_config, log=log)
        db_provider.register_schema("auth", DB_SCHEMA, schema_name="auth")
        
        with pg_pool.connection() as conn:
            row = conn.execute(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema = 'auth' AND table_name = 'users'"
            ).fetchone()
            assert row is not None

    def test_register_schema_idempotent(self, pg_pool):
        """Second call should not fail."""
        from modules.auth.schemas import DB_SCHEMA
        from modules.db.provider import DatabaseProvider
        from modules.db.config import DatabaseConfig
        from modules.log import Log
        
        log = Log(level="WARNING", format="posix")
        db_config = DatabaseConfig()
        db_provider = DatabaseProvider(pool=pg_pool, config=db_config, log=log)
        db_provider.register_schema("auth", DB_SCHEMA, schema_name="auth")
        db_provider.register_schema("auth", DB_SCHEMA, schema_name="auth")  # Second call


@pytest.mark.asyncio
class TestUserCRUD:
    """User CRUD through AuthProvider with real PostgreSQL."""

    def test_create_and_get_user(self, auth_provider):
        """Create user and retrieve by ID."""
        
        user = await auth_provider.create_user("testuser", "SecurePass123"))
        assert user["username"] == "testuser"
        
        fetched = await auth_provider.get_user(user["id"]))
        assert fetched is not None
        assert fetched["username"] == "testuser"

    def test_create_duplicate_user(self, auth_provider):
        """Duplicate username should raise ValueError."""
        
        await auth_provider.create_user("admin", "SecurePass123"))
        with pytest.raises(ValueError, match="already exists"):
            await auth_provider.create_user("admin", "SecurePass123"))

    def test_login_and_logout(self, auth_provider):
        """Login returns tokens, logout revokes session."""
        
        await auth_provider.create_user("admin", "SecurePass123"))
        result = await auth_provider.login("admin", "SecurePass123"))
        assert "access_token" in result
        assert "refresh_token" in result
        
        logout_result = await auth_provider.logout(result["refresh_token"]))
        assert logout_result is True


@pytest.mark.asyncio
class TestRefreshTokenRotation:
    """Refresh token rotation through AuthProvider."""

    def test_refresh_creates_new_tokens(self, auth_provider):
        """Refresh should create new access + refresh tokens."""
        
        await auth_provider.create_user("admin", "SecurePass123"))
        login_result = await auth_provider.login("admin", "SecurePass123"))
        
        refresh_result = await auth_provider.refresh_token(login_result["refresh_token"]))
        assert "access_token" in refresh_result
        assert "refresh_token" in refresh_result
        assert refresh_result["refresh_token"] != login_result["refresh_token"]

    def test_refresh_reuse_revokes_family(self, auth_provider):
        """Reusing old refresh token should revoke entire family."""
        
        await auth_provider.create_user("admin", "SecurePass123"))
        login_result = await auth_provider.login("admin", "SecurePass123"))
        
        # First refresh
        refresh_result = await auth_provider.refresh_token(login_result["refresh_token"]))
        
        # Try to reuse old token — should fail and revoke family
        with pytest.raises(Exception):
            await auth_provider.refresh_token(login_result["refresh_token"]))
        
        # New token should also be revoked
        with pytest.raises(Exception):
            await auth_provider.refresh_token(refresh_result["refresh_token"]))


@pytest.mark.asyncio
class TestAuthSchemaRegistry:
    """AuthSchemaRegistry: permissions and roles registration."""

    def test_register_permissions(self, auth_provider):
        """Register permissions via AuthSchemaRegistry."""
        
        result = await auth_provider.registry.register(
            "test_module",
            {
                "permissions": [
                    {"name": "test_module:read", "description": "Read access"},
                    {"name": "test_module:write", "description": "Write access"},
                ],
                "roles": [
                    {"name": "test_reader", "description": "Reader role", "permissions": ["test_module:read"]},
                ],
            },
            is_builtin=False,
        ))
        assert len(result["created_permissions"]) == 2
        assert len(result["created_roles"]) == 1

    def test_register_idempotent(self, auth_provider):
        """Second registration should update, not duplicate."""
        
        schema = {
            "permissions": [{"name": "test_idempotent:read", "description": "Read"}],
            "roles": [{"name": "test_idempotent_role", "description": "Role", "permissions": ["test_idempotent:read"]}],
        }
        result1 = await auth_provider.registry.register("test_module", schema, is_builtin=False))
        result2 = await auth_provider.registry.register("test_module", schema, is_builtin=False))
        assert len(result1["created_permissions"]) == 1
        assert len(result2["updated_permissions"]) == 1
