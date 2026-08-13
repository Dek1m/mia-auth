# Auth Module for Mia Framework

Provides authentication, authorization, and user management.

## Features

- **User Management**: CRUD operations for users
- **Authentication**: Login/logout with JWT tokens
- **Authorization**: RBAC (Role-Based Access Control)
- **Password Hashing**: PBKDF2 with salt
- **Account Lockout**: Automatic lock after failed attempts

## Installation

```bash
# From GitHub
git clone https://github.com/Dek1m/mia-auth.git
cd mia-auth
pip install -e .
```

## Configuration

### Environment Variables

```bash
AUTH_JWT_SECRET=your-secret-key
AUTH_JWT_ALGORITHM=HS256
AUTH_JWT_EXPIRATION_HOURS=24
AUTH_PASSWORD_MIN_LENGTH=8
AUTH_MAX_LOGIN_ATTEMPTS=5
AUTH_LOCKOUT_DURATION_MINUTES=15
```

### Direct Configuration

```python
from mia.modules.auth import AuthModule, AuthConfig

config = AuthConfig(
    jwt_secret="your-secret-key",
    jwt_expiration_hours=24,
)

module = AuthModule(config)
app.load_module(module)
```

## Usage

### Create User

```python
user = app.services.resolve(AuthProvider).create_user(
    username="admin",
    password="SecurePass123",
    email="admin@example.com",
    roles=["admin"],
)
```

### Login

```python
token = app.services.resolve(AuthProvider).login(
    username="admin",
    password="SecurePass123",
)
```

### Check Permission

```python
has_permission = app.services.resolve(AuthProvider).authorize(
    token=token,
    permission="users:read",
)
```

## Testing

```bash
pytest modules/auth/tests/ -v
```

## License

MIT License
