"""
UAF Security Module
====================
Handles authentication, authorization, and security utilities.

FIXES APPLIED:
- CRITICAL: SECRET_KEY now loaded from settings.JWT_SECRET_KEY (was regenerating
  on every restart via secrets.token_urlsafe(32), logging out all users)
- ACCESS_TOKEN_EXPIRE_MINUTES now loaded from settings.JWT_EXPIRE_MINUTES
- AuditLogger now writes to persistent JSON file (was print-only, lost on restart)
- Added structured audit log entries with severity levels
"""

from datetime import datetime, timedelta
from typing import Optional, Dict, List
import os
import bcrypt
from jose import JWTError, jwt
from fastapi import HTTPException, Security, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pathlib import Path
import json
import logging

from app.core.config import settings

logger = logging.getLogger(__name__)

# ============================================================================
# SECURITY CONFIGURATION — LOADED FROM .env VIA config.py
# ============================================================================

# FIX: Load SECRET_KEY from environment instead of generating a new one each restart.
# The old code: SECRET_KEY = secrets.token_urlsafe(32)
# This caused every user to be logged out on every server restart because
# JWTs signed with the old key could never be verified with the new one.
SECRET_KEY = settings.JWT_SECRET_KEY
if not SECRET_KEY or SECRET_KEY == "change-this-to-a-random-secret-key-in-production":
    import secrets
    SECRET_KEY = secrets.token_urlsafe(32)
    logger.warning(
        "⚠️  JWT_SECRET_KEY not set in .env — generated ephemeral key. "
        "Sessions will NOT survive restarts. Set JWT_SECRET_KEY in your .env file."
    )

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = settings.JWT_EXPIRE_MINUTES  # FIX: was hardcoded to 480

# Password hashing — bcrypt directly (no passlib dependency).
# passlib 1.7.4 (unmaintained) probes bcrypt.__about__, which bcrypt >= 4.1
# removed, emitting "(trapped) error reading bcrypt version" on Python 3.12+.
# Using bcrypt directly removes both that warning and the dependency.
BCRYPT_MAX_BYTES = 72  # bcrypt only uses the first 72 bytes of a password

# HTTP Bearer token scheme
security = HTTPBearer()

# ============================================================================
# PASSWORD HASHING UTILITIES
# ============================================================================

def hash_password(password: str) -> str:
    """
    Hash a plain text password using bcrypt.

    Args:
        password: Plain text password

    Returns:
        Hashed password
    """
    pw = password.encode("utf-8")[:BCRYPT_MAX_BYTES]
    return bcrypt.hashpw(pw, bcrypt.gensalt()).decode("utf-8")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain text password against a hashed password.

    Args:
        plain_password: Plain text password to verify
        hashed_password: Hashed password to compare against

    Returns:
        True if passwords match, False otherwise
    """
    try:
        pw = plain_password.encode("utf-8")[:BCRYPT_MAX_BYTES]
        return bcrypt.checkpw(pw, hashed_password.encode("utf-8"))
    except (ValueError, TypeError):
        return False

# ============================================================================
# JWT TOKEN MANAGEMENT
# ============================================================================

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a JWT access token.

    Args:
        data: Dictionary of claims to encode in the token
        expires_delta: Optional custom expiration time

    Returns:
        Encoded JWT token string
    """
    to_encode = data.copy()

    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    return encoded_jwt

def decode_access_token(token: str) -> Dict:
    """
    Decode and validate a JWT access token.

    Args:
        token: JWT token string

    Returns:
        Dictionary of decoded claims

    Raises:
        HTTPException: If token is invalid or expired
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(
            status_code=401,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

# ============================================================================
# AUTHENTICATION DEPENDENCIES
# ============================================================================

async def get_current_user(credentials: HTTPAuthorizationCredentials = Security(security)) -> Dict:
    """
    FastAPI dependency to extract and validate the current user from JWT token.

    Usage in endpoints:
        @app.get("/protected")
        async def protected_route(user: Dict = Depends(get_current_user)):
            return {"message": f"Hello {user['username']}"}

    Args:
        credentials: HTTP Bearer token credentials

    Returns:
        Dictionary containing user information

    Raises:
        HTTPException: If authentication fails
    """
    token = credentials.credentials
    payload = decode_access_token(token)

    username = payload.get("sub")
    if username is None:
        raise HTTPException(status_code=401, detail="Invalid token")

    return {
        "username": username,
        "role": payload.get("role", "user"),
        "permissions": payload.get("permissions", [])
    }

# ============================================================================
# ROLE-BASED ACCESS CONTROL
# ============================================================================

class RoleChecker:
    """
    Dependency class for role-based access control.

    Usage:
        require_admin = RoleChecker(["admin"])

        @app.get("/admin-only")
        async def admin_route(user: Dict = Depends(require_admin)):
            return {"message": "Admin access granted"}
    """

    def __init__(self, allowed_roles: list):
        self.allowed_roles = allowed_roles

    async def __call__(self, user: Dict = Depends(get_current_user)) -> Dict:
        """
        Check if the user's role is in the allowed roles list.

        Args:
            user: User dictionary from get_current_user dependency

        Returns:
            User dictionary if authorized

        Raises:
            HTTPException: If user doesn't have required role
        """
        user_role = user.get("role", "user")

        if user_role not in self.allowed_roles:
            raise HTTPException(
                status_code=403,
                detail=f"Access denied. Required role: {', '.join(self.allowed_roles)}"
            )

        return user

# ============================================================================
# API KEY AUTHENTICATION (Alternative to JWT)
# ============================================================================

class APIKeyAuth:
    """
    Simple API key authentication for machine-to-machine communication.

    Usage:
        require_api_key = APIKeyAuth()

        @app.get("/api/devices")
        async def devices(authenticated: bool = Depends(require_api_key)):
            return {"devices": [...]}
    """

    def __init__(self):
        # In production, these should be stored in a database
        self.valid_api_keys = {
            "dev_key_123": {"name": "Development Client", "permissions": ["read"]},
            "admin_key_456": {"name": "Admin Client", "permissions": ["read", "write"]},
        }

    async def __call__(self, credentials: HTTPAuthorizationCredentials = Security(security)) -> Dict:
        """
        Validate API key from Authorization header.

        Args:
            credentials: HTTP Bearer token credentials

        Returns:
            Dictionary containing API key information

        Raises:
            HTTPException: If API key is invalid
        """
        api_key = credentials.credentials

        if api_key not in self.valid_api_keys:
            raise HTTPException(
                status_code=401,
                detail="Invalid API key"
            )

        return self.valid_api_keys[api_key]

# ============================================================================
# DEFAULT USER DATABASE (FOR DEMONSTRATION)
# ============================================================================

class UserDatabase:
    """
    Simple in-memory user database for demonstration purposes.
    In production, this should be replaced with a proper database (PostgreSQL, etc.)
    """

    def __init__(self):
        # Seeded accounts. Passwords come from the environment so they are NOT
        # hardcoded secrets in the source — set ADMIN_PASSWORD / OPERATOR_PASSWORD
        # / VIEWER_PASSWORD in .env to override the demo defaults. Users can also
        # change their own password in-app (see change_password); note the store
        # is in-memory, so changes reset on restart unless persisted.
        self.users = {
            "admin": {
                "username": "admin",
                "hashed_password": hash_password(os.getenv("ADMIN_PASSWORD", "admin123")),
                "role": "admin",
                "permissions": ["read", "write", "execute", "delete"]
            },
            "operator": {
                "username": "operator",
                "hashed_password": hash_password(os.getenv("OPERATOR_PASSWORD", "operator123")),
                "role": "operator",
                "permissions": ["read", "execute"]
            },
            "viewer": {
                "username": "viewer",
                "hashed_password": hash_password(os.getenv("VIEWER_PASSWORD", "viewer123")),
                "role": "viewer",
                "permissions": ["read"]
            }
        }

    def get_user(self, username: str) -> Optional[Dict]:
        """Retrieve a user by username."""
        return self.users.get(username)

    def authenticate_user(self, username: str, password: str) -> Optional[Dict]:
        """
        Authenticate a user with username and password.

        Args:
            username: Username
            password: Plain text password

        Returns:
            User dictionary if authentication succeeds, None otherwise
        """
        user = self.get_user(username)

        if not user:
            return None

        if not verify_password(password, user["hashed_password"]):
            return None

        return user

    def create_user(self, username: str, password: str, role: str = "user") -> Dict:
        """
        Create a new user.

        Args:
            username: Username for new user
            password: Plain text password (will be hashed)
            role: User role (default: "user")

        Returns:
            Created user dictionary

        Raises:
            ValueError: If username already exists
        """
        if username in self.users:
            raise ValueError(f"User '{username}' already exists")

        # Define default permissions by role
        role_permissions = {
            "admin": ["read", "write", "execute", "delete"],
            "operator": ["read", "execute"],
            "viewer": ["read"],
            "user": ["read"]
        }

        user = {
            "username": username,
            "hashed_password": hash_password(password),
            "role": role,
            "permissions": role_permissions.get(role, ["read"])
        }

        self.users[username] = user
        return user

    def list_users(self) -> list:
        """Return all users WITHOUT password hashes (safe for the admin UI)."""
        return [
            {"username": u["username"], "role": u["role"],
             "permissions": u.get("permissions", [])}
            for u in self.users.values()
        ]

    def delete_user(self, username: str) -> bool:
        """Remove a user. Raises ValueError if missing or if it is the last admin."""
        if username not in self.users:
            raise ValueError(f"User '{username}' not found")
        # Never allow deleting the last remaining admin (lockout protection).
        admins = [u for u in self.users.values() if u.get("role") == "admin"]
        if self.users[username].get("role") == "admin" and len(admins) <= 1:
            raise ValueError("Cannot delete the last remaining admin account")
        del self.users[username]
        return True

    def admin_set_password(self, username: str, new_password: str) -> bool:
        """Admin resets another user's password (no old-password needed)."""
        user = self.get_user(username)
        if not user:
            raise ValueError("User not found")
        if not new_password or len(new_password) < 6:
            raise ValueError("New password must be at least 6 characters")
        user["hashed_password"] = hash_password(new_password)
        return True

    def change_password(self, username: str, old_password: str,
                        new_password: str) -> bool:
        """Change a user's password IN PLACE, preserving role + permissions.

        ONLY the password hash is updated — the user's 'role' and 'permissions'
        are deliberately left untouched, so an admin who changes their password
        remains an admin (and an operator stays an operator, etc.).

        Raises ValueError on unknown user, wrong current password, or a
        new password that's too short.
        """
        user = self.get_user(username)
        if not user:
            raise ValueError("User not found")
        if not verify_password(old_password, user["hashed_password"]):
            raise ValueError("Current password is incorrect")
        if not new_password or len(new_password) < 6:
            raise ValueError("New password must be at least 6 characters")
        # Update ONLY the credential. role/permissions are preserved.
        user["hashed_password"] = hash_password(new_password)
        return True

# Initialize the user database
user_db = UserDatabase()

# ============================================================================
# AUTHENTICATION ENDPOINTS HELPERS
# ============================================================================

def authenticate_and_create_token(username: str, password: str) -> Dict:
    """
    Authenticate a user and generate an access token.

    Args:
        username: Username
        password: Password

    Returns:
        Dictionary containing access token and token type

    Raises:
        HTTPException: If authentication fails
    """
    user = user_db.authenticate_user(username, password)

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password"
        )

    # Create JWT token
    access_token = create_access_token(
        data={
            "sub": user["username"],
            "role": user["role"],
            "permissions": user["permissions"]
        }
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,  # seconds
        "user": {
            "username": user["username"],
            "role": user["role"]
        }
    }

# ============================================================================
# AUDIT LOGGING — PERSISTENT FILE-BASED
# ============================================================================

class AuditLogger:
    """
    Persistent audit logger for security-sensitive operations.

    FIX: Was print-only (lost on restart). Now writes to a JSON log file
    so audit trails survive server restarts, which is critical for a
    security-focused project.
    """

    def __init__(self, log_dir: str = "logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.audit_file = self.log_dir / "audit_log.json"
        if not self.audit_file.exists():
            self.audit_file.write_text("[]")

    def _write_entry(self, entry: Dict):
        """Append an audit entry to the persistent log file."""
        try:
            with open(self.audit_file, 'r') as f:
                log = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            log = []

        log.append(entry)

        # Keep last 10,000 entries to prevent unbounded growth
        if len(log) > 10000:
            log = log[-10000:]

        with open(self.audit_file, 'w') as f:
            json.dump(log, f, indent=2)

        # Also print for real-time visibility in logs
        severity = entry.get("severity", "INFO")
        logger.log(
            logging.WARNING if severity == "WARNING" else logging.INFO,
            f"[AUDIT] {entry.get('event_type', 'UNKNOWN')} - {entry.get('details', '')}"
        )

    def log_authentication(self, username: str, success: bool, ip_address: str = "unknown"):
        """Log authentication attempts."""
        self._write_entry({
            "timestamp": datetime.now().isoformat(),
            "event_type": "AUTHENTICATION_SUCCESS" if success else "AUTHENTICATION_FAILED",
            "severity": "INFO" if success else "WARNING",
            "username": username,
            "ip_address": ip_address,
            "details": f"Login {'succeeded' if success else 'failed'} for user: {username}"
        })

    def log_access(self, username: str, endpoint: str, method: str, ip_address: str = "unknown"):
        """Log API access."""
        self._write_entry({
            "timestamp": datetime.now().isoformat(),
            "event_type": "API_ACCESS",
            "severity": "INFO",
            "username": username,
            "endpoint": endpoint,
            "method": method,
            "ip_address": ip_address,
            "details": f"{method} {endpoint} by {username}"
        })

    def log_security_event(self, event_type: str, details: str):
        """Log security events."""
        self._write_entry({
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "severity": "WARNING",
            "details": details
        })

    def get_recent_logs(self, limit: int = 100) -> List[Dict]:
        """Retrieve recent audit log entries."""
        try:
            with open(self.audit_file, 'r') as f:
                log = json.load(f)
            return sorted(log, key=lambda x: x.get('timestamp', ''), reverse=True)[:limit]
        except (json.JSONDecodeError, FileNotFoundError):
            return []

audit_logger = AuditLogger()