"""
UAF Authentication Endpoints
==============================
Handles user authentication, token generation, and user management.
"""

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional

from app.core.security import (
    authenticate_and_create_token,
    user_db,
    get_current_user,
    RoleChecker,
    audit_logger
)

router = APIRouter(prefix="/auth", tags=["Authentication"])

# ============================================================================
# REQUEST/RESPONSE MODELS
# ============================================================================

class LoginRequest(BaseModel):
    username: str
    password: str

class LoginResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int
    user: dict

class UserCreateRequest(BaseModel):
    username: str
    password: str
    role: Optional[str] = "user"

class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str

class UserResponse(BaseModel):
    username: str
    role: str
    permissions: list

# ============================================================================
# AUTHENTICATION ENDPOINTS
# ============================================================================

@router.post("/login", response_model=LoginResponse)
async def login(request: LoginRequest):
    """
    Authenticate a user and return a JWT access token.
    
    Default credentials:
    - Admin: username=admin, password=admin123
    - Operator: username=operator, password=operator123
    - Viewer: username=viewer, password=viewer123
    """
    try:
        result = authenticate_and_create_token(request.username, request.password)
        
        # Log successful authentication
        audit_logger.log_authentication(request.username, success=True)
        
        return result
    
    except HTTPException as e:
        # Log failed authentication
        audit_logger.log_authentication(request.username, success=False)
        raise e

@router.get("/me", response_model=UserResponse)
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    """
    Get information about the currently authenticated user.
    Requires a valid JWT token in the Authorization header.
    """
    return {
        "username": current_user["username"],
        "role": current_user["role"],
        "permissions": current_user["permissions"]
    }

@router.post("/change-password")
async def change_password(
    request: ChangePasswordRequest,
    current_user: dict = Depends(get_current_user),
):
    """Change the signed-in user's own password.

    Any authenticated user (admin / operator / viewer) can change their OWN
    password. Only the credential changes — the user's role and permissions are
    preserved, so an admin remains an admin. The current session token stays
    valid; the new password is used at the next sign-in.
    """
    username = current_user["username"]
    try:
        user_db.change_password(username, request.old_password, request.new_password)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    audit_logger.log_security_event(
        "PASSWORD_CHANGED", f"User '{username}' changed their own password"
    )
    return {
        "status": "success",
        "message": "Password updated. Use it at your next sign-in.",
        "username": username,
        "role": current_user["role"],  # echoes back that the role is unchanged
    }


@router.post("/logout")
async def logout(current_user: dict = Depends(get_current_user)):
    """
    Logout endpoint (JWT tokens are stateless, so this is mostly for logging).
    In a production system, you might want to add the token to a blacklist.
    """
    audit_logger.log_security_event(
        "USER_LOGOUT",
        f"User {current_user['username']} logged out"
    )
    
    return {
        "message": "Logout successful",
        "username": current_user["username"]
    }

# ============================================================================
# USER MANAGEMENT ENDPOINTS (Admin Only)
# ============================================================================

require_admin = RoleChecker(["admin"])

@router.post("/users", response_model=UserResponse)
async def create_user(
    request: UserCreateRequest,
    current_user: dict = Depends(require_admin)
):
    """
    Create a new user (Admin only).
    """
    try:
        user = user_db.create_user(
            username=request.username,
            password=request.password,
            role=request.role
        )
        
        audit_logger.log_security_event(
            "USER_CREATED",
            f"User {request.username} created by {current_user['username']}"
        )
        
        return {
            "username": user["username"],
            "role": user["role"],
            "permissions": user["permissions"]
        }
    
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/users")
async def list_users(current_user: dict = Depends(require_admin)):
    """
    List all users (Admin only).
    """
    users = [
        {
            "username": user["username"],
            "role": user["role"],
            "permissions": user["permissions"]
        }
        for user in user_db.users.values()
    ]
    
    return {
        "count": len(users),
        "users": users
    }

# ============================================================================
# TOKEN VALIDATION
# ============================================================================

@router.get("/validate")
async def validate_token(current_user: dict = Depends(get_current_user)):
    """
    Validate a JWT token and return basic user info.
    Useful for frontend token validation.
    """
    return {
        "valid": True,
        "username": current_user["username"],
        "role": current_user["role"]
    }