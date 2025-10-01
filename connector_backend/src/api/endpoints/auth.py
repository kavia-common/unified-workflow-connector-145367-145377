from fastapi import APIRouter, HTTPException, status, Depends
from fastapi.security import HTTPBearer
from pydantic import BaseModel, Field
from typing import Dict, Any, Optional
from datetime import datetime

from src.core.security import (
    token_manager, password_manager, api_key_manager, get_current_user
)
from src.core.database import get_database
from src.core.exceptions import AuthenticationException, ValidationException
from src.models.schemas import StatusResponse
from loguru import logger

router = APIRouter()
security = HTTPBearer()


class LoginRequest(BaseModel):
    """Login request schema"""
    username: str = Field(..., description="Username or email")
    password: str = Field(..., description="Password")


class LoginResponse(BaseModel):
    """Login response schema"""
    access_token: str = Field(..., description="JWT access token")
    token_type: str = Field(default="bearer", description="Token type")
    expires_in: int = Field(..., description="Token expiration time in seconds")
    user_id: str = Field(..., description="User identifier")
    tenant_id: str = Field(..., description="Tenant identifier")


class RegisterRequest(BaseModel):
    """User registration request schema"""
    username: str = Field(..., min_length=3, max_length=50, description="Username")
    email: str = Field(..., description="Email address")
    password: str = Field(..., min_length=8, description="Password")
    full_name: Optional[str] = Field(None, description="Full name")
    tenant_id: Optional[str] = Field(None, description="Tenant identifier")


class UserResponse(BaseModel):
    """User response schema"""
    id: str = Field(..., description="User identifier")
    username: str = Field(..., description="Username")
    email: str = Field(..., description="Email address")
    full_name: Optional[str] = Field(None, description="Full name")
    tenant_id: str = Field(..., description="Tenant identifier")
    is_active: bool = Field(..., description="User active status")
    created_at: str = Field(..., description="Creation timestamp")


class APIKeyResponse(BaseModel):
    """API key response schema"""
    api_key: str = Field(..., description="Generated API key")
    key_id: str = Field(..., description="API key identifier")
    created_at: str = Field(..., description="Creation timestamp")


# PUBLIC_INTERFACE
@router.post("/login", response_model=LoginResponse, summary="User login")
async def login(
    login_request: LoginRequest,
    db = Depends(get_database)
):
    """
    Authenticate user and return JWT token.
    
    Args:
        login_request: Login credentials
        db: Database connection
        
    Returns:
        LoginResponse: JWT token and user information
    """
    try:
        # Find user by username or email
        user = await db.users.find_one({
            "$or": [
                {"username": login_request.username},
                {"email": login_request.username}
            ],
            "is_active": True
        })
        
        if not user:
            raise AuthenticationException("Invalid username or password")
        
        # Verify password
        if not password_manager.verify_password(login_request.password, user["password_hash"]):
            raise AuthenticationException("Invalid username or password")
        
        # Create JWT token
        token_data = {
            "sub": str(user["_id"]),
            "user_id": str(user["_id"]),
            "username": user["username"],
            "email": user["email"],
            "tenant_id": user["tenant_id"],
            "type": "access_token"
        }
        
        access_token = token_manager.create_access_token(token_data)
        
        # Update last login
        from datetime import datetime
        await db.users.update_one(
            {"_id": user["_id"]},
            {"$set": {"last_login": datetime.utcnow()}}
        )
        
        return LoginResponse(
            access_token=access_token,
            token_type="bearer",
            expires_in=60 * 60 * 24 * 8,  # 8 days
            user_id=str(user["_id"]),
            tenant_id=user["tenant_id"]
        )
        
    except AuthenticationException:
        raise
    except Exception as e:
        logger.error(f"Login failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Login failed"
        )


# PUBLIC_INTERFACE
@router.post("/register", response_model=UserResponse, summary="User registration")
async def register(
    register_request: RegisterRequest,
    db = Depends(get_database)
):
    """
    Register a new user account.
    
    Args:
        register_request: Registration data
        db: Database connection
        
    Returns:
        UserResponse: Created user information
    """
    try:
        # Check if username already exists
        existing_user = await db.users.find_one({
            "$or": [
                {"username": register_request.username},
                {"email": register_request.email}
            ]
        })
        
        if existing_user:
            raise ValidationException("Username or email already exists")
        
        # Generate tenant ID if not provided
        tenant_id = register_request.tenant_id
        if not tenant_id:
            import uuid
            tenant_id = str(uuid.uuid4())
        
        # Hash password
        password_hash = password_manager.hash_password(register_request.password)
        
        # Create user document
        from datetime import datetime
        user_doc = {
            "username": register_request.username,
            "email": register_request.email,
            "password_hash": password_hash,
            "full_name": register_request.full_name,
            "tenant_id": tenant_id,
            "is_active": True,
            "created_at": datetime.utcnow(),
            "last_login": None
        }
        
        result = await db.users.insert_one(user_doc)
        
        # Return user information
        return UserResponse(
            id=str(result.inserted_id),
            username=register_request.username,
            email=register_request.email,
            full_name=register_request.full_name,
            tenant_id=tenant_id,
            is_active=True,
            created_at=user_doc["created_at"].isoformat()
        )
        
    except ValidationException:
        raise
    except Exception as e:
        logger.error(f"Registration failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration failed"
        )


# PUBLIC_INTERFACE
@router.get("/me", response_model=UserResponse, summary="Get current user")
async def get_current_user_info(
    current_user: Dict[str, Any] = Depends(get_current_user),
    db = Depends(get_database)
):
    """
    Get current authenticated user information.
    
    Args:
        current_user: Current authenticated user
        db: Database connection
        
    Returns:
        UserResponse: Current user information
    """
    try:
        user_id = current_user.get("user_id")
        if not user_id:
            raise AuthenticationException("Invalid user token")
        
        from bson import ObjectId
        user = await db.users.find_one({"_id": ObjectId(user_id)})
        
        if not user:
            raise AuthenticationException("User not found")
        
        return UserResponse(
            id=str(user["_id"]),
            username=user["username"],
            email=user["email"],
            full_name=user.get("full_name"),
            tenant_id=user["tenant_id"],
            is_active=user["is_active"],
            created_at=user["created_at"].isoformat()
        )
        
    except AuthenticationException:
        raise
    except Exception as e:
        logger.error(f"Failed to get user info: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve user information"
        )


# PUBLIC_INTERFACE
@router.post("/api-key", response_model=APIKeyResponse, summary="Generate API key")
async def generate_api_key(
    current_user: Dict[str, Any] = Depends(get_current_user),
    db = Depends(get_database)
):
    """
    Generate a new API key for the current user.
    
    Args:
        current_user: Current authenticated user
        db: Database connection
        
    Returns:
        APIKeyResponse: Generated API key information
    """
    try:
        user_id = current_user.get("user_id")
        tenant_id = current_user.get("tenant_id")
        
        if not user_id or not tenant_id:
            raise AuthenticationException("Invalid user token")
        
        # Generate API key
        api_key = api_key_manager.generate_api_key()
        
        # Store API key in database
        from datetime import datetime
        api_key_doc = {
            "user_id": user_id,
            "tenant_id": tenant_id,
            "api_key_hash": password_manager.hash_password(api_key),
            "name": f"API Key - {datetime.utcnow().strftime('%Y-%m-%d %H:%M')}",
            "is_active": True,
            "created_at": datetime.utcnow(),
            "last_used": None
        }
        
        result = await db.api_keys.insert_one(api_key_doc)
        
        return APIKeyResponse(
            api_key=api_key,
            key_id=str(result.inserted_id),
            created_at=api_key_doc["created_at"].isoformat()
        )
        
    except AuthenticationException:
        raise
    except Exception as e:
        logger.error(f"Failed to generate API key: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate API key"
        )


# PUBLIC_INTERFACE
@router.delete("/api-key/{key_id}", response_model=StatusResponse, summary="Revoke API key")
async def revoke_api_key(
    key_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db = Depends(get_database)
):
    """
    Revoke an API key.
    
    Args:
        key_id: API key identifier
        current_user: Current authenticated user
        db: Database connection
        
    Returns:
        StatusResponse: Revocation status
    """
    try:
        user_id = current_user.get("user_id")
        
        if not user_id:
            raise AuthenticationException("Invalid user token")
        
        from bson import ObjectId
        
        # Find and deactivate API key
        result = await db.api_keys.update_one(
            {
                "_id": ObjectId(key_id),
                "user_id": user_id,
                "is_active": True
            },
            {
                "$set": {
                    "is_active": False,
                    "revoked_at": datetime.utcnow()
                }
            }
        )
        
        if result.matched_count == 0:
            raise ValidationException("API key not found")
        
        return StatusResponse(
            status="success",
            message="API key revoked successfully"
        )
        
    except (AuthenticationException, ValidationException):
        raise
    except Exception as e:
        logger.error(f"Failed to revoke API key: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to revoke API key"
        )


# PUBLIC_INTERFACE
@router.post("/refresh", response_model=LoginResponse, summary="Refresh token")
async def refresh_token(
    current_user: Dict[str, Any] = Depends(get_current_user),
    db = Depends(get_database)
):
    """
    Refresh JWT access token.
    
    Args:
        current_user: Current authenticated user
        db: Database connection
        
    Returns:
        LoginResponse: New JWT token
    """
    try:
        user_id = current_user.get("user_id")
        
        if not user_id:
            raise AuthenticationException("Invalid user token")
        
        from bson import ObjectId
        
        # Verify user still exists and is active
        user = await db.users.find_one({
            "_id": ObjectId(user_id),
            "is_active": True
        })
        
        if not user:
            raise AuthenticationException("User not found or inactive")
        
        # Create new JWT token
        token_data = {
            "sub": str(user["_id"]),
            "user_id": str(user["_id"]),
            "username": user["username"],
            "email": user["email"],
            "tenant_id": user["tenant_id"],
            "type": "access_token"
        }
        
        access_token = token_manager.create_access_token(token_data)
        
        return LoginResponse(
            access_token=access_token,
            token_type="bearer",
            expires_in=60 * 60 * 24 * 8,  # 8 days
            user_id=str(user["_id"]),
            tenant_id=user["tenant_id"]
        )
        
    except AuthenticationException:
        raise
    except Exception as e:
        logger.error(f"Token refresh failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Token refresh failed"
        )
