import jwt
import bcrypt
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from fastapi import HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import secrets
from loguru import logger

from src.core.config import settings


class SecurityHeaders:
    """Middleware to add security headers to responses"""
    
    def __init__(self, app):
        self.app = app
    
    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            async def send_wrapper(message):
                if message["type"] == "http.response.start":
                    headers = dict(message.get("headers", []))
                    
                    # Add security headers
                    security_headers = {
                        b"x-content-type-options": b"nosniff",
                        b"x-frame-options": b"DENY",
                        b"x-xss-protection": b"1; mode=block",
                        b"strict-transport-security": b"max-age=31536000; includeSubDomains",
                        b"referrer-policy": b"strict-origin-when-cross-origin",
                        b"permissions-policy": b"geolocation=(), microphone=(), camera=()"
                    }
                    
                    headers.update(security_headers)
                    message["headers"] = list(headers.items())
                
                await send(message)
            
            await self.app(scope, receive, send_wrapper)
        else:
            await self.app(scope, receive, send)


class TokenManager:
    """JWT token management utilities"""
    
    @staticmethod
    def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
        """
        Create a JWT access token.
        
        Args:
            data: Token payload data
            expires_delta: Token expiration time delta
            
        Returns:
            str: Encoded JWT token
        """
        to_encode = data.copy()
        
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        
        to_encode.update({"exp": expire, "iat": datetime.utcnow()})
        
        encoded_jwt = jwt.encode(
            to_encode, 
            settings.SECRET_KEY, 
            algorithm="HS256"
        )
        
        return encoded_jwt
    
    @staticmethod
    def verify_token(token: str) -> Dict[str, Any]:
        """
        Verify and decode a JWT token.
        
        Args:
            token: JWT token to verify
            
        Returns:
            dict: Decoded token payload
            
        Raises:
            HTTPException: If token is invalid or expired
        """
        try:
            payload = jwt.decode(
                token, 
                settings.SECRET_KEY, 
                algorithms=["HS256"]
            )
            return payload
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired",
                headers={"WWW-Authenticate": "Bearer"},
            )
        except jwt.JWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )


class EncryptionManager:
    """Encryption utilities for sensitive data"""
    
    def __init__(self):
        self._fernet = self._create_fernet()
    
    def _create_fernet(self) -> Fernet:
        """Create Fernet encryption instance from settings key"""
        # Derive key from settings encryption key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'stable_salt_for_connector',  # In production, use a random salt stored securely
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(settings.ENCRYPTION_KEY.encode()))
        return Fernet(key)
    
    def encrypt(self, data: str) -> str:
        """
        Encrypt sensitive data.
        
        Args:
            data: Plain text data to encrypt
            
        Returns:
            str: Base64 encoded encrypted data
        """
        encrypted_data = self._fernet.encrypt(data.encode())
        return base64.urlsafe_b64encode(encrypted_data).decode()
    
    def decrypt(self, encrypted_data: str) -> str:
        """
        Decrypt sensitive data.
        
        Args:
            encrypted_data: Base64 encoded encrypted data
            
        Returns:
            str: Decrypted plain text data
        """
        try:
            decoded_data = base64.urlsafe_b64decode(encrypted_data.encode())
            decrypted_data = self._fernet.decrypt(decoded_data)
            return decrypted_data.decode()
        except Exception as e:
            logger.error(f"Failed to decrypt data: {e}")
            raise ValueError("Failed to decrypt data")


class PasswordManager:
    """Password hashing and verification utilities"""
    
    @staticmethod
    def hash_password(password: str) -> str:
        """
        Hash a password using bcrypt.
        
        Args:
            password: Plain text password
            
        Returns:
            str: Hashed password
        """
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')
    
    @staticmethod
    def verify_password(password: str, hashed: str) -> bool:
        """
        Verify a password against its hash.
        
        Args:
            password: Plain text password
            hashed: Hashed password
            
        Returns:
            bool: True if password matches hash
        """
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))


class APIKeyManager:
    """API key generation and validation utilities"""
    
    @staticmethod
    def generate_api_key() -> str:
        """
        Generate a secure API key.
        
        Returns:
            str: Generated API key
        """
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def generate_webhook_secret() -> str:
        """
        Generate a webhook secret for signature validation.
        
        Returns:
            str: Generated webhook secret
        """
        return secrets.token_urlsafe(24)


# Global instances
token_manager = TokenManager()
encryption_manager = EncryptionManager()
password_manager = PasswordManager()
api_key_manager = APIKeyManager()


# FastAPI dependency for authentication
security = HTTPBearer()


# PUBLIC_INTERFACE
async def get_current_user(credentials: HTTPAuthorizationCredentials = security) -> Dict[str, Any]:
    """
    FastAPI dependency to get current authenticated user from JWT token.
    
    Args:
        credentials: HTTP Bearer credentials
        
    Returns:
        dict: Current user information
        
    Raises:
        HTTPException: If authentication fails
    """
    return token_manager.verify_token(credentials.credentials)


# PUBLIC_INTERFACE
def create_state_token(tenant_id: str, connector_id: str) -> str:
    """
    Create a state token for OAuth flows.
    
    Args:
        tenant_id: Tenant identifier
        connector_id: Connector identifier
        
    Returns:
        str: State token
    """
    data = {
        "tenant_id": tenant_id,
        "connector_id": connector_id,
        "purpose": "oauth_state",
        "nonce": secrets.token_urlsafe(16)
    }
    
    return token_manager.create_access_token(
        data, 
        expires_delta=timedelta(minutes=10)  # Short expiry for state tokens
    )


# PUBLIC_INTERFACE
def verify_state_token(state_token: str) -> Dict[str, Any]:
    """
    Verify and decode an OAuth state token.
    
    Args:
        state_token: State token to verify
        
    Returns:
        dict: Decoded state token data
        
    Raises:
        HTTPException: If state token is invalid
    """
    payload = token_manager.verify_token(state_token)
    
    if payload.get("purpose") != "oauth_state":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid state token purpose"
        )
    
    return payload
