from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from jose import JWTError, jwt
from typing import Optional, List
import time

from app.database import get_db, redis_client
from app.config import settings
from app.models.user import User, UserRole
from app.core.exceptions import (
    UnauthorizedException, 
    ForbiddenException,
    RateLimitException
)
from app.core.security import verify_token

# Security scheme
security = HTTPBearer(auto_error=False)

# ============================================================================
# AUTHENTICATION DEPENDENCIES
# ============================================================================

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    """Get current authenticated user"""
    if not credentials:
        raise UnauthorizedException("Authentication credentials required")
    
    try:
        # Verify the token
        payload = verify_token(credentials.credentials, "access")
        if not payload:
            raise UnauthorizedException("Invalid authentication token")
        
        user_id: int = int(payload.get("sub"))
        if user_id is None:
            raise UnauthorizedException("Invalid token payload")
            
    except (JWTError, ValueError, TypeError):
        raise UnauthorizedException("Invalid authentication token")
    
    # Get user from database
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise UnauthorizedException("User not found")
    
    if not user.is_active:
        raise ForbiddenException("Account is deactivated")
    
    return user


async def get_current_user_optional(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: Session = Depends(get_db)
) -> Optional[User]:
    """Get current user if authenticated, None otherwise"""
    if not credentials:
        return None
    
    try:
        return await get_current_user(credentials, db)
    except (UnauthorizedException, ForbiddenException):
        return None


async def get_current_active_user(
    current_user: User = Depends(get_current_user)
) -> User:
    """Get current user and verify account is active"""
    if not current_user.is_active:
        raise ForbiddenException("Account is deactivated")
    return current_user


async def get_current_verified_user(
    current_user: User = Depends(get_current_user)
) -> User:
    """Get current user and verify email is verified"""
    if not current_user.is_verified:
        raise ForbiddenException("Email verification required")
    return current_user


# ============================================================================
# AUTHORIZATION DEPENDENCIES
# ============================================================================

async def get_current_active_admin(
    current_user: User = Depends(get_current_user)
) -> User:
    """Get current user and verify admin permissions"""
    if not current_user.is_admin:
        raise ForbiddenException("Admin privileges required")
    return current_user


async def get_current_super_admin(
    current_user: User = Depends(get_current_user)
) -> User:
    """Get current user and verify super admin permissions"""
    if not current_user.is_super_admin:
        raise ForbiddenException("Super admin privileges required")
    return current_user


def require_roles(allowed_roles: List[UserRole]):
    """Dependency factory to require specific roles"""
    def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in allowed_roles:
            raise ForbiddenException(f"Required roles: {[role.value for role in allowed_roles]}")
        return current_user
    return role_checker


def require_verified_user(
    current_user: User = Depends(get_current_user)
) -> User:
    """Require user to have verified email"""
    if not current_user.is_verified:
        raise ForbiddenException("Email verification required to access this resource")
    return current_user


# ============================================================================
# PERMISSION CHECKING DEPENDENCIES
# ============================================================================

def check_user_or_admin(target_user_id: int):
    """Check if current user is the target user or an admin"""
    def checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.id != target_user_id and not current_user.is_admin:
            raise ForbiddenException("Access denied: can only access own resources")
        return current_user
    return checker


async def get_user_or_admin_access(
    user_id: int,
    current_user: User = Depends(get_current_user)
) -> User:
    """Verify user can access resource (own resource or admin)"""
    if current_user.id != user_id and not current_user.is_admin:
        raise ForbiddenException("Access denied: insufficient permissions")
    return current_user


# ============================================================================
# RATE LIMITING DEPENDENCIES
# ============================================================================

def rate_limit(max_requests: int = 60, window_seconds: int = 60, key_func=None):
    """Rate limiting dependency factory"""
    def rate_limiter(request: Request):
        # Get identifier for rate limiting
        if key_func:
            key = key_func(request)
        else:
            # Default to IP address
            key = f"rate_limit:{request.client.host}"
        
        try:
            # Get current count from Redis
            current = redis_client.get(key)
            if current is None:
                # First request in window
                redis_client.setex(key, window_seconds, 1)
                return True
            
            if int(current) >= max_requests:
                raise RateLimitException(
                    f"Rate limit exceeded: {max_requests} requests per {window_seconds} seconds"
                )
            
            # Increment counter
            redis_client.incr(key)
            return True
            
        except Exception as e:
            # If Redis is down, allow the request but log the error
            print(f"Rate limiting error: {e}")
            return True
    
    return rate_limiter


def auth_rate_limit(request: Request):
    """Rate limit for authentication endpoints"""
    key = f"auth_rate_limit:{request.client.host}"
    return rate_limit(max_requests=5, window_seconds=300, key_func=lambda r: key)(request)


def api_rate_limit(request: Request):
    """General API rate limit"""
    key = f"api_rate_limit:{request.client.host}"
    return rate_limit(max_requests=100, window_seconds=60, key_func=lambda r: key)(request)


# ============================================================================
# PAGINATION DEPENDENCIES
# ============================================================================

def get_pagination_params(
    page: int = 1,
    size: int = 20
):
    """Get pagination parameters with validation"""
    if page < 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Page must be greater than 0"
        )
    
    if size < 1 or size > settings.MAX_PAGE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Size must be between 1 and {settings.MAX_PAGE_SIZE}"
        )
    
    return {"page": page, "size": size}


class PaginationParams:
    """Pagination parameters class"""
    def __init__(
        self,
        page: int = 1,
        size: int = 20
    ):
        if page < 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Page must be greater than 0"
            )
        
        if size < 1 or size > settings.MAX_PAGE_SIZE:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Size must be between 1 and {settings.MAX_PAGE_SIZE}"
            )
        
        self.page = page
        self.size = size
        self.offset = (page - 1) * size


# ============================================================================
# SERVICE DEPENDENCIES
# ============================================================================

def get_user_service(db: Session = Depends(get_db)):
    """Get UserService instance"""
    from app.services.user_service import UserService
    return UserService(db)


def get_auth_service(db: Session = Depends(get_db)):
    """Get AuthService instance"""
    from app.services.auth_service import AuthService
    return AuthService(db)


# ============================================================================
# VALIDATION DEPENDENCIES
# ============================================================================

def validate_user_exists(user_id: int, db: Session = Depends(get_db)) -> User:
    """Validate that user exists and return user"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    return user


def validate_active_user(user: User = Depends(validate_user_exists)) -> User:
    """Validate that user is active"""
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    return user


# ============================================================================
# REQUEST CONTEXT DEPENDENCIES
# ============================================================================

def get_request_info(request: Request):
    """Get request information for logging/auditing"""
    return {
        "ip_address": request.client.host,
        "user_agent": request.headers.get("user-agent"),
        "method": request.method,
        "url": str(request.url),
        "timestamp": time.time()
    }


def get_client_ip(request: Request) -> str:
    """Get client IP address, considering proxies"""
    # Check for X-Forwarded-For header (load balancers/proxies)
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    
    # Check for X-Real-IP header (nginx)
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip
    
    # Fallback to client host
    return request.client.host


# ============================================================================
# FEATURE FLAGS DEPENDENCIES
# ============================================================================

def require_feature_enabled(feature_name: str):
    """Dependency to check if a feature is enabled"""
    def feature_checker():
        # TODO: Implement feature flag checking
        # This could check Redis, database, or config
        enabled_features = getattr(settings, 'ENABLED_FEATURES', [])
        if feature_name not in enabled_features:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Feature '{feature_name}' is currently disabled"
            )
        return True
    return feature_checker


# ============================================================================
# SECURITY DEPENDENCIES
# ============================================================================

def check_password_policy(password: str):
    """Check if password meets policy requirements"""
    if len(password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 8 characters long"
        )
    
    if not any(c.isupper() for c in password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must contain at least one uppercase letter"
        )
    
    if not any(c.islower() for c in password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must contain at least one lowercase letter"
        )
    
    if not any(c.isdigit() for c in password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must contain at least one digit"
        )
    
    return True


def check_maintenance_mode():
    """Check if system is in maintenance mode"""
    # TODO: Implement maintenance mode checking
    maintenance = getattr(settings, 'MAINTENANCE_MODE', False)
    if maintenance:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="System is currently under maintenance"
        )
    return True


# ============================================================================
# WEBSOCKET DEPENDENCIES
# ============================================================================

async def get_websocket_user(token: str, db: Session):
    """Get user for WebSocket connections"""
    try:
        payload = verify_token(token, "access")
        if not payload:
            return None
        
        user_id = int(payload.get("sub"))
        user = db.query(User).filter(User.id == user_id).first()
        
        if not user or not user.is_active:
            return None
        
        return user
    except:
        return None