from functools import wraps
from typing import List, Callable
from fastapi import HTTPException, status
from app.models.user import User, UserRole

def require_permissions(allowed_roles: List[UserRole]):
    """Decorator to check user permissions"""
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract current_user from kwargs
            current_user = kwargs.get('current_user')
            if not current_user or not isinstance(current_user, User):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required"
                )
            
            if current_user.role not in allowed_roles:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Insufficient permissions"
                )
            
            return await func(*args, **kwargs)
        return wrapper
    return decorator

def require_admin(func: Callable):
    """Decorator to require admin permissions"""
    return require_permissions([UserRole.ADMIN, UserRole.SUPER_ADMIN])(func)

def require_active_user(func: Callable):
    """Decorator to require active user"""
    @wraps(func)
    async def wrapper(*args, **kwargs):
        current_user = kwargs.get('current_user')
        if not current_user or not current_user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Inactive user account"
            )
        return await func(*args, **kwargs)
    return wrapper