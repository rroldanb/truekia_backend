from datetime import datetime, timedelta
from typing import Optional, Tuple, Dict, Any, List
from sqlalchemy.orm import Session
from jose import JWTError
import secrets
import string

from app.models.user import User, UserRole
from app.schemas.user import (
    UserLogin, 
    Token, 
    TokenRefresh, 
    UserCreate,
    PasswordReset,
    PasswordResetConfirm,
    EmailVerification
)
from app.core.security import (
    create_access_token, 
    create_refresh_token, 
    verify_token,
    get_password_hash,
    verify_password
)
from app.core.exceptions import (
    UnauthorizedException, 
    ValidationException,
    NotFoundException,
    ConflictException,
    ForbiddenException
)
from app.config import settings
from app.services.user_service import UserService


class AuthService:
    """Authentication service for handling user authentication and authorization"""
    
    def __init__(self, db: Session):
        self.db = db
        self.user_service = UserService(db)
    
    def register(self, user_data: UserCreate) -> Tuple[User, str]:
        """Register a new user"""
        try:
            # Create the user using UserService
            user = self.user_service.create_user(user_data)
            
            # Generate verification token if not already set
            if not user.verification_token:
                user.verification_token = self._generate_token()
                self.db.commit()
                self.db.refresh(user)
            
            # TODO: Send verification email here
            verification_message = "Registration successful. Please check your email to verify your account."
            
            return user, verification_message
            
        except ConflictException:
            # Re-raise the exception from UserService
            raise
        except Exception as e:
            raise ValidationException(f"Registration failed: {str(e)}")
    
    def login(self, user_login: UserLogin) -> Tuple[Token, User]:
        """Authenticate user and return tokens"""
        # Authenticate user
        user = self.user_service.authenticate_user(
            user_login.email_or_username, 
            user_login.password
        )
        
        if not user:
            raise UnauthorizedException("Invalid email/username or password")
        
        if not user.is_active:
            raise ForbiddenException("Account is deactivated. Contact support for assistance.")
        
        # Optional: Require email verification
        # if not user.is_verified:
        #     raise ForbiddenException("Please verify your email before logging in")
        
        # Create tokens
        token_data = {
            "sub": str(user.id), 
            "username": user.username,
            "role": user.role.value
        }
        
        access_token = create_access_token(data=token_data)
        refresh_token = create_refresh_token(data=token_data)
        
        # Update last login
        user.last_login = datetime.utcnow()
        self.db.commit()
        
        token = Token(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        )
        
        return token, user
    
    def refresh_access_token(self, refresh_token_data: TokenRefresh) -> Token:
        """Refresh access token using refresh token"""
        payload = verify_token(refresh_token_data.refresh_token, "refresh")
        
        if not payload:
            raise UnauthorizedException("Invalid or expired refresh token")
        
        user_id = int(payload.get("sub"))
        user = self.user_service.get_user_by_id(user_id)
        
        if not user:
            raise UnauthorizedException("User not found")
        
        if not user.is_active:
            raise ForbiddenException("Account is deactivated")
        
        # Create new tokens
        token_data = {
            "sub": str(user.id), 
            "username": user.username,
            "role": user.role.value
        }
        
        access_token = create_access_token(data=token_data)
        new_refresh_token = create_refresh_token(data=token_data)
        
        return Token(
            access_token=access_token,
            refresh_token=new_refresh_token,
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        )
    
    def logout(self, user: User) -> Dict[str, str]:
        """Logout user (for future token blacklisting implementation)"""
        # TODO: Implement token blacklisting in Redis
        # This would involve storing the token JTI in Redis with expiration
        
        return {"message": "Successfully logged out"}
    
    def verify_email(self, verification_data: EmailVerification) -> Dict[str, str]:
        """Verify user email using verification token"""
        success = self.user_service.verify_email(verification_data.token)
        
        if success:
            return {"message": "Email successfully verified"}
        else:
            raise ValidationException("Invalid verification token")
    
    def resend_verification_email(self, email: str) -> Dict[str, str]:
        """Resend email verification"""
        message = self.user_service.resend_verification(email)
        return {"message": message}
    
    def initiate_password_reset(self, reset_data: PasswordReset) -> Dict[str, str]:
        """Initiate password reset process"""
        message = self.user_service.initiate_password_reset(reset_data.email)
        return {"message": message}
    
    def confirm_password_reset(self, reset_data: PasswordResetConfirm) -> Dict[str, str]:
        """Confirm password reset with token"""
        success = self.user_service.reset_password(
            reset_data.token, 
            reset_data.new_password
        )
        
        if success:
            return {"message": "Password successfully reset"}
        else:
            raise ValidationException("Password reset failed")
    
    def change_password(self, user: User, current_password: str, new_password: str) -> Dict[str, str]:
        """Change user password"""
        success = self.user_service.change_password(
            user.id, 
            current_password, 
            new_password
        )
        
        if success:
            return {"message": "Password successfully changed"}
        else:
            raise ValidationException("Password change failed")
    
    def get_current_user_from_token(self, token: str) -> User:
        """Get current user from JWT token"""
        try:
            payload = verify_token(token, "access")
            if not payload:
                raise UnauthorizedException("Invalid token")
            
            user_id = int(payload.get("sub"))
            user = self.user_service.get_user_by_id(user_id)
            
            if not user:
                raise UnauthorizedException("User not found")
            
            if not user.is_active:
                raise ForbiddenException("Account is deactivated")
            
            return user
            
        except (JWTError, ValueError):
            raise UnauthorizedException("Invalid token")
    
    def validate_user_permissions(self, user: User, required_roles: list[UserRole]) -> bool:
        """Validate if user has required permissions"""
        if not user.is_active:
            return False
        
        return user.role in required_roles
    
    def require_admin_access(self, user: User) -> None:
        """Require admin access, raise exception if not authorized"""
        if not user.is_admin:
            raise ForbiddenException("Admin access required")
    
    def require_super_admin_access(self, user: User) -> None:
        """Require super admin access, raise exception if not authorized"""
        if not user.is_super_admin:
            raise ForbiddenException("Super admin access required")
    
    def check_account_status(self, user: User) -> Dict[str, Any]:
        """Check comprehensive account status"""
        return {
            "user_id": user.id,
            "is_active": user.is_active,
            "is_verified": user.is_verified,
            "role": user.role.value,
            "last_login": user.last_login.isoformat() if user.last_login else None,
            "created_at": user.created_at.isoformat(),
            "account_age_days": (datetime.utcnow() - user.created_at).days,
            "requires_verification": not user.is_verified,
            "can_login": user.is_active
        }
    
    def validate_session(self, user: User, max_session_hours: int = 24) -> bool:
        """Validate if user session is still valid based on last login"""
        if not user.last_login:
            return False
        
        session_expiry = user.last_login + timedelta(hours=max_session_hours)
        return datetime.utcnow() < session_expiry
    
    def get_user_login_attempts(self, identifier: str) -> Dict[str, Any]:
        """Get login attempt information (for future rate limiting)"""
        # TODO: Implement Redis-based login attempt tracking
        # This would track failed login attempts per IP/username
        
        return {
            "attempts": 0,
            "locked_until": None,
            "remaining_attempts": 5
        }
    
    def record_login_attempt(self, identifier: str, success: bool, ip_address: str = None) -> None:
        """Record login attempt (for future rate limiting)"""
        # TODO: Implement Redis-based login attempt recording
        # This would increment failed attempts and implement account locking
        pass
    
    def generate_two_factor_token(self, user: User) -> str:
        """Generate 2FA token (for future 2FA implementation)"""
        # TODO: Implement 2FA token generation
        # This would generate TOTP tokens or SMS codes
        
        return self._generate_numeric_token(6)
    
    def verify_two_factor_token(self, user: User, token: str) -> bool:
        """Verify 2FA token (for future 2FA implementation)"""
        # TODO: Implement 2FA token verification
        # This would verify TOTP tokens or SMS codes
        
        return True  # Placeholder
    
    def revoke_all_tokens(self, user: User) -> Dict[str, str]:
        """Revoke all user tokens (for security incidents)"""
        # TODO: Implement token revocation in Redis
        # This would blacklist all user tokens by adding user_id to blacklist
        
        return {"message": f"All tokens revoked for user {user.username}"}
    
    def get_active_sessions(self, user: User) -> List[Dict[str, Any]]:
        """Get user's active sessions (for future session management)"""
        # TODO: Implement session tracking in Redis
        # This would return active sessions with IP, device info, etc.
        
        return [
            {
                "session_id": "session_123",
                "ip_address": "192.168.1.1",
                "user_agent": "Mozilla/5.0...",
                "created_at": datetime.utcnow().isoformat(),
                "last_activity": datetime.utcnow().isoformat()
            }
        ]
    
    def invalidate_session(self, user: User, session_id: str) -> Dict[str, str]:
        """Invalidate specific session"""
        # TODO: Implement session invalidation
        
        return {"message": f"Session {session_id} invalidated"}
    
    def _generate_token(self, length: int = 32) -> str:
        """Generate a secure random token"""
        return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(length))
    
    def _generate_numeric_token(self, length: int = 6) -> str:
        """Generate a numeric token (for 2FA, etc.)"""
        return ''.join(secrets.choice(string.digits) for _ in range(length))
    
    def _hash_token(self, token: str) -> str:
        """Hash a token for secure storage"""
        return get_password_hash(token)
    
    def _verify_hashed_token(self, token: str, hashed_token: str) -> bool:
        """Verify a token against its hash"""
        return verify_password(token, hashed_token)


# Helper functions for dependency injection
def get_auth_service(db: Session) -> AuthService:
    """Get AuthService instance"""
    return AuthService(db)


# Rate limiting helper (for future implementation)
class LoginRateLimiter:
    """Rate limiter for login attempts"""
    
    def __init__(self, redis_client=None):
        self.redis_client = redis_client
        self.max_attempts = 5
        self.lockout_duration = 900  # 15 minutes
    
    def is_locked(self, identifier: str) -> bool:
        """Check if account/IP is locked"""
        # TODO: Implement Redis-based rate limiting
        return False
    
    def record_attempt(self, identifier: str, success: bool) -> None:
        """Record login attempt"""
        # TODO: Implement attempt recording
        pass
    
    def get_remaining_attempts(self, identifier: str) -> int:
        """Get remaining login attempts"""
        # TODO: Implement attempt counting
        return self.max_attempts
    
    def reset_attempts(self, identifier: str) -> None:
        """Reset login attempts for identifier"""
        # TODO: Implement attempt reset
        pass