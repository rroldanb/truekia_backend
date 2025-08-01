from pydantic import BaseModel, EmailStr, validator, Field
from datetime import datetime
from typing import Optional, List
from app.models.user import UserRole

# ============================================================================
# BASE SCHEMAS
# ============================================================================

class UserBase(BaseModel):
    """Base user schema with common fields"""
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=50, pattern="^[a-zA-Z0-9_]+$")
    full_name: str = Field(..., min_length=2, max_length=255)
    phone: Optional[str] = Field(None, pattern="^[+]?[1-9]?[0-9]{7,15}$")
    address: Optional[str] = Field(None, max_length=500)
    bio: Optional[str] = Field(None, max_length=1000)


# ============================================================================
# CREATE SCHEMAS
# ============================================================================

class UserCreate(UserBase):
    """Schema for user registration"""
    password: str = Field(..., min_length=8, max_length=128)
    confirm_password: str
    
    @validator('confirm_password')
    def passwords_match(cls, v, values):
        if 'password' in values and v != values['password']:
            raise ValueError('Passwords do not match')
        return v
    
    @validator('password')
    def validate_password(cls, v):
        """Validate password strength"""
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one digit')
        if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in v):
            raise ValueError('Password must contain at least one special character')
        return v


class AdminUserCreate(UserBase):
    """Schema for admin user creation"""
    password: str = Field(..., min_length=8, max_length=128)
    role: UserRole = UserRole.USER
    is_active: bool = True
    is_verified: bool = False
    
    @validator('password')
    def validate_password(cls, v):
        """Validate password strength"""
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one digit')
        if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in v):
            raise ValueError('Password must contain at least one special character')
        return v


# ============================================================================
# UPDATE SCHEMAS
# ============================================================================

class UserUpdate(BaseModel):
    """Schema for user profile updates"""
    full_name: Optional[str] = Field(None, min_length=2, max_length=255)
    phone: Optional[str] = Field(None, pattern="^[+]?[1-9]?[0-9]{7,15}$")
    address: Optional[str] = Field(None, max_length=500)
    bio: Optional[str] = Field(None, max_length=1000)
    avatar_url: Optional[str] = Field(None, max_length=500)


class AdminUserUpdate(UserUpdate):
    """Schema for admin user updates"""
    is_active: Optional[bool] = None
    is_verified: Optional[bool] = None
    role: Optional[UserRole] = None


# ============================================================================
# RESPONSE SCHEMAS
# ============================================================================

class UserResponse(UserBase):
    """Complete user response schema"""
    id: int
    role: UserRole
    is_active: bool
    is_verified: bool
    avatar_url: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    last_login: Optional[datetime] = None
    email_verified_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True


class UserListResponse(BaseModel):
    """User list item response schema"""
    id: int
    username: str
    full_name: str
    email: EmailStr
    role: UserRole
    is_active: bool
    is_verified: bool
    avatar_url: Optional[str] = None
    created_at: datetime
    last_login: Optional[datetime] = None
    
    class Config:
        from_attributes = True


class UserProfileResponse(BaseModel):
    """Public user profile response schema"""
    id: int
    username: str
    full_name: str
    avatar_url: Optional[str] = None
    bio: Optional[str] = None
    is_verified: bool
    created_at: datetime
    
    class Config:
        from_attributes = True


# ============================================================================
# AUTHENTICATION SCHEMAS
# ============================================================================

class UserLogin(BaseModel):
    """User login schema"""
    email_or_username: str = Field(..., min_length=3)
    password: str = Field(..., min_length=1)


class Token(BaseModel):
    """JWT token response schema"""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class TokenRefresh(BaseModel):
    """Token refresh request schema"""
    refresh_token: str


class TokenPayload(BaseModel):
    """JWT token payload schema"""
    sub: Optional[str] = None
    username: Optional[str] = None
    exp: Optional[datetime] = None


# ============================================================================
# PASSWORD SCHEMAS
# ============================================================================

class PasswordChange(BaseModel):
    """Password change schema"""
    current_password: str
    new_password: str = Field(..., min_length=8, max_length=128)
    confirm_password: str
    
    @validator('confirm_password')
    def passwords_match(cls, v, values):
        if 'new_password' in values and v != values['new_password']:
            raise ValueError('Passwords do not match')
        return v
    
    @validator('new_password')
    def validate_password(cls, v):
        """Validate password strength"""
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one digit')
        if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in v):
            raise ValueError('Password must contain at least one special character')
        return v


class PasswordReset(BaseModel):
    """Password reset request schema"""
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    """Password reset confirmation schema"""
    token: str
    new_password: str = Field(..., min_length=8, max_length=128)
    confirm_password: str
    
    @validator('confirm_password')
    def passwords_match(cls, v, values):
        if 'new_password' in values and v != values['new_password']:
            raise ValueError('Passwords do not match')
        return v
    
    @validator('new_password')
    def validate_password(cls, v):
        """Validate password strength"""
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one digit')
        if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in v):
            raise ValueError('Password must contain at least one special character')
        return v


# ============================================================================
# EMAIL VERIFICATION SCHEMAS
# ============================================================================

class EmailVerification(BaseModel):
    """Email verification schema"""
    token: str


class EmailResendVerification(BaseModel):
    """Resend email verification schema"""
    email: EmailStr


# ============================================================================
# PAGINATION SCHEMAS
# ============================================================================

class PaginatedUsers(BaseModel):
    """Paginated users response schema"""
    items: List[UserListResponse]
    total: int
    page: int
    size: int
    pages: int
    
    @validator('pages', pre=True, always=True)
    def calculate_pages(cls, v, values):
        """Calculate total pages based on total and size"""
        if 'total' in values and 'size' in values:
            total = values['total']
            size = values['size']
            return (total + size - 1) // size if size > 0 else 0
        return v


# ============================================================================
# STATISTICS SCHEMAS
# ============================================================================

class UserStats(BaseModel):
    """User statistics schema"""
    total_users: int
    active_users: int
    inactive_users: int
    verified_users: int
    unverified_users: int
    admin_users: int
    recent_users: int  # Users created in last 30 days


# ============================================================================
# SEARCH AND FILTER SCHEMAS
# ============================================================================

class UserSearchParams(BaseModel):
    """User search and filter parameters"""
    search: Optional[str] = Field(None, max_length=100)
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None
    is_verified: Optional[bool] = None
    page: int = Field(1, ge=1)
    size: int = Field(20, ge=1, le=100)


# ============================================================================
# BULK OPERATIONS SCHEMAS
# ============================================================================

class BulkUserAction(BaseModel):
    """Bulk user action schema"""
    user_ids: List[int] = Field(..., min_items=1, max_items=100)
    action: str = Field(..., pattern="^(activate|deactivate|verify|delete)$")


class BulkActionResult(BaseModel):
    """Bulk action result schema"""
    success_count: int
    failed_count: int
    total_count: int
    errors: List[str] = []


# ============================================================================
# USER ACTIVITY SCHEMAS
# ============================================================================

class UserActivity(BaseModel):
    """User activity schema"""
    user_id: int
    action: str
    timestamp: datetime
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    
    class Config:
        from_attributes = True


class PaginatedUserActivity(BaseModel):
    """Paginated user activity response"""
    items: List[UserActivity]
    total: int
    page: int
    size: int
    pages: int


# ============================================================================
# EXPORT SCHEMAS
# ============================================================================

class UserExportParams(BaseModel):
    """User export parameters"""
    format: str = Field("csv", pattern="^(csv|json|xlsx)$")
    fields: Optional[List[str]] = None
    filters: Optional[UserSearchParams] = None


class UserExportResult(BaseModel):
    """User export result"""
    file_url: str
    file_name: str
    total_records: int
    created_at: datetime