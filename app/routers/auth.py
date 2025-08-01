from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.user import (
    UserCreate, UserLogin, Token, TokenRefresh, 
    PasswordChange, PasswordReset, PasswordResetConfirm,
    UserResponse
)
from app.services.auth_service import AuthService
from app.services.user_service import UserService
from app.dependencies import get_current_user
from app.models.user import User

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(
    user_create: UserCreate,
    db: Session = Depends(get_db)
):
    """Register a new user"""
    user_service = UserService(db)
    user = user_service.create_user(user_create)
    return user

@router.post("/login", response_model=Token)
async def login(
    user_login: UserLogin,
    db: Session = Depends(get_db)
):
    """Login user and return access tokens"""
    auth_service = AuthService(db)
    token, user = auth_service.login(user_login)
    return token

@router.post("/refresh", response_model=Token)
async def refresh_token(
    token_refresh: TokenRefresh,
    db: Session = Depends(get_db)
):
    """Refresh access token"""
    auth_service = AuthService(db)
    new_token = auth_service.refresh_token(token_refresh.refresh_token)
    return new_token

@router.get("/me", response_model=UserResponse)
async def get_current_user_profile(
    current_user: User = Depends(get_current_user)
):
    """Get current user profile"""
    return current_user

@router.post("/change-password")
async def change_password(
    password_change: PasswordChange,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Change user password"""
    user_service = UserService(db)
    user_service.change_password(
        current_user.id,
        password_change.current_password,
        password_change.new_password
    )
    return {"message": "Password changed successfully"}

@router.post("/forgot-password")
async def forgot_password(
    password_reset: PasswordReset,
    db: Session = Depends(get_db)
):
    """Initiate password reset"""
    user_service = UserService(db)
    message = user_service.initiate_password_reset(password_reset.email)
    return {"message": message}

@router.post("/reset-password")
async def reset_password(
    password_reset_confirm: PasswordResetConfirm,
    db: Session = Depends(get_db)
):
    """Reset password using token"""
    user_service = UserService(db)
    user_service.reset_password(
        password_reset_confirm.token,
        password_reset_confirm.new_password
    )
    return {"message": "Password reset successfully"}

@router.post("/verify-email/{token}")
async def verify_email(
    token: str,
    db: Session = Depends(get_db)
):
    """Verify user email"""
    user_service = UserService(db)
    user_service.verify_email(token)
    return {"message": "Email verified successfully"}

@router.post("/resend-verification")
async def resend_verification(
    email_request: PasswordReset,  # Reuse the same schema as it only has email
    db: Session = Depends(get_db)
):
    """Resend email verification"""
    user_service = UserService(db)
    message = user_service.resend_verification(email_request.email)
    return {"message": message}
