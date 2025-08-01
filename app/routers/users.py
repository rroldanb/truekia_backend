from fastapi import APIRouter, Depends, HTTPException, status, Query, UploadFile, File
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_
from typing import Optional, List
import logging
from datetime import datetime

from app.database import get_db
from app.dependencies import get_current_user, get_current_user_optional
from app.models.user import User
from app.schemas.user import (
    UserResponse,
    UserUpdate,
    UserProfileResponse,
    PasswordChange,
    PaginatedUsers,
    UserListResponse,
    UserSearchParams
)
from app.core.security import verify_password, get_password_hash
from app.core.exceptions import (
    NotFoundException,
    BadRequestException,
    UnauthorizedException
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/users", tags=["users"])


# ============================================================================
# USER PROFILE ENDPOINTS
# ============================================================================

@router.get("/me", response_model=UserResponse)
async def get_current_user_profile(
    current_user: User = Depends(get_current_user)
):
    """Get current user profile"""
    return current_user


@router.put("/me", response_model=UserResponse)
async def update_current_user_profile(
    user_update: UserUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update current user profile"""
    try:
        # Update only provided fields
        update_data = user_update.dict(exclude_unset=True)
        
        for field, value in update_data.items():
            setattr(current_user, field, value)
        
        current_user.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(current_user)
        
        logger.info(f"User {current_user.id} updated their profile")
        return current_user
        
    except Exception as e:
        db.rollback()
        logger.error(f"Error updating user profile: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error updating profile"
        )


@router.delete("/me")
async def delete_current_user_account(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Delete current user account (soft delete)"""
    try:
        # Soft delete by deactivating account
        current_user.is_active = False
        current_user.updated_at = datetime.utcnow()
        
        db.commit()
        
        logger.info(f"User {current_user.id} deleted their account")
        return {"message": "Account successfully deleted"}
        
    except Exception as e:
        db.rollback()
        logger.error(f"Error deleting user account: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error deleting account"
        )


# ============================================================================
# PASSWORD MANAGEMENT
# ============================================================================

@router.post("/me/change-password")
async def change_password(
    password_data: PasswordChange,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Change user password"""
    # Verify current password
    if not verify_password(password_data.current_password, current_user.password_hashword):
        raise BadRequestException("Current password is incorrect")
    
    # Check if new password is different from current
    if verify_password(password_data.new_password, current_user.password_hashword):
        raise BadRequestException("New password must be different from current password")
    
    try:
        # Update password
        current_user.password_hashword = get_password_hash(password_data.new_password)
        current_user.updated_at = datetime.utcnow()
        
        db.commit()
        
        logger.info(f"User {current_user.id} changed their password")
        return {"message": "Password successfully changed"}
        
    except Exception as e:
        db.rollback()
        logger.error(f"Error changing password: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error changing password"
        )


# ============================================================================
# PUBLIC USER PROFILES
# ============================================================================

@router.get("/profile/{username}", response_model=UserProfileResponse)
async def get_user_profile_by_username(
    username: str,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    """Get public user profile by username"""
    user = db.query(User).filter(
        and_(
            User.username == username,
            User.is_active == True
        )
    ).first()
    
    if not user:
        raise NotFoundException("User not found")
    
    return UserProfileResponse(
        id=user.id,
        username=user.username,
        full_name=user.full_name,
        avatar_url=user.avatar_url,
        bio=user.bio,
        is_verified=user.is_verified,
        created_at=user.created_at
    )


@router.get("/profile/id/{user_id}", response_model=UserProfileResponse)
async def get_user_profile_by_id(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    """Get public user profile by ID"""
    user = db.query(User).filter(
        and_(
            User.id == user_id,
            User.is_active == True
        )
    ).first()
    
    if not user:
        raise NotFoundException("User not found")
    
    return UserProfileResponse(
        id=user.id,
        username=user.username,
        full_name=user.full_name,
        avatar_url=user.avatar_url,
        bio=user.bio,
        is_verified=user.is_verified,
        created_at=user.created_at
    )


# ============================================================================
# USER SEARCH AND LISTING
# ============================================================================

@router.get("/search", response_model=PaginatedUsers)
async def search_users(
    search: Optional[str] = Query(None, max_length=100, description="Search by username, full name, or email"),
    is_verified: Optional[bool] = Query(None, description="Filter by verification status"),
    page: int = Query(1, ge=1, description="Page number"),
    size: int = Query(20, ge=1, le=100, description="Page size"),
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    """Search and list users with pagination"""
    
    # Build query
    query = db.query(User).filter(User.is_active == True)
    
    # Apply search filter
    if search:
        search_filter = or_(
            User.username.ilike(f"%{search}%"),
            User.full_name.ilike(f"%{search}%"),
            User.email.ilike(f"%{search}%") if current_user and current_user.is_admin else False
        )
        query = query.filter(search_filter)
    
    # Apply verification filter
    if is_verified is not None:
        query = query.filter(User.is_verified == is_verified)
    
    # Order by creation date (newest first)
    query = query.order_by(User.created_at.desc())
    
    # Get total count
    total = query.count()
    
    # Apply pagination
    offset = (page - 1) * size
    users = query.offset(offset).limit(size).all()
    
    # Calculate pages
    pages = (total + size - 1) // size if size > 0 else 0
    
    return PaginatedUsers(
        items=[
            UserListResponse(
                id=user.id,
                username=user.username,
                full_name=user.full_name,
                email=user.email,
                role=user.role,
                is_active=user.is_active,
                is_verified=user.is_verified,
                avatar_url=user.avatar_url,
                created_at=user.created_at,
                last_login=user.last_login
            ) for user in users
        ],
        total=total,
        page=page,
        size=size,
        pages=pages
    )


# ============================================================================
# AVATAR UPLOAD
# ============================================================================

@router.post("/me/avatar")
async def upload_avatar(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Upload user avatar"""
    
    # Validate file type
    if file.content_type not in ["image/jpeg", "image/png", "image/gif"]:
        raise BadRequestException("Invalid file type. Only JPEG, PNG, and GIF are allowed")
    
    # Validate file size (10MB max)
    max_size = 10 * 1024 * 1024  # 10MB
    contents = await file.read()
    if len(contents) > max_size:
        raise BadRequestException("File size too large. Maximum size is 10MB")
    
    try:
        # In a real application, you would:
        # 1. Upload to cloud storage (AWS S3, Google Cloud Storage, etc.)
        # 2. Generate optimized thumbnails
        # 3. Update user's avatar_url with the cloud storage URL
        
        # For this example, we'll simulate the upload process
        filename = f"avatar_{current_user.id}_{int(datetime.utcnow().timestamp())}.{file.filename.split('.')[-1]}"
        avatar_url = f"https://your-storage-bucket.com/avatars/{filename}"
        
        # Update user's avatar URL
        current_user.avatar_url = avatar_url
        current_user.updated_at = datetime.utcnow()
        
        db.commit()
        
        logger.info(f"User {current_user.id} uploaded new avatar")
        return {
            "message": "Avatar uploaded successfully",
            "avatar_url": avatar_url
        }
        
    except Exception as e:
        db.rollback()
        logger.error(f"Error uploading avatar: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error uploading avatar"
        )


@router.delete("/me/avatar")
async def delete_avatar(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Delete user avatar"""
    try:
        # In a real application, you would also delete the file from cloud storage
        current_user.avatar_url = None
        current_user.updated_at = datetime.utcnow()
        
        db.commit()
        
        logger.info(f"User {current_user.id} deleted their avatar")
        return {"message": "Avatar deleted successfully"}
        
    except Exception as e:
        db.rollback()
        logger.error(f"Error deleting avatar: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error deleting avatar"
        )


# ============================================================================
# USER PREFERENCES/SETTINGS
# ============================================================================

@router.get("/me/settings")
async def get_user_settings(
    current_user: User = Depends(get_current_user)
):
    """Get user settings/preferences"""
    return {
        "email_notifications": True,  # These would come from a settings table
        "push_notifications": True,
        "privacy_level": "public",
        "language": "en",
        "timezone": "UTC"
    }


@router.put("/me/settings")
async def update_user_settings(
    settings: dict,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update user settings/preferences"""
    # In a real application, you would have a UserSettings model
    # and update the settings there
    
    logger.info(f"User {current_user.id} updated their settings")
    return {"message": "Settings updated successfully"}


# ============================================================================
# USER STATISTICS
# ============================================================================

@router.get("/me/stats")
async def get_user_stats(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get user statistics"""
    
    # Calculate user-specific statistics
    profile_completion = 0
    if current_user.full_name:
        profile_completion += 20
    if current_user.phone:
        profile_completion += 15
    if current_user.address:
        profile_completion += 15
    if current_user.bio:
        profile_completion += 20
    if current_user.avatar_url:
        profile_completion += 30
    
    return {
        "profile_completion": profile_completion,
        "account_age_days": (datetime.utcnow() - current_user.created_at).days,
        "is_verified": current_user.is_verified,
        "last_login": current_user.last_login,
        "total_logins": 0,  # This would come from a user activity table
        "account_status": "active" if current_user.is_active else "inactive"
    }