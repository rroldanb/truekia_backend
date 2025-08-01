from sqlalchemy.orm import Session
from sqlalchemy import or_, and_, func
from typing import Optional, List, Tuple
from datetime import datetime, timedelta
import secrets
import string

from app.models.user import User, UserRole
from app.schemas.user import UserCreate, UserUpdate, AdminUserCreate, AdminUserUpdate
from app.core.security import get_password_hash, verify_password
from app.core.exceptions import (
    NotFoundException, 
    ConflictException, 
    ValidationException,
    UnauthorizedException
)

class UserService:
    def __init__(self, db: Session):
        self.db = db
    
    def create_user(self, user_create: UserCreate) -> User:
        """Create a new user"""
        # Check if user already exists
        existing_user = self.db.query(User).filter(
            or_(User.email == user_create.email, User.username == user_create.username)
        ).first()
        
        if existing_user:
            if existing_user.email == user_create.email:
                raise ConflictException("Email already registered")
            else:
                raise ConflictException("Username already taken")
        
        # Create new user
        db_user = User(
            email=user_create.email,
            username=user_create.username,
            full_name=user_create.full_name,
            phone=user_create.phone,
            address=user_create.address,
            bio=user_create.bio,
            password_hashword=get_password_hash(user_create.password),
            verification_token=self._generate_token()
        )
        
        self.db.add(db_user)
        self.db.commit()
        self.db.refresh(db_user)
        return db_user
    
   
    def create_admin_user(self, user_create: AdminUserCreate, current_user: User) -> User:
        """Create a new user (admin only)"""
        if not current_user.is_admin:
            raise UnauthorizedException("Admin access required")
        
        # Super admin can create any role, admin can only create users
        if user_create.role in [UserRole.ADMIN, UserRole.SUPER_ADMIN] and not current_user.is_super_admin:
            raise UnauthorizedException("Super admin access required")
        
        # Check if user already exists
        existing_user = self.db.query(User).filter(
            or_(User.email == user_create.email, User.username == user_create.username)
        ).first()
        
        if existing_user:
            if existing_user.email == user_create.email:
                raise ConflictException("Email already registered")
            else:
                raise ConflictException("Username already taken")
        
        # Create new user
        db_user = User(
            email=user_create.email,
            username=user_create.username,
            full_name=user_create.full_name,
            phone=user_create.phone,
            address=user_create.address,
            bio=user_create.bio,
            password_hashword=get_password_hash(user_create.password),
            role=user_create.role,
            is_active=user_create.is_active,
            is_verified=user_create.is_verified,
            email_verified_at=datetime.utcnow() if user_create.is_verified else None
        )
        
        self.db.add(db_user)
        self.db.commit()
        self.db.refresh(db_user)
        return db_user
    
    def get_user_by_id(self, user_id: int) -> Optional[User]:
        """Get user by ID"""
        return self.db.query(User).filter(User.id == user_id).first()
    
    def get_user_by_email(self, email: str) -> Optional[User]:
        """Get user by email"""
        return self.db.query(User).filter(User.email == email).first()
    
    def get_user_by_username(self, username: str) -> Optional[User]:
        """Get user by username"""
        return self.db.query(User).filter(User.username == username).first()
    
    def get_user_by_email_or_username(self, identifier: str) -> Optional[User]:
        """Get user by email or username"""
        return self.db.query(User).filter(
            or_(User.email == identifier, User.username == identifier)
        ).first()
    
    def authenticate_user(self, identifier: str, password: str) -> Optional[User]:
        """Authenticate user with email/username and password"""
        user = self.get_user_by_email_or_username(identifier)
        if not user or not verify_password(password, user.password_hash):
            return None
        
        # Update last login
        user.last_login = datetime.utcnow()
        self.db.commit()
        return user
    
    def update_user(self, user_id: int, user_update: UserUpdate, current_user: User) -> User:
        """Update user information"""
        user = self.get_user_by_id(user_id)
        if not user:
            raise NotFoundException("User not found")
        
        # Users can only update their own profile, admins can update any
        if user.id != current_user.id and not current_user.is_admin:
            raise UnauthorizedException("Can only update own profile")
        
        # Update fields
        update_data = user_update.dict(exclude_unset=True)
        for field, value in update_data.items():
            setattr(user, field, value)
        
        user.updated_at = datetime.utcnow()
        self.db.commit()
        self.db.refresh(user)
        return user
    
    def admin_update_user(self, user_id: int, user_update: AdminUserUpdate, current_user: User) -> User:
        """Update user (admin only)"""
        if not current_user.is_admin:
            raise UnauthorizedException("Admin access required")
        
        user = self.get_user_by_id(user_id)
        if not user:
            raise NotFoundException("User not found")
        
        # Super admin required for role changes to admin/super_admin
        if 'role' in user_update.dict(exclude_unset=True):
            new_role = user_update.role
            if new_role in [UserRole.ADMIN, UserRole.SUPER_ADMIN] and not current_user.is_super_admin:
                raise UnauthorizedException("Super admin access required for role changes")
        
        # Cannot modify super admin unless you are super admin
        if user.is_super_admin and not current_user.is_super_admin:
            raise UnauthorizedException("Cannot modify super admin account")
        
        # Update fields
        update_data = user_update.dict(exclude_unset=True)
        for field, value in update_data.items():
            setattr(user, field, value)
        
        # Handle verification status
        if 'is_verified' in update_data:
            if update_data['is_verified'] and not user.email_verified_at:
                user.email_verified_at = datetime.utcnow()
            elif not update_data['is_verified']:
                user.email_verified_at = None
        
        user.updated_at = datetime.utcnow()
        self.db.commit()
        self.db.refresh(user)
        return user
    
    def delete_user(self, user_id: int, current_user: User) -> bool:
        """Delete user (admin only)"""
        if not current_user.is_admin:
            raise UnauthorizedException("Admin access required")
        
        user = self.get_user_by_id(user_id)
        if not user:
            raise NotFoundException("User not found")
        
        # Cannot delete super admin unless you are super admin
        if user.is_super_admin and not current_user.is_super_admin:
            raise UnauthorizedException("Cannot delete super admin account")
        
        # Cannot delete yourself
        if user.id == current_user.id:
            raise ValidationException("Cannot delete your own account")
        
        self.db.delete(user)
        self.db.commit()
        return True
    
    def get_users_paginated(
        self, 
        page: int = 1, 
        size: int = 20, 
        search: Optional[str] = None,
        role: Optional[UserRole] = None,
        is_active: Optional[bool] = None,
        current_user: Optional[User] = None
    ) -> Tuple[List[User], int]:
        """Get paginated list of users"""
        query = self.db.query(User)
        
        # Apply filters
        if search:
            search_filter = f"%{search}%"
            query = query.filter(
                or_(
                    User.username.ilike(search_filter),
                    User.full_name.ilike(search_filter),
                    User.email.ilike(search_filter)
                )
            )
        
        if role:
            query = query.filter(User.role == role)
        
        if is_active is not None:
            query = query.filter(User.is_active == is_active)
        
        # Non-admin users can only see active, verified users
        if not current_user or not current_user.is_admin:
            query = query.filter(and_(User.is_active == True, User.is_verified == True))
        
        # Get total count
        total = query.count()
        
        # Apply pagination
        offset = (page - 1) * size
        users = query.offset(offset).limit(size).all()
        
        return users, total
    
    def change_password(self, user_id: int, current_password: str, new_password: str) -> bool:
        """Change user password"""
        user = self.get_user_by_id(user_id)
        if not user:
            raise NotFoundException("User not found")
        
        # Verify current password
        if not verify_password(current_password, user.password_hashword):
            raise ValidationException("Current password is incorrect")
        
        # Update password
        user.password_hashword = get_password_hash(new_password)
        user.updated_at = datetime.utcnow()
        self.db.commit()
        return True
    
    def initiate_password_reset(self, email: str) -> str:
        """Initiate password reset process"""
        user = self.get_user_by_email(email)
        if not user:
            # Don't reveal if email exists for security
            return "If the email exists, a reset link has been sent"
        
        # Generate reset token
        reset_token = self._generate_token()
        user.reset_token = reset_token
        user.reset_token_expires = datetime.utcnow() + timedelta(hours=1)  # 1 hour expiry
        user.updated_at = datetime.utcnow()
        
        self.db.commit()
        
        # TODO: Send email with reset link
        # This would typically involve sending an email with the reset token
        
        return "If the email exists, a reset link has been sent"
    
    def reset_password(self, token: str, new_password: str) -> bool:
        """Reset password using token"""
        user = self.db.query(User).filter(
            and_(
                User.reset_token == token,
                User.reset_token_expires > datetime.utcnow()
            )
        ).first()
        
        if not user:
            raise ValidationException("Invalid or expired reset token")
        
        # Update password and clear reset token
        user.password_hashword = get_password_hash(new_password)
        user.reset_token = None
        user.reset_token_expires = None
        user.updated_at = datetime.utcnow()
        
        self.db.commit()
        return True
    
    def verify_email(self, token: str) -> bool:
        """Verify user email using token"""
        user = self.db.query(User).filter(User.verification_token == token).first()
        if not user:
            raise ValidationException("Invalid verification token")
        
        if user.is_verified:
            raise ValidationException("Email already verified")
        
        # Mark as verified
        user.is_verified = True
        user.email_verified_at = datetime.utcnow()
        user.verification_token = None
        user.updated_at = datetime.utcnow()
        
        self.db.commit()
        return True
    
    def resend_verification(self, email: str) -> str:
        """Resend email verification"""
        user = self.get_user_by_email(email)
        if not user:
            return "If the email exists, a verification link has been sent"
        
        if user.is_verified:
            raise ValidationException("Email already verified")
        
        # Generate new verification token
        user.verification_token = self._generate_token()
        user.updated_at = datetime.utcnow()
        
        self.db.commit()
        
        # TODO: Send verification email
        
        return "Verification link has been sent"
    
    def toggle_user_status(self, user_id: int, current_user: User) -> User:
        """Toggle user active status (admin only)"""
        if not current_user.is_admin:
            raise UnauthorizedException("Admin access required")
        
        user = self.get_user_by_id(user_id)
        if not user:
            raise NotFoundException("User not found")
        
        # Cannot deactivate super admin unless you are super admin
        if user.is_super_admin and not current_user.is_super_admin:
            raise UnauthorizedException("Cannot modify super admin account")
        
        # Cannot deactivate yourself
        if user.id == current_user.id:
            raise ValidationException("Cannot deactivate your own account")
        
        user.is_active = not user.is_active
        user.updated_at = datetime.utcnow()
        
        self.db.commit()
        self.db.refresh(user)
        return user
    
    def get_user_stats(self, current_user: User) -> dict:
        """Get user statistics (admin only)"""
        if not current_user.is_admin:
            raise UnauthorizedException("Admin access required")
        
        total_users = self.db.query(func.count(User.id)).scalar()
        active_users = self.db.query(func.count(User.id)).filter(User.is_active == True).scalar()
        verified_users = self.db.query(func.count(User.id)).filter(User.is_verified == True).scalar()
        admin_users = self.db.query(func.count(User.id)).filter(
            User.role.in_([UserRole.ADMIN, UserRole.SUPER_ADMIN])
        ).scalar()
        
        # Users created in last 30 days
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        recent_users = self.db.query(func.count(User.id)).filter(
            User.created_at >= thirty_days_ago
        ).scalar()
        
        return {
            "total_users": total_users,
            "active_users": active_users,
            "verified_users": verified_users,
            "admin_users": admin_users,
            "recent_users": recent_users,
            "inactive_users": total_users - active_users,
            "unverified_users": total_users - verified_users
        }
    
    def _generate_token(self) -> str:
        """Generate a secure random token"""
        return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))

