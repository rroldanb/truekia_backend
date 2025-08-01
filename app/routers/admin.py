from fastapi import APIRouter, Depends, HTTPException, status, Query, BackgroundTasks
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, func, desc
from typing import Optional, List
import logging
from datetime import datetime, timedelta

from app.database import get_db
from app.dependencies import get_current_active_admin
from app.models.user import User, UserRole
from app.schemas.user import (
    UserResponse,
    UserListResponse,
    AdminUserUpdate,
    AdminUserCreate,
    PaginatedUsers,
    UserSearchParams,
    UserStats,
    BulkUserAction,
    BulkActionResult,
    UserExportParams,
    UserExportResult
)
from app.core.security import get_password_hash
from app.core.exceptions import (
    NotFoundException,
    BadRequestException,
    ForbiddenException
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin", tags=["admin"])


# ============================================================================
# USER MANAGEMENT
# ============================================================================

@router.get("/users", response_model=PaginatedUsers)
async def get_all_users(
    search: Optional[str] = Query(None, max_length=100, description="Search by username, email, or full name"),
    role: Optional[UserRole] = Query(None, description="Filter by user role"),
    is_active: Optional[bool] = Query(None, description="Filter by active status"),
    is_verified: Optional[bool] = Query(None, description="Filter by verification status"),
    created_after: Optional[datetime] = Query(None, description="Filter users created after this date"),
    created_before: Optional[datetime] = Query(None, description="Filter users created before this date"),
    page: int = Query(1, ge=1, description="Page number"),
    size: int = Query(20, ge=1, le=100, description="Page size"),
    sort_by: str = Query("created_at", description="Sort field"),
    sort_order: str = Query("desc", regex="^(asc|desc)$", description="Sort order"),
    current_admin: User = Depends(get_current_active_admin),
    db: Session = Depends(get_db)
):
    """Get all users with advanced filtering and pagination (Admin only)"""
    
    # Build query
    query = db.query(User)
    
    # Apply search filter
    if search:
        search_filter = or_(
            User.username.ilike(f"%{search}%"),
            User.full_name.ilike(f"%{search}%"),
            User.email.ilike(f"%{search}%")
        )
        query = query.filter(search_filter)
    
    # Apply filters
    if role:
        query = query.filter(User.role == role)
    if is_active is not None:
        query = query.filter(User.is_active == is_active)
    if is_verified is not None:
        query = query.filter(User.is_verified == is_verified)
    if created_after:
        query = query.filter(User.created_at >= created_after)
    if created_before:
        query = query.filter(User.created_at <= created_before)
    
    # Apply sorting
    sort_column = getattr(User, sort_by, User.created_at)
    if sort_order == "desc":
        query = query.order_by(desc(sort_column))
    else:
        query = query.order_by(sort_column)
    
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


@router.get("/users/{user_id}", response_model=UserResponse)
async def get_user_by_id(
    user_id: int,
    current_admin: User = Depends(get_current_active_admin),
    db: Session = Depends(get_db)
):
    """Get user by ID (Admin only)"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise NotFoundException("User not found")
    
    return user


@router.post("/users", response_model=UserResponse)
async def create_user(
    user_data: AdminUserCreate,
    current_admin: User = Depends(get_current_active_admin),
    db: Session = Depends(get_db)
):
    """Create new user (Admin only)"""
    
    # Check if email or username already exists
    existing_user = db.query(User).filter(
        or_(User.email == user_data.email, User.username == user_data.username)
    ).first()
    
    if existing_user:
        if existing_user.email == user_data.email:
            raise BadRequestException("Email already registered")
        else:
            raise BadRequestException("Username already taken")
    
    # Only super admin can create admin users
    if user_data.role in [UserRole.ADMIN, UserRole.SUPER_ADMIN] and not current_admin.is_super_admin:
        raise ForbiddenException("Only super admin can create admin users")
    
    try:
        # Create new user
        new_user = User(
            email=user_data.email,
            username=user_data.username,
            full_name=user_data.full_name,
            password_hashword=get_password_hash(user_data.password),
            phone=user_data.phone,
            address=user_data.address,
            bio=user_data.bio,
            role=user_data.role,
            is_active=user_data.is_active,
            is_verified=user_data.is_verified
        )
        
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        
        logger.info(f"Admin {current_admin.id} created new user {new_user.id}")
        return new_user
        
    except Exception as e:
        db.rollback()
        logger.error(f"Error creating user: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error creating user"
        )


@router.put("/users/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: int,
    user_update: AdminUserUpdate,
    current_admin: User = Depends(get_current_active_admin),
    db: Session = Depends(get_db)
):
    """Update user (Admin only)"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise NotFoundException("User not found")
    
    # Prevent non-super admin from modifying admin users
    if user.is_admin and not current_admin.is_super_admin:
        raise ForbiddenException("Only super admin can modify admin users")
    
    # Prevent role elevation without proper permissions
    if user_update.role and user_update.role in [UserRole.ADMIN, UserRole.SUPER_ADMIN]:
        if not current_admin.is_super_admin:
            raise ForbiddenException("Only super admin can assign admin roles")
    
    try:
        # Update only provided fields
        update_data = user_update.dict(exclude_unset=True)
        
        for field, value in update_data.items():
            setattr(user, field, value)
        
        user.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(user)
        
        logger.info(f"Admin {current_admin.id} updated user {user.id}")
        return user
        
    except Exception as e:
        db.rollback()
        logger.error(f"Error updating user: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error updating user"
        )


@router.delete("/users/{user_id}")
async def delete_user(
    user_id: int,
    permanent: bool = Query(False, description="Permanently delete user"),
    current_admin: User = Depends(get_current_active_admin),
    db: Session = Depends(get_db)
):
    """Delete user (Admin only)"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise NotFoundException("User not found")
    
    # Prevent deleting admin users without proper permissions
    if user.is_admin and not current_admin.is_super_admin:
        raise ForbiddenException("Only super admin can delete admin users")
    
    # Prevent self-deletion
    if user.id == current_admin.id:
        raise BadRequestException("Cannot delete your own account")
    
    try:
        if permanent:
            # Permanent deletion (use with caution)
            db.delete(user)
            action = "permanently deleted"
        else:
            # Soft deletion
            user.is_active = False
            user.updated_at = datetime.utcnow()
            action = "deactivated"
        
        db.commit()
        
        logger.warning(f"Admin {current_admin.id} {action} user {user.id}")
        return {"message": f"User successfully {action}"}
        
    except Exception as e:
        db.rollback()
        logger.error(f"Error deleting user: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error deleting user"
        )


# ============================================================================
# BULK OPERATIONS
# ============================================================================

@router.post("/users/bulk-action", response_model=BulkActionResult)
async def bulk_user_action(
    bulk_action: BulkUserAction,
    current_admin: User = Depends(get_current_active_admin),
    db: Session = Depends(get_db)
):
    """Perform bulk actions on multiple users (Admin only)"""
    
    # Get users
    users = db.query(User).filter(User.id.in_(bulk_action.user_ids)).all()
    
    if not users:
        raise NotFoundException("No users found with provided IDs")
    
    success_count = 0
    failed_count = 0
    errors = []
    
    try:
        for user in users:
            try:
                # Prevent actions on admin users without proper permissions
                if user.is_admin and not current_admin.is_super_admin:
                    errors.append(f"User {user.id}: Insufficient permissions for admin user")
                    failed_count += 1
                    continue
                
                # Prevent self-actions that could be problematic
                if user.id == current_admin.id and bulk_action.action in ["deactivate", "delete"]:
                    errors.append(f"User {user.id}: Cannot perform this action on your own account")
                    failed_count += 1
                    continue
                
                # Perform action
                if bulk_action.action == "activate":
                    user.is_active = True
                elif bulk_action.action == "deactivate":
                    user.is_active = False
                elif bulk_action.action == "verify":
                    user.is_verified = True
                    user.email_verified_at = datetime.utcnow()
                elif bulk_action.action == "delete":
                    user.is_active = False  # Soft delete
                
                user.updated_at = datetime.utcnow()
                success_count += 1
                
            except Exception as e:
                errors.append(f"User {user.id}: {str(e)}")
                failed_count += 1
        
        db.commit()
        
        logger.info(f"Admin {current_admin.id} performed bulk action '{bulk_action.action}' on {success_count} users")
        
        return BulkActionResult(
            success_count=success_count,
            failed_count=failed_count,
            total_count=len(bulk_action.user_ids),
            errors=errors
        )
        
    except Exception as e:
        db.rollback()
        logger.error(f"Error in bulk action: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error performing bulk action"
        )


# ============================================================================
# STATISTICS AND ANALYTICS
# ============================================================================

@router.get("/stats", response_model=UserStats)
async def get_user_statistics(
    current_admin: User = Depends(get_current_active_admin),
    db: Session = Depends(get_db)
):
    """Get user statistics (Admin only)"""
    
    # Calculate statistics
    total_users = db.query(User).count()
    active_users = db.query(User).filter(User.is_active == True).count()
    inactive_users = total_users - active_users
    verified_users = db.query(User).filter(User.is_verified == True).count()
    unverified_users = total_users - verified_users
    admin_users = db.query(User).filter(User.role.in_([UserRole.ADMIN, UserRole.SUPER_ADMIN])).count()
    
    # Recent users (last 30 days)
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    recent_users = db.query(User).filter(User.created_at >= thirty_days_ago).count()
    
    return UserStats(
        total_users=total_users,
        active_users=active_users,
        inactive_users=inactive_users,
        verified_users=verified_users,
        unverified_users=unverified_users,
        admin_users=admin_users,
        recent_users=recent_users
    )


@router.get("/stats/growth")
async def get_user_growth_stats(
    days: int = Query(30, ge=1, le=365, description="Number of days to analyze"),
    current_admin: User = Depends(get_current_active_admin),
    db: Session = Depends(get_db)
):
    """Get user growth statistics over time (Admin only)"""
    
    start_date = datetime.utcnow() - timedelta(days=days)
    
    # Daily user registrations
    daily_registrations = db.query(
        func.date(User.created_at).label('date'),
        func.count(User.id).label('registrations')
    ).filter(
        User.created_at >= start_date
    ).group_by(
        func.date(User.created_at)
    ).order_by('date').all()
    
    # Convert to list of dictionaries
    growth_data = [
        {
            "date": str(reg.date),
            "registrations": reg.registrations,
            "cumulative": sum(r.registrations for r in daily_registrations[:i+1])
        }
        for i, reg in enumerate(daily_registrations)
    ]
    
    return {
        "period_days": days,
        "start_date": start_date.date(),
        "end_date": datetime.utcnow().date(),
        "total_registrations": sum(reg.registrations for reg in daily_registrations),
        "daily_data": growth_data
    }


@router.get("/stats/roles")
async def get_role_distribution(
    current_admin: User = Depends(get_current_active_admin),
    db: Session = Depends(get_db)
):
    """Get user role distribution statistics (Admin only)"""
    
    role_stats = db.query(
        User.role,
        func.count(User.id).label('count')
    ).group_by(User.role).all()
    
    return {
        "role_distribution": [
            {"role": role.role.value, "count": role.count}
            for role in role_stats
        ]
    }


# ============================================================================
# USER EXPORT
# ============================================================================

@router.post("/users/export", response_model=UserExportResult)
async def export_users(
    export_params: UserExportParams,
    background_tasks: BackgroundTasks,
    current_admin: User = Depends(get_current_active_admin),
    db: Session = Depends(get_db)
):
    """Export users data (Admin only)"""
    
    # Build query based on filters
    query = db.query(User)
    
    if export_params.filters:
        filters = export_params.filters
        if filters.search:
            search_filter = or_(
                User.username.ilike(f"%{filters.search}%"),
                User.full_name.ilike(f"%{filters.search}%"),
                User.email.ilike(f"%{filters.search}%")
            )
            query = query.filter(search_filter)
        
        if filters.role:
            query = query.filter(User.role == filters.role)
        if filters.is_active is not None:
            query = query.filter(User.is_active == filters.is_active)
        if filters.is_verified is not None:
            query = query.filter(User.is_verified == filters.is_verified)
    
    # Get total count
    total_records = query.count()
    
    # Generate filename
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    file_name = f"users_export_{timestamp}.{export_params.format}"
    
    # In a real application, you would:
    # 1. Generate the file in the background
    # 2. Upload to cloud storage
    # 3. Send notification when ready
    
    # For this example, we'll simulate the process
    file_url = f"https://your-storage-bucket.com/exports/{file_name}"
    
    # Schedule background task for actual file generation
    # background_tasks.add_task(generate_export_file, query, export_params, file_name)
    
    logger.info(f"Admin {current_admin.id} initiated user export with {total_records} records")
    
    return UserExportResult(
        file_url=file_url,
        file_name=file_name,
        total_records=total_records,
        created_at=datetime.utcnow()
    )


# ============================================================================
# USER ACTIVITY MONITORING
# ============================================================================

@router.get("/users/{user_id}/activity")
async def get_user_activity(
    user_id: int,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    action_type: Optional[str] = Query(None, description="Filter by action type"),
    current_admin: User = Depends(get_current_active_admin),
    db: Session = Depends(get_db)
):
    """Get user activity history (Admin only)"""
    
    # Verify user exists
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise NotFoundException("User not found")
    
    # In a real application, you would have a UserActivity model
    # For now, we'll return mock data
    
    mock_activities = [
        {
            "id": 1,
            "user_id": user_id,
            "action": "login",
            "timestamp": datetime.utcnow() - timedelta(hours=1),
            "ip_address": "192.168.1.1",
            "user_agent": "Mozilla/5.0..."
        },
        {
            "id": 2,
            "user_id": user_id,
            "action": "profile_update",
            "timestamp": datetime.utcnow() - timedelta(hours=2),
            "ip_address": "192.168.1.1",
            "user_agent": "Mozilla/5.0..."
        }
    ]
    
    return {
        "items": mock_activities,
        "total": len(mock_activities),
        "page": page,
        "size": size,
        "pages": 1
    }


@router.get("/activity/recent")
async def get_recent_system_activity(
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=100),
    current_admin: User = Depends(get_current_active_admin),
    db: Session = Depends(get_db)
):
    """Get recent system-wide activity (Admin only)"""
    
    # In a real application, you would query from an activity log table
    # For now, we'll return mock data showing recent user registrations and logins
    
    recent_users = db.query(User).order_by(desc(User.created_at)).limit(size).all()
    
    activities = []
    for user in recent_users:
        activities.append({
            "id": user.id,
            "action": "user_registered",
            "user_id": user.id,
            "username": user.username,
            "timestamp": user.created_at,
            "details": f"New user {user.username} registered"
        })
    
    return {
        "items": activities,
        "total": len(activities),
        "page": page,
        "size": size
    }


# ============================================================================
# SYSTEM SETTINGS
# ============================================================================

@router.get("/settings")
async def get_system_settings(
    current_admin: User = Depends(get_current_active_admin)
):
    """Get system settings (Admin only)"""
    
    # In a real application, these would come from a settings table/config
    return {
        "registration_enabled": True,
        "email_verification_required": True,
        "max_login_attempts": 5,
        "session_timeout_minutes": 60,
        "password_min_length": 8,
        "require_password_change_days": 90,
        "maintenance_mode": False
    }


@router.put("/settings")
async def update_system_settings(
    settings: dict,
    current_admin: User = Depends(get_current_active_admin),
    db: Session = Depends(get_db)
):
    """Update system settings (Super Admin only)"""
    
    if not current_admin.is_super_admin:
        raise ForbiddenException("Only super admin can modify system settings")
    
    # In a real application, you would validate and save to settings table
    logger.info(f"Super admin {current_admin.id} updated system settings")
    
    return {"message": "System settings updated successfully"}


# ============================================================================
# USER IMPERSONATION (FOR SUPPORT)
# ============================================================================

@router.post("/users/{user_id}/impersonate")
async def impersonate_user(
    user_id: int,
    current_admin: User = Depends(get_current_active_admin),
    db: Session = Depends(get_db)
):
    """Impersonate user for support purposes (Super Admin only)"""
    
    if not current_admin.is_super_admin:
        raise ForbiddenException("Only super admin can impersonate users")
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise NotFoundException("User not found")
    
    if user.is_admin:
        raise ForbiddenException("Cannot impersonate admin users")
    
    # In a real application, you would:
    # 1. Create a special impersonation token
    # 2. Log the impersonation action
    # 3. Return token that allows acting as the user
    
    logger.warning(f"Super admin {current_admin.id} started impersonating user {user.id}")
    
    return {
        "message": f"Impersonation started for user {user.username}",
        "impersonation_token": "mock_impersonation_token",
        "expires_in": 3600  # 1 hour
    }


@router.post("/impersonation/stop")
async def stop_impersonation(
    current_admin: User = Depends(get_current_active_admin)
):
    """Stop current impersonation session"""
    
    logger.info(f"Admin {current_admin.id} stopped impersonation session")
    
    return {"message": "Impersonation session ended"}


# ============================================================================
# AUDIT LOGS
# ============================================================================

@router.get("/audit-logs")
async def get_audit_logs(
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=100),
    action_type: Optional[str] = Query(None),
    user_id: Optional[int] = Query(None),
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    current_admin: User = Depends(get_current_active_admin),
    db: Session = Depends(get_db)
):
    """Get audit logs (Super Admin only)"""
    
    if not current_admin.is_super_admin:
        raise ForbiddenException("Only super admin can view audit logs")
    
    # In a real application, you would have an AuditLog model
    # For now, return mock data
    
    mock_logs = [
        {
            "id": 1,
            "timestamp": datetime.utcnow() - timedelta(minutes=30),
            "admin_id": current_admin.id,
            "admin_username": current_admin.username,
            "action": "user_created",
            "target_user_id": 123,
            "details": "Created new user account",
            "ip_address": "192.168.1.100"
        },
        {
            "id": 2,
            "timestamp": datetime.utcnow() - timedelta(hours=1),
            "admin_id": current_admin.id,
            "admin_username": current_admin.username,
            "action": "user_updated",
            "target_user_id": 456,
            "details": "Updated user role to admin",
            "ip_address": "192.168.1.100"
        }
    ]
    
    return {
        "items": mock_logs,
        "total": len(mock_logs),
        "page": page,
        "size": size,
        "pages": 1
    }


# ============================================================================
# BACKUP AND MAINTENANCE
# ============================================================================

@router.post("/maintenance/enable")
async def enable_maintenance_mode(
    current_admin: User = Depends(get_current_active_admin)
):
    """Enable maintenance mode (Super Admin only)"""
    
    if not current_admin.is_super_admin:
        raise ForbiddenException("Only super admin can enable maintenance mode")
    
    # In a real application, you would update system settings
    logger.warning(f"Super admin {current_admin.id} enabled maintenance mode")
    
    return {"message": "Maintenance mode enabled"}


@router.post("/maintenance/disable")
async def disable_maintenance_mode(
    current_admin: User = Depends(get_current_active_admin)
):
    """Disable maintenance mode (Super Admin only)"""
    
    if not current_admin.is_super_admin:
        raise ForbiddenException("Only super admin can disable maintenance mode")
    
    # In a real application, you would update system settings
    logger.info(f"Super admin {current_admin.id} disabled maintenance mode")
    
    return {"message": "Maintenance mode disabled"}


@router.post("/backup/create")
async def create_system_backup(
    background_tasks: BackgroundTasks,
    current_admin: User = Depends(get_current_active_admin)
):
    """Create system backup (Super Admin only)"""
    
    if not current_admin.is_super_admin:
        raise ForbiddenException("Only super admin can create system backups")
    
    # In a real application, you would:
    # 1. Create database backup
    # 2. Backup uploaded files
    # 3. Create system configuration backup
    
    backup_id = f"backup_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
    
    # Schedule background task
    # background_tasks.add_task(create_backup_task, backup_id)
    
    logger.info(f"Super admin {current_admin.id} initiated system backup {backup_id}")
    
    return {
        "message": "System backup initiated",
        "backup_id": backup_id,
        "status": "in_progress"
    }


# ============================================================================
# HEALTH CHECK AND MONITORING
# ============================================================================

@router.get("/health")
async def admin_health_check(
    current_admin: User = Depends(get_current_active_admin),
    db: Session = Depends(get_db)
):
    """Admin health check with detailed system information"""
    
    try:
        # Test database connection
        db.execute("SELECT 1")
        db_status = "healthy"
    except Exception as e:
        db_status = f"error: {str(e)}"
    
    # System statistics
    total_users = db.query(User).count()
    active_sessions = 0  # Would come from session store
    
    return {
        "status": "healthy" if db_status == "healthy" else "degraded",
        "timestamp": datetime.utcnow(),
        "database": db_status,
        "total_users": total_users,
        "active_sessions": active_sessions,
        "system_load": "normal",  # Would come from system monitoring
        "memory_usage": "45%",    # Would come from system monitoring
        "disk_usage": "60%"       # Would come from system monitoring
    }