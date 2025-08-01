# app/utils/helpers.py
from datetime import datetime, timezone
from typing import Dict, Any, Optional
import hashlib
import secrets
import string

def generate_secure_token(length: int = 32) -> str:
    """Generate a cryptographically secure random token"""
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def generate_verification_code(length: int = 6) -> str:
    """Generate a numeric verification code"""
    return ''.join(secrets.choice(string.digits) for _ in range(length))

def hash_string(text: str) -> str:
    """Generate SHA-256 hash of a string"""
    return hashlib.sha256(text.encode()).hexdigest()

def utc_now() -> datetime:
    """Get current UTC datetime"""
    return datetime.now(timezone.utc)

def format_datetime(dt: datetime) -> str:
    """Format datetime for API responses"""
    return dt.strftime('%Y-%m-%dT%H:%M:%S.%fZ')

def sanitize_search_query(query: str) -> str:
    """Sanitize search query to prevent SQL injection"""
    if not query:
        return ""
    
    # Remove SQL injection attempts
    dangerous_chars = ['%', '_', ';', '--', '/*', '*/', 'xp_', 'sp_']
    sanitized = query
    
    for char in dangerous_chars:
        sanitized = sanitized.replace(char, '')
    
    return sanitized.strip()

def paginate_query(query, page: int, size: int):
    """Apply pagination to SQLAlchemy query"""
    offset = (page - 1) * size
    return query.offset(offset).limit(size)

def build_response_metadata(
    total: int, 
    page: int, 
    size: int, 
    additional_data: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Build pagination metadata for API responses"""
    pages = (total + size - 1) // size  # Ceiling division
    
    metadata = {
        "pagination": {
            "total": total,
            "page": page,
            "size": size,
            "pages": pages,
            "has_next": page < pages,
            "has_prev": page > 1
        }
    }
    
    if additional_data:
        metadata.update(additional_data)
    
    return metadata

# tests/conftest.py
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.database import get_db, Base
from app.models.user import User, UserRole
from app.core.security import get_password_hash

# Test database URL
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db

@pytest.fixture(scope="function")
def db():
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)

@pytest.fixture(scope="function")
def client():
    with TestClient(app) as c:
        yield c

@pytest.fixture
def test_user(db):
    user = User(
        email="test@example.com",
        username="testuser",
        full_name="Test User",
        password_hashword=get_password_hash("TestPassword123!"),
        is_active=True,
        is_verified=True,
        role=UserRole.USER
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

@pytest.fixture
def admin_user(db):
    admin = User(
        email="admin@example.com",
        username="admin",
        full_name="Admin User",
        password_hashword=get_password_hash("AdminPassword123!"),
        is_active=True,
        is_verified=True,
        role=UserRole.ADMIN
    )
    db.add(admin)
    db.commit()
    db.refresh(admin)
    return admin

@pytest.fixture
def user_token(client, test_user):
    response = client.post(
        "/api/v1/auth/login",
        json={
            "email_or_username": test_user.email,
            "password": "TestPassword123!"
        }
    )
    return response.json()["access_token"]

@pytest.fixture
def admin_token(client, admin_user):
    response = client.post(
        "/api/v1/auth/login",
        json={
            "email_or_username": admin_user.email,
            "password": "AdminPassword123!"
        }
    )
    return response.json()["access_token"]

# tests/test_auth.py
import pytest
from fastapi.testclient import TestClient

def test_register_user(client: TestClient):
    """Test user registration"""
    response = client.post(
        "/api/v1/auth/register",
        json={
            "email": "newuser@example.com",
            "username": "newuser",
            "full_name": "New User",
            "password": "NewPassword123!",
            "confirm_password": "NewPassword123!"
        }
    )
    assert response.status_code == 201
    data = response.json()
    assert data["email"] == "newuser@example.com"
    assert data["username"] == "newuser"
    assert data["full_name"] == "New User"
    assert "password_hashword" not in data

def test_register_user_duplicate_email(client: TestClient, test_user):
    """Test registration with duplicate email"""
    response = client.post(
        "/api/v1/auth/register",
        json={
            "email": test_user.email,
            "username": "differentuser",
            "full_name": "Different User",
            "password": "Password123!",
            "confirm_password": "Password123!"
        }
    )
    assert response.status_code == 409
    assert "Email already registered" in response.json()["error"]["message"]

def test_login_success(client: TestClient, test_user):
    """Test successful login"""
    response = client.post(
        "/api/v1/auth/login",
        json={
            "email_or_username": test_user.email,
            "password": "TestPassword123!"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"

def test_login_invalid_credentials(client: TestClient, test_user):
    """Test login with invalid credentials"""
    response = client.post(
        "/api/v1/auth/login",
        json={
            "email_or_username": test_user.email,
            "password": "wrongpassword"
        }
    )
    assert response.status_code == 401
    assert "Invalid credentials" in response.json()["error"]["message"]

def test_get_current_user(client: TestClient, user_token):
    """Test getting current user profile"""
    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {user_token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == "test@example.com"
    assert data["username"] == "testuser"

def test_get_current_user_unauthorized(client: TestClient):
    """Test getting current user without token"""
    response = client.get("/api/v1/auth/me")
    assert response.status_code == 403

# tests/test_users.py
import pytest
from fastapi.testclient import TestClient

def test_get_user_profile(client: TestClient, user_token, test_user):
    """Test getting user profile"""
    response = client.get(
        f"/api/v1/users/{test_user.id}",
        headers={"Authorization": f"Bearer {user_token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == test_user.id
    assert data["username"] == test_user.username

def test_update_user_profile(client: TestClient, user_token):
    """Test updating user profile"""
    response = client.put(
        "/api/v1/users/me",
        headers={"Authorization": f"Bearer {user_token}"},
        json={
            "full_name": "Updated Test User",
            "bio": "This is my updated bio"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["full_name"] == "Updated Test User"
    assert data["bio"] == "This is my updated bio"

def test_get_users_list(client: TestClient):
    """Test getting users list"""
    response = client.get("/api/v1/users")
    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert "total" in data
    assert "page" in data

# tests/test_admin.py
import pytest
from fastapi.testclient import TestClient

def test_admin_create_user(client: TestClient, admin_token):
    """Test admin creating a user"""
    response = client.post(
        "/api/v1/admin/users",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "email": "adminuser@example.com",
            "username": "adminuser",
            "full_name": "Admin Created User",
            "password": "AdminPassword123!",
            "role": "user",
            "is_active": True,
            "is_verified": True
        }
    )
    assert response.status_code == 201
    data = response.json()
    assert data["email"] == "adminuser@example.com"
    assert data["is_verified"] == True

def test_admin_get_users(client: TestClient, admin_token):
    """Test admin getting all users"""
    response = client.get(
        "/api/v1/admin/users",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert "total" in data

def test_admin_get_stats(client: TestClient, admin_token):
    """Test admin getting user statistics"""
    response = client.get(
        "/api/v1/admin/stats",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "total_users" in data
    assert "active_users" in data
    assert "verified_users" in data

def test_non_admin_access_denied(client: TestClient, user_token):
    """Test non-admin user cannot access admin endpoints"""
    response = client.get(
        "/api/v1/admin/users",
        headers={"Authorization": f"Bearer {user_token}"}
    )
    assert response.status_code == 403