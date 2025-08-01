from sqlalchemy.orm import Session
from app.database import SessionLocal, engine
from app.models.user import User, UserRole
from app.core.security import get_password_hash

def create_superuser():
    db = SessionLocal()
    
    # Check if super admin already exists
    existing_admin = db.query(User).filter(User.role == UserRole.SUPER_ADMIN).first()
    if existing_admin:
        print("Super admin already exists!")
        return
    
    # Create super admin
    admin = User(
        email="admin@yourdomain.com",
        username="superadmin",
        full_name="Super Administrator",
        password_hash=get_password_hash("ChangeThisPassword123!"),
        role=UserRole.SUPER_ADMIN,
        is_active=True,
        is_verified=True
    )
    
    db.add(admin)
    db.commit()
    print("Super admin created successfully!")
    print("Email: admin@yourdomain.com")
    print("Password: ChangeThisPassword123!")
    print("Please change the password after first login!")

if __name__ == "__main__":
    create_superuser()



### execute this script to create a superuser in the database
# Make sure to run this script in an environment where the database is accessible.:
### python create_superuser.py