import re
from typing import Optional
from email_validator import validate_email, EmailNotValidError

def validate_password_strength(password: str) -> tuple[bool, list[str]]:
    """Validate password strength and return issues"""
    issues = []
    
    if len(password) < 8:
        issues.append("Password must be at least 8 characters long")
    
    if not any(c.isupper() for c in password):
        issues.append("Password must contain at least one uppercase letter")
    
    if not any(c.islower() for c in password):
        issues.append("Password must contain at least one lowercase letter")
    
    if not any(c.isdigit() for c in password):
        issues.append("Password must contain at least one digit")
    
    if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
        issues.append("Password must contain at least one special character")
    
    return len(issues) == 0, issues

def validate_username(username: str) -> tuple[bool, Optional[str]]:
    """Validate username format"""
    if len(username) < 3:
        return False, "Username must be at least 3 characters long"
    
    if len(username) > 50:
        return False, "Username must be less than 50 characters"
    
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False, "Username can only contain letters, numbers, and underscores"
    
    if username.startswith('_') or username.endswith('_'):
        return False, "Username cannot start or end with underscore"
    
    return True, None

def validate_phone_number(phone: str) -> tuple[bool, Optional[str]]:
    """Validate phone number format"""
    if not phone:
        return True, None  # Phone is optional
    
    # Remove spaces and common separators
    clean_phone = re.sub(r'[\s\-\(\)]', '', phone)
    
    # Basic international phone number validation
    if not re.match(r'^[+]?[1-9]?[0-9]{7,15}$', clean_phone):
        return False, "Invalid phone number format"
    
    return True, None

def validate_email_format(email: str) -> tuple[bool, Optional[str]]:
    """Validate email format"""
    try:
        validate_email(email)
        return True, None
    except EmailNotValidError as e:        return False, str(e)

