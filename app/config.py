from pydantic_settings import BaseSettings

import os
from dotenv import load_dotenv
load_dotenv()

class Settings(BaseSettings):
    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL")
    
    # Security
    SECRET_KEY: str = os.getenv("SECRET_KEY")
    ALGORITHM: str = os.getenv("ALGORITHM", "HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))
    REFRESH_TOKEN_EXPIRE_DAYS: int = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", 7))
    
    # Redis (for caching and real-time features)
    REDIS_URL: str = "redis://localhost:6379"
    
    # API Settings
    API_V1_STR: str = os.getenv("API_V1_STR", "/api/v1")
    PROJECT_NAME: str = os.getenv("PROJECT_NAME", "Trading Platform API")
    VERSION: str = os.getenv("VERSION", "1.0.0")
    PROJECT_DESCRIPTION: str = os.getenv("PROJECT_DESCRIPTION", "A comprehensive trading platform with messaging and transaction management")
    
    # CORS
    BACKEND_CORS_ORIGINS: list = ["http://localhost:3000", "http://localhost:8080"]
    
    # Pagination
    DEFAULT_PAGE_SIZE: int = 20
    MAX_PAGE_SIZE: int = 100
    
    # File uploads
    MAX_FILE_SIZE: int = 10 * 1024 * 1024  # 10MB
    ALLOWED_FILE_TYPES: list = ["image/jpeg", "image/png", "image/gif"]
    
    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()



