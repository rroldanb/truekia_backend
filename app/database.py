from sqlalchemy import create_engine, MetaData, event, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool, QueuePool
from sqlalchemy.engine import Engine
import redis
import logging
from contextlib import contextmanager
from typing import Generator, Optional
import time
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============================================================================
# DATABASE CONFIGURATION
# ============================================================================

# Get database URL from environment
DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise ValueError("DATABASE_URL environment variable is required")

# Determine if we're using SQLite (for development)
IS_SQLITE = DATABASE_URL.startswith("sqlite")

# Engine configuration
if IS_SQLITE:
    # SQLite configuration for development
    engine = create_engine(
        DATABASE_URL,
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
        pool_pre_ping=True,
        echo=bool(os.getenv("SQL_ECHO", False))  # Set to True for SQL query logging
    )
else:
    # PostgreSQL configuration for production
    engine = create_engine(
        DATABASE_URL,
        poolclass=QueuePool,
        pool_size=20,
        max_overflow=30,
        pool_recycle=3600,  # Recycle connections every hour
        pool_pre_ping=True,
        echo=bool(os.getenv("SQL_ECHO", False))
    )

# Session configuration
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
    expire_on_commit=False
)

# Metadata for migrations
metadata = MetaData()

# ============================================================================
# BASE MODEL CLASS
# ============================================================================

class BaseModel:
    """Base model class with common functionality"""
    
    def to_dict(self, exclude_fields: Optional[list] = None) -> dict:
        """Convert model instance to dictionary"""
        exclude_fields = exclude_fields or []
        result = {}
        
        for column in self.__table__.columns:
            if column.name not in exclude_fields:
                value = getattr(self, column.name)
                # Handle datetime serialization
                if hasattr(value, 'isoformat'):
                    value = value.isoformat()
                result[column.name] = value
        
        return result
    
    def update_from_dict(self, data: dict, exclude_fields: Optional[list] = None):
        """Update model instance from dictionary"""
        exclude_fields = exclude_fields or ['id', 'created_at']
        
        for key, value in data.items():
            if key not in exclude_fields and hasattr(self, key):
                setattr(self, key, value)
    
    def __repr__(self):
        """String representation of the model"""
        class_name = self.__class__.__name__
        if hasattr(self, 'id'):
            return f"<{class_name}(id={self.id})>"
        return f"<{class_name}()>"

# Create base class with custom functionality
Base = declarative_base(cls=BaseModel, metadata=metadata)

# ============================================================================
# REDIS CONFIGURATION
# ============================================================================

def get_redis_client():
    """Get Redis client with error handling"""
    try:
        redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
        client = redis.from_url(
            redis_url, 
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=5,
            retry_on_timeout=True,
            health_check_interval=30
        )
        
        # Test connection
        client.ping()
        logger.info("Redis connection established successfully")
        return client
        
    except Exception as e:
        logger.warning(f"Redis connection failed: {e}. Some features may be limited.")
        return None

# Initialize Redis client
redis_client = get_redis_client()

# ============================================================================
# DATABASE SESSION DEPENDENCIES
# ============================================================================

def get_db() -> Generator[Session, None, None]:
    """
    Dependency that provides a SQLAlchemy database session.
    
    Yields
    ------
    db : Session
        SQLAlchemy session object.
    """
    db = SessionLocal()
    try:
        yield db
    except Exception as e:
        logger.error(f"Database session error: {e}")
        db.rollback()
        raise
    finally:
        db.close()


@contextmanager
def get_db_context():
    """
    Context manager for database sessions.
    
    Usage:
        with get_db_context() as db:
            # Use db session
            pass
    """
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception as e:
        logger.error(f"Database context error: {e}")
        db.rollback()
        raise
    finally:
        db.close()


def get_async_db():
    """
    Placeholder for async database session (future implementation)
    """
    # TODO: Implement async database sessions for high-performance operations
    pass

# ============================================================================
# DATABASE UTILITIES
# ============================================================================

def init_db():
    """Initialize database tables"""
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables created successfully")
    except Exception as e:
        logger.error(f"Failed to create database tables: {e}")
        raise


def drop_db():
    """Drop all database tables (use with caution!)"""
    try:
        Base.metadata.drop_all(bind=engine)
        logger.info("Database tables dropped successfully")
    except Exception as e:
        logger.error(f"Failed to drop database tables: {e}")
        raise


def check_db_connection() -> bool:
    """Check if database connection is working"""
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return True
    except Exception as e:
        logger.error(f"Database connection check failed: {e}")
        return False


def get_db_info() -> dict:
    """Get database information"""
    try:
        with engine.connect() as connection:
            if IS_SQLITE:
                result = connection.execute(text("SELECT sqlite_version()"))
                version = result.scalar()
                db_type = "SQLite"
            else:
                result = connection.execute(text("SELECT version()"))
                version = result.scalar()
                db_type = "PostgreSQL"
            
            return {
                "type": db_type,
                "version": version,
                "url": DATABASE_URL.split("@")[-1] if "@" in DATABASE_URL else "localhost",
                "pool_size": engine.pool.size() if hasattr(engine.pool, 'size') else "N/A",
                "checked_in": engine.pool.checkedin() if hasattr(engine.pool, 'checkedin') else "N/A",
                "checked_out": engine.pool.checkedout() if hasattr(engine.pool, 'checkedout') else "N/A",
            }
    except Exception as e:
        logger.error(f"Failed to get database info: {e}")
        return {"error": str(e)}


def get_redis_info() -> dict:
    """Get Redis information"""
    if not redis_client:
        return {"status": "disconnected", "error": "Redis not available"}
    
    try:
        info = redis_client.info()
        return {
            "status": "connected",
            "version": info.get("redis_version"),
            "used_memory": info.get("used_memory_human"),
            "connected_clients": info.get("connected_clients"),
            "total_commands_processed": info.get("total_commands_processed"),
        }
    except Exception as e:
        logger.error(f"Failed to get Redis info: {e}")
        return {"status": "error", "error": str(e)}

# ============================================================================
# DATABASE HEALTH CHECKS
# ============================================================================

def health_check() -> dict:
    """Comprehensive health check for database and Redis"""
    health_status = {
        "database": {
            "status": "healthy" if check_db_connection() else "unhealthy",
            "details": get_db_info()
        },
        "redis": get_redis_info(),
        "timestamp": time.time()
    }
    
    return health_status

# ============================================================================
# TRANSACTION UTILITIES
# ============================================================================

@contextmanager
def db_transaction():
    """Context manager for database transactions with automatic rollback"""
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception as e:
        logger.error(f"Transaction failed, rolling back: {e}")
        db.rollback()
        raise
    finally:
        db.close()


def execute_in_transaction(func, *args, **kwargs):
    """Execute a function within a database transaction"""
    with db_transaction() as db:
        return func(db, *args, **kwargs)

# ============================================================================
# DATABASE EVENTS
# ============================================================================

@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    """Set SQLite pragma for foreign key constraints"""
    if IS_SQLITE:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


@event.listens_for(Engine, "before_cursor_execute")
def receive_before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
    """Log slow queries (optional)"""
    if os.getenv("LOG_SLOW_QUERIES", "false").lower() == "true":
        context._query_start_time = time.time()


@event.listens_for(Engine, "after_cursor_execute")
def receive_after_cursor_execute(conn, cursor, statement, parameters, context, executemany):
    """Log slow queries (optional)"""
    if os.getenv("LOG_SLOW_QUERIES", "false").lower() == "true":
        total = time.time() - context._query_start_time
        if total > float(os.getenv("SLOW_QUERY_THRESHOLD", "1.0")):
            logger.warning(f"Slow query: {total:.2f}s - {statement[:100]}...")

# ============================================================================
# CACHE UTILITIES (Redis)
# ============================================================================

def cache_get(key: str, default=None):
    """Get value from Redis cache"""
    if not redis_client:
        return default
    
    try:
        value = redis_client.get(key)
        return value if value is not None else default
    except Exception as e:
        logger.error(f"Cache get error: {e}")
        return default


def cache_set(key: str, value: str, expire: int = 3600):
    """Set value in Redis cache with expiration"""
    if not redis_client:
        return False
    
    try:
        return redis_client.setex(key, expire, value)
    except Exception as e:
        logger.error(f"Cache set error: {e}")
        return False


def cache_delete(key: str):
    """Delete value from Redis cache"""
    if not redis_client:
        return False
    
    try:
        return redis_client.delete(key)
    except Exception as e:
        logger.error(f"Cache delete error: {e}")
        return False


def cache_exists(key: str) -> bool:
    """Check if key exists in Redis cache"""
    if not redis_client:
        return False
    
    try:
        return bool(redis_client.exists(key))
    except Exception as e:
        logger.error(f"Cache exists error: {e}")
        return False

# ============================================================================
# BACKUP UTILITIES
# ============================================================================

def backup_database(backup_path: str = None):
    """Create database backup (SQLite only)"""
    if not IS_SQLITE:
        raise NotImplementedError("Backup only supported for SQLite databases")
    
    import shutil
    from datetime import datetime
    
    if not backup_path:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = f"backup_{timestamp}.db"
    
    try:
        db_file = DATABASE_URL.replace("sqlite:///", "")
        shutil.copy2(db_file, backup_path)
        logger.info(f"Database backup created: {backup_path}")
        return backup_path
    except Exception as e:
        logger.error(f"Backup failed: {e}")
        raise

# ============================================================================
# MIGRATION UTILITIES
# ============================================================================

def get_alembic_config():
    """Get Alembic configuration for migrations"""
    try:
        from alembic.config import Config
        from alembic import command
        
        config = Config("alembic.ini")
        config.set_main_option("sqlalchemy.url", DATABASE_URL)
        return config
    except ImportError:
        logger.warning("Alembic not installed. Migration commands not available.")
        return None


def run_migrations():
    """Run database migrations"""
    config = get_alembic_config()
    if config:
        try:
            from alembic import command
            command.upgrade(config, "head")
            logger.info("Database migrations completed successfully")
        except Exception as e:
            logger.error(f"Migration failed: {e}")
            raise
    else:
        logger.warning("Cannot run migrations: Alembic not configured")

# ============================================================================
# INITIALIZATION
# ============================================================================

def initialize_application():
    """Initialize application database and cache"""
    logger.info("Initializing application...")
    
    # Check database connection
    if not check_db_connection():
        raise RuntimeError("Database connection failed")
    
    # Initialize tables
    init_db()
    
    # Log system information
    logger.info(f"Database info: {get_db_info()}")
    logger.info(f"Redis info: {get_redis_info()}")
    
    logger.info("Application initialized successfully")


# Run initialization if this module is imported
if __name__ != "__main__":
    # Only run basic checks when imported
    logger.info("Database module loaded")
else:
    # Full initialization when run directly
    initialize_application()