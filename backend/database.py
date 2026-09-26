import os
import logging
from sqlalchemy import create_engine, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import QueuePool

import config

logger = logging.getLogger("CloudVulnDB")

raw_db_url = (config.settings.DATABASE_URL or os.getenv("DATABASE_URL") or "").strip()

if not raw_db_url:
    raise RuntimeError(
        "CRITICAL DATABASE CONFIGURATION ERROR:\n"
        "DATABASE_URL is not set in environment or config.\n"
        "CloudVuln is strictly configured to use Supabase PostgreSQL.\n"
        "Please provide a valid PostgreSQL connection string in DATABASE_URL."
    )

# Normalize postgres URL for modern psycopg driver:
# e.g., postgres:// or postgresql:// -> postgresql+psycopg://
if raw_db_url.startswith("postgres://"):
    SQLALCHEMY_DATABASE_URL = raw_db_url.replace("postgres://", "postgresql+psycopg://", 1)
elif raw_db_url.startswith("postgresql://") and not raw_db_url.startswith("postgresql+"):
    SQLALCHEMY_DATABASE_URL = raw_db_url.replace("postgresql://", "postgresql+psycopg://", 1)
else:
    SQLALCHEMY_DATABASE_URL = raw_db_url

# Production PostgreSQL engine configuration with pooling, pre-ping & SSL
engine_kwargs = {
    "pool_pre_ping": True,
    "pool_recycle": 300,
    "echo": False,
}

if "postgresql" in SQLALCHEMY_DATABASE_URL:
    engine_kwargs.update({
        "poolclass": QueuePool,
        "pool_size": 10,
        "max_overflow": 20,
        "pool_timeout": 30,
    })
    # Add connect_args for SSL if not already specified in query string
    connect_args = {}
    if "sslmode" not in SQLALCHEMY_DATABASE_URL:
        connect_args["sslmode"] = "require"
    if connect_args:
        engine_kwargs["connect_args"] = connect_args

try:
    engine = create_engine(SQLALCHEMY_DATABASE_URL, **engine_kwargs)
except Exception as e:
    logger.critical(f"Failed to create database engine: {e}")
    raise

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)

Base = declarative_base()


def get_db():
    """Dependency: yields a DB session per request, always closes on exit."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def check_db_connection() -> bool:
    """Verifies that the Supabase PostgreSQL connection is active and responsive."""
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception as e:
        logger.error(f"Database connectivity check failed: {e}")
        return False


def init_db():
    """Create all tables in Supabase PostgreSQL and perform schema upgrades if needed."""
    from sqlalchemy import inspect
    import models

    try:
        models.Base.metadata.create_all(bind=engine)
        with engine.connect() as conn:
            inspector = inspect(engine)
            tables = inspector.get_table_names()
            if "users" in tables:
                columns = [c["name"] for c in inspector.get_columns("users")]
                if "last_login" not in columns:
                    conn.execute(text("ALTER TABLE users ADD COLUMN last_login TIMESTAMP;"))
                    conn.commit()
            if "reports" in tables:
                columns = [c["name"] for c in inspector.get_columns("reports")]
                if "storage_path" not in columns:
                    conn.execute(text("ALTER TABLE reports ADD COLUMN storage_path VARCHAR(500);"))
                    conn.commit()
                if "file_name" not in columns:
                    conn.execute(text("ALTER TABLE reports ADD COLUMN file_name VARCHAR(255);"))
                    conn.commit()
                if "file_type" not in columns:
                    conn.execute(text("ALTER TABLE reports ADD COLUMN file_type VARCHAR(20);"))
                    conn.commit()
        logger.info("Supabase PostgreSQL database schema verified and initialized.")
    except Exception as e:
        logger.error(f"Error during init_db(): {e}")
        raise
