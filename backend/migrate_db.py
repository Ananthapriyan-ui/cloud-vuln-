#!/usr/bin/env python3
"""
CloudVuln — Supabase PostgreSQL Schema Verification Utility

This script verifies and applies any pending schema upgrades
to the Supabase PostgreSQL database without data loss.

Usage:
    cd backend
    python migrate_db.py

Requires DATABASE_URL to be set in backend/.env pointing to Supabase PostgreSQL.
"""
import os
import sys
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger("MigrateDB")


def run_migration():
    """Verify Supabase PostgreSQL schema and apply any pending column additions."""
    try:
        from database import engine, init_db, check_db_connection
    except RuntimeError as e:
        logger.critical(str(e))
        sys.exit(1)

    if not check_db_connection():
        logger.critical(
            "Cannot connect to Supabase PostgreSQL.\n"
            "Ensure DATABASE_URL is set correctly in backend/.env and "
            "your Supabase project is active."
        )
        sys.exit(1)

    logger.info("Connected to Supabase PostgreSQL. Running schema migration...")
    init_db()
    logger.info("Schema migration completed successfully.")


if __name__ == "__main__":
    run_migration()