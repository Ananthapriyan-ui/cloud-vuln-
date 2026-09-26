#!/usr/bin/env python3
"""
CloudVuln — Supabase PostgreSQL Schema Export & Data Backup Utility

Since the primary database is Supabase PostgreSQL, backups are handled
via Supabase's built-in Point-in-Time Recovery (PITR) and automated
daily backups (available on Pro plan).

This script exports scan and report data from Supabase PostgreSQL to
a local JSON snapshot as a supplementary backup artifact.

Usage:
    cd backend
    python backup_db.py

Requires DATABASE_URL to be set in backend/.env pointing to Supabase PostgreSQL.
"""
import os
import sys
import json
import datetime
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger("BackupUtility")


def run_backup(backup_dir: str = None, keep_count: int = 7):
    """
    Exports all scans, users (without passwords), and reports from
    Supabase PostgreSQL to a local JSON snapshot.
    """
    try:
        from database import SessionLocal, check_db_connection
        import models
    except RuntimeError as e:
        logger.critical(str(e))
        sys.exit(1)

    if not check_db_connection():
        logger.critical(
            "Cannot connect to Supabase PostgreSQL. "
            "Ensure DATABASE_URL is set correctly in backend/.env."
        )
        sys.exit(1)

    base_dir = os.path.dirname(os.path.abspath(__file__))
    if not backup_dir:
        backup_dir = os.environ.get("BACKUP_DIR", os.path.join(base_dir, "backups"))
    os.makedirs(backup_dir, exist_ok=True)

    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
    backup_filename = f"cloudvuln_backup_{timestamp}.json"
    backup_path = os.path.join(backup_dir, backup_filename)

    logger.info(f"Starting Supabase PostgreSQL data export to '{backup_path}'...")

    db = SessionLocal()
    try:
        scans = db.query(models.Scan).all()
        reports = db.query(models.Report).all()
        users = db.query(models.User).all()
        logs = db.query(models.ActivityLog).order_by(models.ActivityLog.created_at.desc()).limit(500).all()

        def dt(v):
            return v.isoformat() if v else None

        snapshot = {
            "exported_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "database": "Supabase PostgreSQL",
            "counts": {
                "scans": len(scans),
                "reports": len(reports),
                "users": len(users),
                "activity_logs": len(logs),
            },
            "scans": [
                {
                    "id": s.id,
                    "scan_ref": s.scan_ref,
                    "target": s.target,
                    "provider": s.provider,
                    "scan_type": s.scan_type,
                    "status": s.status,
                    "critical_count": s.critical_count,
                    "high_count": s.high_count,
                    "medium_count": s.medium_count,
                    "low_count": s.low_count,
                    "risk_score": s.risk_score,
                    "duration": s.duration,
                    "created_at": dt(s.created_at),
                }
                for s in scans
            ],
            "reports": [
                {
                    "id": r.id,
                    "report_ref": r.report_ref,
                    "scan_ref": r.scan_ref,
                    "target": r.target,
                    "scan_type": r.scan_type,
                    "html_generated": r.html_generated,
                    "csv_generated": r.csv_generated,
                    "storage_path": r.storage_path,
                    "created_at": dt(r.created_at),
                }
                for r in reports
            ],
            "users": [
                {
                    "id": u.id,
                    "email": u.email,
                    "full_name": u.full_name,
                    "is_active": u.is_active,
                    "created_at": dt(u.created_at),
                    "last_login": dt(u.last_login),
                    # NOTE: hashed_password is intentionally excluded from backups
                }
                for u in users
            ],
            "recent_activity": [
                {"id": a.id, "text": a.text, "type": a.type, "created_at": dt(a.created_at)}
                for a in logs
            ],
        }

        with open(backup_path, "w", encoding="utf-8") as f:
            json.dump(snapshot, f, indent=2, default=str)

        file_size_kb = os.path.getsize(backup_path) / 1024
        logger.info(
            f"Backup completed: {backup_path} ({file_size_kb:.2f} KB) | "
            f"scans={len(scans)}, reports={len(reports)}, users={len(users)}"
        )

        # Clean up old backups, keeping only `keep_count` most recent
        existing_backups = sorted(
            [
                os.path.join(backup_dir, f)
                for f in os.listdir(backup_dir)
                if f.startswith("cloudvuln_backup_") and f.endswith(".json")
            ],
            key=os.path.getmtime,
        )
        if len(existing_backups) > keep_count:
            for old in existing_backups[:-keep_count]:
                os.remove(old)
                logger.info(f"Removed old backup: {os.path.basename(old)}")

        return backup_path

    except Exception as e:
        logger.error(f"Backup failed: {e}")
        sys.exit(1)
    finally:
        db.close()


if __name__ == "__main__":
    run_backup()
