import datetime
from typing import Any
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Float, ForeignKey, Index, Text
from sqlalchemy.orm import relationship
from database import Base


def now_utc():
    return datetime.datetime.now(datetime.timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Any = Column(Integer, primary_key=True, index=True)
    email: Any = Column(String(254), unique=True, index=True, nullable=False)
    full_name: Any = Column(String(150), nullable=False)
    hashed_password: Any = Column(String(255), nullable=False)
    is_active: Any = Column(Boolean, default=True, nullable=False)
    created_at: Any = Column(DateTime, default=now_utc)
    last_login: Any = Column(DateTime, nullable=True)

    __table_args__ = (
        Index("ix_users_email_active", "email", "is_active"),
    )


class Scan(Base):
    __tablename__ = "scans"

    id: Any = Column(Integer, primary_key=True, index=True)
    scan_ref: Any = Column(String(50), unique=True, index=True, nullable=False)
    target: Any = Column(String(500), nullable=False)
    provider: Any = Column(String(100), default="AWS US-East-1")
    scan_type: Any = Column(String(100), default="Cloud Misconfig")
    status: Any = Column(String(30), default="passed")  # critical, high, passed, running, failed
    critical_count: Any = Column(Integer, default=0, nullable=False)
    high_count: Any = Column(Integer, default=0, nullable=False)
    medium_count: Any = Column(Integer, default=0, nullable=False)
    low_count: Any = Column(Integer, default=0, nullable=False)
    risk_score: Any = Column(Float, default=0.0, nullable=False)
    duration: Any = Column(String(30), default="2m 15s")
    owasp_version: Any = Column(String(10), default="2025")
    user_id: Any = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    scan_data: Any = Column(Text, nullable=True)  # Store JSON of full analysis results
    created_at: Any = Column(DateTime, default=now_utc, index=True)

    vulnerabilities = relationship(
        "Vulnerability",
        back_populates="scan",
        cascade="all, delete-orphan",
        lazy="select",
    )

    __table_args__ = (
        Index("ix_scans_status_created", "status", "created_at"),
        Index("ix_scans_risk_score", "risk_score"),
    )


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id: Any = Column(Integer, primary_key=True, index=True)
    cve_id: Any = Column(String(30), index=True, nullable=False)
    title: Any = Column(String(300), nullable=False)
    severity: Any = Column(String(20), nullable=False, index=True)
    cvss_score: Any = Column(Float, default=5.0, nullable=False)
    component: Any = Column(String(200), nullable=False)
    description: Any = Column(Text, nullable=False)
    remediation: Any = Column(Text, nullable=False)
    remediation_cmd: Any = Column(Text, nullable=False)
    scan_ref: Any = Column(String(50), ForeignKey("scans.scan_ref", ondelete="CASCADE"), nullable=False, index=True)
    created_at: Any = Column(DateTime, default=now_utc)

    scan = relationship("Scan", back_populates="vulnerabilities")

    __table_args__ = (
        Index("ix_vuln_scan_severity", "scan_ref", "severity"),
    )


class ActivityLog(Base):
    __tablename__ = "activity_logs"

    id: Any = Column(Integer, primary_key=True, index=True)
    text: Any = Column(String(500), nullable=False)
    type: Any = Column(String(20), default="info")  # info, success, warning, error
    time_ago: Any = Column(String(50), default="Just now")
    user_id: Any = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True)
    created_at: Any = Column(DateTime, default=now_utc, index=True)


class Report(Base):
    __tablename__ = "reports"

    id: Any = Column(Integer, primary_key=True, index=True)
    report_ref: Any = Column(String(50), unique=True, index=True, nullable=False)
    scan_ref: Any = Column(String(50), ForeignKey("scans.scan_ref", ondelete="CASCADE"), nullable=False)
    target: Any = Column(String(500), nullable=False)
    executive_summary: Any = Column(Text, nullable=False)
    scan_type: Any = Column(String(100), default="Cloud Misconfig")
    duration: Any = Column(String(30), default="2m 15s")
    owasp_version: Any = Column(String(10), default="2025")
    html_generated: Any = Column(Boolean, default=False)
    csv_generated: Any = Column(Boolean, default=False)
    file_name: Any = Column(String(255), nullable=True)
    file_type: Any = Column(String(20), nullable=True)  # html, csv
    storage_path: Any = Column(String(500), nullable=True)
    created_at: Any = Column(DateTime, default=now_utc)
