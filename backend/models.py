import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Float, ForeignKey, Index, Text
from sqlalchemy.orm import relationship
from database import Base


def now_utc():
    return datetime.datetime.now(datetime.timezone.utc)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(254), unique=True, index=True, nullable=False)
    full_name = Column(String(150), nullable=False)
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=now_utc)
    last_login = Column(DateTime, nullable=True)

    __table_args__ = (
        Index("ix_users_email_active", "email", "is_active"),
    )


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    scan_ref = Column(String(50), unique=True, index=True, nullable=False)
    target = Column(String(500), nullable=False)
    provider = Column(String(100), default="AWS US-East-1")
    scan_type = Column(String(100), default="Cloud Misconfig")
    status = Column(String(30), default="passed")  # critical, high, passed, running, failed
    critical_count = Column(Integer, default=0, nullable=False)
    high_count = Column(Integer, default=0, nullable=False)
    medium_count = Column(Integer, default=0, nullable=False)
    low_count = Column(Integer, default=0, nullable=False)
    risk_score = Column(Float, default=0.0, nullable=False)
    duration = Column(String(30), default="2m 15s")
    scan_data = Column(Text, nullable=True)  # Store JSON of full analysis results
    created_at = Column(DateTime, default=now_utc, index=True)

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

    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String(30), index=True, nullable=False)
    title = Column(String(300), nullable=False)
    severity = Column(String(20), nullable=False, index=True)
    cvss_score = Column(Float, default=5.0, nullable=False)
    component = Column(String(200), nullable=False)
    description = Column(Text, nullable=False)
    remediation = Column(Text, nullable=False)
    remediation_cmd = Column(Text, nullable=False)
    scan_ref = Column(String(50), ForeignKey("scans.scan_ref", ondelete="CASCADE"), nullable=False, index=True)
    created_at = Column(DateTime, default=now_utc)

    scan = relationship("Scan", back_populates="vulnerabilities")

    __table_args__ = (
        Index("ix_vuln_scan_severity", "scan_ref", "severity"),
    )


class ActivityLog(Base):
    __tablename__ = "activity_logs"

    id = Column(Integer, primary_key=True, index=True)
    text = Column(String(500), nullable=False)
    type = Column(String(20), default="info")  # info, success, warning, error
    time_ago = Column(String(50), default="Just now")
    created_at = Column(DateTime, default=now_utc, index=True)


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    report_ref = Column(String(50), unique=True, index=True, nullable=False)
    scan_ref = Column(String(50), ForeignKey("scans.scan_ref", ondelete="CASCADE"), nullable=False)
    target = Column(String(500), nullable=False)
    executive_summary = Column(Text, nullable=False)
    scan_type = Column(String(100), default="Cloud Misconfig")
    duration = Column(String(30), default="2m 15s")
    html_generated = Column(Boolean, default=False)
    csv_generated = Column(Boolean, default=False)
    file_name = Column(String(255), nullable=True)
    file_type = Column(String(20), nullable=True)  # html, csv
    storage_path = Column(String(500), nullable=True)
    created_at = Column(DateTime, default=now_utc)
