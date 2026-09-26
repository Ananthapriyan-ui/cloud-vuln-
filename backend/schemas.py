import re
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, EmailStr, field_validator, model_validator


# ──────────────────────────────────────────────
# Auth Schemas
# ──────────────────────────────────────────────

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    full_name: str

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r"[0-9]", v):
            raise ValueError("Password must contain at least one digit")
        return v

    @field_validator("full_name")
    @classmethod
    def validate_full_name(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Full name cannot be blank")
        if len(v) < 2 or len(v) > 150:
            raise ValueError("Full name must be between 2 and 150 characters")
        return v


class UserLogin(BaseModel):
    email: EmailStr
    password: str

    @field_validator("password")
    @classmethod
    def password_not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Password cannot be empty")
        return v


class UserResponse(BaseModel):
    id: int
    email: str
    full_name: str
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


class OAuthSyncRequest(BaseModel):
    email: EmailStr
    full_name: Optional[str] = None


class Token(BaseModel):
    access_token: str
    refresh_token: Optional[str] = None
    token_type: str = "bearer"
    user: UserResponse


class RefreshTokenRequest(BaseModel):
    refresh_token: str

    @field_validator("refresh_token")
    @classmethod
    def token_not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Refresh token cannot be empty")
        return v


class TokenData(BaseModel):
    email: Optional[str] = None


class ErrorResponse(BaseModel):
    error: bool = True
    message: str
    status_code: int


# ──────────────────────────────────────────────
# Dashboard Schemas
# ──────────────────────────────────────────────

class DashboardSummary(BaseModel):
    total_scans: int
    monitored_assets: int
    critical_vulnerabilities: int
    high_vulnerabilities: int
    medium_vulnerabilities: int
    low_vulnerabilities: int
    info_vulnerabilities: int
    active_scans: int
    compliance_score: float
    posture_score: int


class SeverityCount(BaseModel):
    name: str
    value: int
    color: str


class TrendPoint(BaseModel):
    date: str
    critical: int
    high: int
    medium: int


class RiskStatisticsResponse(BaseModel):
    severity_breakdown: List[SeverityCount]
    trend_history: List[TrendPoint]


# ──────────────────────────────────────────────
# Scan Schemas
# ──────────────────────────────────────────────

class ScanCreate(BaseModel):
    target: str
    provider: Optional[str] = "AWS US-East-1"
    scan_type: Optional[str] = "Cloud Misconfig"
    status: Optional[str] = "passed"
    critical_count: Optional[int] = 0
    high_count: Optional[int] = 0
    medium_count: Optional[int] = 0
    low_count: Optional[int] = 0
    risk_score: Optional[float] = 0.0
    duration: Optional[str] = "2m 15s"
    scan_data: Optional[str] = None

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Target cannot be blank")
        if len(v) > 500:
            raise ValueError("Target URL too long (max 500 chars)")
        return v

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: Optional[str]) -> str:
        allowed = {"passed", "critical", "high", "medium", "running", "failed"}
        if v and v not in allowed:
            raise ValueError(f"Status must be one of: {', '.join(sorted(allowed))}")
        return v or "passed"

    @field_validator("risk_score")
    @classmethod
    def validate_risk_score(cls, v: Optional[float]) -> float:
        if v is not None and not (0.0 <= v <= 10.0):
            raise ValueError("Risk score must be between 0.0 and 10.0")
        return v or 0.0


class ScanResponse(BaseModel):
    id: int
    scan_ref: str
    target: str
    provider: str
    scan_type: str
    status: str
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    risk_score: float
    duration: str
    scan_data: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


class VulnerabilityResponse(BaseModel):
    id: int
    cve_id: str
    title: str
    severity: str
    cvss_score: float
    component: str
    description: str
    remediation: str
    remediation_cmd: str
    scan_ref: str
    created_at: datetime

    class Config:
        from_attributes = True


class ScanDetailResponse(ScanResponse):
    vulnerabilities: List[VulnerabilityResponse] = []


# ──────────────────────────────────────────────
# Activity Schema
# ──────────────────────────────────────────────

class ActivityLogResponse(BaseModel):
    id: int
    text: str
    type: str
    time_ago: str
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# ──────────────────────────────────────────────
# Report Schema
# ──────────────────────────────────────────────

class ReportResponse(BaseModel):
    id: int
    report_ref: str
    scan_ref: str
    target: str
    executive_summary: str
    scan_type: str
    duration: str
    html_generated: bool
    csv_generated: bool
    created_at: datetime

    class Config:
        from_attributes = True

# ──────────────────────────────────────────────
# Security Analysis Schemas
# ──────────────────────────────────────────────

class SecurityAnalysisRequest(BaseModel):
    target_url: str

    @field_validator("target_url")
    @classmethod
    def validate_target_url(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Target URL cannot be blank")
        if len(v) > 2000:
            raise ValueError("Target URL too long (max 2000 chars)")
        # Basic sanity: strip dangerous chars
        dangerous = ["<", ">", '"', "'", ";", "`"]
        for ch in dangerous:
            if ch in v:
                raise ValueError(f"Target URL contains invalid character: {ch}")
        return v


class SSLSummary(BaseModel):
    cert_status: str
    issuer: str
    expiry_date: str
    tls_version: str
    is_valid: bool
    days_until_expiration: int
    recommendations: List[str]


class HeaderCheck(BaseModel):
    name: str
    present: bool
    value: Optional[str] = None
    risk_if_missing: str
    recommendation: str


class HeaderSummary(BaseModel):
    score: int
    passed_count: int
    total_count: int
    checks: List[HeaderCheck]


class CVEResult(BaseModel):
    cve_id: str
    cvss_score: float
    severity: str
    description: str
    published_date: str
    reference_url: str


class WhoisSummary(BaseModel):
    registrar: str
    creation_date: str
    expiry_date: str
    name_servers: List[str]
    domain_status: List[str]
    raw_text: Optional[str] = None


class OWASPFindingItem(BaseModel):
    owasp_id: str
    category: str
    title: str
    status: str  # Verified, Warning, Failed, Passed, Unable to Verify
    severity: str  # Critical, High, Medium, Low, Informational, Passed, Unable to Verify
    description: str
    evidence: str
    affected_component: str
    impact: str
    recommendation: str
    cvss_score: Optional[float] = None
    related_cve: Optional[str] = None
    reference: Optional[str] = None


class OWASPSummary(BaseModel):
    total_checks: int = 10
    passed_checks: int = 0
    failed_checks: int = 0
    warnings_count: int = 0
    unable_to_verify_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    overall_score: int = 100
    risk_level: str = "Low"
    findings: List[OWASPFindingItem] = []


class SecurityAnalysisResponse(BaseModel):
    target: str
    ip_address: str
    scan_timestamp: str
    status: str
    risk_level: str
    security_score: int
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    executive_summary: Optional[str] = None
    whois_summary: Optional[WhoisSummary] = None
    owasp_summary: Optional[OWASPSummary] = None
    ssl_summary: SSLSummary
    headers_summary: HeaderSummary
    cve_findings: List[CVEResult]
    recommendations: List[str]


# ──────────────────────────────────────────────
# Scan Comparison & Trend Schemas
# ──────────────────────────────────────────────

class ScanComparisonOption(BaseModel):
    id: int
    scan_ref: str
    target: str
    provider: str
    scan_type: str
    status: str
    risk_score: float
    security_score: int
    risk_level: str
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    total_findings: int
    duration: str
    created_at: str


class ComparisonSummary(BaseModel):
    security_status: str
    status_category: str  # improved, degraded, neutral
    previous_security_score: int
    latest_security_score: int
    score_difference: int
    percentage_change: float
    findings_fixed_count: int
    new_findings_count: int
    persistent_findings_count: int
    critical_change: int
    high_change: int
    medium_change: int
    low_change: int
    owasp_improvements: int
    owasp_regressions: int
    cve_improvements: int
    cve_regressions: int
    header_improvements: int
    header_regressions: int
    tls_status: str


class ScanComparisonResponse(BaseModel):
    previous_scan: ScanComparisonOption
    latest_scan: ScanComparisonOption
    summary: ComparisonSummary
    severity_comparison: dict
    vulnerability_changes: dict
    owasp_comparison: List[dict]
    cve_comparison: dict
    header_comparison: dict
    ssl_comparison: dict


class SecurityTrendPoint(BaseModel):
    scan_ref: str
    target: str
    date: str
    security_score: int
    risk_score: float


class SeverityTrendPoint(BaseModel):
    scan_ref: str
    target: str
    date: str
    critical: int
    high: int
    medium: int
    low: int
    total: int


class ScanTrendResponse(BaseModel):
    has_sufficient_data: bool
    message: Optional[str] = None
    total_scans: int
    security_trend: List[SecurityTrendPoint] = []
    severity_trend: List[SeverityTrendPoint] = []



